package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/api"
	"dmarcparser/internal/audit"
	"dmarcparser/internal/config"
	"dmarcparser/internal/digest"
	"dmarcparser/internal/enrich"
	"dmarcparser/internal/export"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/migrate"
	"dmarcparser/internal/pipeline"
	"dmarcparser/internal/poller"
	"dmarcparser/internal/retention"
	"dmarcparser/internal/rollup"
	"dmarcparser/internal/selectors"
	"dmarcparser/internal/store"
	"dmarcparser/internal/watchdog"
	"dmarcparser/internal/webhook"
)

func main() {
	backfillRollups := flag.Bool("backfill-rollups", false,
		"rebuild dmarc_agg_daily from report/rptrecord, then exit")
	backfillSources := flag.Bool("backfill-sources", false,
		"populate domain_source from existing reports, then exit")
	backfillSelectors := flag.Bool("backfill-selectors", false,
		"rebuild dkim_auth by re-parsing report.raw_xml, then exit")
	healthcheck := flag.Bool("healthcheck", false,
		"GET /healthz on the local API and exit 0/1 (for the container healthcheck)")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := migrate.Run(ctx, pool, log); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}

	// One-shot backfill modes: run after migrations, then exit.
	switch {
	case *backfillRollups:
		n, err := rollup.Backfill(ctx, pool)
		if err != nil {
			log.Error("backfill rollups", "err", err)
			os.Exit(1)
		}
		log.Info("rollup backfill complete", "rows", n)
		return
	case *backfillSources:
		if err := enrich.Backfill(ctx, pool); err != nil {
			log.Error("backfill sources", "err", err)
			os.Exit(1)
		}
		log.Info("sources backfill complete")
		return
	case *backfillSelectors:
		if err := selectors.Backfill(ctx, pool); err != nil {
			log.Error("backfill selectors", "err", err)
			os.Exit(1)
		}
		log.Info("selectors backfill complete")
		return
	}

	st := store.New(pool)
	m := metrics.New()
	wh := webhook.New(cfg.WebhookURLs, cfg.WebhookSecret, st, m, log)

	enr := enrich.New(cfg.EnrichWorkers, st, log)
	enr.Start(ctx)

	reg := pipeline.NewRegistry(log)
	reg.Register(wh) // webhook report.ingested stays first
	reg.Register(rollup.New(pool, log))
	// Intel after rollup: its anomaly check reads the day bucket the rollup
	// observer just updated.
	reg.Register(enrich.NewObserver(cfg, st, wh, enr, m, log))
	reg.Register(selectors.New(st, log))

	pol := poller.New(cfg, st, m, wh, reg, log)
	go pol.Run(ctx)

	wd := watchdog.New(cfg, st, m, wh, log)
	go wd.Run(ctx)
	go retention.New(cfg, pool, m, log).Run(ctx)

	dig := digest.New(cfg, pool, log)
	go dig.Run(ctx) // no-op unless PARSER_DIGEST_ENABLED=true

	plat := &api.PlatformDeps{
		Cfg:      cfg,
		Exporter: export.New(pool, log),
		Audit:    audit.New(pool, log),
		Digest:   dig,
		Pol:      pol,
		WH:       wh,
		Log:      log,
	}

	srv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           api.New(cfg, st, pol, m, wh, reg, wd, plat, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("api listening", "addr", cfg.APIAddr,
			"poller_enabled", cfg.IMAPAddr != "", "interval", cfg.PollInterval.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

// runHealthcheck probes the local /healthz; it reads only PARSER_API_ADDR so
// it works without the full config (DB URL, IMAP password) being valid.
func runHealthcheck() int {
	addr := os.Getenv("PARSER_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: bad PARSER_API_ADDR:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
