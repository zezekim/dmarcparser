package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/api"
	"dmarcparser/internal/config"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/poller"
	"dmarcparser/internal/store"
	"dmarcparser/internal/webhook"
)

func main() {
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

	st := store.New(pool)
	m := metrics.New()
	wh := webhook.New(cfg.WebhookURL, cfg.WebhookSecret, m, log)
	pol := poller.New(cfg, st, m, wh, log)
	go pol.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           api.New(cfg, st, pol, m, wh, log),
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
