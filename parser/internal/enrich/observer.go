package enrich

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"dmarcparser/internal/config"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/pipeline"
	"dmarcparser/internal/report"
	"dmarcparser/internal/store"
)

// Notifier is the webhook surface the observer needs.
type Notifier interface {
	NotifyEvent(kind string, payload any)
}

// Observer is the INTEL pipeline observer: per record it upserts
// domain_source, enqueues enrichment, and fires sender.new for new pairs;
// per report it runs the day-bucket anomaly check against dmarc_agg_daily.
type Observer struct {
	cfg *config.Config
	st  *store.Store
	wh  Notifier
	enr *Enricher
	m   *metrics.Metrics
	log *slog.Logger
}

func NewObserver(cfg *config.Config, st *store.Store, wh Notifier, enr *Enricher,
	m *metrics.Metrics, log *slog.Logger) pipeline.Observer {
	return &Observer{cfg: cfg, st: st, wh: wh, enr: enr, m: m,
		log: log.With("component", "intel")}
}

func (o *Observer) OnIngest(ctx context.Context, ev pipeline.IngestEvent) {
	domain := ev.Report.Domain
	for _, rec := range ev.Report.Records {
		ip := recordIP(rec)
		if ip == "" {
			continue
		}
		aligned := rec.DKIMAlign == "pass" || rec.SPFAlign == "pass"
		var alignedN int64
		if aligned {
			alignedN = rec.Count
		}
		isNew, firstSeen, err := o.st.UpsertDomainSource(ctx, domain, ip, rec.Count, alignedN, ev.Result.Serial)
		if err != nil {
			o.log.Error("domain_source upsert", "domain", domain, "ip", ip, "err", err)
			continue
		}
		hint := ""
		if rec.DKIMDomain != nil {
			hint = *rec.DKIMDomain
		}
		o.enr.Enqueue(ip, hint)

		if isNew && (rec.Count >= o.cfg.NewSenderMinMsgs || !aligned) {
			ptr, _ := o.st.IPMetaPTR(ctx, ip) // best-effort, IP may be known from another domain
			o.wh.NotifyEvent("sender.new", map[string]any{
				"domain":     domain,
				"ip":         ip,
				"ptr":        ptr,
				"msgs":       rec.Count,
				"aligned":    alignedN,
				"serial":     ev.Result.Serial,
				"first_seen": firstSeen.UTC(),
			})
			o.log.Info("new sender", "domain", domain, "ip", ip,
				"msgs", rec.Count, "aligned", aligned, "serial", ev.Result.Serial)
		}
	}
	o.checkAnomaly(ctx, domain, ev.Report.Begin)
}

// checkAnomaly compares the report's begin-day unaligned volume against the
// trailing 30 days (mean + sigma*stddev, floored at AnomalyMinFails) and
// fires domain.anomaly at most once per (domain, day) via alert_state.
func (o *Observer) checkAnomaly(ctx context.Context, domain string, begin time.Time) {
	day := begin.UTC().Truncate(24 * time.Hour)
	rule := "anomaly:" + domain + ":" + day.Format("2006-01-02")

	last, err := o.st.AlertLastFired(ctx, rule)
	if err != nil {
		o.log.Error("anomaly suppression lookup", "rule", rule, "err", err)
		return
	}
	if !last.IsZero() {
		return
	}
	stats, err := o.st.DomainDayFailStats(ctx, domain, day)
	if err != nil {
		o.log.Error("anomaly stats", "domain", domain, "err", err)
		return
	}
	threshold := stats.Mean + o.cfg.AnomalySigma*stats.Stddev
	if floor := float64(o.cfg.AnomalyMinFails); threshold < floor {
		threshold = floor
	}
	if float64(stats.DayFails) < threshold {
		return
	}
	evidence := map[string]any{
		"domain":       domain,
		"day":          day.Format("2006-01-02"),
		"fails":        stats.DayFails,
		"mean_30d":     stats.Mean,
		"stddev_30d":   stats.Stddev,
		"sigma":        o.cfg.AnomalySigma,
		"threshold":    threshold,
		"history_days": stats.Days,
	}
	if err := o.st.MarkAlertFired(ctx, rule, evidence); err != nil {
		o.log.Error("anomaly mark fired", "rule", rule, "err", err)
	}
	o.wh.NotifyEvent("domain.anomaly", evidence)
	o.m.DomainAnomalies.Add(1)
	o.log.Warn("domain anomaly", "domain", domain, "day", evidence["day"],
		"fails", stats.DayFails, "threshold", threshold)
}

// recordIP renders a parsed record's source IP (stored as packed uint32 /
// 16-byte slice) back into its string form.
func recordIP(rec report.Record) string {
	switch {
	case rec.IPv4 != nil:
		v := uint32(*rec.IPv4)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
	case len(rec.IPv6) == 16:
		var b [16]byte
		copy(b[:], rec.IPv6)
		return netip.AddrFrom16(b).Unmap().String()
	}
	return ""
}
