// Package watchdog evaluates ingestion-health rules every 10 minutes and
// alerts via PARSER_ALERT_URL plus a "poller.degraded" webhook event. Each
// rule has a 6h cooldown persisted in alert_state so restarts do not re-fire.
package watchdog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"dmarcparser/internal/config"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/store"
	"dmarcparser/internal/webhook"
)

const (
	tickInterval = 10 * time.Minute
	cooldown     = 6 * time.Hour

	RuleSilence      = "silence"
	RulePollFailures = "poll_failures"
	RuleFailedSpike  = "failed_spike"
	RuleWebhookDead  = "webhook_dead"
)

type sample struct {
	ts     time.Time
	failed int64
}

type Watchdog struct {
	cfg    *config.Config
	st     *store.Store
	m      *metrics.Metrics
	wh     *webhook.Notifier
	log    *slog.Logger
	client *http.Client

	mu              sync.Mutex
	states          map[string]string // rule -> "ok" | "firing"
	failedSamples   []sample
	lastWebhookFail int64
}

func New(cfg *config.Config, st *store.Store, m *metrics.Metrics, wh *webhook.Notifier, log *slog.Logger) *Watchdog {
	return &Watchdog{
		cfg: cfg, st: st, m: m, wh: wh,
		log:    log.With("component", "watchdog"),
		client: &http.Client{Timeout: 15 * time.Second},
		states: map[string]string{
			RuleSilence: "ok", RulePollFailures: "ok",
			RuleFailedSpike: "ok", RuleWebhookDead: "ok",
		},
		lastWebhookFail: m.WebhookFailures.Load(),
	}
}

// States returns a copy of the current rule states for /healthz.
func (w *Watchdog) States() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]string, len(w.states))
	for k, v := range w.states {
		out[k] = v
	}
	return out
}

func (w *Watchdog) Run(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check(ctx)
		}
	}
}

func (w *Watchdog) check(ctx context.Context) {
	now := time.Now().UTC()

	// silence: nothing ingested for too long.
	silenceState := "ok"
	if last, err := w.st.LastIngestAt(ctx); err != nil {
		w.log.Error("last ingest lookup", "err", err)
	} else if !last.IsZero() && now.Sub(last) > w.cfg.AlertSilence {
		silenceState = "firing"
		w.fire(ctx, RuleSilence,
			fmt.Sprintf("no report ingested since %s", last.Format(time.RFC3339)),
			map[string]any{"last_ingest": last, "threshold": w.cfg.AlertSilence.String()})
	}

	// poll_failures: >=3 consecutive cycle errors.
	pollState := "ok"
	if n := w.m.PollConsecutiveErrors.Load(); n >= 3 {
		pollState = "firing"
		w.fire(ctx, RulePollFailures,
			fmt.Sprintf("%d consecutive poll cycle failures", n),
			map[string]any{"consecutive_errors": n})
	}

	// failed_spike: MailsFailed delta over a trailing 24h window.
	failedState := "ok"
	cur := w.m.MailsFailed.Load()
	w.mu.Lock()
	w.failedSamples = append(w.failedSamples, sample{ts: now, failed: cur})
	for len(w.failedSamples) > 1 && now.Sub(w.failedSamples[0].ts) > 24*time.Hour {
		w.failedSamples = w.failedSamples[1:]
	}
	delta := cur - w.failedSamples[0].failed
	w.mu.Unlock()
	if delta >= w.cfg.AlertFailedSpike {
		failedState = "firing"
		w.fire(ctx, RuleFailedSpike,
			fmt.Sprintf("%d mails failed in the last 24h", delta),
			map[string]any{"failed_24h": delta, "threshold": w.cfg.AlertFailedSpike})
	}

	// webhook_dead: any new delivery failures since the previous check.
	webhookState := "ok"
	w.mu.Lock()
	whCur := w.m.WebhookFailures.Load()
	whDelta := whCur - w.lastWebhookFail
	w.lastWebhookFail = whCur
	w.mu.Unlock()
	if whDelta > 0 {
		webhookState = "firing"
		w.fire(ctx, RuleWebhookDead,
			fmt.Sprintf("%d webhook deliveries failed since last check", whDelta),
			map[string]any{"new_failures": whDelta})
	}

	w.mu.Lock()
	w.states[RuleSilence] = silenceState
	w.states[RulePollFailures] = pollState
	w.states[RuleFailedSpike] = failedState
	w.states[RuleWebhookDead] = webhookState
	w.mu.Unlock()
}

// fire delivers the alert unless the rule is still in its cooldown window.
func (w *Watchdog) fire(ctx context.Context, rule, message string, detail map[string]any) {
	last, err := w.st.AlertLastFired(ctx, rule)
	if err != nil {
		w.log.Error("alert state lookup", "rule", rule, "err", err)
		return
	}
	if !last.IsZero() && time.Since(last) < cooldown {
		return
	}
	w.log.Warn("alert firing", "rule", rule, "message", message)

	payload := map[string]any{
		"rule": rule, "message": message, "detail": detail,
		"ts": time.Now().UTC().Format(time.RFC3339),
	}
	w.postAlert(ctx, payload)
	w.wh.NotifyEvent("poller.degraded", payload)
	if err := w.st.MarkAlertFired(ctx, rule, detail); err != nil {
		w.log.Error("persist alert state", "rule", rule, "err", err)
	}
}

func (w *Watchdog) postAlert(ctx context.Context, payload map[string]any) {
	if w.cfg.AlertURL == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.AlertURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		w.log.Error("alert post failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		w.log.Error("alert post rejected", "status", resp.StatusCode)
	}
}
