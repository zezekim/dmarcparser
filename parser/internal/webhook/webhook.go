// Package webhook delivers event notifications (report.ingested, sender.new,
// domain.anomaly, report.failed, poller.degraded, tlsrpt.ingested,
// forensic.ingested) to the configured endpoints, HMAC-SHA256 signed.
// Deliveries that exhaust all retries land in webhook_deadletter for replay.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"dmarcparser/internal/metrics"
	"dmarcparser/internal/pipeline"
)

// Event is the legacy report.ingested payload, kept for compatibility.
type Event struct {
	Serial    int64     `json:"serial"`
	Domain    string    `json:"domain"`
	Org       string    `json:"org"`
	ReportID  string    `json:"report_id"`
	DateBegin time.Time `json:"date_begin"`
	DateEnd   time.Time `json:"date_end"`
	Records   int       `json:"records"`
	Messages  int64     `json:"messages"`
	Source    string    `json:"source"` // "imap" or "api"
}

// DeadLetterStore persists deliveries that failed all retries. Best-effort:
// insert errors are only logged.
type DeadLetterStore interface {
	InsertWebhookDeadletter(ctx context.Context, endpoint, kind string, payload []byte, lastErr string) error
}

type Notifier struct {
	urls   []string
	secret string
	dls    DeadLetterStore
	log    *slog.Logger
	m      *metrics.Metrics
	client *http.Client
}

func New(urls []string, secret string, dls DeadLetterStore, m *metrics.Metrics, log *slog.Logger) *Notifier {
	return &Notifier{urls: urls, secret: secret, dls: dls, m: m,
		log:    log.With("component", "webhook"),
		client: &http.Client{Timeout: 15 * time.Second}}
}

// Notify is the legacy entry point: a report.ingested event.
func (n *Notifier) Notify(e Event) { n.NotifyEvent("report.ingested", e) }

// OnIngest makes the notifier a pipeline observer emitting report.ingested
// for every new (non-duplicate) report.
func (n *Notifier) OnIngest(_ context.Context, ev pipeline.IngestEvent) {
	n.Notify(Event{
		Serial: ev.Result.Serial, Domain: ev.Report.Domain, Org: ev.Report.Org,
		ReportID: ev.Report.ReportID, DateBegin: ev.Report.Begin, DateEnd: ev.Report.End,
		Records: ev.Result.Records, Messages: ev.Result.Messages, Source: ev.Source,
	})
}

// NotifyEvent delivers payload to every configured endpoint asynchronously
// (3 attempts each, exponential backoff). kind becomes the JSON "event"
// field and the X-Parser-Event header.
func (n *Notifier) NotifyEvent(kind string, payload any) {
	if len(n.urls) == 0 {
		return
	}
	body, err := encode(kind, payload)
	if err != nil {
		n.log.Error("encode event", "kind", kind, "err", err)
		return
	}
	for _, url := range n.urls {
		go n.send(url, kind, body)
	}
}

// encode marshals payload and injects the "event" field. Non-object payloads
// are wrapped under "payload".
func encode(kind string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	obj := map[string]any{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		obj = map[string]any{"payload": json.RawMessage(raw)}
	}
	obj["event"] = kind
	return json.Marshal(obj)
}

func (n *Notifier) send(url, kind string, body []byte) {
	var lastErr string
	for attempt, delay := 1, 2*time.Second; attempt <= 3; attempt, delay = attempt+1, delay*4 {
		if ok, errMsg := n.deliver(url, kind, body); ok {
			return
		} else {
			lastErr = errMsg
		}
		if attempt < 3 {
			time.Sleep(delay)
		}
	}
	n.m.WebhookFailures.Add(1)
	n.log.Error("delivery failed after retries", "kind", kind, "endpoint", url, "err", lastErr)
	if n.dls != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.dls.InsertWebhookDeadletter(ctx, url, kind, body, lastErr); err != nil {
			n.log.Error("deadletter insert failed", "kind", kind, "err", err)
			return
		}
		n.m.WebhookDeadletters.Add(1)
	}
}

// DeliverOnce attempts one synchronous delivery (no retries, no deadletter).
// Used by the deadletter replay endpoint.
func (n *Notifier) DeliverOnce(url, kind string, body []byte) error {
	if ok, errMsg := n.deliver(url, kind, body); !ok {
		return errors.New(errMsg)
	}
	return nil
}

func (n *Notifier) deliver(url, kind string, body []byte) (bool, string) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Parser-Event", kind)
	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		mac.Write(body)
		req.Header.Set("X-Parser-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, ""
	}
	return false, "status " + resp.Status
}
