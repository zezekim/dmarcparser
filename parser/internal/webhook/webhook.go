// Package webhook delivers report.ingested notifications to a configured URL.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"dmarcparser/internal/metrics"
)

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

type Notifier struct {
	url    string
	secret string
	log    *slog.Logger
	m      *metrics.Metrics
	client *http.Client
}

func New(url, secret string, m *metrics.Metrics, log *slog.Logger) *Notifier {
	return &Notifier{url: url, secret: secret, m: m,
		log:    log.With("component", "webhook"),
		client: &http.Client{Timeout: 15 * time.Second}}
}

// Notify fires asynchronously with 3 attempts and exponential backoff.
func (n *Notifier) Notify(e Event) {
	if n.url == "" {
		return
	}
	body, err := json.Marshal(struct {
		Kind string `json:"event"`
		Event
	}{Kind: "report.ingested", Event: e})
	if err != nil {
		return
	}
	go func() {
		for attempt, delay := 1, 2*time.Second; attempt <= 3; attempt, delay = attempt+1, delay*4 {
			if n.deliver(body) {
				return
			}
			if attempt < 3 {
				time.Sleep(delay)
			}
		}
		n.m.WebhookFailures.Add(1)
		n.log.Error("delivery failed after retries", "serial", e.Serial)
	}()
}

func (n *Notifier) deliver(body []byte) bool {
	req, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Parser-Event", "report.ingested")
	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		mac.Write(body)
		req.Header.Set("X-Parser-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
