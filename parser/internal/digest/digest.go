// Package digest sends weekly per-domain DMARC summary emails to
// digest_subscription recipients: 7-day volume/pass-rate vs the prior week,
// top failing sources, and newly seen senders, rendered as inline-styled
// HTML and delivered over SMTP STARTTLS to the local mailserver.
package digest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/config"
)

type Digester struct {
	cfg  *config.Config
	pool *pgxpool.Pool
	log  *slog.Logger
}

func New(cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger) *Digester {
	return &Digester{cfg: cfg, pool: pool, log: log.With("component", "digest")}
}

// Run is the weekly scheduler: every 15 minutes it checks whether the
// configured day/hour has been reached and sends any digests not yet logged
// for the current period (digest_log is the dedup guard, so restarts and
// multiple ticks within the window are safe).
func (d *Digester) Run(ctx context.Context) {
	if !d.cfg.DigestEnabled {
		d.log.Info("digest disabled (PARSER_DIGEST_ENABLED=false)")
		return
	}
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now().UTC()
		if now.Weekday() != d.cfg.DigestDay || now.Hour() < d.cfg.DigestHour {
			continue
		}
		if _, err := d.run(ctx, false); err != nil {
			d.log.Error("digest run failed", "err", err)
		}
	}
}

// RunSummary reports one forced or scheduled run.
type RunSummary struct {
	DomainsSent    int      `json:"domains_sent"`
	DomainsSkipped int      `json:"domains_skipped"`
	EmailsSent     int      `json:"emails_sent"`
	Errors         []string `json:"errors,omitempty"`
}

// RunNow force-sends digests for every subscription, ignoring the
// digest_log guard. Used by POST /digest/run.
func (d *Digester) RunNow(ctx context.Context) (RunSummary, error) {
	return d.run(ctx, true)
}

func (d *Digester) run(ctx context.Context, force bool) (RunSummary, error) {
	var sum RunSummary
	subs, err := d.subscriptionsByDomain(ctx)
	if err != nil {
		return sum, err
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.AddDate(0, 0, -7)

	for domain, emails := range subs {
		if !force {
			done, err := d.alreadySent(ctx, domain, end)
			if err != nil {
				return sum, err
			}
			if done {
				sum.DomainsSkipped++
				continue
			}
		}
		data, err := d.gather(ctx, domain, start, end)
		if err != nil {
			sum.Errors = append(sum.Errors, fmt.Sprintf("%s: data: %v", domain, err))
			continue
		}
		body, err := render(data, d.cfg.ViewerURL)
		if err != nil {
			sum.Errors = append(sum.Errors, fmt.Sprintf("%s: render: %v", domain, err))
			continue
		}
		sent := 0
		for _, to := range emails {
			if err := d.send(to, "DMARC weekly digest — "+domain, body); err != nil {
				d.log.Error("digest send failed", "domain", domain, "to", to, "err", err)
				sum.Errors = append(sum.Errors, fmt.Sprintf("%s → %s: %v", domain, to, err))
				continue
			}
			sent++
		}
		if sent == 0 {
			continue
		}
		sum.DomainsSent++
		sum.EmailsSent += sent
		if _, err := d.pool.Exec(ctx, `
			INSERT INTO digest_log (domain, period_start, period_end)
			VALUES ($1, $2, $3)`, domain, start, end); err != nil {
			d.log.Error("digest_log insert failed", "domain", domain, "err", err)
		}
		d.log.Info("digest sent", "domain", domain, "recipients", sent,
			"period_start", start.Format("2006-01-02"), "period_end", end.Format("2006-01-02"))
	}
	return sum, nil
}

func (d *Digester) subscriptionsByDomain(ctx context.Context) (map[string][]string, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT domain, email FROM digest_subscription ORDER BY domain, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var domain, email string
		if err := rows.Scan(&domain, &email); err != nil {
			return nil, err
		}
		out[domain] = append(out[domain], email)
	}
	return out, rows.Err()
}

func (d *Digester) alreadySent(ctx context.Context, domain string, periodEnd time.Time) (bool, error) {
	var exists bool
	err := d.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM digest_log WHERE domain = $1 AND period_end = $2)`,
		domain, periodEnd).Scan(&exists)
	return exists, err
}

// --- SMTP delivery ---

// send delivers one HTML mail via the configured submission port with
// STARTTLS + AUTH PLAIN (credentials default to the IMAP account).
func (d *Digester) send(to, subject, htmlBody string) error {
	host, _, err := net.SplitHostPort(d.cfg.DigestSMTPAddr)
	if err != nil {
		return fmt.Errorf("PARSER_DIGEST_SMTP_ADDR: %w", err)
	}
	c, err := smtp.Dial(d.cfg.DigestSMTPAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()

	if err := c.StartTLS(&tls.Config{
		ServerName:         host,
		InsecureSkipVerify: d.cfg.IMAPTLSSkipVerify,
	}); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	auth := smtp.PlainAuth("", d.cfg.DigestSMTPUser, d.cfg.IMAPPassword, host)
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if err := c.Mail(d.cfg.DigestFrom); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n",
		d.cfg.DigestFrom, to, subject, time.Now().UTC().Format(time.RFC1123Z), htmlBody)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return c.Quit()
}

// --- Subscription CRUD (used by api_platform handlers) ---

type Subscription struct {
	ID     int64  `json:"id"`
	Domain string `json:"domain"`
	Email  string `json:"email"`
}

func (d *Digester) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, domain, email FROM digest_subscription ORDER BY domain, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		var s Subscription
		if err := rows.Scan(&s.ID, &s.Domain, &s.Email); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AddSubscription upserts (domain, email); created=false when it existed.
func (d *Digester) AddSubscription(ctx context.Context, domain, email string) (Subscription, bool, error) {
	s := Subscription{Domain: domain, Email: email}
	err := d.pool.QueryRow(ctx, `
		INSERT INTO digest_subscription (domain, email) VALUES ($1, $2)
		ON CONFLICT (domain, email) DO NOTHING
		RETURNING id`, domain, email).Scan(&s.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = d.pool.QueryRow(ctx,
			`SELECT id FROM digest_subscription WHERE domain = $1 AND email = $2`,
			domain, email).Scan(&s.ID)
		return s, false, err
	}
	return s, true, err
}

func (d *Digester) DeleteSubscription(ctx context.Context, id int64) (bool, error) {
	tag, err := d.pool.Exec(ctx, `DELETE FROM digest_subscription WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
