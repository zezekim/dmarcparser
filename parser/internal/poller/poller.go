// Package poller drains the DMARC mailbox on an interval: fetch UNSEEN mail,
// parse report payloads, store them, then file each message under
// Processed / Ignored / Failed. DB or connection errors leave the message
// UNSEEN in INBOX (bodies are fetched with PEEK) so the next cycle retries.
package poller

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"dmarcparser/internal/config"
	"dmarcparser/internal/forensic"
	"dmarcparser/internal/mailx"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/pipeline"
	"dmarcparser/internal/report"
	"dmarcparser/internal/store"
	"dmarcparser/internal/tlsrpt"
	"dmarcparser/internal/webhook"
)

type Status struct {
	Enabled     bool       `json:"enabled"`
	Interval    string     `json:"interval"`
	LastPoll    *time.Time `json:"last_poll"`
	LastSuccess *time.Time `json:"last_success"`
	LastError   string     `json:"last_error,omitempty"`
}

type Poller struct {
	cfg   *config.Config
	store *store.Store
	m     *metrics.Metrics
	wh    *webhook.Notifier
	reg   *pipeline.Registry
	log   *slog.Logger
	kick  chan struct{}

	mu        sync.Mutex
	lastError string
}

func New(cfg *config.Config, st *store.Store, m *metrics.Metrics, wh *webhook.Notifier, reg *pipeline.Registry, log *slog.Logger) *Poller {
	return &Poller{cfg: cfg, store: st, m: m, wh: wh, reg: reg,
		log:  log.With("component", "poller"),
		kick: make(chan struct{}, 1)}
}

// Connect dials the configured IMAP server and logs in. Shared by the
// poller, retention expunge, and the failed-mail requeue endpoint.
// The caller owns Close.
func Connect(cfg *config.Config) (*imapclient.Client, error) {
	c, err := imapclient.DialTLS(cfg.IMAPAddr, &imapclient.Options{
		TLSConfig: &tls.Config{InsecureSkipVerify: cfg.IMAPTLSSkipVerify},
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.IMAPAddr, err)
	}
	if err := c.Login(cfg.IMAPUser, cfg.IMAPPassword).Wait(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("login: %w", err)
	}
	return c, nil
}

// TriggerNow requests an immediate cycle (non-blocking; coalesces).
func (p *Poller) TriggerNow() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *Poller) Status() Status {
	s := Status{Enabled: p.cfg.IMAPAddr != "", Interval: p.cfg.PollInterval.String()}
	if t := p.m.LastPoll.Load(); t > 0 {
		tt := time.Unix(t, 0).UTC()
		s.LastPoll = &tt
	}
	if t := p.m.LastPollSuccess.Load(); t > 0 {
		tt := time.Unix(t, 0).UTC()
		s.LastSuccess = &tt
	}
	p.mu.Lock()
	s.LastError = p.lastError
	p.mu.Unlock()
	return s
}

func (p *Poller) setError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.lastError = err.Error()
	} else {
		p.lastError = ""
	}
}

func (p *Poller) Run(ctx context.Context) {
	if p.cfg.IMAPAddr == "" {
		p.log.Info("poller disabled (PARSER_IMAP_ADDR empty)")
		return
	}
	timer := time.NewTimer(5 * time.Second) // let the mailserver finish booting
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-p.kick:
		}
		if err := p.cycle(ctx); err != nil {
			p.m.PollErrors.Add(1)
			p.m.PollConsecutiveErrors.Add(1)
			p.setError(err)
			p.log.Error("poll cycle failed", "err", err)
		} else {
			p.m.LastPollSuccess.Store(time.Now().Unix())
			p.m.PollConsecutiveErrors.Store(0)
			p.setError(nil)
		}
		p.m.LastPoll.Store(time.Now().Unix())
		timer.Reset(p.cfg.PollInterval)
	}
}

func (p *Poller) cycle(ctx context.Context) error {
	c, err := Connect(p.cfg)
	if err != nil {
		return err
	}
	defer c.Close()

	for _, folder := range []string{p.cfg.FolderProcessed, p.cfg.FolderIgnored, p.cfg.FolderFailed} {
		// Ignore "already exists" errors.
		_ = c.Create(folder, nil).Wait()
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return fmt.Errorf("select inbox: %w", err)
	}

	sd, err := c.UIDSearch(&imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	if err != nil {
		return fmt.Errorf("search unseen: %w", err)
	}
	uids := sd.AllUIDs()
	if len(uids) == 0 {
		_ = c.Logout().Wait()
		return nil
	}
	p.log.Info("processing mail", "count", len(uids))

	section := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		Envelope:    true,
		BodySection: []*imap.FetchItemBodySection{section},
	}).Collect()
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	moves := map[string][]imap.UID{}
	for _, msg := range msgs {
		raw := msg.FindBodySection(section)
		subject, from := envelopeInfo(msg)
		if len(raw) == 0 {
			p.log.Warn("empty body section", "uid", msg.UID, "subject", subject)
			moves[p.cfg.FolderFailed] = append(moves[p.cfg.FolderFailed], msg.UID)
			p.m.MailsFailed.Add(1)
			p.notifyFailed(subject, from, "empty body section")
			continue
		}
		outcome := p.processMail(ctx, raw, subject, from)
		switch outcome {
		case outcomeProcessed:
			moves[p.cfg.FolderProcessed] = append(moves[p.cfg.FolderProcessed], msg.UID)
			p.m.MailsProcessed.Add(1)
		case outcomeIgnored:
			moves[p.cfg.FolderIgnored] = append(moves[p.cfg.FolderIgnored], msg.UID)
			p.m.MailsIgnored.Add(1)
		case outcomeFailed:
			moves[p.cfg.FolderFailed] = append(moves[p.cfg.FolderFailed], msg.UID)
			p.m.MailsFailed.Add(1)
			p.notifyFailed(subject, from, "unparsable report payload")
		case outcomeRetry:
			// leave unseen in INBOX
		}
	}

	for folder, set := range moves {
		if _, err := c.Move(imap.UIDSetNum(set...), folder).Wait(); err != nil {
			return fmt.Errorf("move %d msgs to %s: %w", len(set), folder, err)
		}
	}
	_ = c.Logout().Wait()
	return nil
}

type outcome int

const (
	outcomeProcessed outcome = iota
	outcomeIgnored
	outcomeFailed
	outcomeRetry
)

func (p *Poller) processMail(ctx context.Context, raw []byte, subject, from string) outcome {
	log := p.log.With("subject", subject, "from", from)

	pl, err := mailx.ExtractPayloads(raw)
	if err != nil {
		log.Warn("unreadable report payload", "err", err)
		return outcomeFailed
	}
	if len(pl.Aggregates) == 0 && len(pl.TLSRPT) == 0 && len(pl.Forensic) == 0 {
		log.Info("no report payload, ignoring")
		return outcomeIgnored
	}

	stored, parseErrs := 0, 0
	for _, x := range pl.Aggregates {
		rep, err := report.ParseXML(x)
		if err != nil {
			log.Warn("parse failed", "err", err)
			parseErrs++
			continue
		}
		res, err := p.store.SaveReport(ctx, rep, p.cfg.StoreRawXML)
		if err != nil {
			// DB problem — retry the whole mail next cycle.
			log.Error("store failed", "domain", rep.Domain, "report_id", rep.ReportID, "err", err)
			return outcomeRetry
		}
		stored++
		if res.Duplicate {
			p.m.ReportsDuplicate.Add(1)
			log.Info("duplicate report", "serial", res.Serial, "domain", rep.Domain, "org", rep.Org)
			continue
		}
		p.m.ReportsIngested.Add(1)
		p.m.RecordsInserted.Add(int64(res.Records))
		log.Info("report stored", "serial", res.Serial, "domain", rep.Domain,
			"org", rep.Org, "records", res.Records, "messages", res.Messages)
		p.reg.Emit(ctx, pipeline.IngestEvent{Report: rep, Result: res, Source: "imap"})
	}

	for _, doc := range pl.TLSRPT {
		rep, err := tlsrpt.Parse(doc)
		if err != nil {
			log.Warn("tlsrpt parse failed", "err", err)
			parseErrs++
			continue
		}
		id, dup, err := p.store.SaveTLSRPT(ctx, rep, doc)
		if err != nil {
			log.Error("tlsrpt store failed", "org", rep.OrganizationName,
				"report_id", rep.ReportID, "err", err)
			return outcomeRetry
		}
		stored++
		if dup {
			log.Info("duplicate tlsrpt report", "id", id, "org", rep.OrganizationName)
			continue
		}
		p.m.TLSRPTIngested.Add(1)
		log.Info("tlsrpt report stored", "id", id,
			"org", rep.OrganizationName, "report_id", rep.ReportID)
		p.wh.NotifyEvent("tlsrpt.ingested", map[string]any{
			"id": id, "org": rep.OrganizationName, "report_id": rep.ReportID,
			"date_begin": rep.DateRange.Start, "date_end": rep.DateRange.End,
			"policies": len(rep.Policies), "source": "imap",
		})
	}

	for _, fp := range pl.Forensic {
		fr, err := forensic.Parse(fp.Feedback, fp.Original, p.cfg.RUFRedact)
		if err != nil {
			log.Warn("forensic parse failed", "err", err)
			parseErrs++
			continue
		}
		id, err := p.store.SaveForensic(ctx, fr)
		if err != nil {
			log.Error("forensic store failed", "err", err)
			return outcomeRetry
		}
		stored++
		p.m.ForensicIngested.Add(1)
		log.Info("forensic report stored", "id", id)
		p.wh.NotifyEvent("forensic.ingested", map[string]any{
			"id": id, "feedback_type": fr.FeedbackType, "auth_failure": fr.AuthFailure,
			"source_ip": fr.SourceIP, "reported_domain": fr.ReportedDomain,
			"source": "imap",
		})
	}

	if stored == 0 && parseErrs > 0 {
		return outcomeFailed
	}
	return outcomeProcessed
}

func (p *Poller) notifyFailed(subject, from, reason string) {
	p.wh.NotifyEvent("report.failed", map[string]string{
		"subject": subject, "from": from, "reason": reason,
	})
}

func envelopeInfo(msg *imapclient.FetchMessageBuffer) (subject, from string) {
	if msg.Envelope == nil {
		return "", ""
	}
	subject = msg.Envelope.Subject
	if len(msg.Envelope.From) > 0 {
		a := msg.Envelope.From[0]
		from = a.Mailbox + "@" + a.Host
	}
	return
}
