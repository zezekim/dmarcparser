// Package retention enforces data-retention policy on a daily ticker:
// raw_xml is nulled out past PARSER_RAW_XML_RETENTION (batched so the live
// report table is never locked for long), and Processed/Ignored mail older
// than PARSER_MAIL_RETENTION is expunged from the mailbox.
package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/config"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/poller"
)

const (
	firstRunDelay = 5 * time.Minute
	tickInterval  = 24 * time.Hour
	purgeBatch    = 5000
)

type Retention struct {
	cfg  *config.Config
	pool *pgxpool.Pool
	m    *metrics.Metrics
	log  *slog.Logger
}

func New(cfg *config.Config, pool *pgxpool.Pool, m *metrics.Metrics, log *slog.Logger) *Retention {
	return &Retention{cfg: cfg, pool: pool, m: m, log: log.With("component", "retention")}
}

func (r *Retention) Run(ctx context.Context) {
	timer := time.NewTimer(firstRunDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		r.runOnce(ctx)
		timer.Reset(tickInterval)
	}
}

func (r *Retention) runOnce(ctx context.Context) {
	if r.cfg.RawXMLRetention > 0 {
		if n, err := r.purgeRawXML(ctx); err != nil {
			r.log.Error("raw_xml purge failed", "err", err)
		} else if n > 0 {
			r.m.RetentionPurgedRawXML.Add(n)
			r.log.Info("raw_xml purged", "rows", n)
			r.audit(ctx, "raw_xml", n)
		}
	}
	if r.cfg.MailRetention > 0 && r.cfg.IMAPAddr != "" {
		if n, err := r.expungeMail(ctx); err != nil {
			r.log.Error("mail expunge failed", "err", err)
		} else if n > 0 {
			r.m.RetentionPurgedMail.Add(n)
			r.log.Info("mail expunged", "messages", n)
			r.audit(ctx, "mail", n)
		}
	}
}

// purgeRawXML nulls raw_xml in batches via a ctid subselect so each UPDATE
// touches at most purgeBatch rows.
func (r *Retention) purgeRawXML(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-r.cfg.RawXMLRetention)
	var total int64
	for {
		tag, err := r.pool.Exec(ctx, `
			UPDATE report SET raw_xml = NULL
			WHERE ctid IN (
				SELECT ctid FROM report
				WHERE seen < $1 AND raw_xml IS NOT NULL
				LIMIT $2)`,
			cutoff, purgeBatch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < purgeBatch {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
}

func (r *Retention) expungeMail(ctx context.Context) (int64, error) {
	c, err := poller.Connect(r.cfg)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	cutoff := time.Now().UTC().Add(-r.cfg.MailRetention)
	var total int64
	for _, folder := range []string{r.cfg.FolderProcessed, r.cfg.FolderIgnored} {
		n, err := expungeFolder(c, folder, cutoff)
		if err != nil {
			return total, fmt.Errorf("folder %s: %w", folder, err)
		}
		total += n
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
	_ = c.Logout().Wait()
	return total, nil
}

func expungeFolder(c *imapclient.Client, folder string, cutoff time.Time) (int64, error) {
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		return 0, fmt.Errorf("select: %w", err)
	}
	sd, err := c.UIDSearch(&imap.SearchCriteria{Before: cutoff}, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("search: %w", err)
	}
	uids := sd.AllUIDs()
	if len(uids) == 0 {
		return 0, nil
	}
	storeCmd := c.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{
		Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		return 0, fmt.Errorf("flag deleted: %w", err)
	}
	if _, err := c.Expunge().Collect(); err != nil {
		return 0, fmt.Errorf("expunge: %w", err)
	}
	return int64(len(uids)), nil
}

// audit records the purge in parser_audit (best-effort).
func (r *Retention) audit(ctx context.Context, kind string, rows int64) {
	detail, _ := json.Marshal(map[string]any{"kind": kind, "rows": rows})
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO parser_audit (actor, action, detail) VALUES ('retention', 'purge', $1)`,
		detail); err != nil {
		r.log.Error("audit insert failed", "err", err)
	}
}
