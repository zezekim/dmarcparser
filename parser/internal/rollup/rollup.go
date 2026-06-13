// Package rollup maintains dmarc_agg_daily, the per-day/per-domain rollup
// behind /stats and the viewer charts: a pipeline observer applies every
// newly ingested report, and Backfill rebuilds the whole table from
// report/rptrecord for the -backfill-rollups flag.
package rollup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/pipeline"
)

type Rollup struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Rollup {
	return &Rollup{pool: pool, log: log.With("component", "rollup")}
}

const upsertSQL = `
	INSERT INTO dmarc_agg_daily (day, domain, msgs_total, msgs_aligned,
	                             msgs_dkim_aligned, msgs_spf_aligned,
	                             msgs_none, msgs_quarantine, msgs_reject, reports)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1)
	ON CONFLICT (day, domain) DO UPDATE SET
	    msgs_total        = dmarc_agg_daily.msgs_total        + EXCLUDED.msgs_total,
	    msgs_aligned      = dmarc_agg_daily.msgs_aligned      + EXCLUDED.msgs_aligned,
	    msgs_dkim_aligned = dmarc_agg_daily.msgs_dkim_aligned + EXCLUDED.msgs_dkim_aligned,
	    msgs_spf_aligned  = dmarc_agg_daily.msgs_spf_aligned  + EXCLUDED.msgs_spf_aligned,
	    msgs_none         = dmarc_agg_daily.msgs_none         + EXCLUDED.msgs_none,
	    msgs_quarantine   = dmarc_agg_daily.msgs_quarantine   + EXCLUDED.msgs_quarantine,
	    msgs_reject       = dmarc_agg_daily.msgs_reject       + EXCLUDED.msgs_reject,
	    reports           = dmarc_agg_daily.reports + 1`

// OnIngest folds a newly stored (non-duplicate) report into the day bucket
// of its date_range begin. Duplicates never reach observers, so buckets are
// never double-counted.
func (ro *Rollup) OnIngest(ctx context.Context, ev pipeline.IngestEvent) {
	rep := ev.Report
	if rep == nil {
		return
	}
	var total, aligned, dkim, spf, none, quarantine, reject int64
	for _, rec := range rep.Records {
		total += rec.Count
		dkimPass := rec.DKIMAlign == "pass"
		spfPass := rec.SPFAlign == "pass"
		if dkimPass {
			dkim += rec.Count
		}
		if spfPass {
			spf += rec.Count
		}
		if dkimPass || spfPass {
			aligned += rec.Count
		}
		if rec.Disposition != nil {
			switch *rec.Disposition {
			case "none":
				none += rec.Count
			case "quarantine":
				quarantine += rec.Count
			case "reject":
				reject += rec.Count
			}
		}
	}
	day := rep.Begin.UTC().Truncate(24 * time.Hour)
	if _, err := ro.pool.Exec(ctx, upsertSQL, day, rep.Domain,
		total, aligned, dkim, spf, none, quarantine, reject); err != nil {
		ro.log.Error("rollup upsert failed", "err", err,
			"serial", ev.Result.Serial, "domain", rep.Domain)
	}
}

const backfillSQL = `
	INSERT INTO dmarc_agg_daily (day, domain, msgs_total, msgs_aligned,
	                             msgs_dkim_aligned, msgs_spf_aligned,
	                             msgs_none, msgs_quarantine, msgs_reject, reports)
	SELECT date_trunc('day', r.mindate)::date, r.domain,
	       COALESCE(SUM(rr.rcount), 0),
	       COALESCE(SUM(rr.rcount) FILTER (WHERE rr.dkim_align = 'pass' OR rr.spf_align = 'pass'), 0),
	       COALESCE(SUM(rr.rcount) FILTER (WHERE rr.dkim_align = 'pass'), 0),
	       COALESCE(SUM(rr.rcount) FILTER (WHERE rr.spf_align = 'pass'), 0),
	       COALESCE(SUM(rr.rcount) FILTER (WHERE rr.disposition = 'none'), 0),
	       COALESCE(SUM(rr.rcount) FILTER (WHERE rr.disposition = 'quarantine'), 0),
	       COALESCE(SUM(rr.rcount) FILTER (WHERE rr.disposition = 'reject'), 0),
	       COUNT(DISTINCT r.serial)
	FROM report r
	LEFT JOIN rptrecord rr ON rr.serial = r.serial
	GROUP BY 1, 2`

// Backfill rebuilds dmarc_agg_daily from scratch (DELETE + one
// INSERT…SELECT…GROUP BY) in a single transaction, so readers never observe
// an empty table. Returns the number of bucket rows written.
func Backfill(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM dmarc_agg_daily`); err != nil {
		return 0, fmt.Errorf("clear rollups: %w", err)
	}
	tag, err := tx.Exec(ctx, backfillSQL)
	if err != nil {
		return 0, fmt.Errorf("rebuild rollups: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
