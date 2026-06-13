// Package selectors captures the DKIM selector inventory: a pipeline
// observer writing dkim_auth rows for every newly ingested report, and the
// -backfill-selectors job that re-parses stored raw_xml for history.
package selectors

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/pipeline"
	"dmarcparser/internal/report"
	"dmarcparser/internal/store"
)

type Observer struct {
	st  *store.Store
	log *slog.Logger
}

func New(st *store.Store, log *slog.Logger) *Observer {
	return &Observer{st: st, log: log.With("component", "selectors")}
}

// OnIngest persists the full DKIM auth entries of a new report. SaveDKIMAuth
// is idempotent per serial, so a re-emitted report just rewrites its rows.
func (o *Observer) OnIngest(ctx context.Context, ev pipeline.IngestEvent) {
	entries := store.DKIMAuthEntries(ev.Report)
	if len(entries) == 0 {
		return
	}
	if err := o.st.SaveDKIMAuth(ctx, ev.Result.Serial, entries); err != nil {
		o.log.Error("save dkim_auth", "serial", ev.Result.Serial, "err", err)
	}
}

const backfillBatch = 500 // raw_xml rows per keyset page; keeps memory and locks small

// Backfill re-parses report.raw_xml (keyset-batched by serial) and rewrites
// dkim_auth for each report. NULL raw_xml rows are skipped by the query;
// per-serial delete+insert makes reruns safe. Wired to -backfill-selectors.
func Backfill(ctx context.Context, pool *pgxpool.Pool) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "backfill-selectors")
	st := store.New(pool)

	var after int64
	var reports, entries, parseErrs int64
	for {
		batch, err := st.ReportRawXMLBatch(ctx, after, backfillBatch)
		if err != nil {
			return fmt.Errorf("batch after serial %d: %w", after, err)
		}
		if len(batch) == 0 {
			break
		}
		for _, row := range batch {
			after = row.Serial
			rep, err := report.ParseXML(row.RawXML)
			if err != nil {
				parseErrs++
				log.Warn("raw_xml no longer parses", "serial", row.Serial, "err", err)
				continue
			}
			es := store.DKIMAuthEntries(rep)
			if err := st.SaveDKIMAuth(ctx, row.Serial, es); err != nil {
				return fmt.Errorf("save dkim_auth serial %d: %w", row.Serial, err)
			}
			reports++
			entries += int64(len(es))
		}
		log.Info("batch done", "through_serial", after, "reports", reports, "entries", entries)
	}
	log.Info("backfill complete", "reports", reports, "entries", entries, "parse_errors", parseErrs)
	return nil
}
