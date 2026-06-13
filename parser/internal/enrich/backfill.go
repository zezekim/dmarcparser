package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/store"
)

const backfillStep = 5000 // serials per batch; keeps locks short on a live DB

// Backfill populates domain_source from all existing report/rptrecord rows
// (inserted acked so history never fires sender.new) and seeds ip_meta
// skeleton rows for the enrichment sweep. Keyset-batched by serial. Counts
// accumulate on conflict, so run it once (wired to -backfill-sources).
func Backfill(ctx context.Context, pool *pgxpool.Pool) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("component", "backfill-sources")
	st := store.New(pool)

	maxSerial, err := st.MaxReportSerial(ctx)
	if err != nil {
		return fmt.Errorf("max serial: %w", err)
	}
	var total int64
	for from := int64(0); from < maxSerial; from += backfillStep {
		to := from + backfillStep
		n, err := st.BackfillDomainSourceBatch(ctx, from, to)
		if err != nil {
			return fmt.Errorf("batch %d..%d: %w", from, to, err)
		}
		total += n
		log.Info("batch done", "through_serial", to, "rows", n)
	}
	seeded, err := st.SeedIPMetaFromSources(ctx)
	if err != nil {
		return fmt.Errorf("seed ip_meta: %w", err)
	}
	log.Info("backfill complete", "max_serial", maxSerial,
		"domain_source_rows", total, "ips_seeded", seeded)
	return nil
}
