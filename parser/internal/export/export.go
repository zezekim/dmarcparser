// Package export streams flattened report×record rows as CSV or JSONL and
// serves raw_xml downloads. Rows are streamed straight off the pgx cursor —
// no full materialization — with periodic flushes for chunked transfer.
package export

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Exporter struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Exporter {
	return &Exporter{pool: pool, log: log.With("component", "export")}
}

type Filter struct {
	Domain, Org  string
	Since, Until *time.Time
}

// row mirrors one report×record line; pointers keep SQL NULLs as JSON null.
type row struct {
	Serial      int64      `json:"serial"`
	Domain      string     `json:"domain"`
	Org         string     `json:"org"`
	ReportID    string     `json:"report_id"`
	DateBegin   *time.Time `json:"date_begin"`
	DateEnd     *time.Time `json:"date_end"`
	SourceIP    *string    `json:"source_ip"`
	Count       int64      `json:"count"`
	Disposition *string    `json:"disposition"`
	Reason      *string    `json:"reason"`
	DKIMAlign   *string    `json:"dkim_align"`
	SPFAlign    *string    `json:"spf_align"`
	DKIMDomain  *string    `json:"dkim_domain"`
	DKIMResult  *string    `json:"dkim_result"`
	SPFDomain   *string    `json:"spf_domain"`
	SPFResult   *string    `json:"spf_result"`
	HeaderFrom  *string    `json:"header_from"`
}

var csvHeader = []string{"serial", "domain", "org", "report_id", "date_begin",
	"date_end", "source_ip", "count", "disposition", "reason", "dkim_align",
	"spf_align", "dkim_domain", "dkim_result", "spf_domain", "spf_result",
	"header_from"}

const exportSQL = `
	SELECT r.serial, r.domain, r.org, r.reportid, r.mindate, r.maxdate,
	       host(CASE
	         WHEN rr.ip IS NOT NULL THEN '0.0.0.0'::inet + rr.ip
	         WHEN length(rr.ip6) = 16 THEN
	           (trim(trailing ':' from regexp_replace(encode(rr.ip6,'hex'),'(....)','\1:','g')))::inet
	         ELSE NULL END),
	       rr.rcount, rr.disposition::text, rr.reason,
	       rr.dkim_align::text, rr.spf_align::text,
	       rr.dkimdomain, rr.dkimresult::text, rr.spfdomain, rr.spfresult::text,
	       rr.identifier_hfrom
	FROM report r
	JOIN rptrecord rr ON rr.serial = r.serial
	WHERE ($1 = '' OR r.domain = $1)
	  AND ($2 = '' OR r.org = $2)
	  AND ($3::timestamptz IS NULL OR r.maxdate >= $3)
	  AND ($4::timestamptz IS NULL OR r.mindate <= $4)
	ORDER BY r.serial, rr.id`

// Stream writes matching rows to w in the given format ("csv" or "jsonl"),
// calling flush every flushEvery rows (and at the end). Returns rows written.
func (e *Exporter) Stream(ctx context.Context, w io.Writer, flush func(), format string, f Filter) (int64, error) {
	rows, err := e.pool.Query(ctx, exportSQL, f.Domain, f.Org, f.Since, f.Until)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	const flushEvery = 500
	var n int64
	var cw *csv.Writer
	var enc *json.Encoder
	switch format {
	case "csv":
		cw = csv.NewWriter(w)
		if err := cw.Write(csvHeader); err != nil {
			return 0, err
		}
	case "jsonl":
		enc = json.NewEncoder(w)
	default:
		return 0, fmt.Errorf("unsupported format %q", format)
	}

	for rows.Next() {
		var r row
		if err := rows.Scan(&r.Serial, &r.Domain, &r.Org, &r.ReportID,
			&r.DateBegin, &r.DateEnd, &r.SourceIP, &r.Count, &r.Disposition,
			&r.Reason, &r.DKIMAlign, &r.SPFAlign, &r.DKIMDomain, &r.DKIMResult,
			&r.SPFDomain, &r.SPFResult, &r.HeaderFrom); err != nil {
			return n, err
		}
		if cw != nil {
			if err := cw.Write(r.csvRecord()); err != nil {
				return n, err
			}
		} else if err := enc.Encode(r); err != nil {
			return n, err
		}
		n++
		if n%flushEvery == 0 {
			if cw != nil {
				cw.Flush()
				if err := cw.Error(); err != nil {
					return n, err
				}
			}
			if flush != nil {
				flush()
			}
		}
	}
	if cw != nil {
		cw.Flush()
		if err := cw.Error(); err != nil {
			return n, err
		}
	}
	if flush != nil {
		flush()
	}
	return n, rows.Err()
}

func (r row) csvRecord() []string {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	ts := func(p *time.Time) string {
		if p == nil {
			return ""
		}
		return p.UTC().Format(time.RFC3339)
	}
	return []string{
		strconv.FormatInt(r.Serial, 10), r.Domain, r.Org, r.ReportID,
		ts(r.DateBegin), ts(r.DateEnd), str(r.SourceIP),
		strconv.FormatInt(r.Count, 10), str(r.Disposition), str(r.Reason),
		str(r.DKIMAlign), str(r.SPFAlign), str(r.DKIMDomain), str(r.DKIMResult),
		str(r.SPFDomain), str(r.SPFResult), str(r.HeaderFrom),
	}
}

// RawXML returns the stored raw report XML. found=false when the serial does
// not exist or raw_xml was aged out by retention.
func (e *Exporter) RawXML(ctx context.Context, serial int64) (xml string, found bool, err error) {
	var raw *string
	err = e.pool.QueryRow(ctx,
		`SELECT raw_xml FROM report WHERE serial = $1`, serial).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil || raw == nil {
		return "", false, err
	}
	return *raw, true, nil
}
