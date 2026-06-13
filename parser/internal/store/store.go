// Package store writes parsed reports into the legacy dmarcts-style schema
// (tables report/rptrecord) that the dmarc.example.org viewer reads.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"dmarcparser/internal/report"
)

type Store struct {
	pool *pgxpool.Pool

	lastInsert atomic.Int64 // unix seconds of last successful non-duplicate insert
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

type SaveResult struct {
	Serial    int64
	Duplicate bool
	Records   int
	Messages  int64
}

const insertReportSQL = `
	INSERT INTO report (mindate, maxdate, domain, org, reportid, email,
	                    extra_contact_info, policy_adkim, policy_aspf,
	                    policy_p, policy_sp, policy_pct, raw_xml, seen)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
	ON CONFLICT (domain, reportid) DO NOTHING
	RETURNING serial`

const insertRecordSQL = `
	INSERT INTO rptrecord (serial, ip, ip6, rcount, disposition, reason,
	                       dkimdomain, dkimresult, spfdomain, spfresult,
	                       spf_align, dkim_align, identifier_hfrom)
	VALUES ($1,$2,$3,$4,
	        $5::rptrecord_disposition, $6, $7,
	        $8::rptrecord_dkimresult, $9, $10::rptrecord_spfresult,
	        $11::rptrecord_spf_align, $12::rptrecord_dkim_align, $13)`

// SaveReport stores a report and its records in one transaction. A report
// already present (same domain + reportid) is a no-op returning the existing
// serial with Duplicate=true.
func (s *Store) SaveReport(ctx context.Context, r *report.Report, storeRaw bool) (SaveResult, error) {
	var res SaveResult

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	var raw *string
	if storeRaw && r.RawXML != "" {
		raw = &r.RawXML
	}
	err = tx.QueryRow(ctx, insertReportSQL,
		r.Begin, r.End, r.Domain, r.Org, r.ReportID, r.Email,
		r.ExtraContact, r.ADKIM, r.ASPF, r.P, r.SP, r.Pct, raw,
	).Scan(&res.Serial)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := s.pool.QueryRow(ctx,
			`SELECT serial FROM report WHERE domain=$1 AND reportid=$2`,
			r.Domain, r.ReportID).Scan(&res.Serial); err != nil {
			return res, fmt.Errorf("lookup duplicate: %w", err)
		}
		res.Duplicate = true
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("insert report: %w", err)
	}

	for _, rec := range r.Records {
		_, err := tx.Exec(ctx, insertRecordSQL,
			res.Serial, rec.IPv4, rec.IPv6, rec.Count,
			rec.Disposition, rec.Reason,
			rec.DKIMDomain, rec.DKIMResult,
			rec.SPFDomain, rec.SPFResult,
			rec.SPFAlign, rec.DKIMAlign, rec.HeaderFrom,
		)
		if err != nil {
			return res, fmt.Errorf("insert record: %w", err)
		}
		res.Records++
		res.Messages += rec.Count
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	s.lastInsert.Store(time.Now().Unix())
	return res, nil
}

// LastIngestAt returns the time of the most recent stored report: max(seen)
// from the database, or the in-memory last-insert mark if that is newer.
func (s *Store) LastIngestAt(ctx context.Context) (time.Time, error) {
	var seen *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT max(seen) FROM report`).Scan(&seen); err != nil {
		return time.Time{}, err
	}
	var t time.Time
	if seen != nil {
		t = seen.UTC()
	}
	if mem := s.lastInsert.Load(); mem > 0 {
		if mt := time.Unix(mem, 0).UTC(); mt.After(t) {
			t = mt
		}
	}
	return t, nil
}

// InsertWebhookDeadletter records a webhook delivery that exhausted all
// retries so it can be replayed later.
func (s *Store) InsertWebhookDeadletter(ctx context.Context, endpoint, kind string, payload []byte, lastErr string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO webhook_deadletter (endpoint, kind, payload, last_error) VALUES ($1,$2,$3,$4)`,
		endpoint, kind, payload, lastErr)
	return err
}

// AlertLastFired returns when a rule last fired (zero time if never).
func (s *Store) AlertLastFired(ctx context.Context, rule string) (time.Time, error) {
	var t *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT last_fired FROM alert_state WHERE rule=$1`, rule).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if t == nil {
		return time.Time{}, nil
	}
	return t.UTC(), nil
}

// MarkAlertFired upserts the cooldown timestamp + detail for a rule.
func (s *Store) MarkAlertFired(ctx context.Context, rule string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		b = []byte("null")
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO alert_state (rule, last_fired, detail) VALUES ($1, now(), $2)
		ON CONFLICT (rule) DO UPDATE SET last_fired = now(), detail = EXCLUDED.detail`,
		rule, b)
	return err
}

// --- Query API ---

type ReportSummary struct {
	Serial    int64      `json:"serial"`
	Org       string     `json:"org"`
	Domain    string     `json:"domain"`
	ReportID  string     `json:"report_id"`
	DateBegin *time.Time `json:"date_begin"`
	DateEnd   *time.Time `json:"date_end"`
	Records   int64      `json:"records"`
	Messages  int64      `json:"messages"`
}

type RecordOut struct {
	ID          int64   `json:"id"`
	SourceIP    string  `json:"source_ip"`
	Count       int64   `json:"count"`
	Disposition *string `json:"disposition"`
	Reason      *string `json:"reason"`
	DKIMDomain  *string `json:"dkim_domain"`
	DKIMResult  *string `json:"dkim_result"`
	SPFDomain   *string `json:"spf_domain"`
	SPFResult   *string `json:"spf_result"`
	SPFAlign    string  `json:"spf_align"`
	DKIMAlign   string  `json:"dkim_align"`
	HeaderFrom  *string `json:"header_from"`
}

type ReportDetail struct {
	ReportSummary
	Email        *string     `json:"email"`
	ExtraContact *string     `json:"extra_contact_info"`
	PolicyADKIM  *string     `json:"policy_adkim"`
	PolicyASPF   *string     `json:"policy_aspf"`
	PolicyP      *string     `json:"policy_p"`
	PolicySP     *string     `json:"policy_sp"`
	PolicyPct    *int16      `json:"policy_pct"`
	RecordRows   []RecordOut `json:"record_rows"`
}

type ListFilter struct {
	Domain, Org  string
	Since, Until *time.Time
	Limit        int
	Offset       int
}

func (s *Store) ListReports(ctx context.Context, f ListFilter) ([]ReportSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.serial, r.org, r.domain, r.reportid, r.mindate, r.maxdate,
		       COUNT(rr.id), COALESCE(SUM(rr.rcount), 0)
		FROM report r
		LEFT JOIN rptrecord rr ON rr.serial = r.serial
		WHERE ($1 = '' OR r.domain = $1)
		  AND ($2 = '' OR r.org = $2)
		  AND ($3::timestamptz IS NULL OR r.maxdate >= $3)
		  AND ($4::timestamptz IS NULL OR r.mindate <= $4)
		GROUP BY r.serial
		ORDER BY r.mindate DESC, r.serial DESC
		LIMIT $5 OFFSET $6`,
		f.Domain, f.Org, f.Since, f.Until, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ReportSummary{}
	for rows.Next() {
		var r ReportSummary
		if err := rows.Scan(&r.Serial, &r.Org, &r.Domain, &r.ReportID,
			&r.DateBegin, &r.DateEnd, &r.Records, &r.Messages); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetReport(ctx context.Context, serial int64) (*ReportDetail, error) {
	var d ReportDetail
	err := s.pool.QueryRow(ctx, `
		SELECT serial, org, domain, reportid, mindate, maxdate, email,
		       extra_contact_info, policy_adkim, policy_aspf, policy_p,
		       policy_sp, policy_pct
		FROM report WHERE serial = $1`, serial).Scan(
		&d.Serial, &d.Org, &d.Domain, &d.ReportID, &d.DateBegin, &d.DateEnd,
		&d.Email, &d.ExtraContact, &d.PolicyADKIM, &d.PolicyASPF,
		&d.PolicyP, &d.PolicySP, &d.PolicyPct)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, ip, ip6, rcount, disposition::text, reason, dkimdomain,
		       dkimresult::text, spfdomain, spfresult::text,
		       spf_align::text, dkim_align::text, identifier_hfrom
		FROM rptrecord WHERE serial = $1 ORDER BY rcount DESC, id`, serial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	d.RecordRows = []RecordOut{}
	for rows.Next() {
		var rec RecordOut
		var ip4 *int64
		var ip6 []byte
		if err := rows.Scan(&rec.ID, &ip4, &ip6, &rec.Count, &rec.Disposition,
			&rec.Reason, &rec.DKIMDomain, &rec.DKIMResult, &rec.SPFDomain,
			&rec.SPFResult, &rec.SPFAlign, &rec.DKIMAlign, &rec.HeaderFrom); err != nil {
			return nil, err
		}
		rec.SourceIP = renderIP(ip4, ip6)
		d.RecordRows = append(d.RecordRows, rec)
		d.Records++
		d.Messages += rec.Count
	}
	return &d, rows.Err()
}

func (s *Store) Totals(ctx context.Context) (reports, records int64, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM report), (SELECT count(*) FROM rptrecord)`,
	).Scan(&reports, &records)
	return
}

func renderIP(ip4 *int64, ip6 []byte) string {
	if ip4 != nil {
		v := uint32(*ip4)
		return fmt.Sprintf("%d.%d.%d.%d", v>>24&255, v>>16&255, v>>8&255, v&255)
	}
	if len(ip6) == 16 {
		return net.IP(ip6).String()
	}
	return ""
}
