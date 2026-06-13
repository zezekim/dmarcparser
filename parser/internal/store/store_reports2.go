// REPORTS2 store helpers: dkim_auth selector capture (per-serial idempotent),
// TLS-RPT and forensic persistence with their read queries, and the raw_xml
// batch reader behind -backfill-selectors.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"dmarcparser/internal/forensic"
	"dmarcparser/internal/report"
	"dmarcparser/internal/tlsrpt"
)

// --- dkim_auth ---

type DKIMAuthEntry struct {
	Domain   *string
	Selector *string
	Result   *string
}

// DKIMAuthEntries flattens every auth_results/dkim entry of a parsed report
// into dkim_auth rows.
func DKIMAuthEntries(r *report.Report) []DKIMAuthEntry {
	var out []DKIMAuthEntry
	for _, rec := range r.Records {
		for _, a := range rec.DKIMAll {
			out = append(out, DKIMAuthEntry{
				Domain:   optTrunc(a.Domain, 255),
				Selector: optTrunc(a.Selector, 255),
				Result:   optTrunc(strings.ToLower(a.Result), 20),
			})
		}
	}
	return out
}

// SaveDKIMAuth replaces the dkim_auth rows for one report serial — idempotent,
// so the selectors observer and -backfill-selectors can both re-run it.
func (s *Store) SaveDKIMAuth(ctx context.Context, serial int64, entries []DKIMAuthEntry) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM dkim_auth WHERE serial = $1`, serial); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := tx.Exec(ctx,
			`INSERT INTO dkim_auth (serial, dkimdomain, selector, result) VALUES ($1,$2,$3,$4)`,
			serial, e.Domain, e.Selector, e.Result); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RawXMLRow is one report with its stored raw XML, for selector backfill.
type RawXMLRow struct {
	Serial int64
	RawXML []byte
}

// ReportRawXMLBatch keyset-pages reports that still hold raw_xml, ordered by
// serial, starting after afterSerial.
func (s *Store) ReportRawXMLBatch(ctx context.Context, afterSerial int64, limit int) ([]RawXMLRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT serial, raw_xml FROM report
		WHERE serial > $1 AND raw_xml IS NOT NULL
		ORDER BY serial LIMIT $2`, afterSerial, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RawXMLRow
	for rows.Next() {
		var r RawXMLRow
		if err := rows.Scan(&r.Serial, &r.RawXML); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- selectors API ---

type SelectorRow struct {
	DKIMDomain *string    `json:"dkim_domain"`
	Selector   *string    `json:"selector"`
	FirstSeen  *time.Time `json:"first_seen"`
	LastSeen   *time.Time `json:"last_seen"`
	PassCount  int64      `json:"pass_count"`
	FailCount  int64      `json:"fail_count"`
}

// DomainSelectors inventories DKIM domain/selector pairs seen in reports for
// a policy domain. Counts are dkim_auth occurrences; first/last seen come
// from the owning report's date range.
func (s *Store) DomainSelectors(ctx context.Context, domain string) ([]SelectorRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT da.dkimdomain, da.selector, min(r.mindate), max(r.maxdate),
		       count(*) FILTER (WHERE da.result = 'pass'),
		       count(*) FILTER (WHERE da.result IS DISTINCT FROM 'pass')
		FROM dkim_auth da
		JOIN report r ON r.serial = da.serial
		WHERE r.domain = $1
		GROUP BY da.dkimdomain, da.selector
		ORDER BY max(r.maxdate) DESC NULLS LAST, da.dkimdomain, da.selector`,
		domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SelectorRow{}
	for rows.Next() {
		var r SelectorRow
		if err := rows.Scan(&r.DKIMDomain, &r.Selector, &r.FirstSeen,
			&r.LastSeen, &r.PassCount, &r.FailCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- tlsrpt ---

// SaveTLSRPT stores a parsed TLS report with its per-policy rows in one
// transaction. Duplicates (same org + report-id) return the existing id and
// write nothing.
func (s *Store) SaveTLSRPT(ctx context.Context, r *tlsrpt.Report, raw []byte) (id int64, duplicate bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO tlsrpt_report (org, report_id, contact, date_begin, date_end, raw_json)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (org, report_id) DO NOTHING
		RETURNING id`,
		r.OrganizationName, r.ReportID, nullable(r.ContactInfo),
		r.DateRange.Start, r.DateRange.End, raw).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := s.pool.QueryRow(ctx,
			`SELECT id FROM tlsrpt_report WHERE org = $1 AND report_id = $2`,
			r.OrganizationName, r.ReportID).Scan(&id); err != nil {
			return 0, false, err
		}
		return id, true, nil
	}
	if err != nil {
		return 0, false, err
	}

	for _, p := range r.Policies {
		var details []byte
		if len(p.FailureDetails) > 0 {
			if details, err = json.Marshal(p.FailureDetails); err != nil {
				return 0, false, err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tlsrpt_policy (report_fk, policy_type, policy_domain, mx_host,
			                           success_count, failure_count, failure_details)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, nullable(p.Policy.Type), nullable(p.Policy.Domain),
			nullable(strings.Join(p.Policy.MXHost, ", ")),
			p.Summary.TotalSuccess, p.Summary.TotalFailure, details); err != nil {
			return 0, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	return id, false, nil
}

type TLSRPTSummary struct {
	ID           int64      `json:"id"`
	Org          string     `json:"org"`
	ReportID     string     `json:"report_id"`
	Contact      *string    `json:"contact"`
	DateBegin    *time.Time `json:"date_begin"`
	DateEnd      *time.Time `json:"date_end"`
	Seen         *time.Time `json:"seen"`
	Policies     int64      `json:"policies"`
	SuccessTotal int64      `json:"success_total"`
	FailureTotal int64      `json:"failure_total"`
}

type TLSRPTPolicyRow struct {
	PolicyType     *string         `json:"policy_type"`
	PolicyDomain   *string         `json:"policy_domain"`
	MXHost         *string         `json:"mx_host"`
	SuccessCount   int64           `json:"success_count"`
	FailureCount   int64           `json:"failure_count"`
	FailureDetails json.RawMessage `json:"failure_details"`
}

type TLSRPTDetail struct {
	TLSRPTSummary
	PolicyRows []TLSRPTPolicyRow `json:"policy_rows"`
}

type TLSRPTFilter struct {
	Domain, Org  string
	Since, Until *time.Time
	Limit        int
	Offset       int
}

func (s *Store) ListTLSRPT(ctx context.Context, f TLSRPTFilter) ([]TLSRPTSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.org, t.report_id, t.contact, t.date_begin, t.date_end, t.seen,
		       count(p.id), COALESCE(sum(p.success_count), 0), COALESCE(sum(p.failure_count), 0)
		FROM tlsrpt_report t
		LEFT JOIN tlsrpt_policy p ON p.report_fk = t.id
		WHERE ($1 = '' OR EXISTS (SELECT 1 FROM tlsrpt_policy pd
		                          WHERE pd.report_fk = t.id AND pd.policy_domain = $1))
		  AND ($2 = '' OR t.org = $2)
		  AND ($3::timestamptz IS NULL OR t.date_end >= $3)
		  AND ($4::timestamptz IS NULL OR t.date_begin <= $4)
		GROUP BY t.id
		ORDER BY t.date_begin DESC NULLS LAST, t.id DESC
		LIMIT $5 OFFSET $6`,
		f.Domain, f.Org, f.Since, f.Until, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TLSRPTSummary{}
	for rows.Next() {
		var r TLSRPTSummary
		if err := rows.Scan(&r.ID, &r.Org, &r.ReportID, &r.Contact, &r.DateBegin,
			&r.DateEnd, &r.Seen, &r.Policies, &r.SuccessTotal, &r.FailureTotal); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetTLSRPT(ctx context.Context, id int64) (*TLSRPTDetail, error) {
	var d TLSRPTDetail
	err := s.pool.QueryRow(ctx, `
		SELECT id, org, report_id, contact, date_begin, date_end, seen
		FROM tlsrpt_report WHERE id = $1`, id).Scan(
		&d.ID, &d.Org, &d.ReportID, &d.Contact, &d.DateBegin, &d.DateEnd, &d.Seen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT policy_type, policy_domain, mx_host, success_count, failure_count, failure_details
		FROM tlsrpt_policy WHERE report_fk = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	d.PolicyRows = []TLSRPTPolicyRow{}
	for rows.Next() {
		var p TLSRPTPolicyRow
		if err := rows.Scan(&p.PolicyType, &p.PolicyDomain, &p.MXHost,
			&p.SuccessCount, &p.FailureCount, &p.FailureDetails); err != nil {
			return nil, err
		}
		d.PolicyRows = append(d.PolicyRows, p)
		d.Policies++
		d.SuccessTotal += p.SuccessCount
		d.FailureTotal += p.FailureCount
	}
	return &d, rows.Err()
}

// --- forensic ---

func (s *Store) SaveForensic(ctx context.Context, fr *forensic.Report) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO forensic_report (feedback_type, auth_failure, source_ip,
		                             reported_domain, original_mail_from, arrival_date,
		                             subject, message_id, header_from, raw_headers)
		VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id`,
		fr.FeedbackType, fr.AuthFailure, fr.SourceIP, fr.ReportedDomain,
		fr.OriginalMailFrom, fr.ArrivalDate, fr.Subject, fr.MessageID,
		fr.HeaderFrom, fr.RawHeaders).Scan(&id)
	return id, err
}

type ForensicRow struct {
	ID               int64      `json:"id"`
	Seen             *time.Time `json:"seen"`
	FeedbackType     *string    `json:"feedback_type"`
	AuthFailure      *string    `json:"auth_failure"`
	SourceIP         *string    `json:"source_ip"`
	ReportedDomain   *string    `json:"reported_domain"`
	OriginalMailFrom *string    `json:"original_mail_from"`
	ArrivalDate      *time.Time `json:"arrival_date"`
	Subject          *string    `json:"subject"`
	MessageID        *string    `json:"message_id"`
	HeaderFrom       *string    `json:"header_from"`
	RawHeaders       *string    `json:"raw_headers,omitempty"`
}

type ForensicFilter struct {
	Domain       string
	Since, Until *time.Time
	Limit        int
	Offset       int
}

const forensicCols = `id, seen, feedback_type, auth_failure, host(source_ip),
	reported_domain, original_mail_from, arrival_date, subject, message_id, header_from`

func (s *Store) ListForensic(ctx context.Context, f ForensicFilter) ([]ForensicRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+forensicCols+`
		FROM forensic_report
		WHERE ($1 = '' OR reported_domain = $1)
		  AND ($2::timestamptz IS NULL OR seen >= $2)
		  AND ($3::timestamptz IS NULL OR seen <= $3)
		ORDER BY seen DESC, id DESC
		LIMIT $4 OFFSET $5`,
		f.Domain, f.Since, f.Until, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ForensicRow{}
	for rows.Next() {
		var r ForensicRow
		if err := rows.Scan(&r.ID, &r.Seen, &r.FeedbackType, &r.AuthFailure,
			&r.SourceIP, &r.ReportedDomain, &r.OriginalMailFrom, &r.ArrivalDate,
			&r.Subject, &r.MessageID, &r.HeaderFrom); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetForensic(ctx context.Context, id int64) (*ForensicRow, error) {
	var r ForensicRow
	err := s.pool.QueryRow(ctx, `
		SELECT `+forensicCols+`, raw_headers
		FROM forensic_report WHERE id = $1`, id).Scan(
		&r.ID, &r.Seen, &r.FeedbackType, &r.AuthFailure, &r.SourceIP,
		&r.ReportedDomain, &r.OriginalMailFrom, &r.ArrivalDate, &r.Subject,
		&r.MessageID, &r.HeaderFrom, &r.RawHeaders)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// --- small helpers (local to reports2) ---

func optTrunc(s string, n int) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if len(s) > n {
		s = s[:n]
	}
	return &s
}

func nullable(s string) *string { return optTrunc(s, 1<<30) }
