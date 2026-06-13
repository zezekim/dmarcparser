// Threat-intel store helpers: domain_source + ip_meta upserts, enrichment
// queue queries, anomaly stats, and the read queries behind the INTEL API.
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// validUTF8 strips invalid UTF-8 bytes from a *string so Postgres text columns
// accept it. Many real PTR/AS-org records carry latin-1/non-UTF8 bytes which
// Postgres rejects with SQLSTATE 22021. Nil pointers pass through unchanged.
func validUTF8(s *string) *string {
	if s == nil {
		return nil
	}
	clean := strings.ToValidUTF8(*s, "")
	return &clean
}

// --- ip_meta ---

type IPMeta struct {
	IP          string     `json:"ip"`
	PTR         *string    `json:"ptr"`
	ASN         *int64     `json:"asn"`
	ASOrg       *string    `json:"as_org"`
	Country     *string    `json:"country"`
	SenderClass *string    `json:"sender_class"`
	FirstSeen   *time.Time `json:"first_seen"`
	RefreshedAt *time.Time `json:"refreshed_at"`
}

// IPMetaNeedsRefresh reports whether ip is unknown or its enrichment data is
// older than maxAge.
func (s *Store) IPMetaNeedsRefresh(ctx context.Context, ip string, maxAge time.Duration) (bool, error) {
	var refreshed *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT refreshed_at FROM ip_meta WHERE ip = $1::inet`, ip).Scan(&refreshed)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return refreshed == nil || time.Since(*refreshed) > maxAge, nil
}

func (s *Store) UpsertIPMeta(ctx context.Context, m IPMeta) error {
	// Sanitize free-form text from PTR/Cymru lookups before it hits Postgres.
	m.PTR = validUTF8(m.PTR)
	m.ASOrg = validUTF8(m.ASOrg)
	m.Country = validUTF8(m.Country)
	m.SenderClass = validUTF8(m.SenderClass)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ip_meta (ip, ptr, asn, as_org, country, sender_class, refreshed_at)
		VALUES ($1::inet, $2, $3, $4, $5, $6, now())
		ON CONFLICT (ip) DO UPDATE SET
		  ptr          = EXCLUDED.ptr,
		  asn          = COALESCE(EXCLUDED.asn, ip_meta.asn),
		  as_org       = COALESCE(EXCLUDED.as_org, ip_meta.as_org),
		  country      = COALESCE(EXCLUDED.country, ip_meta.country),
		  sender_class = COALESCE(EXCLUDED.sender_class, ip_meta.sender_class),
		  refreshed_at = now()`,
		m.IP, m.PTR, m.ASN, m.ASOrg, m.Country, m.SenderClass)
	return err
}

func (s *Store) GetIPMeta(ctx context.Context, ip string) (*IPMeta, error) {
	var m IPMeta
	err := s.pool.QueryRow(ctx, `
		SELECT host(ip), ptr, asn, as_org, country, sender_class, first_seen, refreshed_at
		FROM ip_meta WHERE ip = $1::inet`, ip).Scan(
		&m.IP, &m.PTR, &m.ASN, &m.ASOrg, &m.Country, &m.SenderClass,
		&m.FirstSeen, &m.RefreshedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// IPMetaPTR returns the known PTR for ip (nil when the IP is unknown or has
// no PTR yet). Best-effort lookup for the sender.new payload.
func (s *Store) IPMetaPTR(ctx context.Context, ip string) (*string, error) {
	var ptr *string
	err := s.pool.QueryRow(ctx,
		`SELECT ptr FROM ip_meta WHERE ip = $1::inet`, ip).Scan(&ptr)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return ptr, err
}

// UnenrichedIPs lists IPs that were seeded into ip_meta but never enriched,
// oldest first, for the enrichment sweep.
func (s *Store) UnenrichedIPs(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host(ip) FROM ip_meta WHERE refreshed_at IS NULL
		ORDER BY first_seen NULLS LAST LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// --- domain_source ---

// UpsertDomainSource accumulates message counts for a (domain, ip) pair.
// isNew is true when this is the first time the pair was seen.
func (s *Store) UpsertDomainSource(ctx context.Context, domain, ip string, msgs, aligned, serial int64) (isNew bool, firstSeen time.Time, err error) {
	err = s.pool.QueryRow(ctx, `
		INSERT INTO domain_source (domain, ip, first_serial, msg_count, aligned_count)
		VALUES ($1, $2::inet, $3, $4, $5)
		ON CONFLICT (domain, ip) DO UPDATE SET
		  last_seen     = now(),
		  msg_count     = domain_source.msg_count + EXCLUDED.msg_count,
		  aligned_count = domain_source.aligned_count + EXCLUDED.aligned_count
		RETURNING (xmax = 0), first_seen`,
		domain, ip, serial, msgs, aligned).Scan(&isNew, &firstSeen)
	return
}

// AckSource marks a (domain, ip) pair acknowledged; false when no such row.
func (s *Store) AckSource(ctx context.Context, domain, ip string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE domain_source SET acked = true WHERE domain = $1 AND ip = $2::inet`,
		domain, ip)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// --- anomaly stats ---

// DayFailStats compares one day's unaligned volume against the trailing
// 30 days for a domain (from dmarc_agg_daily).
type DayFailStats struct {
	DayFails int64   // unaligned messages on the day itself
	Mean     float64 // trailing-30d mean of daily unaligned messages
	Stddev   float64 // trailing-30d sample stddev
	Days     int64   // days of history available in the window
}

func (s *Store) DomainDayFailStats(ctx context.Context, domain string, day time.Time) (DayFailStats, error) {
	var st DayFailStats
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT msgs_total - msgs_aligned FROM dmarc_agg_daily
		                 WHERE domain = $1 AND day = $2::date), 0),
		       COALESCE(avg(msgs_total - msgs_aligned), 0),
		       COALESCE(stddev_samp(msgs_total - msgs_aligned), 0),
		       count(*)
		FROM dmarc_agg_daily
		WHERE domain = $1 AND day >= $2::date - 30 AND day < $2::date`,
		domain, day).Scan(&st.DayFails, &st.Mean, &st.Stddev, &st.Days)
	return st, err
}

// --- backfill ---

func (s *Store) MaxReportSerial(ctx context.Context) (int64, error) {
	var max *int64
	if err := s.pool.QueryRow(ctx, `SELECT max(serial) FROM report`).Scan(&max); err != nil {
		return 0, err
	}
	if max == nil {
		return 0, nil
	}
	return *max, nil
}

// rptrecord stores IPv4 as a packed bigint and IPv6 as 16-byte bytea; this
// expression renders either as inet.
const recordInetExpr = `CASE WHEN rr.ip IS NOT NULL THEN '0.0.0.0'::inet + rr.ip
	ELSE rtrim(regexp_replace(encode(rr.ip6, 'hex'), '(....)', '\1:', 'g'), ':')::inet END`

// BackfillDomainSourceBatch aggregates one serial range of historical
// records into domain_source. Rows are inserted acked so history does not
// fire sender.new alerts; counts accumulate on conflict, so run the full
// backfill only once.
func (s *Store) BackfillDomainSourceBatch(ctx context.Context, fromSerial, toSerial int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO domain_source (domain, ip, first_seen, last_seen, first_serial,
		                           msg_count, aligned_count, acked)
		SELECT r.domain, src.ip, min(r.mindate), max(r.maxdate), min(r.serial),
		       sum(rr.rcount),
		       sum(CASE WHEN rr.dkim_align = 'pass' OR rr.spf_align = 'pass'
		                THEN rr.rcount ELSE 0 END),
		       true
		FROM report r
		JOIN rptrecord rr ON rr.serial = r.serial
		CROSS JOIN LATERAL (SELECT `+recordInetExpr+` AS ip) src
		WHERE r.serial > $1 AND r.serial <= $2
		  AND (rr.ip IS NOT NULL OR rr.ip6 IS NOT NULL)
		GROUP BY r.domain, src.ip
		ON CONFLICT (domain, ip) DO UPDATE SET
		  first_seen    = LEAST(domain_source.first_seen, EXCLUDED.first_seen),
		  last_seen     = GREATEST(domain_source.last_seen, EXCLUDED.last_seen),
		  first_serial  = LEAST(domain_source.first_serial, EXCLUDED.first_serial),
		  msg_count     = domain_source.msg_count + EXCLUDED.msg_count,
		  aligned_count = domain_source.aligned_count + EXCLUDED.aligned_count`,
		fromSerial, toSerial)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SeedIPMetaFromSources inserts skeleton ip_meta rows for every known source
// IP; the enrichment sweep fills them in over time.
func (s *Store) SeedIPMetaFromSources(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO ip_meta (ip)
		SELECT DISTINCT ip FROM domain_source
		ON CONFLICT (ip) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- INTEL API queries ---

type SourceFilter struct {
	Domain    string
	MinFailed int64
	Since     *time.Time
	Limit     int
}

type SourceRow struct {
	IP          string    `json:"ip"`
	MsgsTotal   int64     `json:"msgs_total"`
	MsgsFailed  int64     `json:"msgs_failed"`
	Domains     int64     `json:"domains"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	PTR         *string   `json:"ptr"`
	ASN         *int64    `json:"asn"`
	ASOrg       *string   `json:"as_org"`
	Country     *string   `json:"country"`
	SenderClass *string   `json:"sender_class"`
}

func (s *Store) ListSources(ctx context.Context, f SourceFilter) ([]SourceRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host(ds.ip), sum(ds.msg_count), sum(ds.msg_count - ds.aligned_count),
		       count(DISTINCT ds.domain), min(ds.first_seen), max(ds.last_seen),
		       im.ptr, im.asn, im.as_org, im.country, im.sender_class
		FROM domain_source ds
		LEFT JOIN ip_meta im ON im.ip = ds.ip
		WHERE ($1 = '' OR ds.domain = $1)
		  AND ($2::timestamptz IS NULL OR ds.last_seen >= $2)
		GROUP BY ds.ip, im.ptr, im.asn, im.as_org, im.country, im.sender_class
		HAVING sum(ds.msg_count - ds.aligned_count) >= $3
		ORDER BY 3 DESC, 2 DESC
		LIMIT $4`,
		f.Domain, f.Since, f.MinFailed, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SourceRow{}
	for rows.Next() {
		var r SourceRow
		if err := rows.Scan(&r.IP, &r.MsgsTotal, &r.MsgsFailed, &r.Domains,
			&r.FirstSeen, &r.LastSeen, &r.PTR, &r.ASN, &r.ASOrg,
			&r.Country, &r.SenderClass); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type DomainSourceRow struct {
	Domain       string    `json:"domain"`
	IP           string    `json:"ip"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	FirstSerial  *int64    `json:"first_serial"`
	MsgCount     int64     `json:"msg_count"`
	AlignedCount int64     `json:"aligned_count"`
	Acked        bool      `json:"acked"`
	PTR          *string   `json:"ptr"`
	ASN          *int64    `json:"asn"`
	ASOrg        *string   `json:"as_org"`
	Country      *string   `json:"country"`
	SenderClass  *string   `json:"sender_class"`
}

const domainSourceSelect = `
	SELECT ds.domain, host(ds.ip), ds.first_seen, ds.last_seen, ds.first_serial,
	       ds.msg_count, ds.aligned_count, ds.acked,
	       im.ptr, im.asn, im.as_org, im.country, im.sender_class
	FROM domain_source ds
	LEFT JOIN ip_meta im ON im.ip = ds.ip`

func (s *Store) DomainSources(ctx context.Context, domain string, unackedOnly bool) ([]DomainSourceRow, error) {
	return s.queryDomainSources(ctx, domainSourceSelect+`
		WHERE ds.domain = $1 AND (NOT $2 OR NOT ds.acked)
		ORDER BY ds.last_seen DESC`, domain, unackedOnly)
}

func (s *Store) IPDomainSources(ctx context.Context, ip string) ([]DomainSourceRow, error) {
	return s.queryDomainSources(ctx, domainSourceSelect+`
		WHERE ds.ip = $1::inet
		ORDER BY ds.last_seen DESC`, ip)
}

func (s *Store) queryDomainSources(ctx context.Context, sql string, args ...any) ([]DomainSourceRow, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DomainSourceRow{}
	for rows.Next() {
		var r DomainSourceRow
		if err := rows.Scan(&r.Domain, &r.IP, &r.FirstSeen, &r.LastSeen,
			&r.FirstSerial, &r.MsgCount, &r.AlignedCount, &r.Acked,
			&r.PTR, &r.ASN, &r.ASOrg, &r.Country, &r.SenderClass); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type IPActivityRow struct {
	Serial      int64      `json:"serial"`
	Domain      string     `json:"domain"`
	Org         string     `json:"org"`
	DateBegin   *time.Time `json:"date_begin"`
	DateEnd     *time.Time `json:"date_end"`
	Messages    int64      `json:"messages"`
	Disposition *string    `json:"disposition"`
	DKIMAlign   string     `json:"dkim_align"`
	SPFAlign    string     `json:"spf_align"`
	HeaderFrom  *string    `json:"header_from"`
}

// IPReportActivity lists the most recent report records mentioning addr,
// across all domains.
func (s *Store) IPReportActivity(ctx context.Context, addr netip.Addr, limit int) ([]IPActivityRow, error) {
	cond, arg := "rr.ip = $1", any(nil)
	if a := addr.Unmap(); a.Is4() {
		b := a.As4()
		arg = int64(binary.BigEndian.Uint32(b[:]))
	} else {
		cond = "rr.ip6 = $1"
		b := a.As16()
		arg = b[:]
	}
	rows, err := s.pool.Query(ctx, `
		SELECT r.serial, r.domain, r.org, r.mindate, r.maxdate, rr.rcount,
		       rr.disposition::text, rr.dkim_align::text, rr.spf_align::text,
		       rr.identifier_hfrom
		FROM rptrecord rr
		JOIN report r ON r.serial = rr.serial
		WHERE `+cond+`
		ORDER BY r.mindate DESC, rr.id DESC
		LIMIT $2`, arg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []IPActivityRow{}
	for rows.Next() {
		var r IPActivityRow
		if err := rows.Scan(&r.Serial, &r.Domain, &r.Org, &r.DateBegin, &r.DateEnd,
			&r.Messages, &r.Disposition, &r.DKIMAlign, &r.SPFAlign,
			&r.HeaderFrom); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
