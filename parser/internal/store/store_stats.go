// Analytics queries: timeseries + top-N over dmarc_agg_daily/rptrecord,
// domain list with health score, health breakdown, deployment readiness.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// recIPExpr renders rptrecord's split ip (uint32 bigint) / ip6 (16-byte
// bytea) columns as one inet, NULL when the record carried no parseable IP.
// Requires the rptrecord alias `rr`.
const recIPExpr = `CASE
	WHEN rr.ip IS NOT NULL THEN '0.0.0.0'::inet + rr.ip
	WHEN length(rr.ip6) = 16 THEN
	  (trim(trailing ':' from regexp_replace(encode(rr.ip6,'hex'),'(....)','\1:','g')))::inet
	ELSE NULL END`

type StatsFilter struct {
	Domain       string
	Since, Until *time.Time
}

// --- timeseries ---

type TimeseriesPoint struct {
	Bucket         string  `json:"bucket"`
	MsgsTotal      int64   `json:"msgs_total"`
	MsgsAligned    int64   `json:"msgs_aligned"`
	PassRate       float64 `json:"pass_rate"`
	MsgsNone       int64   `json:"msgs_none"`
	MsgsQuarantine int64   `json:"msgs_quarantine"`
	MsgsReject     int64   `json:"msgs_reject"`
}

// StatsTimeseries aggregates dmarc_agg_daily into day or week buckets.
// bucket must be "day" or "week" (validated by the caller).
func (s *Store) StatsTimeseries(ctx context.Context, f StatsFilter, bucket string) ([]TimeseriesPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc($4, day::timestamp)::date,
		       SUM(msgs_total)::bigint, SUM(msgs_aligned)::bigint,
		       SUM(msgs_none)::bigint, SUM(msgs_quarantine)::bigint,
		       SUM(msgs_reject)::bigint
		FROM dmarc_agg_daily
		WHERE ($1 = '' OR domain = $1)
		  AND ($2::date IS NULL OR day >= $2::date)
		  AND ($3::date IS NULL OR day <= $3::date)
		GROUP BY 1 ORDER BY 1`,
		f.Domain, f.Since, f.Until, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TimeseriesPoint{}
	for rows.Next() {
		var p TimeseriesPoint
		var day time.Time
		if err := rows.Scan(&day, &p.MsgsTotal, &p.MsgsAligned,
			&p.MsgsNone, &p.MsgsQuarantine, &p.MsgsReject); err != nil {
			return nil, err
		}
		p.Bucket = day.Format("2006-01-02")
		p.PassRate = ratio(p.MsgsAligned, p.MsgsTotal)
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- top-N ---

type TopRow struct {
	Key        string `json:"key"`
	Msgs       int64  `json:"msgs"`
	MsgsFailed int64  `json:"msgs_failed"`
	Reports    int64  `json:"reports"`
}

var topDimExpr = map[string]string{
	"ip":          "host(" + recIPExpr + ")",
	"org":         "r.org",
	"header_from": "rr.identifier_hfrom",
}

// StatsTop ranks senders by message volume along one dimension
// (ip | org | header_from). failing restricts to fully unaligned records.
func (s *Store) StatsTop(ctx context.Context, f StatsFilter, dimension string, failing bool, limit int) ([]TopRow, error) {
	expr, ok := topDimExpr[dimension]
	if !ok {
		return nil, fmt.Errorf("unknown dimension %q", dimension)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT t.key, t.msgs, t.failed, t.reports FROM (
		  SELECT `+expr+` AS key,
		         COALESCE(SUM(rr.rcount), 0)::bigint AS msgs,
		         COALESCE(SUM(rr.rcount) FILTER (WHERE rr.dkim_align <> 'pass' AND rr.spf_align <> 'pass'), 0)::bigint AS failed,
		         COUNT(DISTINCT rr.serial) AS reports
		  FROM rptrecord rr
		  JOIN report r ON r.serial = rr.serial
		  WHERE ($1 = '' OR r.domain = $1)
		    AND ($2::timestamptz IS NULL OR r.mindate >= $2)
		    AND ($3::timestamptz IS NULL OR r.mindate <= $3)
		    AND (NOT $4::bool OR (rr.dkim_align <> 'pass' AND rr.spf_align <> 'pass'))
		  GROUP BY 1
		) t
		WHERE t.key IS NOT NULL AND t.key <> ''
		ORDER BY t.msgs DESC, t.key
		LIMIT $5`,
		f.Domain, f.Since, f.Until, failing, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TopRow{}
	for rows.Next() {
		var t TopRow
		if err := rows.Scan(&t.Key, &t.Msgs, &t.MsgsFailed, &t.Reports); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- health score ---

// HealthInputs is everything the (pure) health computation needs; the viewer
// duplicates ComputeHealth against the same shared tables.
type HealthInputs struct {
	Msgs30d, Aligned30d     int64 // dmarc_agg_daily, last 30 days
	MsgsPrior, AlignedPrior int64 // days 31-60, for the trend component
	DaysWithData            int   // distinct days with traffic in last 30
	UnknownFailing          int64 // 30d failing msgs from sources without a sender_class
	PolicyP                 *string
	PolicyPct               *int16
}

type HealthComponent struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Max    float64 `json:"max"`
	Detail string  `json:"detail"`
}

// ComputeHealth scores a domain 0-100. Weights per DESIGN.md: alignment 40,
// trend 15, policy strength 20, coverage 10, unknown-source failing 15.
func ComputeHealth(in HealthInputs) (int, []HealthComponent) {
	rate30 := ratio(in.Aligned30d, in.Msgs30d)

	alignment := 40 * rate30
	alignDetail := fmt.Sprintf("%.1f%% of %d messages aligned (30d)", 100*rate30, in.Msgs30d)
	if in.Msgs30d == 0 {
		alignDetail = "no traffic in last 30 days"
	}

	// Trend: no penalty when stable or improving (or no prior data); a 25
	// percentage-point drop in aligned rate zeroes the component.
	trend, trendDetail := 15.0, "no prior-period data"
	if in.MsgsPrior > 0 && in.Msgs30d > 0 {
		delta := rate30 - ratio(in.AlignedPrior, in.MsgsPrior)
		if delta < 0 {
			trend = 15 * max(0, 1+delta*4)
		}
		trendDetail = fmt.Sprintf("aligned rate %+.1f pp vs prior 30d", 100*delta)
	}

	policy, policyDetail := policyStrength(in.PolicyP, in.PolicyPct)

	coverage := 10 * min(1, float64(in.DaysWithData)/14)
	coverageDetail := fmt.Sprintf("reports on %d of last 30 days", in.DaysWithData)

	// Unknown sources: failing volume from unclassified IPs as a share of all
	// traffic; 10%+ zeroes the component.
	unknown, unknownDetail := 15.0, "no failing traffic from unknown sources"
	if in.Msgs30d > 0 && in.UnknownFailing > 0 {
		share := float64(in.UnknownFailing) / float64(in.Msgs30d)
		unknown = 15 * max(0, 1-share*10)
		unknownDetail = fmt.Sprintf("%d failing messages from unknown sources (%.1f%% of traffic)",
			in.UnknownFailing, 100*share)
	}

	comps := []HealthComponent{
		{"alignment", round1(alignment), 40, alignDetail},
		{"trend", round1(trend), 15, trendDetail},
		{"policy", round1(policy), 20, policyDetail},
		{"coverage", round1(coverage), 10, coverageDetail},
		{"unknown_sources", round1(unknown), 15, unknownDetail},
	}
	total := 0.0
	for _, c := range comps {
		total += c.Score
	}
	return int(total + 0.5), comps
}

func policyStrength(p *string, pct *int16) (float64, string) {
	pol := "none"
	if p != nil && *p != "" {
		pol = *p
	}
	base := map[string]float64{"reject": 1, "quarantine": 0.6, "none": 0.1}[pol]
	frac := 1.0
	if pct != nil && *pct >= 0 && *pct <= 100 {
		frac = float64(*pct) / 100
	}
	detail := fmt.Sprintf("p=%s pct=%.0f%%", pol, 100*frac)
	if pol == "none" {
		frac = 1 // pct is meaningless when nothing is enforced
	}
	return 20 * base * frac, detail
}

// --- domain list ---

type DomainSummary struct {
	Domain         string     `json:"domain"`
	Msgs30d        int64      `json:"msgs_30d"`
	AlignedRate30d float64    `json:"aligned_rate_30d"`
	LastReport     *time.Time `json:"last_report"`
	PolicyP        *string    `json:"policy_p"`
	PolicySP       *string    `json:"policy_sp"`
	PolicyPct      *int16     `json:"policy_pct"`
	Health         int        `json:"health"`
}

const listDomainsSQL = `
	WITH doms AS (SELECT DISTINCT domain FROM report),
	cur AS (
	  SELECT domain, SUM(msgs_total)::bigint AS msgs, SUM(msgs_aligned)::bigint AS aligned,
	         COUNT(*) FILTER (WHERE msgs_total > 0) AS days
	  FROM dmarc_agg_daily WHERE day >= current_date - 30 GROUP BY domain),
	prior AS (
	  SELECT domain, SUM(msgs_total)::bigint AS msgs, SUM(msgs_aligned)::bigint AS aligned
	  FROM dmarc_agg_daily WHERE day >= current_date - 60 AND day < current_date - 30 GROUP BY domain),
	lastr AS (SELECT domain, max(maxdate) AS last_report FROM report GROUP BY domain),
	pol AS (
	  SELECT DISTINCT ON (domain) domain, policy_p, policy_sp, policy_pct
	  FROM report ORDER BY domain, mindate DESC, serial DESC),
	unk AS (
	  SELECT r.domain, COALESCE(SUM(rr.rcount), 0)::bigint AS fails
	  FROM rptrecord rr
	  JOIN report r ON r.serial = rr.serial
	  LEFT JOIN ip_meta im ON im.ip = ` + recIPExpr + `
	  WHERE r.mindate >= now() - interval '30 days'
	    AND rr.dkim_align <> 'pass' AND rr.spf_align <> 'pass'
	    AND (im.sender_class IS NULL OR im.sender_class = '')
	  GROUP BY r.domain)
	SELECT d.domain,
	       COALESCE(cur.msgs, 0), COALESCE(cur.aligned, 0), COALESCE(cur.days, 0),
	       COALESCE(prior.msgs, 0), COALESCE(prior.aligned, 0),
	       lastr.last_report, pol.policy_p, pol.policy_sp, pol.policy_pct,
	       COALESCE(unk.fails, 0)
	FROM doms d
	LEFT JOIN cur USING (domain)
	LEFT JOIN prior USING (domain)
	LEFT JOIN lastr USING (domain)
	LEFT JOIN pol USING (domain)
	LEFT JOIN unk ON unk.domain = d.domain
	ORDER BY COALESCE(cur.msgs, 0) DESC, d.domain`

// ListDomains returns every reported-on domain with its 30d volume, aligned
// rate, last report, latest published policy and health score.
func (s *Store) ListDomains(ctx context.Context) ([]DomainSummary, error) {
	rows, err := s.pool.Query(ctx, listDomainsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DomainSummary{}
	for rows.Next() {
		var d DomainSummary
		var in HealthInputs
		var days int64
		if err := rows.Scan(&d.Domain, &in.Msgs30d, &in.Aligned30d, &days,
			&in.MsgsPrior, &in.AlignedPrior, &d.LastReport,
			&d.PolicyP, &d.PolicySP, &d.PolicyPct, &in.UnknownFailing); err != nil {
			return nil, err
		}
		in.DaysWithData = int(days)
		in.PolicyP, in.PolicyPct = d.PolicyP, d.PolicyPct
		d.Msgs30d = in.Msgs30d
		d.AlignedRate30d = ratio(in.Aligned30d, in.Msgs30d)
		d.Health, _ = ComputeHealth(in)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DomainHealthInputs gathers health inputs for one domain; found=false when
// the domain has never appeared in a report.
func (s *Store) DomainHealthInputs(ctx context.Context, domain string) (HealthInputs, bool, error) {
	var in HealthInputs
	err := s.pool.QueryRow(ctx, `
		SELECT policy_p, policy_pct FROM report
		WHERE domain = $1 ORDER BY mindate DESC, serial DESC LIMIT 1`,
		domain).Scan(&in.PolicyP, &in.PolicyPct)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, false, nil
	}
	if err != nil {
		return in, false, err
	}

	var days int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(msgs_total)   FILTER (WHERE day >= current_date - 30), 0)::bigint,
		       COALESCE(SUM(msgs_aligned) FILTER (WHERE day >= current_date - 30), 0)::bigint,
		       COUNT(*) FILTER (WHERE day >= current_date - 30 AND msgs_total > 0),
		       COALESCE(SUM(msgs_total)   FILTER (WHERE day < current_date - 30), 0)::bigint,
		       COALESCE(SUM(msgs_aligned) FILTER (WHERE day < current_date - 30), 0)::bigint
		FROM dmarc_agg_daily WHERE domain = $1 AND day >= current_date - 60`,
		domain).Scan(&in.Msgs30d, &in.Aligned30d, &days, &in.MsgsPrior, &in.AlignedPrior); err != nil {
		return in, false, err
	}
	in.DaysWithData = int(days)

	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(rr.rcount), 0)::bigint
		FROM rptrecord rr
		JOIN report r ON r.serial = rr.serial
		LEFT JOIN ip_meta im ON im.ip = `+recIPExpr+`
		WHERE r.domain = $1 AND r.mindate >= now() - interval '30 days'
		  AND rr.dkim_align <> 'pass' AND rr.spf_align <> 'pass'
		  AND (im.sender_class IS NULL OR im.sender_class = '')`,
		domain).Scan(&in.UnknownFailing); err != nil {
		return in, false, err
	}
	return in, true, nil
}

// --- readiness ---

type FailSource struct {
	IP          string  `json:"ip"`
	Msgs        int64   `json:"msgs"`
	PTR         *string `json:"ptr"`
	ASOrg       *string `json:"as_org"`
	SenderClass *string `json:"sender_class"`
}

type CurrentPolicy struct {
	P   *string `json:"p"`
	SP  *string `json:"sp"`
	Pct *int16  `json:"pct"`
}

type Readiness struct {
	Domain         string        `json:"domain"`
	AlignedRate30d float64       `json:"aligned_rate_30d"`
	AlignedRate90d float64       `json:"aligned_rate_90d"`
	Msgs30d        int64         `json:"msgs_30d"`
	Msgs90d        int64         `json:"msgs_90d"`
	FailSources    []FailSource  `json:"fail_sources"`
	CurrentPolicy  CurrentPolicy `json:"current_policy"`
	Recommendation string        `json:"recommendation"`
	Blockers       []string      `json:"blockers"`
}

// DomainReadiness builds the enforcement-readiness verdict for a domain;
// nil when the domain has never appeared in a report.
func (s *Store) DomainReadiness(ctx context.Context, domain string) (*Readiness, error) {
	rd := &Readiness{Domain: domain, FailSources: []FailSource{}}

	err := s.pool.QueryRow(ctx, `
		SELECT policy_p, policy_sp, policy_pct FROM report
		WHERE domain = $1 ORDER BY mindate DESC, serial DESC LIMIT 1`,
		domain).Scan(&rd.CurrentPolicy.P, &rd.CurrentPolicy.SP, &rd.CurrentPolicy.Pct)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var aligned30, aligned90 int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(msgs_total)   FILTER (WHERE day >= current_date - 30), 0)::bigint,
		       COALESCE(SUM(msgs_aligned) FILTER (WHERE day >= current_date - 30), 0)::bigint,
		       COALESCE(SUM(msgs_total), 0)::bigint,
		       COALESCE(SUM(msgs_aligned), 0)::bigint
		FROM dmarc_agg_daily WHERE domain = $1 AND day >= current_date - 90`,
		domain).Scan(&rd.Msgs30d, &aligned30, &rd.Msgs90d, &aligned90); err != nil {
		return nil, err
	}
	rd.AlignedRate30d = ratio(aligned30, rd.Msgs30d)
	rd.AlignedRate90d = ratio(aligned90, rd.Msgs90d)

	rows, err := s.pool.Query(ctx, `
		SELECT host(t.sip), t.msgs, im.ptr, im.as_org, im.sender_class
		FROM (
		  SELECT `+recIPExpr+` AS sip, SUM(rr.rcount)::bigint AS msgs
		  FROM rptrecord rr
		  JOIN report r ON r.serial = rr.serial
		  WHERE r.domain = $1 AND r.mindate >= now() - interval '90 days'
		    AND rr.dkim_align <> 'pass' AND rr.spf_align <> 'pass'
		  GROUP BY 1
		) t
		LEFT JOIN ip_meta im ON im.ip = t.sip
		WHERE t.sip IS NOT NULL
		ORDER BY t.msgs DESC
		LIMIT 10`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fs FailSource
		if err := rows.Scan(&fs.IP, &fs.Msgs, &fs.PTR, &fs.ASOrg, &fs.SenderClass); err != nil {
			return nil, err
		}
		rd.FailSources = append(rd.FailSources, fs)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rd.Recommendation, rd.Blockers = Recommend(
		rd.CurrentPolicy.P, rd.CurrentPolicy.Pct, rd.AlignedRate90d, rd.Msgs90d, rd.FailSources)
	return rd, nil
}

// Recommend is the pure readiness rules function (the viewer keeps an exact
// duplicate — see NOTES-analytics.md). Gate to advance enforcement: >=99.5%
// aligned over 90 days AND no unknown-class source with >100 failing msgs.
func Recommend(p *string, pct *int16, rate90 float64, msgs90 int64, fails []FailSource) (string, []string) {
	blockers := []string{}
	if msgs90 == 0 {
		return "monitor", []string{"no traffic observed in the last 90 days"}
	}
	if rate90 < 0.995 {
		blockers = append(blockers,
			fmt.Sprintf("aligned rate 90d %.2f%% is below 99.5%%", 100*rate90))
	}
	knownClassFailing := false
	for _, f := range fails {
		if f.SenderClass != nil && *f.SenderClass != "" {
			knownClassFailing = true
		} else if f.Msgs > 100 {
			blockers = append(blockers,
				fmt.Sprintf("unknown source %s: %d failing messages (90d)", f.IP, f.Msgs))
		}
	}
	if len(blockers) > 0 {
		if knownClassFailing {
			// Known ESPs are failing alignment: fixable misconfiguration.
			return "fix_alignment", blockers
		}
		return "monitor", blockers
	}

	pol := "none"
	if p != nil && *p != "" {
		pol = *p
	}
	fullPct := pct == nil || *pct >= 100
	switch {
	case pol == "reject" && fullPct:
		return "monitor", blockers // fully enforced already
	case (pol == "reject" || pol == "quarantine") && !fullPct:
		return "step_pct", blockers
	case pol == "quarantine":
		return "enforce", blockers // quarantine at 100% -> move to reject
	default:
		return "enforce", blockers // p=none and clean: start enforcing
	}
}

func ratio(part, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func round1(v float64) float64 {
	if v < 0 {
		return 0
	}
	return float64(int(v*10+0.5)) / 10
}
