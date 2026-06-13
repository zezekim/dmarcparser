package digest

import (
	"context"
	"time"
)

type weekStats struct {
	Msgs    int64
	Aligned int64
}

func (w weekStats) PassRate() float64 {
	if w.Msgs == 0 {
		return 0
	}
	return float64(w.Aligned) / float64(w.Msgs) * 100
}

type failSource struct {
	IP          string
	Msgs        int64
	PTR         string
	SenderClass string
}

type newSender struct {
	IP        string
	FirstSeen time.Time
	Msgs      int64
	Aligned   int64
	PTR       string
}

type domainDigest struct {
	Domain     string
	Start, End time.Time // [Start, End)
	This, Prev weekStats
	TopFailing []failSource
	NewSenders []newSender
}

func (d *Digester) gather(ctx context.Context, domain string, start, end time.Time) (*domainDigest, error) {
	out := &domainDigest{Domain: domain, Start: start, End: end}

	err := d.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(msgs_total),0), COALESCE(SUM(msgs_aligned),0)
		FROM dmarc_agg_daily WHERE domain=$1 AND day >= $2 AND day < $3`,
		domain, start, end).Scan(&out.This.Msgs, &out.This.Aligned)
	if err != nil {
		return nil, err
	}
	err = d.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(msgs_total),0), COALESCE(SUM(msgs_aligned),0)
		FROM dmarc_agg_daily WHERE domain=$1 AND day >= $2 AND day < $3`,
		domain, start.AddDate(0, 0, -7), start).Scan(&out.Prev.Msgs, &out.Prev.Aligned)
	if err != nil {
		return nil, err
	}

	rows, err := d.pool.Query(ctx, `
		SELECT host(f.ip), SUM(f.msgs) AS msgs, COALESCE(MAX(im.ptr),''), COALESCE(MAX(im.sender_class),'')
		FROM (
		  SELECT CASE
		           WHEN rr.ip IS NOT NULL THEN '0.0.0.0'::inet + rr.ip
		           WHEN length(rr.ip6) = 16 THEN
		             (trim(trailing ':' from regexp_replace(encode(rr.ip6,'hex'),'(....)','\1:','g')))::inet
		           ELSE NULL END AS ip,
		         rr.rcount AS msgs
		  FROM report r JOIN rptrecord rr ON rr.serial = r.serial
		  WHERE r.domain = $1 AND r.mindate >= $2 AND r.mindate < $3
		    AND rr.dkim_align <> 'pass' AND rr.spf_align <> 'pass'
		) f
		LEFT JOIN ip_meta im ON im.ip = f.ip
		WHERE f.ip IS NOT NULL
		GROUP BY f.ip
		ORDER BY msgs DESC
		LIMIT 5`, domain, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var f failSource
		if err := rows.Scan(&f.IP, &f.Msgs, &f.PTR, &f.SenderClass); err != nil {
			return nil, err
		}
		out.TopFailing = append(out.TopFailing, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = d.pool.Query(ctx, `
		SELECT host(ds.ip), ds.first_seen, ds.msg_count, ds.aligned_count, COALESCE(im.ptr,'')
		FROM domain_source ds
		LEFT JOIN ip_meta im ON im.ip = ds.ip
		WHERE ds.domain = $1 AND ds.first_seen >= $2 AND ds.first_seen < $3
		ORDER BY ds.msg_count DESC
		LIMIT 10`, domain, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n newSender
		if err := rows.Scan(&n.IP, &n.FirstSeen, &n.Msgs, &n.Aligned, &n.PTR); err != nil {
			return nil, err
		}
		n.FirstSeen = n.FirstSeen.UTC()
		out.NewSenders = append(out.NewSenders, n)
	}
	return out, rows.Err()
}
