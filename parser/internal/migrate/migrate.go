// Package migrate applies the additive, idempotent v2 DDL at startup,
// before anything else touches the database. The legacy report/rptrecord
// tables are never altered beyond ADD COLUMN IF NOT EXISTS.
package migrate

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

var statements = []string{
	`ALTER TABLE report ADD COLUMN IF NOT EXISTS seen timestamptz DEFAULT now()`,
	`CREATE INDEX IF NOT EXISTS idx_report_domain_mindate ON report(domain, mindate)`,
	`CREATE INDEX IF NOT EXISTS idx_report_seen ON report(seen)`,

	`CREATE TABLE IF NOT EXISTS dmarc_agg_daily (
	  day date NOT NULL, domain varchar(255) NOT NULL,
	  msgs_total bigint NOT NULL DEFAULT 0, msgs_aligned bigint NOT NULL DEFAULT 0,
	  msgs_dkim_aligned bigint NOT NULL DEFAULT 0, msgs_spf_aligned bigint NOT NULL DEFAULT 0,
	  msgs_none bigint NOT NULL DEFAULT 0, msgs_quarantine bigint NOT NULL DEFAULT 0,
	  msgs_reject bigint NOT NULL DEFAULT 0, reports int NOT NULL DEFAULT 0,
	  PRIMARY KEY (day, domain))`,

	`CREATE TABLE IF NOT EXISTS ip_meta (
	  ip inet PRIMARY KEY, ptr text, asn bigint, as_org text, country varchar(2),
	  sender_class text, first_seen timestamptz DEFAULT now(), refreshed_at timestamptz)`,

	`CREATE TABLE IF NOT EXISTS domain_source (
	  domain varchar(255) NOT NULL, ip inet NOT NULL,
	  first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
	  first_serial bigint, msg_count bigint NOT NULL DEFAULT 0,
	  aligned_count bigint NOT NULL DEFAULT 0, acked boolean NOT NULL DEFAULT false,
	  PRIMARY KEY (domain, ip))`,

	// rptrecord IP lookups for /ips/{ip} (INTEL).
	`CREATE INDEX IF NOT EXISTS idx_rptrecord_ip ON rptrecord(ip)`,
	`CREATE INDEX IF NOT EXISTS idx_rptrecord_ip6 ON rptrecord(ip6)`,

	`CREATE TABLE IF NOT EXISTS dkim_auth (
	  id bigserial PRIMARY KEY, serial bigint NOT NULL,
	  dkimdomain varchar(255), selector varchar(255), result varchar(20))`,
	`CREATE INDEX IF NOT EXISTS idx_dkim_auth_serial ON dkim_auth(serial)`,
	`CREATE INDEX IF NOT EXISTS idx_dkim_auth_sel ON dkim_auth(dkimdomain, selector)`,

	`CREATE TABLE IF NOT EXISTS tlsrpt_report (
	  id bigserial PRIMARY KEY, org text NOT NULL, report_id text NOT NULL,
	  contact text, date_begin timestamptz, date_end timestamptz,
	  raw_json jsonb, seen timestamptz DEFAULT now(), UNIQUE(org, report_id))`,
	`CREATE TABLE IF NOT EXISTS tlsrpt_policy (
	  id bigserial PRIMARY KEY,
	  report_fk bigint NOT NULL REFERENCES tlsrpt_report(id) ON DELETE CASCADE,
	  policy_type text, policy_domain text, mx_host text,
	  success_count bigint NOT NULL DEFAULT 0, failure_count bigint NOT NULL DEFAULT 0,
	  failure_details jsonb)`,

	`CREATE TABLE IF NOT EXISTS forensic_report (
	  id bigserial PRIMARY KEY, seen timestamptz DEFAULT now(),
	  feedback_type text, auth_failure text, source_ip inet,
	  reported_domain varchar(255), original_mail_from text, arrival_date timestamptz,
	  subject text, message_id text, header_from text, raw_headers text)`,

	`CREATE TABLE IF NOT EXISTS parser_audit (
	  id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(),
	  actor text, action text, route text, status int, client_ip inet, detail jsonb)`,
	`CREATE INDEX IF NOT EXISTS idx_parser_audit_ts ON parser_audit(ts)`,

	`CREATE TABLE IF NOT EXISTS webhook_deadletter (
	  id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(),
	  endpoint text, kind text, payload jsonb, last_error text, replayed_at timestamptz)`,

	`CREATE TABLE IF NOT EXISTS share_token (
	  token text PRIMARY KEY, label text, domains text[] NOT NULL,
	  created_at timestamptz DEFAULT now(), revoked boolean NOT NULL DEFAULT false)`,

	`CREATE TABLE IF NOT EXISTS digest_subscription (
	  id bigserial PRIMARY KEY, domain varchar(255) NOT NULL, email text NOT NULL,
	  UNIQUE(domain, email))`,
	`CREATE TABLE IF NOT EXISTS digest_log (
	  id bigserial PRIMARY KEY, domain varchar(255), sent_at timestamptz DEFAULT now(),
	  period_start date, period_end date)`,

	`CREATE TABLE IF NOT EXISTS alert_state (
	  rule text PRIMARY KEY, last_fired timestamptz, detail jsonb)`,
}

// Run executes every DDL statement in order. All statements are idempotent,
// so a partial earlier run is harmless.
func Run(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	log = log.With("component", "migrate")
	for i, stmt := range statements {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("migrate statement %d (%s): %w", i+1, summary(stmt), err)
		}
		log.Info("applied", "n", i+1, "stmt", summary(stmt))
	}
	log.Info("migrations complete", "statements", len(statements))
	return nil
}

func summary(stmt string) string {
	first := strings.Join(strings.Fields(stmt), " ")
	if len(first) > 64 {
		first = first[:64] + "…"
	}
	return first
}
