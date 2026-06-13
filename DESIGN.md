# DESIGN: dmarcparser v2 feature build

Contract for the v2 feature batch. Every implementing agent MUST read this
fully before writing code. The base system is described in SPEC.md/README.md.
Live deployment notes: real domains/secrets live in untracked `.env` — never
hardcode real domains/hostnames anywhere; use config/env.

## Goals

Build all v2 features. Everything must be reachable via the parser REST API
(consumers: mxsentinel services on the `mxsentinel_default` network, and WHMCS
over HTTP). Viewer (separate app `/opt/dmarc/app`, same Postgres) gets
human-facing pages for the same data by querying the shared DB directly.

## Hard rules

1. **Additive schema only.** Never ALTER existing column types or drop
   anything in `report`/`rptrecord`. All DDL lives in
   `parser/internal/migrate/migrate.go` (new package) as a list of idempotent
   statements (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF NOT
   EXISTS`, `CREATE INDEX IF NOT EXISTS`) run at parser startup before
   anything else.
2. **File ownership** (see matrix below). Do not edit files owned by another
   agent. If you need a change in a shared file, write it into your
   `NOTES-<yourname>.md` at repo root; the Integration agent applies it.
3. Go only, std-lib bias. Allowed new deps: `golang.org/x/time/rate`. No cgo,
   no MaxMind mmdb (ASN/country via Team Cymru DNS, see Enrichment).
4. Verify your package compiles:
   `docker run --rm -v /opt/dmarcparser/parser:/src -w /src golang:1.25-alpine go build ./...`
   (and `go vet ./...`). For viewer work use `-v /opt/dmarc/app:/src`.
5. Do NOT restart/rebuild the running containers and do NOT touch git —
   integration/verification handles that.
6. Match existing code style: slog JSON logging, chi router patterns in
   api.go, pgx pool, writeJSON/writeErr helpers, table-driven config in
   config.go.

## File / package ownership matrix

| Owner | Files (parser unless noted) |
|---|---|
| FOUNDATION | internal/migrate/* (new), internal/config/config.go, internal/api/api.go (auth/middleware/router skeleton), internal/webhook/webhook.go, internal/metrics/metrics.go, internal/store/store.go (seen column + SaveResult extension + LastIngest), internal/poller/poller.go (emit hooks), internal/pipeline/* (new), internal/retention/* (new), internal/watchdog/* (new) |
| INTEL | internal/enrich/* (new), internal/store/store_intel.go (new), internal/api/api_intel.go (new) |
| ANALYTICS | internal/rollup/* (new), internal/store/store_stats.go (new), internal/api/api_stats.go (new) |
| REPORTS2 | internal/report/report.go + payload.go (selector capture, TLS-RPT sniff), internal/mailx/mailx.go (forensic part detection), internal/tlsrpt/* (new), internal/forensic/* (new), internal/store/store_reports2.go (new), internal/api/api_reports2.go (new) |
| PLATFORM | internal/export/* (new), internal/audit/* (new), internal/digest/* (new), internal/api/api_platform.go (new), openapi.yaml (new, repo root) |
| BACKUP | backup/* (new: scripts + README), compose snippet in NOTES-backup.md |
| VIEWER | /opt/dmarc/app/** (all of it) |
| INTEGRATION | parser/main.go, compose.yaml, parser/Dockerfile, applying every NOTES-*.md, final build |

API route registration: each API-owning agent defines
`func RegisterX(r chi.Router, deps …)` in their own api_*.go file; the
Integration agent calls them from the router setup. Same pattern for pipeline
observers: each feature package exposes `New(…) pipeline.Observer`;
Integration wires registration in main.go.

## Shared spine (FOUNDATION builds this first)

### pipeline package

```go
package pipeline
type IngestEvent struct {
    Report  *report.Report   // parsed report
    Result  store.SaveResult // serial, duplicate, records, messages
    Source  string           // "imap" | "api"
}
type Observer interface{ OnIngest(ctx context.Context, ev IngestEvent) }
type Registry struct{ … } // Register(Observer); Emit(ctx, ev) — synchronous, in order,
                          // each observer error logged but never blocks ingest
```
Poller and API call `registry.Emit` after every successful **non-duplicate**
save. Existing webhook send becomes the first registered observer.

### Auth: scoped keys + rate limit (in api.go)

`PARSER_API_KEYS` new format: comma-separated `name=key=scopes`, scopes
pipe-separated from {read, ingest, admin}; `*` = all. Backward compat: a bare
`key` entry → name "default", all scopes. Constant-time compare
(crypto/subtle). Per-key token bucket via golang.org/x/time/rate
(`PARSER_RATE_LIMIT_RPS` default 10, burst 3×; 429 + Retry-After on exceed).
Key name goes into request context + all logs + audit. Middleware
`requireScope(scope string)` for route groups.

Scope map: ingest→{ingest}; poll/requeue/audit/webhook-replay/sources-ack→{admin};
everything else read→{read}. /healthz, /metrics, /api/v1/openapi.json unauthenticated.

### Webhook generalization

`Notifier.NotifyEvent(kind string, payload any)` — kind sets JSON "event"
field and X-Parser-Event header. Multi-endpoint: `PARSER_WEBHOOK_URLS`
(comma-separated; fallback to legacy `PARSER_WEBHOOK_URL`). After final retry
failure, insert into `webhook_deadletter` (best-effort) and increment metric.
Keep `Notify(Event)` as a thin wrapper emitting kind "report.ingested".
Event kinds: report.ingested, sender.new, domain.anomaly, report.failed,
poller.degraded, tlsrpt.ingested, forensic.ingested.

### Store / poller spine changes

- `insertReportSQL` adds `seen` (now()). `SaveResult` unchanged shape plus
  nothing — feature data flows through pipeline observers re-reading the
  parsed report.
- Store exposes `LastIngestAt(ctx) (time.Time, error)` (max(seen)) for the
  watchdog, and tracks an in-memory atomic of last successful insert.
- Poller: on `outcomeFailed` emit webhook "report.failed" (subject/from);
  on cycle error emit "poller.degraded" (rate-limited by watchdog cooldown).

### retention package

Daily ticker (first run 5 min after boot):
- `UPDATE report SET raw_xml=NULL WHERE seen < now()-$RAW_RETENTION AND raw_xml IS NOT NULL`
  batched 5000 rows via ctid subselect loop; skip if retention 0.
- Optional IMAP expunge of Processed/Ignored older than `PARSER_MAIL_RETENTION`
  (reuse poller dial/login helpers; factor a small shared connect func).
- Audit-log row counts; metrics `dmarcparser_retention_rows_purged_total{kind}`.

### watchdog package

Ticker 10 min. Rules (each fires `PARSER_ALERT_URL` POST {rule, message,
detail, ts} AND webhook kind "poller.degraded"-style events; 6h cooldown per
rule persisted in `alert_state`):
- silence: LastIngestAt older than `PARSER_ALERT_SILENCE` (default 36h)
- poll_failures: ≥3 consecutive cycle errors (read metrics atomics)
- failed_spike: MailsFailed delta ≥ `PARSER_ALERT_FAILED_SPIKE` (default 10)/24h
- webhook_dead: WebhookFailures delta > 0 since last check
healthz exposes rule states: `"alerts": {"silence":"ok"|"firing", …}`.

### Config additions (config.go; all with sane defaults)

```
PARSER_RATE_LIMIT_RPS=10
PARSER_WEBHOOK_URLS=            (fallback PARSER_WEBHOOK_URL)
PARSER_ALERT_URL=               PARSER_ALERT_SILENCE=36h
PARSER_ALERT_FAILED_SPIKE=10    PARSER_ANOMALY_SIGMA=3
PARSER_ANOMALY_MIN_FAILS=50     PARSER_NEWSENDER_MIN_MSGS=5
PARSER_RAW_XML_RETENTION=2160h  (0=keep)   PARSER_MAIL_RETENTION=720h (0=keep)
PARSER_RUF_REDACT=true          PARSER_ENRICH_WORKERS=4
PARSER_DIGEST_ENABLED=false     PARSER_DIGEST_SMTP_ADDR=mailserver:587
PARSER_DIGEST_SMTP_USER=        (default = PARSER_IMAP_USER)
PARSER_DIGEST_FROM=             (default = PARSER_IMAP_USER)
PARSER_DIGEST_DAY=Monday        PARSER_DIGEST_HOUR=7
PARSER_VIEWER_URL=              (for links in digests/webhooks)
```

## Schema (migrate package, exact DDL)

```sql
ALTER TABLE report ADD COLUMN IF NOT EXISTS seen timestamptz DEFAULT now();
CREATE INDEX IF NOT EXISTS idx_report_domain_mindate ON report(domain, mindate);
CREATE INDEX IF NOT EXISTS idx_report_seen ON report(seen);

CREATE TABLE IF NOT EXISTS dmarc_agg_daily (
  day date NOT NULL, domain varchar(255) NOT NULL,
  msgs_total bigint NOT NULL DEFAULT 0, msgs_aligned bigint NOT NULL DEFAULT 0,
  msgs_dkim_aligned bigint NOT NULL DEFAULT 0, msgs_spf_aligned bigint NOT NULL DEFAULT 0,
  msgs_none bigint NOT NULL DEFAULT 0, msgs_quarantine bigint NOT NULL DEFAULT 0,
  msgs_reject bigint NOT NULL DEFAULT 0, reports int NOT NULL DEFAULT 0,
  PRIMARY KEY (day, domain));

CREATE TABLE IF NOT EXISTS ip_meta (
  ip inet PRIMARY KEY, ptr text, asn bigint, as_org text, country varchar(2),
  sender_class text, first_seen timestamptz DEFAULT now(), refreshed_at timestamptz);

CREATE TABLE IF NOT EXISTS domain_source (
  domain varchar(255) NOT NULL, ip inet NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
  first_serial bigint, msg_count bigint NOT NULL DEFAULT 0,
  aligned_count bigint NOT NULL DEFAULT 0, acked boolean NOT NULL DEFAULT false,
  PRIMARY KEY (domain, ip));

CREATE TABLE IF NOT EXISTS dkim_auth (
  id bigserial PRIMARY KEY, serial bigint NOT NULL,
  dkimdomain varchar(255), selector varchar(255), result varchar(20));
CREATE INDEX IF NOT EXISTS idx_dkim_auth_serial ON dkim_auth(serial);
CREATE INDEX IF NOT EXISTS idx_dkim_auth_sel ON dkim_auth(dkimdomain, selector);

CREATE TABLE IF NOT EXISTS tlsrpt_report (
  id bigserial PRIMARY KEY, org text NOT NULL, report_id text NOT NULL,
  contact text, date_begin timestamptz, date_end timestamptz,
  raw_json jsonb, seen timestamptz DEFAULT now(), UNIQUE(org, report_id));
CREATE TABLE IF NOT EXISTS tlsrpt_policy (
  id bigserial PRIMARY KEY,
  report_fk bigint NOT NULL REFERENCES tlsrpt_report(id) ON DELETE CASCADE,
  policy_type text, policy_domain text, mx_host text,
  success_count bigint NOT NULL DEFAULT 0, failure_count bigint NOT NULL DEFAULT 0,
  failure_details jsonb);

CREATE TABLE IF NOT EXISTS forensic_report (
  id bigserial PRIMARY KEY, seen timestamptz DEFAULT now(),
  feedback_type text, auth_failure text, source_ip inet,
  reported_domain varchar(255), original_mail_from text, arrival_date timestamptz,
  subject text, message_id text, header_from text, raw_headers text);

CREATE TABLE IF NOT EXISTS parser_audit (
  id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(),
  actor text, action text, route text, status int, client_ip inet, detail jsonb);
CREATE INDEX IF NOT EXISTS idx_parser_audit_ts ON parser_audit(ts);

CREATE TABLE IF NOT EXISTS webhook_deadletter (
  id bigserial PRIMARY KEY, ts timestamptz DEFAULT now(),
  endpoint text, kind text, payload jsonb, last_error text, replayed_at timestamptz);

CREATE TABLE IF NOT EXISTS share_token (
  token text PRIMARY KEY, label text, domains text[] NOT NULL,
  created_at timestamptz DEFAULT now(), revoked boolean NOT NULL DEFAULT false);

CREATE TABLE IF NOT EXISTS digest_subscription (
  id bigserial PRIMARY KEY, domain varchar(255) NOT NULL, email text NOT NULL,
  UNIQUE(domain, email));
CREATE TABLE IF NOT EXISTS digest_log (
  id bigserial PRIMARY KEY, domain varchar(255), sent_at timestamptz DEFAULT now(),
  period_start date, period_end date);

CREATE TABLE IF NOT EXISTS alert_state (
  rule text PRIMARY KEY, last_fired timestamptz, detail jsonb);
```

## Features by agent

### INTEL — enrichment + new-sender + threat views

- `internal/enrich`: worker pool (PARSER_ENRICH_WORKERS) consuming a buffered
  channel of IPs. For each: PTR via net.LookupAddr (5s timeout); ASN+country
  via Team Cymru DNS TXT (`<reversed-ip>.origin.asn.cymru.com` /
  `origin6.asn.cymru.com`, then `AS<asn>.asn.cymru.com` for as_org). Upsert
  ip_meta (refresh if older than 30d). sender_class via embedded PTR-suffix /
  dkim-domain rules table (google.com→google, *.protection.outlook.com→microsoft365,
  amazonses.com→amazon-ses, sendgrid.net→sendgrid, mailgun→mailgun,
  mcsv.net|mailchimp→mailchimp, pphosted.com→proofpoint, mimecast→mimecast,
  zoho→zoho, ovh→ovh, hetzner→hetzner, …extendable).
- Pipeline observer: on ingest, for each record IP: upsert domain_source
  (counts, last_seen, first_serial on insert); enqueue enrichment; if the
  (domain, ip) pair is NEW and report-msgs ≥ PARSER_NEWSENDER_MIN_MSGS or
  unaligned → NotifyEvent("sender.new", {domain, ip, ptr?, msgs, aligned,
  serial, first_seen}).
- Anomaly check (same observer or post-cycle): current-day fails for touched
  domains vs trailing 30d mean+SIGMA*stddev from dmarc_agg_daily (floor
  PARSER_ANOMALY_MIN_FAILS) → NotifyEvent("domain.anomaly", evidence) with
  per-day suppression via alert_state (rule "anomaly:<domain>:<day>").
- Backfill: binary flag `-backfill-sources` → one INSERT…SELECT from
  rptrecord/report into domain_source (acked=true so history doesn't alarm),
  plus seed enrichment queue with distinct IPs.
- API (api_intel.go): GET /sources (threat list: per IP totals, failed msgs,
  domains targeted, ip_meta join; filters domain/min_failed/since),
  GET /ips/{ip} (cross-report activity + meta), GET /domains/{domain}/sources
  (?unacked=true), POST /sources/ack {domain, ip} [admin].

### ANALYTICS — rollups, stats, readiness

- `internal/rollup`: pipeline observer upserting dmarc_agg_daily buckets by
  date_trunc('day', report.mindate) from the parsed records (aligned = dkim
  OR spf align pass; dkim/spf split; disposition buckets; reports+1 on the
  report's begin day). Duplicates never reach observers, so no double count.
- Backfill flag `-backfill-rollups`: single INSERT…SELECT…GROUP BY over
  existing data (truncate-and-rebuild semantics: DELETE FROM dmarc_agg_daily
  first).
- store_stats.go + api_stats.go:
  - GET /stats/timeseries?domain&bucket=day|week&since&until → rows {bucket,
    msgs_total, msgs_aligned, pass_rate, none/quarantine/reject}
  - GET /stats/top?dimension=ip|org|header_from&domain&since&until&limit&failing=true
  - GET /domains → list with 30d msgs, aligned rate, last_report (max maxdate),
    latest published policy (DISTINCT ON), health score
  - GET /domains/{domain}/health → score 0–100 + component breakdown
    (weights: alignment 40, trend 15, policy strength 20, coverage 10,
    unknown-source failing volume 15)
  - GET /domains/{domain}/readiness → {aligned_rate_30d, aligned_rate_90d,
    fail_sources: top unaligned senders w/ class, current_policy,
    recommendation: enforce|step_pct|fix_alignment|monitor, blockers: […]}.
    Pure-Go rules: ≥99.5% aligned 90d & no unknown source >100 msgs → step up.

### REPORTS2 — selectors, TLS-RPT, forensic

- report.go: authResult gains Selector `xml:"selector"`; Record keeps full
  DKIM/SPF slices (new fields DKIMAll/SPFAll) while existing collapsed fields
  stay for the frozen tables. store_reports2.go writes dkim_auth rows in the
  SaveReport observer? No — dkim_auth needs the tx; instead expose
  store.SaveDKIMAuth(ctx, serial, entries) called from a pipeline observer
  (own tx, idempotent: DELETE WHERE serial=$1 then insert).
- payload.go: ExpandPayload returns typed payloads: add JSON sniff (leading
  '{' containing "organization-name" and "policies") → kind tlsrpt. Public
  API becomes ExpandPayloadTyped returning []TypedPayload{Kind, Data} with
  the old func kept as a shim for aggregate-only callers.
- internal/tlsrpt: RFC 8460 structs, Parse(data) → model; store into
  tlsrpt_report/tlsrpt_policy with ON CONFLICT (org, report_id) DO NOTHING;
  poller files such mail as Processed; NotifyEvent("tlsrpt.ingested", …);
  metric dmarcparser_tlsrpt_ingested_total.
- internal/forensic: detect multipart/report (Content-Type message/
  feedback-report) in mailx walk; parse key-value AFRF fields + selected
  headers of the message/rfc822 part; PARSER_RUF_REDACT strips recipient
  localparts (keep domain); store forensic_report; file as Processed;
  NotifyEvent("forensic.ingested", …); metric.
- Backfill flag `-backfill-selectors`: iterate report.raw_xml (batched,
  serial-ordered) re-running ParseXML → SaveDKIMAuth. Skip NULL raw_xml.
- API (api_reports2.go): GET /domains/{domain}/selectors (inventory w/
  first/last seen, pass/fail counts), GET /tlsrpt (+/{id}), GET /forensic
  (+/{id}, admin scope because PII-ish? keep read but honor redaction).

### PLATFORM — export, OpenAPI, audit, digest, requeue

- internal/export: GET /export?format=csv|jsonl&domain&org&since&until —
  streams flattened report×record rows (serial, domain, org, reportid, dates,
  source_ip rendered, rcount, disposition, aligns, auth results,
  header_from). Chunked streaming via pgx rows, http.Flusher.
  GET /reports/{serial}/raw → raw_xml download (Content-Type text/xml;
  404 if aged out).
- internal/audit: chi middleware (after auth) wrapping ResponseWriter,
  fire-and-forget insert into parser_audit (actor=key name, action=method,
  route pattern, status, client ip, detail: ingested serials when available
  via context). Also helpers for poller (mail→Failed) + webhook deadletter.
  GET /audit?since&actor&limit [admin].
- POST /requeue-failed [admin]: IMAP-move everything in Failed back to INBOX
  (unseen) + TriggerNow. Reuse poller connect helper.
- POST /webhooks/replay [admin]: re-deliver un-replayed webhook_deadletter
  rows (mark replayed_at on success).
- internal/digest: weekly scheduler (DIGEST_DAY/HOUR, guarded by digest_log);
  per digest_subscription domain: 7d vs prior-7d volume/pass-rate from
  dmarc_agg_daily, top failing sources, new senders; render inline-styled
  HTML (no external CSS); send via SMTP AUTH (net/smtp, PARSER_DIGEST_SMTP_*,
  STARTTLS with InsecureSkipVerify matching IMAP setting) to each subscriber.
  API: GET/POST/DELETE /digest/subscriptions [admin], POST /digest/run
  [admin] (force-send now, for testing).
- openapi.yaml (root): OpenAPI 3.1 covering EVERY /api/v1 route incl. auth
  scheme, scopes, schemas. Served at GET /api/v1/openapi.json (convert
  YAML→JSON at build? simpler: also commit openapi.json generated by hand —
  keep both in sync; serving reads the embedded JSON via go:embed).

### BACKUP — sidecar

backup/ dir: backup.sh (pg_dump -Fc via PARSER_DATABASE_URL → /backups/
dmarc-YYYY-MM-DD.dump + tar of /mailconfig (ro mount of docker-data/dms/
config); prune: keep 14 daily, 8 weekly), verify.sh (weekly pg_restore
--list integrity + monthly full test-restore into a scratch `postgres`
container via docker CLI? No docker inside container — instead do pg_restore
--list always and document manual full-restore drill), entry crond setup,
README-backup.md with restore runbook. NOTES-backup.md: compose service
snippet (postgres:16-alpine image, dmarc_default network, /var/backups/dmarc
host mount, env from .env) + healthcheck reading /backups/.last-success age.

### VIEWER — /opt/dmarc/app (Go templates + htmx + Tailwind CDN)

All data read directly from the shared Postgres (new tables above).
- Report list: since/until date inputs + free-text q (domain/org/reportid/
  header_from/dkim/spf domains via EXISTS subquery) + status filter moved
  into SQL (HAVING on aggregated pass/fail) + "load more" pagination
  (offset, hx-get beforeend). Show NEW badge on reports whose serial matches
  an unacked domain_source.first_serial.
- /domains: health grid (per-domain: aligned rate 30d, trend vs prior 30d,
  policy posture, last-report age, sparkline inline SVG from dmarc_agg_daily).
  /domains/{domain}: detail w/ timeseries chart, top failing sources (joined
  ip_meta: ptr/asn/class), selectors table (dkim_auth), readiness verdict
  (same rules as parser — duplicate the small pure function), unacked new
  sources with ack button (POST /sources/ack updates domain_source).
- /ips/{ip}: cross-report drill-down + ip_meta card; every IP in record
  tables becomes a link.
- /misalignment: explorer grouping failing traffic by identifier_hfrom ×
  dkimdomain/spfdomain with classification chips ("fix alignment" vs "likely
  spoofing") + volumes; filterable by domain + range.
- /analytics: add timeseries chart (Chart.js from CDN, fed by a JSON
  <script> block from dmarc_agg_daily) with domain + range filters.
- /share/{token}: unauthenticated route group (outside basicAuth) rendering
  the domain detail/analytics scoped to share_token.domains (verify not
  revoked). /shares admin page (behind basicAuth): create (crypto/rand 32
  hex)/revoke tokens. No raw-xml or report-detail under /share.
- POST /hooks/parser (unauth route, HMAC verify X-Parser-Signature against
  PARSER_WEBHOOK_SECRET env shared with parser): receives sender.new etc. —
  used to invalidate a tiny in-memory cache of unacked counts (optional, keep
  simple: just 204 it; the navbar badge queries live).
- Header From column added to the report detail record table.

## Compose / hardening (INTEGRATION applies)

- parser: USER nonroot in Dockerfile (adduser -D -u 65532), read_only root fs,
  cap_drop ALL, no-new-privileges, tmpfs /tmp, healthcheck wget /healthz
  (apk add wget in final stage or use the binary's own `-healthcheck` flag —
  add tiny flag in main.go that GETs healthz and exits 0/1).
- mailserver: ports "127.0.0.1:993:993" (was public).
- new backup service per NOTES-backup.md; mount /var/backups/dmarc.
- compose env passthrough for all new PARSER_* vars (with :-defaults).
- viewer compose (/opt/dmarc/docker-compose.yml): no changes expected beyond
  rebuild; if env needed (PARSER_WEBHOOK_SECRET for /hooks/parser), NOTES it.

## Verification checklist (VERIFY agent)

Build both images; `docker compose up -d` both stacks; then:
1. /healthz ok incl. "alerts" map; migrations created all tables (psql \dt).
2. Backfills: run -backfill-rollups, -backfill-sources, -backfill-selectors
   via `docker compose run --rm --no-deps parser -backfill-…` (flag-only —
   the image ENTRYPOINT is already /dmarc-parser, so passing /dmarc-parser
   again makes it a positional arg and flag.Parse() ignores the -backfill-*
   flag, booting a second live poller instead); spot-check row counts vs
   report/rptrecord.
3. Ingest the sample report (testdata in /tmp) via API with an ingest-scoped
   key → 201; duplicate → 200; read-scoped key on /ingest → 403; bad key 401;
   hammer to trigger 429.
4. Rollup row updated for the day; /stats/timeseries + /stats/top return it.
5. domain_source row created; second distinct-IP ingest fires sender.new
   (point PARSER_WEBHOOK_URLS at a netcat/python listener in a sidecar to
   capture; verify HMAC header present).
6. /sources, /ips/{ip}, /domains, /domains/{d}/health, /readiness,
   /selectors, /export (csv lines >0), /reports/{serial}/raw, /audit rows
   exist, openapi.json serves.
7. TLS-RPT: craft RFC 8460 JSON (gzip), mail it in → Processed + /tlsrpt
   shows it. Forensic: craft a small AFRF multipart/report mail → Processed +
   /forensic shows it (redaction on).
8. Viewer: every new page 200s with real data through https://… (use Host
   header against the caddy container or localhost mapping); share token
   create → /share/{token} works unauthenticated and is scoped; revoke kills.
9. Backup: exec backup.sh once; dump file exists; verify.sh passes.
10. Watchdog: /healthz alerts map present; force webhook_dead by pointing a
    second webhook URL at a closed port and ingesting (after retries ~10s
    backoff… acceptable to assert deadletter row instead).
11. Existing regression: viewer report list loads; old API routes unchanged;
    poller cycle completes clean.
Cleanup: delete synthetic test reports (domain like 'parsertest%' or
selftest reportids) from report/rptrecord/domain_source/rollups (rebuild
rollups via backfill after cleanup), remove webhook-capture sidecar.

## Notes for all agents

- The DB has 158k reports/1.3M records — backfills must batch and must not
  lock tables for minutes. Use keyset batching by serial.
- Production is live; do not break the running poller. Code changes only;
  restarts happen in INTEGRATION/VERIFY.
- All timestamps UTC. All new API output JSON snake_case like existing code.
- Errors: writeErr(w, code, msg); never leak SQL.
- Keep functions small; comments only where the code can't say it.
