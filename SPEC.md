# dmarc-parser — DMARC aggregate report parser & ingestion API

A single Go service that turns DMARC aggregate (rua) report emails into rows in
the `dmarc` Postgres database (the one behind https://dmarc.example.org), and
exposes a REST API so other services can ingest, query, and get notified.

```
                       ┌──────────────────────────── this host ───────────────────────────┐
 reporters (Google,    │  host Postfix :25 → dmarc-mailserver :2525 → dmarc@example.org    │
 Microsoft, …) ──mail──▶                                  │ IMAPS (self-signed)            │
                       │                         dmarc-parser ──INSERT──▶ dmarc-db-1 (PG)  │
 other services ──HTTP─▶  :8081 / dmarcparser:8080        │                  ▲             │
                       │      (REST API)            webhook POST     dmarc.example.org     │
                       └──────────────────────────────────────────────── (viewer reads) ───┘
```

## Responsibilities

1. **IMAP poller** — every `PARSER_POLL_INTERVAL` (default `5m`), connect to the
   local docker-mailserver over IMAPS, fetch UNSEEN messages from INBOX,
   extract report payloads, parse, store, then file the message away:
   - `Processed` — at least one report stored (or all were duplicates)
   - `Ignored`   — mail contained no DMARC report payload (e.g. human mail)
   - `Failed`    — payload found but could not be parsed/stored
   - DB/transient errors: message is left UNSEEN in INBOX and retried next cycle
     (bodies are fetched with PEEK so retries are possible).
2. **REST API** — ingest reports directly (bypass email), query stored data,
   sender intelligence, analytics/readiness, selectors/TLS-RPT/forensic,
   export, audit, digest admin, trigger/inspect the poller, health and
   Prometheus metrics. Auth is **scoped API keys** with per-key rate limiting.
3. **Webhook** — POST signed JSON events to every `PARSER_WEBHOOK_URLS`
   endpoint (HMAC-SHA256), seven event kinds, failed deliveries deadlettered
   and replayable, so downstream services react without polling.
4. **Pipeline** — every non-duplicate aggregate save (poller or API) fans out
   to in-order observers (webhook → rollup → selectors → enrichment).
5. **Background services** — enrichment (PTR/ASN/country/sender-class via Team
   Cymru DNS), daily `dmarc_agg_daily` rollups, raw-xml/mail retention, an
   alerting watchdog, a weekly email digest, and a nightly backup sidecar.

All v2 data lives in **additive** tables created idempotently at startup by
`internal/migrate`; the frozen `report`/`rptrecord` tables are never altered
destructively. The viewer reads the same tables directly.

## Payload handling

Attachment/content detection is by magic bytes, not by declared MIME type
(reporters are sloppy): `PK..` → zip, `\x1f\x8b` → gzip, leading `<` → XML.
Zip archives may contain multiple XML reports; all are processed. A payload is
considered a DMARC report only if `<feedback` appears near the start of the
XML. Decompression is capped at 256 MB per payload (zip-bomb guard).

## Data mapping (existing dmarcts-style schema, do not change)

| XML (RFC 7489)                              | column                         |
|---------------------------------------------|--------------------------------|
| `report_metadata/org_name`                  | `report.org`                   |
| `report_metadata/email`                     | `report.email`                 |
| `report_metadata/extra_contact_info`        | `report.extra_contact_info`    |
| `report_metadata/report_id`                 | `report.reportid`              |
| `report_metadata/date_range/begin,end`      | `report.mindate,maxdate` (UTC) |
| `policy_published/domain`                   | `report.domain`                |
| `policy_published/adkim,aspf,p,sp,pct`      | `report.policy_*`              |
| raw XML (after decompression)               | `report.raw_xml` (toggleable)  |
| `row/source_ip` (v4)                        | `rptrecord.ip` (uint32 as bigint) |
| `row/source_ip` (v6)                        | `rptrecord.ip6` (16-byte bytea)|
| `row/count`                                 | `rptrecord.rcount`             |
| `row/policy_evaluated/disposition`          | `rptrecord.disposition`        |
| `row/policy_evaluated/reason` (joined)      | `rptrecord.reason`             |
| `row/policy_evaluated/dkim,spf`             | `rptrecord.dkim_align,spf_align` |
| `auth_results/dkim` (prefer `pass`, else first) | `rptrecord.dkimdomain,dkimresult` |
| `auth_results/spf`  (prefer `pass`, else first) | `rptrecord.spfdomain,spfresult`  |
| `identifiers/header_from`                   | `rptrecord.identifier_hfrom`   |

Values outside an enum's set are normalized to `unknown`. Strings are
truncated to the column width. **Dedup**: `INSERT … ON CONFLICT (domain,
reportid) DO NOTHING` — a duplicate report returns the existing serial and
inserts no records. Report + records are written in one transaction.

## REST API

Base URL: `http://127.0.0.1:8081` on the host, `http://dmarcparser:8080` from
containers on the `mxsentinel_default` or `dmarcparser_default` networks.

Auth: every `/api/v1/*` route (except `/api/v1/openapi.json`) requires a key
from `PARSER_API_KEYS` (entries `name=key=scopes`, scopes pipe-separated from
`{read, ingest, admin}` or `*`; bare key = name `default`, all scopes) via
`Authorization: Bearer <key>` or `X-API-Key: <key>`. Constant-time compare; key
name flows into context/logs/audit. Per-key token-bucket rate limit
(`PARSER_RATE_LIMIT_RPS`, default 10, burst 3×; 429 + `Retry-After`). Missing
key → 401, missing scope → 403. `/healthz`, `/metrics`, `/api/v1/openapi.json`
are unauthenticated. Full machine contract: `openapi.yaml` (served as
`GET /api/v1/openapi.json`).

| Method & path | Scope | Description |
|---|---|---|
| `POST /api/v1/ingest` | ingest | Ingest aggregate report(s): raw XML/gzip/zip or multipart file. `201` new / `200` all-dup / `400` non-report. |
| `POST /api/v1/poll` | admin | Trigger an immediate IMAP cycle (async). `202`. |
| `GET /api/v1/status` | read | Poller state + lifetime counters + DB totals. |
| `GET /api/v1/reports` · `/{serial}` | read | List (filters `domain`/`org`/`since`/`until`/`limit`≤500/`offset`) / full report. |
| `GET /api/v1/reports/{serial}/raw` | read | Raw XML download (`404` if aged out). |
| `GET /api/v1/export` | read | Stream `csv`/`jsonl` flattened report×record rows. |
| `GET /api/v1/sources` · `/ips/{ip}` · `/domains/{domain}/sources` | read | Sender intelligence (threat list, per-IP, new senders). |
| `GET /api/v1/domains` · `/{domain}/health` · `/{domain}/readiness` | read | Fleet grid + health score + enforcement readiness. |
| `GET /api/v1/domains/{domain}/selectors` | read | DKIM selector inventory. |
| `GET /api/v1/stats/timeseries` · `/stats/top` | read | Rollup analytics. |
| `GET /api/v1/tlsrpt[/{id}]` · `/forensic[/{id}]` | read | TLS-RPT and forensic reports (forensic redacted at store time). |
| `POST /api/v1/sources/ack` | admin | Acknowledge a `{domain, ip}` source. |
| `GET /api/v1/audit` | admin | API audit trail (`since`/`actor`/`limit`). |
| `POST /api/v1/requeue-failed` · `/webhooks/replay` | admin | Requeue `Failed` mail / replay deadlettered webhooks. |
| `GET·POST /api/v1/digest/subscriptions` · `DELETE …/{id}` · `POST /digest/run` | admin | Digest subscription CRUD + force-send. |
| `GET /api/v1/openapi.json` | — | OpenAPI 3.1 (unauthenticated). |
| `GET /healthz` | — | `200`/`503`; body includes the watchdog `alerts` map. |
| `GET /metrics` | — | Prometheus text format. |

### Examples

```sh
# ingest a gzipped report
curl -sS -X POST http://127.0.0.1:8081/api/v1/ingest \
  -H "Authorization: Bearer $KEY" --data-binary @report.xml.gz

# → {"results":[{"serial":157827,"domain":"example.org","org":"google.com",
#     "report_id":"1234","records":3,"messages":17,"duplicate":false}]}

curl -sS "http://127.0.0.1:8081/api/v1/reports?domain=example.org&since=2026-06-01&limit=10" \
  -H "X-API-Key: $KEY"
```

### Webhook contract

Signed events POST to every `PARSER_WEBHOOK_URLS` endpoint (fallback legacy
`PARSER_WEBHOOK_URL`); 3 attempts, exponential backoff; on final failure the
event is deadlettered (`webhook_deadletter`) and replayable via
`POST /api/v1/webhooks/replay`.

```
POST <each PARSER_WEBHOOK_URLS entry>
Content-Type: application/json
X-Parser-Event: <kind>
X-Parser-Signature: hex(hmac-sha256(body, $PARSER_WEBHOOK_SECRET))

{"event":"report.ingested","serial":157827,"domain":"example.org",
 "org":"google.com","report_id":"1234","date_begin":"…","date_end":"…",
 "records":3,"messages":17,"source":"imap"}
```

Event kinds: `report.ingested`, `report.failed`, `sender.new`,
`domain.anomaly`, `poller.degraded`, `tlsrpt.ingested`, `forensic.ingested`.

## v2 features (brief)

- **Enrichment / intelligence** — IP worker pool (`PARSER_ENRICH_WORKERS`)
  → `ip_meta` (PTR/ASN/country/sender_class via Team Cymru DNS); `domain_source`
  tracking; `sender.new` + `domain.anomaly` webhooks. Backfill `-backfill-sources`.
- **Rollups / stats** — `dmarc_agg_daily` observer; `/stats/*`, `/domains*`,
  health score (0–100), readiness verdict (enforce/step_pct/fix_alignment/
  monitor). Backfill `-backfill-rollups`.
- **Selectors / TLS-RPT / forensic** — `dkim_auth` selector inventory
  (backfill `-backfill-selectors`); RFC 8460 TLS-RPT (`tlsrpt_report`/`_policy`,
  dedup on org+report_id); RFC 6591 forensic (`forensic_report`, redacted when
  `PARSER_RUF_REDACT`). All filed `Processed`.
- **Export / audit** — streaming CSV/JSONL `/export` + `/reports/{serial}/raw`;
  `parser_audit` middleware + `/audit`.
- **Digest** — weekly per-domain HTML email (`digest_subscription`/`digest_log`)
  over SMTP; admin CRUD + `/digest/run`.
- **Retention** — daily ticker nulls old `raw_xml` and expunges old mail.
- **Watchdog** — 10-min checks (silence / poll_failures / failed_spike /
  webhook_dead) → `PARSER_ALERT_URL` + healthz `alerts` map; `alert_state`
  cooldown.
- **Backup** — `postgres:16-alpine` sidecar: nightly `pg_dump` + mailconfig
  tar → `/var/backups/dmarc` (14 daily / 8 weekly); restore runbook in
  `backup/README-backup.md`.

## Configuration (environment)

| Variable | Default | Notes |
|---|---|---|
| `PARSER_DATABASE_URL` | — (required) | Postgres DSN of the dmarc viewer DB |
| `PARSER_IMAP_ADDR` | `mailserver:993` | empty string disables the poller (API-only) |
| `PARSER_IMAP_USER` | `dmarc@example.org` | |
| `PARSER_IMAP_PASSWORD_FILE` | `/run/secrets/mailbox-password` | or `PARSER_IMAP_PASSWORD` |
| `PARSER_IMAP_TLS_SKIP_VERIFY` | `false` | `true` here: mailserver cert is self-signed |
| `PARSER_POLL_INTERVAL` | `5m` | Go duration |
| `PARSER_FOLDER_PROCESSED/IGNORED/FAILED` | `Processed`/`Ignored`/`Failed` | created on demand |
| `PARSER_API_ADDR` | `:8080` | |
| `PARSER_API_KEYS` | — | `name=key=scopes` (or bare key); empty = API refuses requests |
| `PARSER_RATE_LIMIT_RPS` | `10` | per-key bucket, burst 3×; `0` disables |
| `PARSER_WEBHOOK_URLS` / `PARSER_WEBHOOK_URL` / `PARSER_WEBHOOK_SECRET` | — | endpoints (multi/legacy) + HMAC secret |
| `PARSER_ALERT_URL` / `PARSER_ALERT_SILENCE` / `PARSER_ALERT_FAILED_SPIKE` | — / `36h` / `10` | watchdog |
| `PARSER_ANOMALY_SIGMA` / `_MIN_FAILS` / `PARSER_NEWSENDER_MIN_MSGS` | `3` / `50` / `5` | anomaly + new-sender |
| `PARSER_RAW_XML_RETENTION` / `PARSER_MAIL_RETENTION` | `2160h` / `720h` | `0` = keep forever |
| `PARSER_ENRICH_WORKERS` / `PARSER_RUF_REDACT` | `4` / `true` | enrichment / forensic redaction |
| `PARSER_DIGEST_ENABLED` / `_SMTP_ADDR` / `_SMTP_USER` / `_FROM` / `_DAY` / `_HOUR` | `false` / `mailserver:587` / =IMAP user / =IMAP user / `Monday` / `7` | weekly digest |
| `PARSER_VIEWER_URL` | — | viewer base URL for deep-links |
| `PARSER_STORE_RAW_XML` | `true` | set `false` to save DB space |
| `PARSER_MAX_BODY_BYTES` | `67108864` (64 MB) | ingest request limit |

Secrets live in `/opt/dmarcparser/.env` (mode 600) and
`/opt/dmarcparser/.mailbox-password` (mounted read-only into the container).

CLI flags (run after migrations and exit; invoke flag-only via
`docker compose run --rm --no-deps parser -<flag>`): `-backfill-rollups`,
`-backfill-sources`, `-backfill-selectors`, `-healthcheck`.

## Integrations

mxsentinel / WHMCS consume the parser over HTTP (`http://dmarcparser:8080`)
with **scoped read keys** (`name=key=read`; attributable in `/audit`), generate
clients from `GET /api/v1/openapi.json`, optionally receive webhooks, and can
hand customers scoped, unauthenticated viewer **share links** (`/share/{token}`)
instead of API keys.

## Metrics

`dmarcparser_mails_total{outcome=processed|ignored|failed}`,
`dmarcparser_reports_ingested_total`, `dmarcparser_reports_duplicate_total`,
`dmarcparser_records_inserted_total`, `dmarcparser_poll_errors_total`,
`dmarcparser_webhook_failures_total`, `dmarcparser_webhook_deadletters_total`,
`dmarcparser_tlsrpt_ingested_total`, `dmarcparser_forensic_ingested_total`,
`dmarcparser_domain_anomalies_total`,
`dmarcparser_retention_rows_purged_total{kind}`,
`dmarcparser_last_poll_timestamp_seconds`,
`dmarcparser_last_poll_success_timestamp_seconds`.

## Operations

```sh
cd /opt/dmarcparser
docker compose up -d --build parser   # build & (re)start
docker compose logs -f parser         # JSON logs (slog)
curl -s localhost:8081/healthz        # liveness
```

The container joins three networks: its own (to reach `mailserver`),
`dmarc_default` (to reach the viewer's `db`), and `mxsentinel_default`
(reachable as `dmarcparser` by the mxsentinel stack). The `dmarc-backup`
sidecar joins only `dmarc` (to reach `db`).

## Non-goals (for now)

- Schema changes to the frozen `report`/`rptrecord` tables — the parser keeps
  writing the legacy dmarcts schema the viewer reads; v2 data is additive only.
- MaxMind GeoIP — enrichment is Team Cymru DNS only.
- API ingest of TLS-RPT / forensic — `/ingest` is aggregate-only; those arrive
  via the poller.

> Forensic (ruf) and SMTP TLS (RFC 8460) reports — previously non-goals — are
> now parsed, stored, and queryable in v2.
