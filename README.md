# dmarcparser — self-hosted DMARC report mailbox, parser & ingestion API

A complete, self-contained Docker stack that **receives DMARC aggregate
(rua) report emails, parses them, and serves them to humans and machines**:

- a receive-only mail server hosting `dmarc@example.org`
  (with `dmarc@example.com` aliased into the same inbox),
- **Roundcube** webmail for eyeballing the raw mail,
- a **custom Go parser** that polls the inbox over IMAPS, extracts and parses
  the report payloads, and writes them into the Postgres database behind the
  viewer at <https://dmarc.example.org>,
- a **REST API** (ingest, query, **sender intelligence, analytics, readiness,
  selectors, TLS-RPT, forensic, export, audit, digest admin**, poller control,
  health, Prometheus metrics) with **scoped API keys**,
- optional **signed multi-endpoint webhooks** (seven event kinds) so other
  services can integrate without touching the mailbox or the database,
- background services for **enrichment** (PTR/ASN/country/sender-class),
  **daily rollups**, **retention**, an **alerting watchdog**, a weekly **email
  digest**, and a nightly **backup** sidecar.

```
                            ┌────────────────────────────── this host ──────────────────────────────┐
 reporters (Google,         │                                                                        │
 Microsoft, Yahoo, …) ─mail─▶ host Postfix :25 ──relay──▶ dmarc-mailserver :2525 ─▶ INBOX            │
                            │                                       │                                │
                            │                              IMAPS :993 (self-signed)                  │
                            │   ┌── enrich · rollup · retention · watchdog · digest (goroutines) ──┐ │
                            │   ▼                   │                                              │ │
 other services ────HTTP────▶ :8081 ─────────────▶ dmarc-parser ────┴─INSERT──▶ Postgres (dmarc db) ┘
                            │  (REST API, scoped       │                            ▲                │
                            │   keys + rate limit)     └──webhook POST (7 kinds)──▶ …│  ▲            │
 humans ─────────────▶ https://<your-host>/roundcube/         dmarc.example.org (viewer reads DB)    │
                            │                          backup sidecar ──▶ /var/backups/dmarc         │
                            └────────────────────────────────────────────────────────────────────────┘

 The pipeline: every non-duplicate save (poller OR API) fans out to in-order
 observers — webhook → rollup → selectors → enrichment/new-sender/anomaly.
```

---

## Table of contents

1. [Repository layout](#repository-layout)
2. [Components](#components)
3. [Mail flow](#mail-flow)
4. [The parser](#the-parser)
   - [Processing pipeline](#processing-pipeline)
   - [Payload detection](#payload-detection)
   - [Data mapping](#data-mapping)
   - [Deduplication & idempotency](#deduplication--idempotency)
   - [Failure handling](#failure-handling)
5. [REST API](#rest-api)
   - [Scoped API keys & rate limiting](#scoped-api-keys--rate-limiting)
   - [Route reference](#route-reference)
   - [Examples](#examples)
   - [OpenAPI](#openapi)
6. [Webhooks](#webhooks)
7. [v2 feature reference](#v2-feature-reference)
   - [Enrichment & sender intelligence](#enrichment--sender-intelligence)
   - [Rollups, stats & readiness](#rollups-stats--readiness)
   - [Selectors, TLS-RPT & forensic](#selectors-tls-rpt--forensic)
   - [Export & raw download](#export--raw-download)
   - [Audit trail](#audit-trail)
   - [Weekly digest](#weekly-digest)
   - [Retention](#retention)
   - [Watchdog & alerting](#watchdog--alerting)
   - [Backups & restore](#backups--restore)
8. [Configuration](#configuration)
9. [Integrations (mxsentinel & WHMCS)](#integrations-mxsentinel--whmcs)
10. [Deployment](#deployment)
11. [Operations](#operations)
12. [Monitoring](#monitoring)
13. [Security notes](#security-notes)
14. [Testing](#testing)
15. [DNS records](#dns-records)
16. [Troubleshooting](#troubleshooting)
17. [Non-goals / future work](#non-goals--future-work)

---

## Repository layout

```
.
├── compose.yaml              # the whole stack: mailserver, roundcube, parser, backup
├── README.md                 # this file
├── SPEC.md                   # condensed design spec for the parser service
├── DESIGN.md                 # v2 build contract (schema DDL, ownership) — historical
├── openapi.yaml              # OpenAPI 3.1 source of truth (served as JSON, see below)
├── .env.example              # template for the (untracked) .env secrets file
├── backup/                   # nightly pg_dump + mailconfig backup sidecar
│   ├── backup.sh  verify.sh  entrypoint.sh  crontab
│   └── README-backup.md      # restore runbook (quarterly drill)
├── parser/                   # custom Go parser + API service
│   ├── Dockerfile            # two-stage build → static nonroot binary on alpine
│   ├── go.mod
│   ├── main.go               # wiring: config → migrate → pool → observers → poller + http
│   └── internal/
│       ├── api/              # chi router; api_intel/_stats/_reports2/_platform.go + openapi.json (go:embed)
│       ├── config/           # env-driven configuration (scoped keys, all v2 vars)
│       ├── migrate/          # idempotent DDL run at startup (all v2 tables/indexes)
│       ├── pipeline/         # ingest-event registry + Observer interface
│       ├── mailx/            # MIME walking: raw RFC 822 → aggregate / TLS-RPT / forensic payloads
│       ├── metrics/          # dependency-free Prometheus text exposition
│       ├── poller/           # IMAP cycle: fetch → parse → store → file away (+ Connect helper)
│       ├── report/           # DMARC XML parsing + typed payload expansion (selectors)
│       ├── store/            # Postgres writes/reads; store_intel/_stats/_reports2.go
│       ├── webhook/          # signed multi-endpoint NotifyEvent + deadletter
│       ├── enrich/           # PTR/ASN/country/sender-class worker pool + new-sender/anomaly observer
│       ├── rollup/           # dmarc_agg_daily observer + backfill
│       ├── selectors/        # dkim_auth observer + backfill
│       ├── tlsrpt/           # RFC 8460 TLS-RPT parsing
│       ├── forensic/         # AFRF (ruf) parsing + recipient redaction
│       ├── export/           # streaming CSV/JSONL export + raw_xml lookup
│       ├── audit/            # parser_audit middleware + deadletter helpers
│       ├── digest/           # weekly email digest scheduler + SMTP send
│       ├── retention/        # raw_xml / mail purge ticker
│       └── watchdog/         # silence / poll-failure / spike / deadletter alerting
└── roundcube/                # Roundcube config (self-signed IMAP, /roundcube prefix)
```

**Not in the repo** (see [.gitignore](.gitignore)): `.env` (DB URL, API keys),
`.mailbox-password` (IMAP password), and `docker-data/` (mail spool, mail
state/logs, TLS certs, account files). Those live only on the host.

## Components

| Service | Container | Image | Access |
|---|---|---|---|
| Mail server | `dmarc-mailserver` | `docker-mailserver` 15.1 | SMTP `127.0.0.1:2525`, IMAPS `127.0.0.1:993` |
| Webmail | `dmarc-roundcube` | `roundcube/roundcubemail` 1.6 | `https://<your-host>/roundcube/` (fallback `127.0.0.1:8090`) |
| Parser + API | `dmarc-parser` | built from `./parser` | host `127.0.0.1:8081`; containers `http://dmarcparser:8080` |
| Backup sidecar | `dmarc-backup` | `postgres:16-alpine` | none (writes `/var/backups/dmarc`); see [Backups & restore](#backups--restore) |

The stack spans three Docker networks:

- its own default network (parser ↔ mailserver),
- `dmarc_default` (external) — gives the parser the `db` hostname of the
  viewer's Postgres,
- `mxsentinel_default` (external) — the shared Caddy reverse-proxies
  `/roundcube`, and any mxsentinel service can call the parser as
  `dmarcparser:8080`.

The mail server is deliberately lean: it only ever receives DMARC reports, so
ClamAV/amavis/rspamd/SpamAssassin/fail2ban are disabled, as are the
SPF/OpenDKIM/OpenDMARC milters (mail arrives relayed from the host Postfix,
so the container only ever sees the docker gateway IP and those checks would
reject everything).

## Mail flow

Port 25 on this host belongs to the system Postfix (`host.example.net`),
so the container does not bind it. The host Postfix relays both domains into
the container:

```
internet → host Postfix :25 → 127.0.0.1:2525 → dmarc-mailserver → INBOX
```

Host Postfix changes (additive; originals backed up as
`/etc/postfix/main.cf.bak.*`):

- `relay_domains = example.org, example.com`
- `transport_maps = hash:/etc/postfix/transport_dmarc`
- `/etc/postfix/transport_dmarc` routes both domains to `smtp:[127.0.0.1]:2525`

Account and alias live in the mailserver config volume:

- `docker-data/dms/config/postfix-accounts.cf` — the `dmarc@example.org` mailbox
- `docker-data/dms/config/postfix-virtual.cf` — `dmarc@example.com → dmarc@example.org`
- `docker-data/certs/` — self-signed cert (CN `mail.example.org`) for
  STARTTLS/IMAPS; both Roundcube and the parser are configured to accept it

## The parser

A single static Go binary (`parser/`) that is both the IMAP consumer and the
HTTP API. Logs are structured JSON (`log/slog`).

### Processing pipeline

Every `PARSER_POLL_INTERVAL` (default **5m**, plus once ~5s after boot, plus
on demand via `POST /api/v1/poll`):

1. Dial IMAPS, login, ensure the `Processed`/`Ignored`/`Failed` folders exist.
2. `UID SEARCH UNSEEN` in INBOX; fetch envelope + full body for each hit
   (**with PEEK**, so messages stay unseen until explicitly filed away).
3. For each message, walk every MIME part ([mailx](parser/internal/mailx)),
   expand candidate payloads, parse each contained XML document
   ([report](parser/internal/report)), and store report + records in one
   transaction ([store](parser/internal/store)).
4. File the message: → `Processed` (≥1 aggregate/TLS-RPT/forensic report stored,
   duplicates count), → `Ignored` (no report payload — human mail),
   → `Failed` (payload present but unreadable/unparseable).
5. For every **newly stored aggregate report** (poller *or* API), emit a
   pipeline `IngestEvent` to the in-order, panic-recovered observer chain:
   **webhook → rollup → selectors → enrichment/new-sender/anomaly**. Duplicates
   never reach observers, so counters never double. TLS-RPT and forensic
   reports are stored and notified directly (outside the aggregate pipeline).

Observers run synchronously in registration order; an observer error is logged
but never blocks ingest. See [v2 feature reference](#v2-feature-reference).

### Payload detection

Content types and filenames from reporters are unreliable, so detection is
done by **magic bytes** on every MIME part:

| Magic | Treated as | Notes |
|---|---|---|
| `PK\x03\x04` | zip | every entry that sniffs as report XML is parsed (archives can hold several) |
| `\x1f\x8b` | gzip | single document (aggregate XML *or* TLS-RPT JSON) |
| leading `<` | XML | accepted only if `<feedback` appears in the first 2 KB |
| leading `{` + `organization-name` + `policies` | TLS-RPT JSON | RFC 8460 (see [TLS-RPT](#selectors-tls-rpt--forensic)) |
| `Content-Type: message/feedback-report` MIME part | forensic (AFRF) | RFC 6591 (see [forensic](#selectors-tls-rpt--forensic)) |

Decompression is capped at 256 MB per payload (zip-bomb guard). A part that
*looks* like a report container but fails to read marks the mail `Failed`;
parts that don't sniff as reports at all are simply skipped. The poller's
typed payload expander recognizes aggregate, TLS-RPT, and forensic parts in a
single mail; `POST /api/v1/ingest` accepts aggregate documents only.

### Data mapping

The parser writes the **pre-existing dmarcts-report-parser schema**
(`report` + `rptrecord`) that the dmarc.example.org viewer reads — the schema
is treated as frozen. Mapping from RFC 7489 appendix-C XML:

| XML | Column | Notes |
|---|---|---|
| `report_metadata/org_name` | `report.org` | |
| `report_metadata/email` | `report.email` | |
| `report_metadata/extra_contact_info` | `report.extra_contact_info` | |
| `report_metadata/report_id` | `report.reportid` | required |
| `report_metadata/date_range/begin,end` | `report.mindate,maxdate` | epoch → UTC |
| `policy_published/domain` | `report.domain` | required |
| `policy_published/adkim,aspf,p,sp,pct` | `report.policy_*` | |
| decompressed XML | `report.raw_xml` | toggle `PARSER_STORE_RAW_XML` |
| `row/source_ip` (IPv4) | `rptrecord.ip` | packed big-endian uint32 in a bigint |
| `row/source_ip` (IPv6) | `rptrecord.ip6` | 16-byte bytea |
| `row/count` | `rptrecord.rcount` | |
| `row/policy_evaluated/disposition` | `rptrecord.disposition` | enum |
| `row/policy_evaluated/reason` | `rptrecord.reason` | `type[: comment]` joined with `;` |
| `row/policy_evaluated/dkim,spf` | `rptrecord.dkim_align,spf_align` | enums, NOT NULL |
| `auth_results/dkim` | `rptrecord.dkimdomain,dkimresult` | prefers the entry that passed, else first |
| `auth_results/spf` | `rptrecord.spfdomain,spfresult` | same rule |
| `identifiers/header_from` | `rptrecord.identifier_hfrom` | |

Values outside an enum's set normalize to `unknown`; strings are truncated to
their column width; assorted charset declarations are tolerated (payloads are
ASCII in practice).

### Deduplication & idempotency

`INSERT … ON CONFLICT (domain, reportid) DO NOTHING` — backed by the schema's
unique index. A duplicate returns the existing serial, inserts zero records,
and responds `200` (vs `201`) on the API. Report + records are committed in a
single transaction, so a crash mid-report never leaves partial records.

### Failure handling

| Failure | Behavior |
|---|---|
| IMAP unreachable / login failed | cycle aborts, `poll_errors_total`++, retried next interval |
| DB error while storing | message **left UNSEEN in INBOX** (PEEK fetch) → retried next cycle |
| Unparseable payload | message → `Failed` folder (preserved for inspection) |
| Mail without report payload | message → `Ignored` folder |
| Webhook endpoint down | 3 attempts (2 s/8 s backoff), then `webhook_failures_total`++ and a `webhook_deadletter` row (replayable) |

## REST API

Base URLs: `http://127.0.0.1:8081` (host) · `http://dmarcparser:8080`
(containers on the shared networks).

### Scoped API keys & rate limiting

`PARSER_API_KEYS` is comma-separated; each entry is `name=key=scopes` where
`scopes` is pipe-separated from `{read, ingest, admin}` (or `*` for all):

```
PARSER_API_KEYS=mxsentinel=dprs-aaaa=read,whmcs=dprs-bbbb=read|ingest,ops=dprs-cccc=*
```

A **bare** `key` entry (no `=`) is accepted for backward compatibility as name
`default` with all scopes — existing single-key deployments need no change.
Keys are matched in constant time (`crypto/subtle`). The matched **key name**
travels in the request context and appears in every log line and audit row.

Send the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`. Each
route requires a scope:

- **ingest** → `POST /ingest`
- **admin** → `/poll`, `/audit`, `/requeue-failed`, `/webhooks/replay`,
  `/sources/ack`, all `/digest/*`
- **read** → everything else under `/api/v1`

Missing/invalid key → `401`; valid key lacking the scope → `403`. With no keys
configured the API answers `503` (fail closed). `/healthz`, `/metrics`, and
`GET /api/v1/openapi.json` are unauthenticated.

Each key has its own token-bucket rate limiter (`PARSER_RATE_LIMIT_RPS`,
default 10 req/s, burst 3×; `0` disables). Exceeding it → `429` with a
`Retry-After` header.

### Route reference

| Method & path | Scope | Description |
|---|---|---|
| `POST /api/v1/ingest` | ingest | Ingest aggregate report(s): raw XML / gzip / zip body (any `Content-Type`), or `multipart/form-data` file field. `201` if anything new stored, `200` if all duplicates, `400` for non-reports. |
| `POST /api/v1/poll` | admin | Trigger an immediate IMAP cycle (async). `202`. |
| `GET /api/v1/status` | read | Poller state, lifetime counters, DB totals. |
| `GET /api/v1/reports` | read | List. Filters: `domain`, `org`, `since`, `until` (RFC 3339 or `YYYY-MM-DD`), `limit` ≤ 500 (default 50), `offset`. |
| `GET /api/v1/reports/{serial}` | read | Full report incl. records, IPs rendered as strings. |
| `GET /api/v1/reports/{serial}/raw` | read | Raw `text/xml` download; `404` if unknown serial **or** raw_xml aged out by retention. |
| `GET /api/v1/export` | read | Stream flattened report×record rows. `format=csv\|jsonl`, `domain`, `org`, `since`, `until`. |
| `GET /api/v1/sources` | read | Threat list: per-IP totals/failed msgs, domains targeted, `ip_meta` join. `domain`, `min_failed`, `since`, `limit`. |
| `GET /api/v1/ips/{ip}` | read | Cross-report activity + `ip_meta` for one IP (`404` if never seen). |
| `GET /api/v1/domains` | read | Per-domain 30d volume, aligned rate, last report, latest policy, health score. |
| `GET /api/v1/domains/{domain}/sources` | read | New-sender list (`?unacked=true`). |
| `GET /api/v1/domains/{domain}/health` | read | Health score 0–100 + component breakdown. |
| `GET /api/v1/domains/{domain}/readiness` | read | Enforcement readiness verdict + blockers. |
| `GET /api/v1/domains/{domain}/selectors` | read | DKIM selector inventory (first/last seen, pass/fail counts). |
| `GET /api/v1/stats/timeseries` | read | `domain`, `bucket=day\|week`, `since`, `until`. |
| `GET /api/v1/stats/top` | read | `dimension=ip\|org\|header_from`, `domain`, `since`, `until`, `limit`, `failing=true`. |
| `GET /api/v1/tlsrpt` · `GET /api/v1/tlsrpt/{id}` | read | TLS-RPT (RFC 8460) reports + policies. |
| `GET /api/v1/forensic` · `GET /api/v1/forensic/{id}` | read | Forensic (ruf/AFRF) reports (recipient-redacted at store time). |
| `POST /api/v1/sources/ack` | admin | Acknowledge a `{domain, ip}` source (clears NEW). |
| `GET /api/v1/audit` | admin | API audit trail. `since`, `actor`, `limit` ≤ 1000. |
| `POST /api/v1/requeue-failed` | admin | Move all `Failed` mail back to INBOX (unseen) + poll. |
| `POST /api/v1/webhooks/replay` | admin | Re-deliver un-replayed `webhook_deadletter` rows. |
| `GET·POST /api/v1/digest/subscriptions` · `DELETE …/{id}` | admin | Digest subscription CRUD (`{domain, email}`). |
| `POST /api/v1/digest/run` | admin | Force-send all digests now (testing). |
| `GET /api/v1/openapi.json` | — | OpenAPI 3.1 document (unauthenticated). |
| `GET /healthz` | — | `200` ok / `503` degraded (DB down, or last successful poll older than 3×interval+2m); body includes the watchdog `alerts` map. |
| `GET /metrics` | — | Prometheus text format. |

### Examples

```sh
KEY=…   # from .env

# ingest a gzipped aggregate report
curl -X POST http://127.0.0.1:8081/api/v1/ingest \
     -H "Authorization: Bearer $KEY" --data-binary @report.xml.gz
# {"results":[{"serial":157828,"domain":"example.org","org":"google.com",
#   "report_id":"1234…","records":2,"messages":6,"duplicate":false}]}

# what's been happening?
curl -H "X-API-Key: $KEY" http://127.0.0.1:8081/api/v1/status
# {"counters":{"mails_processed":2,"mails_ignored":1,"mails_failed":0,
#   "reports_ingested":3,"reports_duplicate":1,"records_inserted":21},
#  "database":{"reports":157827,"records":1291707},
#  "poller":{"enabled":true,"interval":"5m0s","last_poll":"…","last_success":"…"}}

# query
curl -H "X-API-Key: $KEY" \
  "http://127.0.0.1:8081/api/v1/reports?domain=example.org&since=2026-06-01&limit=10"
curl -H "X-API-Key: $KEY" http://127.0.0.1:8081/api/v1/reports/157827

# v2: threat sources, domain health, enforcement readiness, CSV export
curl -H "X-API-Key: $KEY" "http://127.0.0.1:8081/api/v1/sources?domain=example.org&min_failed=10"
curl -H "X-API-Key: $KEY" http://127.0.0.1:8081/api/v1/domains/example.org/health
curl -H "X-API-Key: $KEY" http://127.0.0.1:8081/api/v1/domains/example.org/readiness
curl -H "X-API-Key: $KEY" "http://127.0.0.1:8081/api/v1/export?format=csv&domain=example.org" -o export.csv
```

### OpenAPI

The full machine-readable contract lives in [`openapi.yaml`](openapi.yaml)
(OpenAPI 3.1, the source of truth) and is served — unauthenticated — as JSON
at `GET /api/v1/openapi.json` (embedded into the binary via `go:embed` from
`parser/internal/api/openapi.json`). The two files are kept in sync; regenerate
the JSON after editing the YAML:

```sh
cd /opt/dmarcparser
python3 -c 'import yaml,json; json.dump(yaml.safe_load(open("openapi.yaml")), open("parser/internal/api/openapi.json","w"), indent=2)'
```

It documents every route above, the `bearerAuth`/`apiKeyAuth` schemes, each
operation's required scope (`x-required-scope`), and response schemas. Point
Swagger UI / client generators at `http://dmarcparser:8080/api/v1/openapi.json`.

## Webhooks

Set `PARSER_WEBHOOK_URLS` (comma-separated; legacy single `PARSER_WEBHOOK_URL`
is the fallback) and ideally `PARSER_WEBHOOK_SECRET` in `.env`, and the parser
POSTs JSON events to **every** endpoint:

```
POST <each PARSER_WEBHOOK_URLS entry>
Content-Type: application/json
X-Parser-Event: report.ingested
X-Parser-Signature: hex(hmac-sha256(body, $PARSER_WEBHOOK_SECRET))

{"event":"report.ingested","serial":157827,"domain":"example.org",
 "org":"google.com","report_id":"…","date_begin":"2026-06-10T00:00:00Z",
 "date_end":"2026-06-11T00:00:00Z","records":17,"messages":17,"source":"imap"}
```

Every event JSON carries an `event` field and the `X-Parser-Event` header set
from the kind. Delivery is at-most-3 attempts with backoff; aggregate
duplicates never fire. Verify by HMAC-ing the raw body with the shared secret
and comparing constant-time.

**Event kinds:**

| Kind | Fired when | Key payload fields |
|---|---|---|
| `report.ingested` | aggregate report stored (`source` = `imap`\|`api`) | serial, domain, org, report_id, date_begin/end, records, messages, source |
| `report.failed` | a mail lands in `Failed` (poller) | subject, from |
| `sender.new` | a new `(domain, ip)` pair with ≥ `PARSER_NEWSENDER_MIN_MSGS` msgs or unaligned | domain, ip, ptr?, msgs, aligned, serial, first_seen |
| `domain.anomaly` | current-day fails exceed trailing-30d mean + `SIGMA`·stddev (floor `MIN_FAILS`) | domain, day, fails, mean_30d, stddev_30d, sigma, threshold |
| `poller.degraded` | poller cycle error / watchdog rule (rate-limited by cooldown) | rule, message, detail, ts |
| `tlsrpt.ingested` | a TLS-RPT report stored | id, org, report_id, date_begin/end, policies, source |
| `forensic.ingested` | a forensic (ruf) report stored | id, feedback_type, auth_failure, source_ip, reported_domain, source |

**Deadletter & replay:** after the final retry to an endpoint fails, the event
is best-effort inserted into `webhook_deadletter` and
`dmarcparser_webhook_deadletters_total` increments. Re-deliver un-replayed rows
with `POST /api/v1/webhooks/replay` (admin), which marks `replayed_at` on
success.

## v2 feature reference

All v2 data lives in additive tables created idempotently at startup by
`internal/migrate` (`CREATE TABLE/INDEX IF NOT EXISTS`, `ADD COLUMN IF NOT
EXISTS`) before anything else runs; the frozen `report`/`rptrecord` tables are
never altered destructively. The viewer at dmarc.example.org reads these same
tables directly for its human-facing pages.

### Enrichment & sender intelligence

A worker pool (`PARSER_ENRICH_WORKERS`, default 4) resolves each source IP:
PTR via reverse DNS, ASN + country + AS-org via **Team Cymru DNS** (no MaxMind
mmdb), and a `sender_class` from PTR-suffix / DKIM-domain rules
(google, microsoft365, amazon-ses, sendgrid, mailgun, mailchimp, proofpoint,
mimecast, zoho, ovh, hetzner, …). Results upsert into `ip_meta` (refreshed when
older than 30 days); non-UTF-8 PTR/AS-org bytes are sanitized before storage.

On every aggregate ingest the observer upserts `domain_source` (per-(domain,ip)
counts, last-seen, first-serial) and enqueues enrichment. A **new** `(domain,
ip)` pair fires `sender.new`; a current-day failure spike fires
`domain.anomaly` (per-day suppressed via `alert_state`). Query via
`GET /sources`, `GET /ips/{ip}`, `GET /domains/{domain}/sources`; acknowledge
with `POST /sources/ack`.

**Backfill** (one-shot, run once): `-backfill-sources` populates
`domain_source` from history (`acked=true` so it never alarms) and seeds the
enrichment queue.

### Rollups, stats & readiness

A rollup observer maintains `dmarc_agg_daily` (per day×domain message totals,
aligned / dkim-aligned / spf-aligned, none/quarantine/reject dispositions,
report count) so analytics never scan the 1.3M-row record table. Endpoints:

- `GET /stats/timeseries` — daily/weekly buckets.
- `GET /stats/top` — top IPs / orgs / header-froms (optionally failing-only).
- `GET /domains` — fleet grid with a 0–100 **health score**.
- `GET /domains/{domain}/health` — score + component breakdown
  (alignment 40, trend 15, policy strength 20, coverage 10, unknown-source
  failing volume 15).
- `GET /domains/{domain}/readiness` — `enforce` / `step_pct` / `fix_alignment`
  / `monitor` recommendation with blockers (gate: ≥ 99.5 % aligned over 90 d,
  no unknown source > 100 msgs).

**Backfill** (rebuild semantics — safe to re-run): `-backfill-rollups`
truncates and rebuilds `dmarc_agg_daily` from `report`×`rptrecord`.

### Selectors, TLS-RPT & forensic

- **DKIM selectors** — the aggregate parser captures `auth_results/dkim`
  selectors; a selectors observer writes `dkim_auth` rows per report (idempotent
  per serial). Inventory at `GET /domains/{domain}/selectors`. Backfill:
  `-backfill-selectors` re-parses stored `raw_xml` (skips aged-out NULLs).
- **TLS-RPT (RFC 8460)** — JSON reports mailed in (gzipped or inline) are
  detected, parsed into `tlsrpt_report`/`tlsrpt_policy` (dedup on
  `org, report_id`), filed `Processed`, and fire `tlsrpt.ingested`. Query
  `GET /tlsrpt` / `GET /tlsrpt/{id}`.
- **Forensic (ruf / AFRF, RFC 6591)** — `message/feedback-report` MIME parts
  are parsed into `forensic_report`, filed `Processed`, and fire
  `forensic.ingested`. With `PARSER_RUF_REDACT=true` (default) recipient
  localparts are stripped (domain kept) **before storage**. Query
  `GET /forensic` / `GET /forensic/{id}`.

### Export & raw download

- `GET /export?format=csv|jsonl&domain&org&since&until` — streams flattened
  report×record rows directly off the pgx cursor (chunked / flushed), so large
  exports don't buffer in memory.
- `GET /reports/{serial}/raw` — original `text/xml` download; `404` once
  retention has nulled the `raw_xml`.

### Audit trail

A post-auth chi middleware records every authenticated request into
`parser_audit` (actor = key name, action = method, route pattern, status,
client IP, and ingested serials when available) fire-and-forget. Query newest
-first with `GET /audit?since&actor&limit`. The auditor also owns the
`webhook_deadletter` helpers used by `/webhooks/replay`.

### Weekly digest

When `PARSER_DIGEST_ENABLED=true`, a scheduler ticks every 15 min and, on
`PARSER_DIGEST_DAY` at/after `PARSER_DIGEST_HOUR` (UTC), sends a per-domain
HTML digest (7d vs prior-7d volume & pass-rate, top failing sources, new
senders) to each `digest_subscription` address, deduped via `digest_log`. Mail
goes out over SMTP+STARTTLS+AUTH (`PARSER_DIGEST_SMTP_*`, defaulting the user /
from / password to the IMAP account). Manage subscriptions via
`GET·POST·DELETE /digest/subscriptions[/{id}]` and force a send with
`POST /digest/run`. Digest emails deep-link into the viewer when
`PARSER_VIEWER_URL` is set.

### Retention

A daily ticker (first run ~5 min after boot):

- nulls `report.raw_xml` older than `PARSER_RAW_XML_RETENTION` (default 2160h /
  90d; `0` = keep forever), batched 5000 rows at a time so no long table lock;
- optionally IMAP-expunges `Processed`/`Ignored` mail older than
  `PARSER_MAIL_RETENTION` (default 720h / 30d; `0` = keep).

Purged counts go to `parser_audit` and
`dmarcparser_retention_rows_purged_total{kind}`.

### Watchdog & alerting

A watchdog ticks every 10 min and evaluates four rules, each with a 6h
per-rule cooldown persisted in `alert_state`. On fire it POSTs
`{rule, message, detail, ts}` to `PARSER_ALERT_URL` and emits a degraded-style
webhook event:

| Rule | Fires when |
|---|---|
| `silence` | last successful ingest older than `PARSER_ALERT_SILENCE` (default 36h) |
| `poll_failures` | ≥ 3 consecutive poll-cycle errors |
| `failed_spike` | `MailsFailed` delta ≥ `PARSER_ALERT_FAILED_SPIKE` (default 10) / 24h |
| `webhook_dead` | any new `webhook_deadletter` rows since the last check |

`GET /healthz` exposes the live rule states under
`"alerts": {"silence":"ok"|"firing", …}`.

### Backups & restore

A `postgres:16-alpine` **backup sidecar** (`dmarc-backup`, on the `dmarc`
network only) runs `pg_dump -Fc` of the database plus a tar of the mailserver
config nightly (03:15 UTC), keeping 14 daily + 8 weekly sets under
`/var/backups/dmarc`; `verify.sh` runs a weekly `pg_restore --list` integrity
check (Mon 04:45). A healthcheck reads `/backups/.last-success` age (unhealthy
> 26h). One-time host prep: `install -d -m 700 /var/backups/dmarc`. The full
restore runbook and quarterly test-restore drill are in
[`backup/README-backup.md`](backup/README-backup.md).

## Configuration

All parser configuration is via environment (set in `compose.yaml`; secrets
interpolated from the untracked `.env` — see [.env.example](.env.example)):

| Variable | Default | Notes |
|---|---|---|
| `PARSER_DATABASE_URL` | — (required) | Postgres DSN of the viewer DB |
| `PARSER_IMAP_ADDR` | `mailserver:993` | empty string = API-only mode (poller off) |
| `PARSER_IMAP_USER` | `dmarc@example.org` | |
| `PARSER_IMAP_PASSWORD_FILE` | `/run/secrets/mailbox-password` | `.mailbox-password` mounted read-only; `PARSER_IMAP_PASSWORD` overrides |
| `PARSER_IMAP_TLS_SKIP_VERIFY` | `false` | `true` in this stack (self-signed cert) |
| `PARSER_POLL_INTERVAL` | `5m` | Go duration |
| `PARSER_FOLDER_PROCESSED` / `_IGNORED` / `_FAILED` | `Processed`/`Ignored`/`Failed` | created on demand |
| `PARSER_API_ADDR` | `:8080` | |
| `PARSER_API_KEYS` | — | comma-separated `name=key=scopes` (or bare key = all scopes); empty = API refuses requests |
| `PARSER_RATE_LIMIT_RPS` | `10` | per-key token bucket, burst 3×; `0` disables |
| `PARSER_WEBHOOK_URLS` | — | comma-separated endpoints (fallback `PARSER_WEBHOOK_URL`) |
| `PARSER_WEBHOOK_URL` / `PARSER_WEBHOOK_SECRET` | — | legacy single URL / HMAC-SHA256 signing secret |
| `PARSER_STORE_RAW_XML` | `true` | `false` saves DB space |
| `PARSER_MAX_BODY_BYTES` | `67108864` (64 MB) | ingest request cap |
| **Alerting / watchdog** | | |
| `PARSER_ALERT_URL` | — | POST target for watchdog alerts |
| `PARSER_ALERT_SILENCE` | `36h` | no-ingest silence threshold |
| `PARSER_ALERT_FAILED_SPIKE` | `10` | failed-mail/24h spike threshold |
| **Anomaly / new-sender** | | |
| `PARSER_ANOMALY_SIGMA` | `3` | std-devs above 30d mean to flag |
| `PARSER_ANOMALY_MIN_FAILS` | `50` | floor before anomaly fires |
| `PARSER_NEWSENDER_MIN_MSGS` | `5` | min msgs for a `sender.new` |
| **Retention** | | |
| `PARSER_RAW_XML_RETENTION` | `2160h` (90d) | null `raw_xml` older than this; `0` = keep |
| `PARSER_MAIL_RETENTION` | `720h` (30d) | expunge filed mail older than this; `0` = keep |
| **Enrichment / forensic** | | |
| `PARSER_ENRICH_WORKERS` | `4` | IP enrichment worker pool size |
| `PARSER_RUF_REDACT` | `true` | strip recipient localparts from forensic reports |
| **Digest** | | |
| `PARSER_DIGEST_ENABLED` | `false` | enable the weekly email digest |
| `PARSER_DIGEST_SMTP_ADDR` | `mailserver:587` | SMTP STARTTLS submission |
| `PARSER_DIGEST_SMTP_USER` | = `PARSER_IMAP_USER` | AUTH user (password = IMAP password) |
| `PARSER_DIGEST_FROM` | = `PARSER_IMAP_USER` | digest From address |
| `PARSER_DIGEST_DAY` | `Monday` | weekday to send |
| `PARSER_DIGEST_HOUR` | `7` | hour (0–23, UTC) to send |
| **Links** | | |
| `PARSER_VIEWER_URL` | — | viewer base URL for deep-links in digests/webhooks |

CLI flags (one-shot modes that run after migrations and exit — invoke
**flag-only**, e.g. `docker compose run --rm --no-deps parser -backfill-rollups`,
because the binary is the image entrypoint): `-backfill-rollups`,
`-backfill-sources`, `-backfill-selectors`, and `-healthcheck` (GET /healthz,
exit 0/1 — used by the container healthcheck).

## Integrations (mxsentinel & WHMCS)

Other services consume the parser over HTTP on the shared Docker networks
(`http://dmarcparser:8080`) — they never touch the mailbox or DB:

- **Scoped read keys** — issue each consumer its own `name=key=read` entry in
  `PARSER_API_KEYS`. The key name shows up in `/audit` and logs, so per-consumer
  usage is attributable, and a leaked read key can't ingest or run admin
  actions. mxsentinel and WHMCS dashboards should use `read`-only keys; only an
  ops/automation key needs `ingest` or `admin`.
- **OpenAPI** — generate clients from
  `http://dmarcparser:8080/api/v1/openapi.json` (unauthenticated). Useful read
  routes for embedding: `/domains`, `/domains/{domain}/health`,
  `/domains/{domain}/readiness`, `/stats/timeseries`, `/sources`, `/export`.
- **Webhooks** — point `PARSER_WEBHOOK_URLS` at consumer receivers (the viewer
  receives at `http://dmarc:8080/hooks/parser`, HMAC-verified against the shared
  `PARSER_WEBHOOK_SECRET`) to react to `sender.new` / `domain.anomaly` etc.
  without polling.
- **Share links** — the viewer exposes unauthenticated, scoped
  `/share/{token}` pages (domain detail/analytics limited to the token's
  domains, no raw XML); create/revoke tokens on the viewer's `/shares` admin
  page. Hand a share token to a customer instead of a parser API key when they
  only need to see their own domains.

## Deployment

Prerequisites on the host:

1. Docker + compose v2.
2. The external networks exist (`dmarc_default` from the viewer stack,
   `mxsentinel_default` from the mxsentinel stack) — bring those stacks up
   first.
3. Host Postfix relays the two domains to `127.0.0.1:2525` (see
   [Mail flow](#mail-flow)).
4. Secrets in place:

```sh
cd /opt/dmarcparser
cp .env.example .env && $EDITOR .env     # DB URL + API key(s)
chmod 600 .env
echo '<imap password>' > .mailbox-password && chmod 600 .mailbox-password
# the same password must be set for the account in
# docker-data/dms/config/postfix-accounts.cf (docker-mailserver `setup email update`)
```

Then:

```sh
docker compose up -d --build
curl -s localhost:8081/healthz          # → {"status":"ok",…}
```

## Operations

```sh
cd /opt/dmarcparser
docker compose ps                        # stack status
docker compose logs -f parser            # structured JSON logs
docker compose logs -f mailserver        # SMTP/IMAP log
docker compose up -d --build parser      # rebuild & redeploy the parser only

curl -s -X POST localhost:8081/api/v1/poll -H "X-API-Key: $KEY"   # poll right now
```

Common tasks:

- **Replay a failed mail** — in Roundcube (or any IMAP client) move it from
  `Failed` back to INBOX and mark unread; next cycle retries it. Or download
  the attachment and `POST /api/v1/ingest` it.
- **Rotate the mailbox password** — update it in docker-mailserver
  (`setup email update dmarc@example.org`), write the new password to
  `.mailbox-password`, then `docker compose restart parser`.
- **Rotate/add API keys** — edit `PARSER_API_KEYS` in `.env`, then
  `docker compose up -d parser` (recreates with the new env).
- **Backfill old reports** — loop `POST /api/v1/ingest` over the files;
  duplicates are skipped automatically, so re-running is safe.

## Monitoring

`GET /metrics` (Prometheus text):

| Metric | Meaning |
|---|---|
| `dmarcparser_mails_total{outcome=processed\|ignored\|failed}` | mails filed per outcome |
| `dmarcparser_reports_ingested_total` | new reports stored |
| `dmarcparser_reports_duplicate_total` | duplicates skipped |
| `dmarcparser_records_inserted_total` | `rptrecord` rows written |
| `dmarcparser_poll_errors_total` | failed IMAP cycles |
| `dmarcparser_webhook_failures_total` | webhooks dead after retries |
| `dmarcparser_webhook_deadletters_total` | events dropped to `webhook_deadletter` |
| `dmarcparser_tlsrpt_ingested_total` | TLS-RPT reports stored |
| `dmarcparser_forensic_ingested_total` | forensic (ruf) reports stored |
| `dmarcparser_domain_anomalies_total` | `domain.anomaly` events fired |
| `dmarcparser_retention_rows_purged_total{kind}` | rows purged by retention (`raw_xml`/`mail`) |
| `dmarcparser_last_poll_timestamp_seconds` | gauge, unix time |
| `dmarcparser_last_poll_success_timestamp_seconds` | gauge, unix time |

`GET /healthz` is suitable for liveness checks: it verifies DB connectivity,
that the last successful poll is fresher than `3 × interval + 2m`, and reports
the watchdog `alerts` map (`silence` / `poll_failures` / `failed_spike` /
`webhook_dead`).

## Security notes

- **Secrets are never committed**: `.env`, `.mailbox-password`, and the whole
  `docker-data/` tree (mail spool, account hashes, TLS keys) are
  git-ignored. Use `.env.example` as the template.
- The API binds to `127.0.0.1` on the host; from the network it is reachable
  only by containers on the shared Docker networks. Expose it publicly only
  behind the reverse proxy, and only if you need to.
- The API fails closed (503) when no keys are configured.
- The IMAP connection skips certificate verification **only because** the
  mailserver presents a known self-signed cert over an internal Docker
  network. If you front the mailserver with a real cert, set
  `PARSER_IMAP_TLS_SKIP_VERIFY=false`.
- The mailbox is receive-only; the stack never sends mail.

## Testing

The stack was verified end-to-end against production data:

- real Microsoft/Google aggregate reports parse and render in the viewer;
- gzip ingest → `201`, repeat → `200 duplicate`, garbage → `400`,
  missing key → `401`;
- a zip report emailed through SMTP (including via the `dmarc@example.com`
  alias) is stored and the mail lands in `Processed`;
- a plain human mail lands in `Ignored`;
- IPv4 (packed uint32) and IPv6 (bytea) both round-trip correctly.

Quick self-test against a running stack:

```sh
# craft a minimal report and ingest it twice
curl -s -X POST localhost:8081/api/v1/ingest -H "X-API-Key: $KEY" \
     --data-binary @testdata/minimal-report.xml        # 201
curl -s -X POST localhost:8081/api/v1/ingest -H "X-API-Key: $KEY" \
     --data-binary @testdata/minimal-report.xml        # 200, duplicate:true
# then delete the test rows:
#   DELETE FROM rptrecord WHERE serial = <serial>; DELETE FROM report WHERE serial = <serial>;
```

## DNS records

1. **MX** for both domains pointing at this host:
   ```
   example.org.  MX 10 host.example.net.
   example.com.  MX 10 host.example.net.
   ```
2. **DMARC records** on the domains you want reports for:
   ```
   _dmarc.example.org. TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.org; ruf=mailto:dmarc@example.org"
   _dmarc.example.org. TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com"
   ```
   Using each domain's own report address (that's what the alias is for)
   avoids external-destination authorization records. If a *third* domain
   reports to `dmarc@example.org`, also publish:
   ```
   <thirddomain>._report._dmarc.example.org. TXT "v=DMARC1"
   ```

## Troubleshooting

| Symptom | Check |
|---|---|
| `healthz` says `last successful poll too old` | `docker compose logs parser` — IMAP login (password rotated?), mailserver up? |
| Mail accepted but report missing in viewer | Is the mail in `Failed`? Inspect it in Roundcube; the raw mail is preserved. |
| Sender rejected `Domain not found` / `nullMX` | The mailserver validates sender domains; test mails need a resolvable, mail-accepting From domain. |
| API returns 503 | `PARSER_API_KEYS` empty in the container env — check `.env` and recreate. |
| Parser can't reach `db` | Is the viewer stack (`dmarc_default` network) up? `docker network inspect dmarc_default`. |
| `caddy reload` doesn't pick up Caddyfile edits | The shared Caddy bind-mounts a single file; restart the container (`docker restart mxsentinel-caddy-1`). |

## Non-goals / future work

- **Schema evolution of the frozen tables** — the parser intentionally keeps
  writing the legacy dmarcts `report`/`rptrecord` schema so the existing viewer
  keeps working; v2 data lives only in additive tables. A normalized schema
  would be a joint migration with the viewer.
- **MaxMind GeoIP** — enrichment uses Team Cymru DNS only; no mmdb dependency.
- **API ingest of TLS-RPT / forensic** — `POST /ingest` is aggregate-only; the
  poller is the only path for TLS-RPT and forensic reports.

> Forensic (ruf) reports and SMTP TLS reports (RFC 8460), once non-goals, are
> now first-class in v2 — see [Selectors, TLS-RPT & forensic](#selectors-tls-rpt--forensic).
