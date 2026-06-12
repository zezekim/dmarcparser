# dmarcparser — self-hosted DMARC report mailbox, parser & ingestion API

A complete, self-contained Docker stack that **receives DMARC aggregate
(rua) report emails, parses them, and serves them to humans and machines**:

- a receive-only mail server hosting `dmarc@example.org`
  (with `dmarc@example.com` aliased into the same inbox),
- **Roundcube** webmail for eyeballing the raw mail,
- a **custom Go parser** that polls the inbox over IMAPS, extracts and parses
  the report payloads, and writes them into the Postgres database behind the
  viewer at <https://dmarc.example.org>,
- a **REST API** (ingest, query, poller control, health, Prometheus metrics)
  and optional **signed webhooks** so other services can integrate without
  touching the mailbox or the database.

```
                            ┌────────────────────────────── this host ──────────────────────────────┐
 reporters (Google,         │                                                                        │
 Microsoft, Yahoo, …) ─mail─▶ host Postfix :25 ──relay──▶ dmarc-mailserver :2525 ─▶ INBOX            │
                            │                                       │                                │
                            │                              IMAPS :993 (self-signed)                  │
                            │                                       │                                │
 other services ────HTTP────▶ :8081 ─────────────▶ dmarc-parser ────┴─INSERT──▶ Postgres (dmarc db)  │
                            │  (REST API)              │                            ▲                │
                            │                          └──webhook POST──▶ …         │                │
 humans ────────────────────▶ https://<your-host>/roundcube/   dmarc.example.org (viewer)   │
                            └────────────────────────────────────────────────────────────────────────┘
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
6. [Webhooks](#webhooks)
7. [Configuration](#configuration)
8. [Deployment](#deployment)
9. [Operations](#operations)
10. [Monitoring](#monitoring)
11. [Security notes](#security-notes)
12. [Testing](#testing)
13. [DNS records](#dns-records)
14. [Troubleshooting](#troubleshooting)
15. [Non-goals / future work](#non-goals--future-work)

---

## Repository layout

```
.
├── compose.yaml              # the whole stack: mailserver, roundcube, parser
├── README.md                 # this file
├── SPEC.md                   # condensed design spec for the parser service
├── .env.example              # template for the (untracked) .env secrets file
├── parser/                   # custom Go parser + API service
│   ├── Dockerfile            # two-stage build → static binary on alpine
│   ├── go.mod
│   ├── main.go               # wiring: config → db pool → poller + http server
│   └── internal/
│       ├── api/              # chi router: ingest/query/status/health/metrics
│       ├── config/           # env-driven configuration
│       ├── mailx/            # MIME walking: raw RFC 822 → report payloads
│       ├── metrics/          # dependency-free Prometheus text exposition
│       ├── poller/           # IMAP cycle: fetch → parse → store → file away
│       ├── report/           # DMARC XML parsing + zip/gzip/xml expansion
│       ├── store/            # Postgres writes/reads (legacy dmarcts schema)
│       └── webhook/          # signed report.ingested notifications
└── roundcube/                # Roundcube config (self-signed IMAP, /roundcube prefix)
```

**Not in the repo** (see [.gitignore](.gitignore)): `.env` (DB URL, API keys),
`.mailbox-password` (IMAP password), and `docker-data/` (mail spool, mail
state/logs, TLS certs, account files). Those live only on the host.

## Components

| Service | Container | Image | Access |
|---|---|---|---|
| Mail server | `dmarc-mailserver` | `docker-mailserver` 15.1 | SMTP `127.0.0.1:2525`, IMAPS `:993` |
| Webmail | `dmarc-roundcube` | `roundcube/roundcubemail` 1.6 | `https://<your-host>/roundcube/` (fallback `127.0.0.1:8090`) |
| Parser + API | `dmarc-parser` | built from `./parser` | host `127.0.0.1:8081`; containers `http://dmarcparser:8080` |

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
4. File the message: → `Processed` (≥1 report stored, duplicates count),
   → `Ignored` (no report payload — human mail, ruf forensic reports, etc.),
   → `Failed` (payload present but unreadable/unparseable).
5. Fire a webhook for every newly stored report.

### Payload detection

Content types and filenames from reporters are unreliable, so detection is
done by **magic bytes** on every MIME part:

| Magic | Treated as | Notes |
|---|---|---|
| `PK\x03\x04` | zip | every entry that sniffs as report XML is parsed (archives can hold several) |
| `\x1f\x8b` | gzip | single document |
| leading `<` | XML | accepted only if `<feedback` appears in the first 2 KB |

Decompression is capped at 256 MB per payload (zip-bomb guard). A part that
*looks* like a report container but fails to read marks the mail `Failed`;
parts that don't sniff as reports at all are simply skipped.

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
| Webhook endpoint down | 3 attempts (2 s/8 s backoff), then `webhook_failures_total`++ |

## REST API

Base URLs: `http://127.0.0.1:8081` (host) · `http://dmarcparser:8080`
(containers on the shared networks).

**Auth:** every `/api/v1/*` route requires a key from `PARSER_API_KEYS`
(comma-separated in `.env`), passed as `Authorization: Bearer <key>` or
`X-API-Key: <key>`. `/healthz` and `/metrics` are unauthenticated. With no
keys configured the API answers `503` (fail closed).

| Method & path | Description |
|---|---|
| `POST /api/v1/ingest` | Ingest report(s): raw XML / gzip / zip body (any `Content-Type`), or `multipart/form-data` with a file field. `201` if anything new stored, `200` if all duplicates, `400` for non-reports. |
| `POST /api/v1/poll` | Trigger an immediate IMAP cycle (async). `202`. |
| `GET /api/v1/status` | Poller state, lifetime counters, DB totals. |
| `GET /api/v1/reports` | List. Filters: `domain`, `org`, `since`, `until` (RFC 3339 or `YYYY-MM-DD`), `limit` ≤ 500 (default 50), `offset`. |
| `GET /api/v1/reports/{serial}` | Full report incl. records, IPs rendered as strings. |
| `GET /healthz` | `200` ok / `503` degraded (DB down, or last successful poll older than 3×interval+2m). |
| `GET /metrics` | Prometheus text format. |

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
```

## Webhooks

Set `PARSER_WEBHOOK_URL` (and ideally `PARSER_WEBHOOK_SECRET`) in `.env` and
every **newly stored** report — from either the poller or the ingest API —
fires:

```
POST $PARSER_WEBHOOK_URL
Content-Type: application/json
X-Parser-Event: report.ingested
X-Parser-Signature: hex(hmac-sha256(body, $PARSER_WEBHOOK_SECRET))

{"event":"report.ingested","serial":157827,"domain":"example.org",
 "org":"google.com","report_id":"…","date_begin":"2026-06-10T00:00:00Z",
 "date_end":"2026-06-11T00:00:00Z","records":17,"messages":17,"source":"imap"}
```

`source` is `imap` or `api`. Delivery is async, at-most-3 attempts with
backoff; duplicates never fire. Verify the signature by HMAC-ing the raw body
with the shared secret and comparing constant-time.

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
| `PARSER_API_KEYS` | — | comma-separated; empty = API refuses requests |
| `PARSER_WEBHOOK_URL` / `PARSER_WEBHOOK_SECRET` | — | optional |
| `PARSER_STORE_RAW_XML` | `true` | `false` saves DB space |
| `PARSER_MAX_BODY_BYTES` | `67108864` (64 MB) | ingest request cap |

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
| `dmarcparser_last_poll_timestamp_seconds` | gauge, unix time |
| `dmarcparser_last_poll_success_timestamp_seconds` | gauge, unix time |

`GET /healthz` is suitable for liveness checks: it verifies DB connectivity
and that the last successful poll is fresher than `3 × interval + 2m`.

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

- **Forensic (ruf) reports** — currently filed under `Ignored` with raw mail
  preserved; a `failure report` parser could be added in `report/`.
- **SMTP TLS reports** (RFC 8460 `smtp-tls-rpt`) — same.
- **Schema evolution** — the parser intentionally writes the legacy dmarcts
  schema so the existing viewer keeps working; a normalized schema would be a
  joint migration with the viewer.
