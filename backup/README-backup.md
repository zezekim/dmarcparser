# dmarc backup sidecar

Nightly backups of the dmarc Postgres database and the docker-mailserver
configuration, taken by a small `postgres:16-alpine` sidecar (service
`backup` in `compose.yaml`) running busybox crond. No Go, no daemons beyond
crond; everything is POSIX sh in this directory, bind-mounted read-only into
the container at `/opt/backup` and invoked via `/bin/sh`.

## What is backed up, when, where

| What | How | Schedule (UTC) |
|---|---|---|
| Postgres `dmarc` DB (reports, records, all v2 tables) | `pg_dump --format=custom --compress=6` via `$PARSER_DATABASE_URL` | daily 03:15 |
| Mailserver config (`docker-data/dms/config`: accounts, virtual maps, quotas) | `tar -czf` of the ro mount `/mailconfig` | daily 03:15 |
| Integrity verification of the newest dump + tarball | `pg_restore --list` + `gzip -t`/`tar -t` | weekly Mon 04:45 |

Backups land on the **host** in `/var/backups/dmarc` (bind mount `/backups`):

```
/var/backups/dmarc/
  dmarc-YYYY-MM-DD.dump          # daily, newest 14 kept
  mailconfig-YYYY-MM-DD.tar.gz   # daily, newest 14 kept
  weekly/                        # Sunday's set hardlinked here, newest 8 kept
    dmarc-YYYY-MM-DD.dump
    mailconfig-YYYY-MM-DD.tar.gz
  .last-success                  # stamp written after every fully successful backup
  .last-verified                 # stamp written after every successful verify
```

Dumps are written to a `.tmp` name first and renamed only on success — a file
matching `dmarc-*.dump` is always a complete archive. Rotation: 14 daily +
8 weekly sets (`KEEP_DAILY`, `KEEP_WEEKLY`, `WEEKLY_DOW` env overrides).

## Health

- The compose healthcheck fails when `/backups/.last-success` is older than
  26 h (one missed nightly run + slack), so a broken backup shows up as an
  unhealthy container in `docker compose ps` / monitoring.
- On container start, `entrypoint.sh` takes an immediate backup if the stamp
  is missing or older than a day, then runs crond in the foreground. All job
  output is in `docker compose logs backup`.
- Credentials never appear in logs; the DSN only travels via the
  `PARSER_DATABASE_URL` environment variable.

## Manual operations

```sh
cd /opt/dmarcparser
docker compose exec backup sh /opt/backup/backup.sh   # take a backup now
docker compose exec backup sh /opt/backup/verify.sh   # verify newest set now
docker compose logs backup                            # job output
```

## Restore runbook

`verify.sh` proves the archive is complete and readable. It does **not**
prove the data is sane — run the test-restore drill (section 2) quarterly.

### 1. Full database restore (disaster recovery)

Restores the chosen dump over the live `dmarc` database. The dump is
self-consistent (single `pg_dump` snapshot); everything ingested after it
was taken is lost (reporters resend little — expect a permanent gap).

```sh
cd /opt/dmarcparser
# 1. Stop writers so nothing races the restore.
docker compose stop parser
# 2. Pick a dump (host path /var/backups/dmarc == container /backups).
ls /var/backups/dmarc/dmarc-*.dump /var/backups/dmarc/weekly/
# 3. Restore. --clean --if-exists drops & recreates objects from the dump;
#    --no-owner keeps everything owned by the connecting role.
docker compose exec backup sh -c \
  'pg_restore --clean --if-exists --no-owner --exit-on-error \
     --dbname="$PARSER_DATABASE_URL" /backups/dmarc-YYYY-MM-DD.dump'
# 4. Sanity-check before restarting ingestion.
docker compose exec backup sh -c \
  'psql "$PARSER_DATABASE_URL" -c "SELECT count(*) AS reports, max(seen) FROM report;"'
# 5. Restart the parser; startup migrations are idempotent and will no-op.
docker compose start parser
curl -s localhost:8081/healthz
```

If the database itself is gone (fresh Postgres), first create an empty
`dmarc` database and role matching the DSN (in the viewer's db container,
e.g. `docker exec -it dmarc-db-1 psql -U postgres`), then run step 3 without
`--clean`.

### 2. Test-restore drill (quarterly, no impact on live data)

Restore the newest dump into a scratch database on the same server, check
row counts, drop it.

```sh
cd /opt/dmarcparser
# Scratch DSN = live DSN with the database name swapped (adapt if your DSN differs).
docker compose exec backup sh -c '
  set -eu
  SCRATCH=$(printf "%s" "$PARSER_DATABASE_URL" | sed "s|/dmarc?|/dmarc_restore_test?|")
  psql "$PARSER_DATABASE_URL" -c "DROP DATABASE IF EXISTS dmarc_restore_test;" \
                              -c "CREATE DATABASE dmarc_restore_test;"
  pg_restore --no-owner --exit-on-error --dbname="$SCRATCH" \
    "$(ls -1 /backups/dmarc-*.dump | sort -r | head -n 1)"
  psql "$SCRATCH" -c "SELECT count(*) AS reports FROM report;" \
                  -c "SELECT count(*) AS records FROM rptrecord;" \
                  -c "SELECT max(seen) AS newest FROM report;"
  psql "$PARSER_DATABASE_URL" -c "DROP DATABASE dmarc_restore_test;"
'
```

Compare the counts against the live DB (they should differ only by what
arrived since 03:15 UTC). If `CREATE DATABASE` is refused, the app role
lacks `CREATEDB` — run the create/drop statements as `postgres` inside the
db container instead and keep the `pg_restore`/check lines as above.

### 3. Mailserver config restore

The tarball holds the contents of `docker-data/dms/config`
(postfix-accounts.cf, postfix-virtual.cf, dovecot-quotas.cf, …).

```sh
cd /opt/dmarcparser
mkdir -p docker-data/dms/config
tar -xzf /var/backups/dmarc/mailconfig-YYYY-MM-DD.tar.gz -C docker-data/dms/config
docker compose restart mailserver
```

Mail *data* (the mailbox itself) is intentionally not backed up: every mail
is parsed into the database within one poll interval; the mailbox is a queue,
not a store of record.

### 4. Bare-host rebuild order

1. Restore `/opt/dmarcparser` (git) + `.env` + `.mailbox-password`
   (from your secrets store — they are not in these backups by design),
   and `/var/backups/dmarc` from off-host copies.
2. Bring up the viewer stack's Postgres; create role + empty `dmarc` DB.
3. Database restore (section 1, step 3 without `--clean`).
4. Mail config restore (section 3), then `docker compose up -d`.
5. Check `/healthz`, viewer pages, and that the next poll cycle files mail.

> Off-host copies: `/var/backups/dmarc` is a single-disk location. Sync it
> off the machine (restic/rclone/borg from the host) — outside this
> sidecar's scope.
