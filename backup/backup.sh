#!/bin/sh
# dmarcparser backup: pg_dump (custom format) + mailserver-config tarball,
# with 14-daily / 8-weekly rotation. Writes $BACKUP_DIR/.last-success on
# full success (the compose healthcheck watches its age).
#
# Runs inside the postgres:16-alpine backup sidecar (busybox ash, POSIX sh).
# Daily files live in $BACKUP_DIR, weekly hardlink copies in $BACKUP_DIR/weekly.
# Credentials only ever travel via $PARSER_DATABASE_URL; never printed.
set -eu

BACKUP_DIR=${BACKUP_DIR:-/backups}
MAILCONFIG_DIR=${MAILCONFIG_DIR:-/mailconfig}
KEEP_DAILY=${KEEP_DAILY:-14}
KEEP_WEEKLY=${KEEP_WEEKLY:-8}
WEEKLY_DOW=${WEEKLY_DOW:-7} # ISO day-of-week feeding the weekly set (7=Sunday)
WEEKLY_DIR=$BACKUP_DIR/weekly

log() { printf '%s backup %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "ERROR: $*"; exit 1; }

# prune <keep> <files...> — delete all but the <keep> lexically newest files.
# Callers pass date-named files, so lexical order == chronological order.
prune() {
	_keep=$1
	shift
	[ $# -gt 0 ] && [ -e "$1" ] || return 0
	ls -1 "$@" | sort -r | tail -n +"$((_keep + 1))" | while IFS= read -r _old; do
		rm -f -- "$_old"
		log "pruned ${_old##*/}"
	done
}

[ -n "${PARSER_DATABASE_URL:-}" ] || fail "PARSER_DATABASE_URL is not set"
[ -d "$MAILCONFIG_DIR" ] || fail "mail config dir $MAILCONFIG_DIR is not mounted"
mkdir -p "$BACKUP_DIR" "$WEEKLY_DIR"

today=$(date -u +%Y-%m-%d)
dump=$BACKUP_DIR/dmarc-$today.dump
tarball=$BACKUP_DIR/mailconfig-$today.tar.gz

# Database dump (custom format -> single compressed, pg_restore-able file).
# Written to a .tmp first so a partial dump never looks like a backup.
rm -f -- "$dump.tmp"
PGCONNECT_TIMEOUT=${PGCONNECT_TIMEOUT:-15} pg_dump \
	--format=custom --compress=6 --no-password \
	--dbname="$PARSER_DATABASE_URL" --file="$dump.tmp" \
	|| fail "pg_dump failed"
mv -- "$dump.tmp" "$dump"
log "database dump ${dump##*/} ($(du -h "$dump" | cut -f1))"

# Mailserver config (docker-mailserver accounts/virtual maps, ro mount).
rm -f -- "$tarball.tmp"
tar -czf "$tarball.tmp" -C "$MAILCONFIG_DIR" . || fail "mail config tar failed"
mv -- "$tarball.tmp" "$tarball"
log "mail config ${tarball##*/} ($(du -h "$tarball" | cut -f1))"

# On the weekly day, hardlink today's set into weekly/ (same filesystem; cp
# as a fallback) so it survives the 14-day daily prune.
if [ "$(date -u +%u)" = "$WEEKLY_DOW" ]; then
	for f in "$dump" "$tarball"; do
		w=$WEEKLY_DIR/${f##*/}
		rm -f -- "$w"
		ln -- "$f" "$w" 2>/dev/null || cp -- "$f" "$w"
	done
	log "weekly set updated"
fi

prune "$KEEP_DAILY" "$BACKUP_DIR"/dmarc-*.dump
prune "$KEEP_DAILY" "$BACKUP_DIR"/mailconfig-*.tar.gz
prune "$KEEP_WEEKLY" "$WEEKLY_DIR"/dmarc-*.dump
prune "$KEEP_WEEKLY" "$WEEKLY_DIR"/mailconfig-*.tar.gz

date -u +%Y-%m-%dT%H:%M:%SZ >"$BACKUP_DIR/.last-success"
log "complete"
