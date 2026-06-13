#!/bin/sh
# dmarcparser backup verification: integrity-check the newest database dump
# (pg_restore --list must succeed and contain table data) and the newest
# mail config tarball (gzip + tar listing). Writes $BACKUP_DIR/.last-verified
# on success.
#
# This does NOT replace the quarterly full test-restore drill documented in
# README-backup.md — pg_restore --list proves the file is a complete,
# readable archive, not that the data inside is sane.
set -eu

BACKUP_DIR=${BACKUP_DIR:-/backups}

log() { printf '%s verify %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "ERROR: $*"; exit 1; }

# latest <files...> — lexically newest existing match (date-named files).
latest() {
	[ -e "$1" ] || { echo ""; return 0; }
	ls -1 "$@" | sort -r | head -n 1
}

dump=$(latest "$BACKUP_DIR"/dmarc-*.dump)
[ -n "$dump" ] || fail "no database dump found in $BACKUP_DIR"
toc=$(pg_restore --list -- "$dump") || fail "pg_restore --list failed for ${dump##*/}"
printf '%s\n' "$toc" | grep -q 'TABLE DATA' || fail "${dump##*/} contains no table data"
log "dump ${dump##*/} ok ($(printf '%s\n' "$toc" | grep -c '^[0-9]') TOC entries)"

tarball=$(latest "$BACKUP_DIR"/mailconfig-*.tar.gz)
[ -n "$tarball" ] || fail "no mail config tarball found in $BACKUP_DIR"
gzip -t -- "$tarball" || fail "gzip integrity check failed for ${tarball##*/}"
[ "$(tar -tzf "$tarball" | wc -l)" -gt 0 ] || fail "${tarball##*/} is empty"
log "tarball ${tarball##*/} ok"

date -u +%Y-%m-%dT%H:%M:%SZ >"$BACKUP_DIR/.last-verified"
log "complete"
