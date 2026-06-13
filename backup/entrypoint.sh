#!/bin/sh
# Entrypoint for the dmarc backup sidecar (postgres:16-alpine + busybox crond).
# Installs the crontab, takes an immediate backup if the success stamp is
# missing or older than a day (fresh container, long downtime), then runs
# crond in the foreground as PID 1 — cron jobs write to /proc/1/fd/1 so their
# output lands in `docker logs`.
set -eu

BACKUP_DIR=${BACKUP_DIR:-/backups}
mkdir -p "$BACKUP_DIR"

cp /opt/backup/crontab /etc/crontabs/root

if [ -z "$(find "$BACKUP_DIR/.last-success" -mmin -1440 2>/dev/null)" ]; then
	/bin/sh /opt/backup/backup.sh \
		|| printf '%s entrypoint initial backup failed; next cron run retries\n' \
			"$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

exec crond -f -d 8
