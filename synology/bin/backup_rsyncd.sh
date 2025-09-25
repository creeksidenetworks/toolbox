#!/bin/bash
# (c) 2025 Creekside Networks LLC, Jackson Tong
# Usage: backup_rsyncd.sh -s <source> -d <dest> -u <user> -p <password>

while getopts "s:d:u:p:" opt; do
    case $opt in
        s) SRC="$OPTARG" ;;
        d) DEST="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASS="$OPTARG" ;;
        *) echo "Usage: $0 -s <source> -d <dest> -u <user> -p <password>"; exit 1 ;;
    esac
done

if [[ -z "$SRC" || -z "$DEST" || -z "$USER" || -z "$PASS" ]]; then
    echo "Missing arguments"
    echo "Usage: $0 -s <source> -d <dest> -u <user> -p <password>";
    exit 1
fi

LOG_TAG="csn-backup"

# --- Local Logging Setup ---
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
LOG_FILE="$SCRIPT_DIR/backup_rsyncd.log"

# Function for local logging with timestamp
mylog() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

logger -t $LOG_TAG "Starting backup from $SRC to $DEST..."

# Create backup directory for today
TODAY=$(date +%Y-%m-%d)
BACKUP_DIR="$DEST/$TODAY"
mkdir -p "$BACKUP_DIR"

# Find latest backup for incremental
LATEST=$(ls -1d $DEST/*/ 2>/dev/null | grep -v "$TODAY" | sort | tail -n 1)

# Rsync options
RSYNC_OPTS="-a --delete --stats"
if [[ -n "$LATEST" ]]; then
    RSYNC_OPTS="$RSYNC_OPTS --link-dest=$LATEST"
fi

# Create password file
PASSFILE=$(mktemp)
echo "$PASS" > "$PASSFILE"
chmod 600 "$PASSFILE"

# Set pipefail to ensure the exit code of rsync is captured
set -o pipefail

# Run rsync and log its output to the local log file
mylog "--- rsync execution started ---"
rsync $RSYNC_OPTS --password-file="$PASSFILE" "$USER@$SRC::module" "$BACKUP_DIR" >> "$LOG_FILE" 2>&1

rsync_exit_code=${PIPESTATUS[0]}
mylog "--- rsync execution finished with exit code: $rsync_exit_code ---"
set +o pipefail

rm -f "$PASSFILE"

# Remove backups older than 31 days
find "$DEST" -maxdepth 1 -type d -mtime +31 | while read -r old_backup; do
    mylog "Removing old backup: $old_backup"
    rm -rf "$old_backup"
done

if [ "$rsync_exit_code" -eq 0 ]; then
    logger -t "$LOG_TAG" "Backup completed successfully."
else
    logger -t "$LOG_TAG" "Backup failed with exit code $rsync_exit_code."
    exit 1
fi
