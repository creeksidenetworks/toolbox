#!/bin/bash
# Linux backup script using rsync with rotation and logging
# Usage: backup.sh -p <port> -s user@server:/path/to/source -d /path/to/destination -x exclude_file
# Notes: if source is a Synology NAS, ensure the admin user is enabled, and add your ssh public key to /root/.ssh/authorized_keys
# Author: Jackson Tong
# (c) 2020-2025 Jackson Tong
# License: MIT

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

# backup.sh - Incremental backup script using rsync with rotation and logging
BACKUPS_TO_KEEP=30 

RUN_DIR="$(cd "$(dirname "$(dirname "$0")")" && pwd)"/run
CONF_DIR="$(cd "$(dirname "$(dirname "$0")")" && pwd)"/conf
LOCK_FILE="$RUN_DIR/backup.lock"
LOG_FILE="/var/log/backup.log"
EXCLUDE_FILE="$CONF_DIR/backup.exclude"

mkdir -p "$RUN_DIR"

# Convert TOTAL_SIZE from bytes to human readable values
human_readable_size() { 
    local size=$(echo "$1" | tr -d ',')
    local units=(Bytes KB MB GB TB PB)
    local i=0
    while [ "$size" -ge 1024 ] && [ $i -lt 5 ]; do
        size=$((size / 1024))
        i=$((i + 1))
    done
    echo "${size} ${units[$i]}"
}

# Log function
log() {
    # Truncate log file if it exceeds 10000 lines
    if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE")" -gt 10000 ]; then
        tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}


clean_exit() {
    rm -f "$LOCK_FILE"
    exit $1
}   

parse_args() {
    SRC_PORT=""
    SRC_PATH=""
    DEST_DIR=""

    while getopts "p:s:d:x:" opt; do
        case "$opt" in
            p) SRC_PORT="$OPTARG" ;;
            s) SRC_PATH="$OPTARG" ;;
            d) DEST_DIR="$OPTARG" ;;
            x) EXCLUDE_FILE="$OPTARG" ;;
            *) log "Usage: $0 -s <source_dir> -d <dest_dir> [-p <port>] [-x <exclude_file>]"; clean_exit 1 ;;
        esac
    done
}


main() {
    # Prevent concurrent execution
    if [ -e "$LOCK_FILE" ]; then
        PID=$(cat "$LOCK_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            log "Backup already running with PID $PID. Exiting."
            exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE"

    # Check for backup.exclude file
    
    if [ -f "$EXCLUDE_FILE" ]; then
        RSYNC_OPTS="--exclude-from=$EXCLUDE_FILE"
    else
        RSYNC_OPTS=""
    fi

    # Truncate log file to last 10000 lines
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    elif [ "$(wc -l < "$LOG_FILE")" -gt 10000 ]; then
        tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi

    parse_args "$@"

    if [ -z "$SRC_PATH" ] || [ -z "$DEST_DIR" ]; then
        log "Source or destination not specified. Usage: $0 -s <user@host:/path_to_source> -d <dest_dir>"
        rm -f "$LOCK_FILE"
        exit 1
    fi

    # Check source is a local folder or remote via SSH
    if [[ "$SRC_PATH" == *:* ]]; then
        # Remote source via SSH
        $RSYNC_OPTS="-z"
        if [[ -n "$SRC_PORT" ]]; then
            RSYNC_OPTS="$RSYNC_OPTS -e 'ssh -p $SRC_PORT'"
        fi
        MODE="remote"
    else
        # Local source
        MODE="local"
    fi

    # Ensure destination directory exists
    mkdir -p "$DEST_DIR"

    # List subfolders in source and backup them one by one
    if [ "$MODE" = "remote" ]; then
        # Remote source: list subfolders via rsync -t, exclude "."
        SUBFOLDERS=$(rsync $RSYNC_OPTS --list-only "$SRC_PATH/" | awk '/^d/ {for(i=5;i<=NF;++i) printf "%s%s", $i,(i<NF?" ":"\n")}' | grep -v '^\.\/\?$')
        SRC="$SRC_PATH"
    else
        # Local source
        SUBFOLDERS=$(find "$SRC_PATH" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
        SRC="$SRC_PATH"
    fi

    if [ -z "$SUBFOLDERS" ]; then
        log "No subfolders found in source $SRC_PATH. Exiting."
        rm -f "$LOCK_FILE"
        exit 1
    fi

    # Prepare backup directory
    TODAY=$(date '+%Y-%m-%d')
    TODAY_BACKUP="$DEST_DIR/$TODAY"

    LAST_BACKUP=$(ls -1d "$DEST_DIR"/20* 2>/dev/null | sort | tail -n 1)
    # Handle first time backup (no previous backup)
    if [ -z "$LAST_BACKUP" ] || [ "$LAST_BACKUP" = "$TODAY_BACKUP" ]; then
        log "No previous backup found. Performing full backup."
    else
        LINK_DEST_OPT="$LAST_BACKUP"
        log "Using hard-linking to previous backup at $LAST_BACKUP for unchanged files."
    fi

    log "Starting backup of $SRC"
    echo "$SUBFOLDERS" | while read -r SUB; do
        [ -z "$SUB" ] && continue
        # Check if SUB matches any pattern in exclude file, if yes, skip it
        if [ -f "$EXCLUDE_FILE" ] && grep -q -E "^$(basename "$SUB")$" "$EXCLUDE_FILE"; then
            echo "Skipping excluded folder: $SUB"
            continue
        fi

        # Ensure destination directory exists
        mkdir -p "$TODAY_BACKUP/$SUB"
        
        # Use rsync with --link-dest for hard-linking unchanged files
        RSYNC_OPTS="-a --delete ${RSYNC_EXCLUDE_FROM}"
        if [ -n "$LINK_DEST_OPT" ] && [ -d "$LINK_DEST_OPT/$SUB" ]; then
            RSYNC_OPTS="$RSYNC_OPTS --link-dest=$LINK_DEST_OPT/$SUB"
        fi

        # log backup information
        RSYNC_OUTPUT=$(rsync $RSYNC_OPTS --stats "$SRC/$SUB/" "$TODAY_BACKUP/$SUB/" 2>&1)
        FILES_TRANSFERRED=$(echo "$RSYNC_OUTPUT" | grep "Number of regular files transferred:" | awk -F: '{print $2}' | awk '{print $1}')
        TOTAL_SIZE=$(echo "$RSYNC_OUTPUT" | grep "Total transferred file size:" | awk -F: '{print $2}' | awk '{print $1}')
        HR_TOTAL_SIZE=$(human_readable_size "$TOTAL_SIZE")
        log "Backup of $SUB completed: $FILES_TRANSFERRED files, $HR_TOTAL_SIZE"
    done

    # Rotate backups (keep at least $BACKUPS_TO_KEEP copies, regardless of age)
    TOTAL_BACKUPS=$(ls -1d "$DEST_DIR"/20* 2>/dev/null | wc -l)
    if [ "$TOTAL_BACKUPS" -gt "$BACKUPS_TO_KEEP" ]; then
        OLD_BACKUPS=$(ls -1d "$DEST_DIR"/20* 2>/dev/null | sort | head -n $(("$TOTAL_BACKUPS" - "$BACKUPS_TO_KEEP")))
        for BACKUP in $OLD_BACKUPS; do
            log "Deleting old backup: $BACKUP"
            rm -rf "$BACKUP"
        done
    fi

    log "Backup completed for $TODAY."
    clean_exit 0
}

main "$@"
