\#!/bin/bash
# filepath: /Users/jtong/toolbox/linux/backup/bin/backup.sh
# Linux backup script using rsync with rotation and logging
# Usage: backup.sh -p <port> -s user@server:/path/to/source -s user@server2:/path/to/source2 -d /path/to/destination -x exclude_file
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

# Array to store multiple sources
SOURCES=()

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
    DEST_DIR=""

    while getopts "p:s:d:x:" opt; do
        case "$opt" in
            p) SRC_PORT="$OPTARG" ;;
            s) SOURCES+=("$OPTARG") ;;
            d) DEST_DIR="$OPTARG" ;;
            x) EXCLUDE_FILE="$OPTARG" ;;
            *) log "Usage: $0 -s <source1> -s <source2> -d <dest_dir> [-p <port>] [-x <exclude_file>]"; clean_exit 1 ;;
        esac
    done
}

# Function to get host identifier from source path
get_host_identifier() {
    local src_path="$1"
    if [[ "$src_path" == *:* ]]; then
        # Remote source: extract host part
        echo "${src_path%%:*}"
    else
        # Local source
        echo "local"
    fi
}

# Function to get source directory name
get_source_dir_name() {
    local src_path="$1"
    if [[ "$src_path" == *:* ]]; then
        # Remote source: extract path part and get basename
        local remote_path="${src_path#*:}"
        basename "$remote_path"
    else
        # Local source: get basename
        basename "$src_path"
    fi
}

# Function to backup a single source
backup() {
    local src_path="$1"
    local host_id="$2"
    local src_dir_name="$3"
    
    log "Starting backup of '$src_path' to host directory '$host_id'"
    
    # Create host-specific backup directory structure
    local host_backup_dir="$DEST_DIR/$host_id/$src_dir_name"
    mkdir -p "$host_backup_dir"
    
    # Check source is local or remote
    local mode rsync_opts
    if [[ "$src_path" == *:* ]]; then
        # Remote source via SSH
        mode="remote"
        rsync_opts="-z"
        if [[ -n "$SRC_PORT" ]]; then
            rsync_opts="$rsync_opts -e 'ssh -p $SRC_PORT'"
        fi
    else
        # Local source
        mode="local"
        rsync_opts=""
    fi

    # Check for exclude file
    if [ -f "$EXCLUDE_FILE" ]; then
        rsync_opts="$rsync_opts --exclude-from=$EXCLUDE_FILE"
    fi

    # List subfolders in source
    local subfolders
    if [ "$mode" = "remote" ]; then
        # Remote source: list subfolders via rsync
        subfolders=$(eval "rsync $rsync_opts --list-only \"$src_path/\"" | awk '/^d/ {for(i=5;i<=NF;++i) printf "%s%s", $i,(i<NF?" ":"\n")}' | grep -v '^\.\/\?$')
    else
        # Local source
        subfolders=$(find "$src_path" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    fi

    if [ -z "$subfolders" ]; then
        log "No subfolders found in source $src_path. Skipping."
        return 1
    fi

    # Prepare backup directory with date
    local today=$(date '+%Y-%m-%d')
    local today_backup="$host_backup_dir/$today"
    mkdir -p "$today_backup"

    # Find last backup for this specific source
    local last_backup=$(ls -1d "$host_backup_dir"/20* 2>/dev/null | sort | tail -n 1)
    
    local link_dest_opt=""
    if [ -z "$last_backup" ] || [ "$last_backup" = "$today_backup" ]; then
        log "No previous backup found for $src_path. Performing full backup."
    else
        link_dest_opt="$last_backup"
        log "Using hard-linking to previous backup at $last_backup for unchanged files."
    fi

    # Backup each subfolder
    echo "$subfolders" | while read -r sub; do
        [ -z "$sub" ] && continue
        
        # Check if subfolder should be excluded
        if [ -f "$EXCLUDE_FILE" ] && grep -q -E "^$(basename "$sub")$" "$EXCLUDE_FILE"; then
            continue
        fi

        echo "Backing up subfolder: $sub"
        # Ensure destination directory exists
        mkdir -p "$today_backup/$(basename "$sub")"
        
        # Prepare rsync command with hard-linking
        local rsync_cmd="-a --delete"
        if [ -n "$link_dest_opt" ] && [ -d "$link_dest_opt/$(basename "$sub")" ]; then
            rsync_cmd="$rsync_cmd --link-dest=$link_dest_opt/$(basename "$sub")"
        fi
        
        # Add source-specific options
        rsync_cmd="$rsync_cmd $rsync_opts"

        # Execute backup
        local rsync_output
        if [ "$mode" = "remote" ]; then
            rsync_output=$(eval "rsync $rsync_cmd --stats \"$src_path/$(basename "$sub")/\" \"$today_backup/$(basename "$sub")/\"" 2>&1)
        else
            rsync_output=$(rsync $rsync_cmd --stats "$sub/" "$today_backup/$(basename "$sub")/" 2>&1)
        fi

        # Log backup statistics
        local files_transferred=$(echo "$rsync_output" | grep "Number of regular files transferred:" | awk -F: '{print $2}' | awk '{print $1}')
        local total_size=$(echo "$rsync_output" | grep "Total transferred file size:" | awk -F: '{print $2}' | awk '{print $1}')
        local hr_total_size=$(human_readable_size "$total_size")
        log "Backup of $src_path/$(basename "$sub") completed: $files_transferred files, $hr_total_size"
    done

    # Rotate backups for this specific source (keep at least $BACKUPS_TO_KEEP copies)
    local total_backups=$(ls -1d "$host_backup_dir"/20* 2>/dev/null | wc -l)
    if [ "$total_backups" -gt "$BACKUPS_TO_KEEP" ]; then
        local old_backups=$(ls -1d "$host_backup_dir"/20* 2>/dev/null | sort | head -n $(("$total_backups" - "$BACKUPS_TO_KEEP")))
        for backup in $old_backups; do
            log "Deleting old backup: $backup"
            rm -rf "$backup"
        done
    fi

    log "Backup of $src_path completed for $today."
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

    # Initialize log file
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    elif [ "$(wc -l < "$LOG_FILE")" -gt 10000 ]; then
        tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi

    parse_args "$@"

    # Validate arguments
    if [ ${#SOURCES[@]} -eq 0 ] || [ -z "$DEST_DIR" ]; then
        log "No sources or destination not specified. Usage: $0 -s <source1> -s <source2> -d <dest_dir>"
        clean_exit 1
    fi

    # Ensure destination directory exists
    mkdir -p "$DEST_DIR"

    # Process each source
    for src_path in "${SOURCES[@]}"; do
        log "Starting backup from ${src_path}"
        host_id=$(get_host_identifier "$src_path")
        src_dir_name=$(get_source_dir_name "$src_path")
        
        backup "$src_path" "$host_id" "$src_dir_name"
    done

    log "All backup operations completed."
    clean_exit 0
}

main "$@"
