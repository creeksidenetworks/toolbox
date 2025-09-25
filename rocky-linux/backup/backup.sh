#!/bin/bash
# (c) 2025 Creekside Networks LLC, Jackson Tong
# This script will decide the best tunnel for jailbreak based on ping result
# for EdgeOS & VyOS 1.3.4

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# Log file path
LOG_FILE="/var/log/backup.log"

# Default values
SOURCE_DIR=""
DEST_DIR=""

# Function to log messages
log_message() {
    local message=$1
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    printf "%-10s %s\n" "$timestamp" "$message" | sudo tee -a "$LOG_FILE" # > /dev/null

    # Ensure the log file does not exceed 1000 lines
    line_count=$(sudo wc -l < "$LOG_FILE")
    if [ "$line_count" -gt 1000 ]; then
        sudo tail -n 500 "$LOG_FILE" | sudo tee "$LOG_FILE.tmp" > /dev/null
        sudo mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}

main() {
    # Parse command line arguments
    while getopts "s:d:" opt; do
        case $opt in
            s) SOURCE_DIR="$OPTARG"
            ;;
            d) DEST_DIR="$OPTARG"
            ;;
            \?) echo "Invalid option -$OPTARG" >&2
                exit 1
            ;;
        esac
    done

    # Detect destination type
    if [[ "$DEST_DIR" =~ ^([^@]+)@([^:]+):(.+) ]]; then
        # SSH remote: user@host:/path
        REMOTE_USER="${BASH_REMATCH[1]}"
        REMOTE_HOST="${BASH_REMATCH[2]}"
        REMOTE_PATH="${BASH_REMATCH[3]}"
        DEST_TYPE="ssh"
    elif [[ "$DEST_DIR" =~ ^([^:]+)::(.+) ]]; then
        # rsyncd remote: host::module/path
        RSYNCD_HOST="${BASH_REMATCH[1]}"
        RSYNCD_PATH="${BASH_REMATCH[2]}"
        DEST_TYPE="rsyncd"
    else
        # Local folder
        DEST_TYPE="local"
    fi


    # Check if source and destination directories are provided
    if [ -z "$SOURCE_DIR" ] || [ -z "$DEST_DIR" ]; then
        echo "Usage: $0 -s <source_directory> -d <destination_directory>"
        exit 1
    fi

    # Check if source directory exists
    if [ ! -d "$SOURCE_DIR" ]; then
        echo "Error: Source directory '$SOURCE_DIR' does not exist."
        exit 1
    fi

    # Check destination based on type
    case "$DEST_TYPE" in
        local)
            if [ ! -d "$DEST_DIR" ]; then
                mkdir -p "$DEST_DIR"
                if [ $? -ne 0 ]; then
                    echo "Error: Could not create destination directory '$DEST_DIR'."
                    exit 1
                fi
            fi
            ;;
        ssh)
            # Check remote directory existence via SSH
            ssh "${REMOTE_USER}@${REMOTE_HOST}" "test -d '${REMOTE_PATH}'" 2>/dev/null
            if [ $? -ne 0 ]; then
                echo "Error: Remote directory '${REMOTE_PATH}' does not exist on ${REMOTE_HOST}."
                exit 1
            fi
            ;;
        rsyncd)
            # Cannot check rsyncd remote directory existence directly; skip check
            ;;
    esac

    # Check if source directory exists
    if [ ! -d "$SOURCE_DIR" ]; then
        echo "Error: Source directory '$SOURCE_DIR' does not exist."
        exit 1
    fi

    # Create destination directory if it doesn't exist
    if [ ! -d "$DEST_DIR" ]; then
        mkdir -p "$DEST_DIR"
        if [ $? -ne 0 ]; then
            echo "Error: Could not create destination directory '$DEST_DIR'."
            exit 1
        fi
    fi

    # Get current date for backup filename
    log_message "Starting backup of '$SOURCE_DIR' to '$DEST_DIR'."
    DATE=$(date +%Y-%m-%d)
    BACKUP_FILE="$DEST_DIR/backup-$DATE.tar.gz"

    echo "Starting backup of '$SOURCE_DIR' to '$BACKUP_FILE'..."

    # Create the backup
    tar -czf "$BACKUP_FILE" -C "$(dirname "$SOURCE_DIR")" "$(basename "$SOURCE_DIR")" 

    if [ $? -eq 0 ]; then # Check the exit status of the tar command
        log_message "Backup completed successfully: $BACKUP_FILE"
        echo "Backup completed successfully."
    else
        log_message "Error: Backup failed for '$SOURCE_DIR'."
        echo "Error: Backup failed."
        exit 1
    fi

    # Clean up old backups (keep up to 31 days)
    echo "Cleaning up old backups..."
    log_message "Cleaning up old backups in '$DEST_DIR'."
    find "$DEST_DIR" -name "backup-*.tar.gz" -mtime +30 -delete

    if [ $? -eq 0 ]; then
        log_message "Old backups cleaned up successfully."
    else
        log_message "Warning: Some old backups might not have been cleaned up."
    fi
        log_message "Backup process finished."
}

# Check if a previous instance of the script is still running
PID_FILE="/var/run/backup_script.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null; then
        log_message "Previous backup script instance (PID: $PID) is still running. Exiting."
        exit 1
    else
        # Previous PID file found, but process is not running. Clean up.
        log_message "Stale PID file found. Removing $PID_FILE."
        rm -f "$PID_FILE"
    fi
fi

# Create PID file
echo $$ > "$PID_FILE"

# Ensure PID file is removed on exit
trap "rm -f '$PID_FILE'; log_message 'Removed PID file: $PID_FILE'" EXIT

main "$@"