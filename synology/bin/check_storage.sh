#!/bin/bash
# Check home usages for Synology DSM 
# (c) 2025 Creekside Networks LLC, Jackson Tong
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
DEFAULT_HOME=/volume1/homes
DU_OPTIONS="-sh"
BASE_PATH=$(dirname $(dirname "$(readlink -f "$0")"))
NAS_NAME=$(hostname -s)

LOG_PATH=$BASE_PATH/log
LOG_FILE="$LOG_PATH/${NAS_NAME}.log"
RPT_FILE="$LOG_PATH/${NAS_NAME}.rpt"

# Function to log messages
log_message() {
    local message=$1
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    printf "%-10s : %s\n" "$timestamp" "$message" | sudo tee -a "$LOG_FILE" &> /dev/null

    # Ensure the log file does not exceed 1000 lines
    line_count=$(sudo wc -l < "$LOG_FILE")
    if [ "$line_count" -gt 1000 ]; then
        sudo tail -n 500 "$LOG_FILE" | sudo tee "$LOG_FILE.tmp" &> /dev/null
        sudo mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}

# Function to parse command line arguments
parse_args() {
    HOME_PATH="${DEFAULT_HOME}"
    THRESHOLD="1T"
    LEVEL=1

    SUBJECT="$NAS_NAME"
    while getopts ":p:t:d:s:" opt; do
        case $opt in
            p)
                HOME_PATH="$OPTARG"
                ;;
            t)
                # Convert threshold to bytes
                arg=$(echo "$OPTARG" | tr '[:lower:]' '[:upper:]')
                if [[ "$arg" =~ ^([0-9]+)(T|TB)$ ]]; then
                    THRESHOLD_BYTES=$(( ${BASH_REMATCH[1]} * 1024 * 1024 * 1024 * 1024 ))
                    THRESHOLD="${BASH_REMATCH[1]}TB"
                elif [[ "$arg" =~ ^([0-9]+)(G|GB)$ ]]; then
                    THRESHOLD_BYTES=$(( ${BASH_REMATCH[1]} * 1024 * 1024 * 1024 ))
                    THRESHOLD="${BASH_REMATCH[1]}GB"
                elif [[ "$arg" =~ ^([0-9]+)$ ]]; then
                    THRESHOLD_BYTES=$(( ${BASH_REMATCH[1]} * 1024 * 1024 * 1024 * 1024 ))
                    THRESHOLD="${BASH_REMATCH[1]}TB"
                else
                    THRESHOLD="1T"
                    THRESHOLD_BYTES=$(( 1 * 1024 * 1024 * 1024 * 1024 ))
                fi
                ;;
            d)
                LEVEL=2
                ;;
            s)
                SUBJECT="$OPTARG"
                ;;
            \?)
                echo "Usage: $0 [-p <HOME_PATH>] [-t <THRESHOLD>] [-d] [-s <SUBJECT>]"
                exit 1
                ;;
        esac
    done
    shift $((OPTIND -1))
}

bytes_to_hr() {
    local size_bytes=$1
    local size_hr=""

    #echo "Converting $size_bytes bytes to human-readable format"

    if [ "$size_bytes" -ge 1099511627776 ]; then
        size_hr=$(printf "%8d TB"  $((size_bytes/1099511627776)))
    elif [ "$size_bytes" -ge 1073741824 ]; then
        size_hr=$(printf "%8d GB"  $((size_bytes/1073741824)))
    elif [ "$size_bytes" -ge 1048576 ]; then
        size_hr=$(printf "%8d MB"  $((size_bytes/1048576)))
    elif [ "$size_bytes" -ge 1024 ]; then
        size_hr=$(printf "%8d KB"  $((size_bytes/1024)))
    else
        size_hr=$(printf "%8d  B" $size_bytes)
    fi

    echo "$size_hr"
}

main() {

    parse_args "$@"

    printf "Checking storage usage in $HOME_PATH over $THRESHOLD\n"

    today_date=$(date +"%y-%m-%d")
    REPORT="0"
    rm -f $RPT_FILE

    if [ ! -d $HOME_PATH ]; then
        log_message "Home path $HOME_PATH does not exist. Exiting."
        exit 1
    fi

    if [ ! -d $LOG_PATH ]; then
        mkdir -p $LOG_PATH
    fi

    if [ "$LEVEL" -eq 1 ]; then
        while read target; do
            if [[ -z "$target" ]]; then 
                continue
            fi 

            # Get size in bytes (fast, using stat)
            size_bytes=$(du -s "${HOME_PATH}/$target"  | awk '{print $1}' 2>/dev/null || echo 0)

            # Convert bytes to human-readable format
            size_hr=$(bytes_to_hr "$size_bytes")

            log_message "$(printf "%-30s : %-8s\n" "$target" "$size_hr")"

            if [ "$size_bytes" -ge "$THRESHOLD_BYTES" ]; then
                printf "%-30s : %-8s\n" "$target" "$size_hr" >> "$RPT_FILE"
                REPORT="1"
            fi
        done < <(find "${HOME_PATH}" -maxdepth 1 -mindepth 1 -type d | sed "s|^${HOME_PATH}/||" | sort -f)
    else
        while read l1; do
            if [[ -z "$l1" ]]; then
                continue
            fi
            while read l2; do
                if [[ -z "$l2" ]]; then
                    continue
                fi
                # Get size in bytes for L2
                size_bytes=$(du -s "${HOME_PATH}/$l1/$l2"  | awk '{print $1}' 2>/dev/null || echo 0)
                size_hr=$(bytes_to_hr "$size_bytes")

                log_message "$(printf "%-20s/%-20s : %-8s\n" "$l1" "$l2" "$size_hr")"

                if [ "$size_bytes" -ge "$THRESHOLD_BYTES" ]; then
                    printf "%-20s/%-20s : %-8s\n" "$l1" "$l2" "$size_hr" >> "$RPT_FILE"
                    REPORT="1"
                fi
            done < <(find "${HOME_PATH}/$l1" -maxdepth 1 -mindepth 1 -type d | sed "s|^${HOME_PATH}/$l1/||" | sort -f)
        done < <(find "${HOME_PATH}" -maxdepth 1 -mindepth 1 -type d | sed "s|^${HOME_PATH}/||" | sort -f)
    fi


    if [ $REPORT -eq 1 ]; then
        printf "=========================================\n"
        printf "Home usage report for $SUBJECT\n"
        printf "Report date: $today_date\n\n"
        printf "=========================================\n"
        cat "$RPT_FILE"
        printf "=========================================\n"
    fi  

    exit $REPORT
}

main "$@"
