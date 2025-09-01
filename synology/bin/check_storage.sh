#!/bin/bash
# Check home usages for Synology DSM 
# (c) 2025 Creekside Networks LLC, Jackson Tong
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Function to log messages
log_message() {
    local message=$1

    printf "%-10s : %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$message" | sudo tee -a "$LOG_FILE" &> /dev/null

}

# Function to parse command line arguments
parse_args() {
    while getopts ":p:t:d:s:" opt; do
        case $opt in
            p)
                HOME_PATH="$OPTARG"
                ;;
            t)
                # Convert threshold to bytes
                arg=$(echo "$OPTARG" | tr '[:lower:]' '[:upper:]')
                if [[ "$arg" =~ ^([0-9]+)(T|TB)$ ]]; then
                    THRESHOLD_KB=$(( ${BASH_REMATCH[1]} * 1024 * 1024 * 1024 ))
                    THRESHOLD="${BASH_REMATCH[1]}TB"
                elif [[ "$arg" =~ ^([0-9]+)(G|GB)$ ]]; then
                    THRESHOLD_KB=$(( ${BASH_REMATCH[1]} * 1024 * 1024 ))
                    THRESHOLD="${BASH_REMATCH[1]}GB"
                elif [[ "$arg" =~ ^([0-9]+)$ ]]; then
                    THRESHOLD_KB=$(( ${BASH_REMATCH[1]} * 1024 * 1024 * 1024  ))
                    THRESHOLD="${BASH_REMATCH[1]}TB"
                else
                    THRESHOLD="1T"
                    THRESHOLD_KB=$(( 1 * 1024 * 1024 * 1024 ))
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

kbytes_to_hr() {
    local size_kb=$1
    local size_hr=""

    #echo "Converting $size_kb bytes to human-readable format"
    if [ "$size_kb" -ge 1073741824 ]; then
        size_hr=$(printf "%8d TB"  $((size_kb/1073741824)))
    elif [ "$size_kb" -ge 1048576 ]; then
        size_hr=$(printf "%8d GB"  $((size_kb/1048576)))
    elif [ "$size_kb" -ge 1024 ]; then
        size_hr=$(printf "%8d MB"  $((size_kb/1024)))
    else
        size_hr=$(printf "%8d  KB" $size_kb)
    fi

    echo "$size_hr"
}

check_usage() {
    local chk_path=$1
    local subject_report="false"

    log_message "Checking storage usage in $chk_path over $THRESHOLD\n"

    while read target; do
        if [[ -z "$target" ]]; then 
            continue
        fi 

        # Get size in bytes (fast, using stat)
        size_KB=$(du -s "${chk_path}/$target"  | awk '{print $1}' 2>/dev/null || echo 0)

        # Convert bytes to human-readable format
        size_hr=$(kbytes_to_hr "$size_KB")

        log_message "$(printf "%-30s : %-8s\n" "$target" "$size_hr")"

        if [ "$size_KB" -ge "$THRESHOLD_KB" ]; then
            if [ "$subject_report" = "false" ]; then
                printf "\n%s\n" "$chk_path" >> "$RPT_FILE"
                subject_report="true"
            fi
            printf "%-30s : %-8s\n" "$target" "$size_hr" >> "$RPT_FILE"
            REPORT="1"
        fi
    done < <(find "${chk_path}" -maxdepth 1 -mindepth 1 -type d | sed "s|^${chk_path}/||" | sort -f)
}

main() {

    HOME_PATH="/volume1/homes"
    THRESHOLD="1T"
    THRESHOLD_KB=$(( 1 * 1024 * 1024 * 1024 ))
    LEVEL=1
    SUBJECT="$(hostname -s)"

    parse_args "$@"

    BASE_PATH=$(dirname $(dirname "$(readlink -f "$0")"))
    LOG_PATH=$BASE_PATH/log
    LOG_FILE="$LOG_PATH/${SUBJECT}.log"
    RPT_FILE="$LOG_PATH/${SUBJECT}.rpt"

    rm -f $RPT_FILE
    rm -f $LOG_FILE

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
        check_usage "$HOME_PATH"
    else
        while read l1; do
            check_usage "${HOME_PATH}/$l1"
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
