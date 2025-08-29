#!/bin/bash
# (c) 2022-2024 Creekside Networks LLC, Jackson Tong
# This script will decide the best tunnel for jailbreak based on ping result
# for EdgeOS & VyOS 1.3.x

# Routing table to update
GFW_ROUTING_TABLE="100"
# Log file path
LOG_FILE="/var/log/gfw.log"
# interface switch decision threshold
THRESHOLD="10"



# Function to parse command line arguments
parse_args() {
    PING_COUNT=60
    PING_TARGET_IP="8.8.8.8"
    GFW_ROUTING_TABLE="100"
    PRIMARY_IF="wg252"
    SECONDARY_IF="wg253"

    SUBJECT="$NAS_NAME"
    while getopts ":p:s:t:c:" opt; do
        case $opt in
            c)
                PING_COUNT="$OPTARG"
                ;;
            t)
                # Convert threshold to bytes
                PING_TARGET_IP="$OPTARG"
                ;;
            p)
                PRIMARY_IF="$OPTARG"
                ;;
            s)
                SECONDARY_IF="$OPTARG"
                ;;
            \?)
                echo "Usage: $0 [-p <primary i/f>] [-s <secondary if>] [-p <target ping test IP>] [-c <ping counts>]"
                exit 1
                ;;
        esac
    done
    shift $((OPTIND -1))
}

# Function to get the current default route interface for the specified table
get_current_route_interface() {
    sudo ip -4 -oneline route show table "$GFW_ROUTING_TABLE" | grep -o "dev.*" | awk '{print $2}'
}

# Function to ping from a specific interface
ping_from_interface() {
    local interface=$1
    local result_file=$2
    sudo ping -q -I "$interface" -c "$PING_COUNT" "$PING_TARGET_IP" > "$result_file" 2>&1
    echo $? > "${result_file}.status"
}

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

# Function to delete all routes in the specified table
delete_routes() {
    sudo ip route flush table "$GFW_ROUTING_TABLE"
    echo "Flushed all routes in table $GFW_ROUTING_TABLE"
}

clean_and_exit(){
    # Clean up temp files

    rm -rf $TMP_DIR
    [ $1 -eq 0 ] || printf 'Exit with Error code '$1'.\n'
    exit $1
}

main() {
    parse_args "$@"
    # Array to hold the result files
    result_files=()

    TMP_DIR=$(mktemp -d)
    PRIMARY_RESULT_FILE="$TMP_DIR/primary_ping_result.txt"
    SECONDARY_RESULT_FILE="$TMP_DIR/secondary_ping_result.txt"

    # Print message indicating start of pings
    echo "$(date '+%Y-%m-%d %H:%M:%S') Ping test: ${PRIMARY_IF}, ${SECONDARY_IF}."

    # Ping from each interface in the background and store the result files
    ping_from_interface "$PRIMARY_IF" "$PRIMARY_RESULT_FILE" &
    ping_from_interface "$SECONDARY_IF" "$SECONDARY_RESULT_FILE" &

    # Wait for all background jobs to complete
    wait

    # Process the results
    get_loss_rate() {
        local result_file=$1
        local loss=$(awk -F'[, ]' '/packet loss/{gsub("%","",$8); print $8}' "$result_file")
        if [ -z "$loss" ]; then
            echo "100"
        else
            echo "$loss"
        fi
    }

    PRIMARY_LOSS=$(get_loss_rate "$PRIMARY_RESULT_FILE")
    SECONDARY_LOSS=$(get_loss_rate "$SECONDARY_RESULT_FILE")

    echo "Ping results: $PRIMARY_IF: $PRIMARY_LOSS%, $SECONDARY_IF: $SECONDARY_LOSS%"

    # Get current interface
    CURRENT_IF=$(sudo ip -4 -oneline route show table "$GFW_ROUTING_TABLE" | grep -o "dev.*" | awk '{print $2}')
    DEFAULT_ROUTE=$(ip -4 -oneline route show default 0.0.0.0/0)
    DEFAULT_IF=$(echo "$DEFAULT_ROUTE" | grep -oP 'dev \K\S+')

    # Make the interface switch decision by following rules
    if [ "$PRIMARY_LOSS" -gt "$THRESHOLD" ] && [ "$SECONDARY_LOSS" -gt "$THRESHOLD" ]; then
        # If both interfaces are down, then switch to default route
        NEXT_IF="$DEFAULT_IF"
    elif [ "$PRIMARY_LOSS" -lt "$THRESHOLD" ] && [ "$SECONDARY_LOSS" -gt "$THRESHOLD" ]; then
        NEXT_IF=$PRIMARY_IF
    elif [ "$PRIMARY_LOSS" -gt "$THRESHOLD" ] && [ "$SECONDARY_LOSS" -lt "$THRESHOLD" ]; then
        NEXT_IF=$SECONDARY_IF
    elif [ "$CURRENT_IF" = "$DEFAULT_IF" ]; then
        NEXT_IF=$PRIMARY_IF
    else
        NEXT_IF=$CURRENT_IF
    fi

    if [ "$NEXT_IF" = "$CURRENT_IF" ]; then
        echo "Stay with $CURRENT_IF"
        clean_and_exit 0
    elif [ "$NEXT_IF" = "$PRIMARY_IF" ]; then
        log_message "Switching to $PRIMARY_IF ($PRIMARY_LOSS%)."
        delete_routes
        sudo ip route replace default dev "$PRIMARY_IF" table "$GFW_ROUTING_TABLE"
        sudo ip route replace "$PING_TARGET_IP" dev "$PRIMARY_IF"
        clean_and_exit 0
    elif [ "$NEXT_IF" = "$SECONDARY_IF" ]; then
        log_message "Switching to $SECONDARY_IF ($SECONDARY_LOSS%)."
        delete_routes
        sudo ip route replace default dev "$SECONDARY_IF" table "$GFW_ROUTING_TABLE"
        sudo ip route replace "$PING_TARGET_IP" dev "$SECONDARY_IF"
        clean_and_exit 0
    else
        log_message "Both interfaces loss > $THRESHOLD%. Switching to main routing table."
        delete_routes
        default_route=$(ip -4 -oneline route show default 0.0.0.0/0)
        default_route_interface=$(echo "$default_route" | grep -oP 'dev \K\S+')
        new_route=$(echo "$default_route" | grep -o "via.*" | awk '{print $1 " " $2}')
        new_route="$new_route $(echo "$default_route" | grep -o "dev.*" | awk '{print $1 " " $2}')"
        sudo ip route replace default $new_route table "$GFW_ROUTING_TABLE"
        sudo ip route replace "$PING_TARGET_IP" $new_route
        clean_and_exit 0
    fi
}

main "$@"