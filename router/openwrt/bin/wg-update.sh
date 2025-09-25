#!/bin/ash
# (c) 2022-2024 Creekside Networks LLC, Jackson Tong
# This script will update the sdw peer's ip 
# Please setup a cron job to run it every 2-3 minutes
# for Openwrt

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# Log function
log() {
    local log_file="/var/log/gfw.log"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$log_file"

    # Ensure the log file does not exceed 1000 lines
    line_count=$(sudo wc -l < "$log_file")
    if [ "$line_count" -gt 1000 ]; then
        sudo tail -n 500 "$log_file" | sudo tee "$log_file.tmp" > /dev/null
        sudo mv "$log_file.tmp" "$log_file"
    fi
}


# Get the current script's path
ROOT_PATH="$(dirname $(dirname "$(readlink -f "$0")"))"

# Bring up wireguard interfaces
for config_file in ${ROOT_PATH}/conf/wireguard/*.conf; do
    interface=$(basename "$config_file" .conf)

    # Read configuration from file
    endpoint=$(grep 'Endpoint' "$config_file" | awk '{print $3}')
    public_key=$(grep 'PublicKey' "$config_file" | awk '{print $3}')
    endpoint=$(grep 'Endpoint' "$config_file" | awk '{print $3}')
    port=$(echo "$endpoint" | awk -F: '{print $2}')

    # Extract hostname from endpoint
    hostname=$(echo "$endpoint" | awk -F: '{print $1}')

    #echo $hostname

    # Check if hostname is a valid FQDN
    if echo "$hostname" | grep -Eq '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'; then
        # Lookup IPv4 address using host command
        # Get all IPv4 addresses from nslookup, pick the first one
        ipv4=$(nslookup "$hostname" | awk '/^Address(:| [0-9]+:)? / { print $2 }' | head -n 1)
        #echo $ipv4:$port
        if [ -z "$ipv4" ]; then
            log "Failed to resolve hostname: $hostname"
            continue
        fi
    else
        echo "Invalid hostname: $hostname"
        continue
    fi

    # Get current endpoint IP from WireGuard interface
    current_ip=$(wg show "$interface" endpoints | awk '{print $2}' | awk -F: '{print $1}')
    #cho $current_ip:$port

    # Compare current IP with resolved IP
    if [ "$current_ip" != "$ipv4" ]; then
        # Update WireGuard peer endpoint
        wg set "$interface" peer "$public_key" endpoint "$ipv4:$port"
        log "Updated $interface endpoint from $current_ip to $ipv4."
    fi

done