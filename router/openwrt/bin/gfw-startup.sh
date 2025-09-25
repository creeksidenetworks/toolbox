#!/bin/ash
# (c) 2022-2024 Creekside Networks LLC, Jackson Tong
# This script will prepare for the gfw jailbreak. Need to run one time after reboot.
# for Openwrt

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

replace_conf_entry() {
    key="$1"
    value="$2"
    conf_file="$3"

    if grep -q "^[[:space:]]*${key}[[:space:]]*=" "$conf_file"; then
        current_value=$(grep "^[[:space:]]*${key}[[:space:]]*=" "$conf_file" | awk -F'=' '{print $2}' | tr -d '[:space:]')
        if [ "$current_value" = "$value" ]; then
            return 1
        else
            sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}=${value}|" "$conf_file"
            return 0
        fi
    else
        echo "${key}=${value}" >> "$conf_file"
        return 0
    fi
}

check_and_add_entry() {
    local key="$1"
    local value="$2"
    local conf_file="$3"

    if grep -q "^[[:space:]]*${key}[[:space:]]*=" "$conf_file"; then
        # Entry exists, check if value is the same
        current_value=$(grep "^[[:space:]]*${key}[[:space:]]*=" "$conf_file" | awk -F'=' '{print $2}' | tr -d '[:space:]')
        if [ "$current_value" = "$value" ]; then
            return 1 # Entry already exists with the same value
        else
            # Update existing entry
            sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}=${value}|" "$conf_file"
            return 0
        fi
    else
        # Append if missing
        echo "${key}=${value}" >> "$conf_file"
        return 0
    fi
}

install_necessary_packages() {
        # List of packages to check and install
    PACKAGES="coreutils-base64 nano tcpdump bind-dig"

    opkg update

    for pkg in $PACKAGES; do
        if ! opkg list-installed | grep -q "$pkg"; then
            echo "$pkg is not installed. Installing..."
            opkg install "$pkg"

            if [ $? -eq 0 ]; then
                log "$pkg installed successfully."
            else
                log "Failed to install $pkg."
                # Decide if you want to exit on failure or continue
                # exit 1
            fi
        else
            echo "$pkg is already installed."
        fi
    done
}

# Log function
log() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"

    # Ensure the log file does not exceed 10000 lines
    line_count=$(wc -l < "$LOG_FILE")
    if [ "$line_count" -gt 10000 ]; then
        tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp"
        mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}

main () {
    # Get the current script's path
    ROOT_PATH="$(dirname $(dirname "$(readlink -f "$0")"))"
    sdw_backup="40.118.161.200"

    CONF_PATH="${ROOT_PATH}/conf"
    SCRIPTS_DIR="${ROOT_PATH}/bin"
    LOG_FILE="/var/log/gfw.log"
    SYSCTL_CONF="/etc/sysctl.conf"

    # Log startup
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    fi

    log "Starting gfw-startup script"

    #install_necessary_packages

    # Bring up wireguard interfaces
    for config_file in ${ROOT_PATH}/conf/wireguard/*.conf; do
        interface=$(basename "$config_file" .conf)
        # Check if the interface already exists and tear it down
        if ip link show "$interface" > /dev/null 2>&1; then
            ip link set "$interface" down
            ip link delete "$interface"
        fi

        # Read configuration from file
        address=$(grep 'Address' "$config_file" | awk '{print $3}')
        private_key=$(grep 'PrivateKey' "$config_file" | awk '{print $3}')
        public_key=$(grep 'PublicKey' "$config_file" | awk '{print $3}')
        allowed_ips=$(grep 'AllowedIPs' "$config_file" | awk '{print $3}')
        endpoint=$(grep 'Endpoint' "$config_file" | awk '{print $3}')
        persistent_keepalive=$(grep 'PersistentKeepalive' "$config_file" | awk '{print $3}')


        # Split endpoint into hostname and port
        endpoint_host=$(echo "$endpoint" | awk -F':' '{print $1}')
        endpoint_port=$(echo "$endpoint" | awk -F':' '{print $2}')

        # Resolve endpoint_host to IP if it is a FQDN
        if ! echo "$endpoint_host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            #endpoint_ip=$(nslookup "$endpoint_host" | awk '/^Address 1:/ { print $3; exit }')
            endpoint_ip=$(nslookup "$endpoint_host" | awk '/^Address(:| [0-9]+:)? / { print $2 }' | head -n 1)
            if [ -z "$endpoint_ip" ]; then
                log "Failed to resolve $endpoint_host, using backup IP $sdw_backup"
                endpoint_ip="$sdw_backup"
            fi
            endpoint="$endpoint_ip:$endpoint_port"
        fi

        # Set up WireGuard interface
        ip link add "$interface" type wireguard
        ip address add "$address" dev "$interface"
        
        temp_private_key_file=$(mktemp)
        echo "$private_key" > "$temp_private_key_file"
        wg set "$interface" private-key "$temp_private_key_file"
        rm "$temp_private_key_file"
        
        wg set "$interface" peer "$public_key" allowed-ips "$allowed_ips" endpoint "$endpoint" persistent-keepalive "$persistent_keepalive"
        ip link set "$interface" up

        # Allow traffic forwarding between br-lan/br-guest and wgx interfaces
        iptables -I FORWARD 1 -i br-lan -o "$interface" -j ACCEPT
        iptables -I FORWARD 1 -i br-guest -o "$interface" -j ACCEPT

        # Enable source NAT for traffic to wgx interfaces
        iptables -t nat -A POSTROUTING -o "$interface" -j MASQUERADE

        log "$interface configured."
    done

    #  Disable IPv6
    replace_conf_entry "net.ipv6.conf.all.disable_ipv6" 1 "$SYSCTL_CONF" 
    replace_conf_entry "net.ipv6.conf.default.disable_ipv6" 1 "$SYSCTL_CONF"

    # Enable IPv4 forwarding
    replace_conf_entry "net.ipv4.ip_forward" 1 "$SYSCTL_CONF"

    # Apply changes immediately
    /etc/init.d/sysctl restart

    # Add gooogle DNS routing and gfw routing table
    ip route add 8.8.8.8/32 dev $interface metric 100
    ip route add table 100 default dev $interface metric 100

    log "routing table configured."

    # create ip ipset LIBERTY_ADDRESS_GRP and add 8.8.8.8/8.8.4.4 to it
    if ! ipset list LIBERTY_ADDRESS_GRP > /dev/null 2>&1; then
        ipset create LIBERTY_ADDRESS_GRP hash:ip
        ipset add LIBERTY_ADDRESS_GRP 8.8.8.8
        ipset add LIBERTY_ADDRESS_GRP 8.8.4.4
        log "created ipset LIBERTY_ADDRESS_GRP."
    else
        log "ipset LIBERTY_ADDRESS_GRP already exists."
    fi

    # Add policy route for LIBERTY_ADDRESS_GRP
    ip rule add from all fwmark 1 lookup 100
    iptables -t mangle -I PREROUTING -m set --match-set LIBERTY_ADDRESS_GRP dst -j MARK --set-mark 1
    iptables -t mangle -I PREROUTING -s 192.168.9.0/24 -j MARK --set-mark 1
    log "Policy routing for LIBERTY_ADDRESS_GRP configured."


    # force global network 192.168.9.0/24 dns requst to google dns
    iptables -t nat -I PREROUTING -s 192.168.9.0/24 -p udp --dport 53 -j DNAT --to-destination 8.8.8.8:53

    log "DNAT for DNS requests configured."

   # make sure dnsmasq.conf include gfw dnsmasq conf files
    # Define the desired configuration
    TARGET_DIR="/etc/config/gfw/conf/dnsmasq.d"

    # Get the current confdir setting. The -q flag prevents errors if it doesn't exist.
    CURRENT_CONFDIR=$(uci -q get dhcp.@dnsmasq[0].confdir)

    # Check if the current confdir is already set to the target directory
    if [ "$CURRENT_CONFDIR" = "$TARGET_DIR" ]; then
        log "Configuration for confdir already exists. Skipping."
    else
        log "Adding confdir configuration..."
        # Add the new configuration
        uci set dhcp.@dnsmasq[0].confdir="$TARGET_DIR"
        uci commit dhcp
        log "Restarting dnsmasq service..."
        /etc/init.d/dnsmasq restart
    fi

 
    # check if the cron tab file is linked to /etc/crontabs/root
    if [ ! -L /etc/crontabs/root ]; then
        ln -fs ${ROOT_PATH}/conf/crontabs.root /etc/crontabs/root
        log "linked crontab file."
    else
        log "crontab file already linked."
    fi
}

main "$@"
