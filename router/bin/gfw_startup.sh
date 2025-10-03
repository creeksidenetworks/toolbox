#!/bin/sh
# (c) 2022-2025 Creekside Networks LLC, Jackson Tong
# This script will prepare for the gfw jailbreak. Need to run one time after reboot.
# designed for Openwrt/EdgeOS & VyOS 1.3.4

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
LOG_FILE="/var/log/gfw.log"
GLOBAL_DNS="8.8.8.8"
LOOPBACK_IP="10.255.255.254"
GFW_ROUTING_TABLE="100"
GFW_IPSET="LIBERTY_ADDRESS_GRP"
DNSMASQ_PORT="53"

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

# clean up and exit
clean_exit() {
    exit $1
} 

# Detect OS type
detect_os_type() {
    if [ -f /etc/openwrt_release ]; then
        os="OpenWrt"
    elif grep -q "VyOS" /etc/os-release 2>/dev/null; then
        os="VyOS"
        version=$(grep VERSION_ID /etc/os-release | awk -F'"' '{print $2}')
        if [ "$version" != "1.3.4" ]; then
            echo "Error: Only VyOS 1.3.4 is supported. Detected version: $version"
            clean_exit 1
        fi
    elif grep -q "EdgeRouter" /etc/version 2>/dev/null; then
        os="EdgeOS"
    else
        echo "Error: Unsupported OS. Only VyOS 1.3.4 or EdgeOS (EdgeRouter) are supported."
        clean_exit 1
    fi
    echo "$os"
}

# Function to parse command line arguments
parse_args() {
    SMART_IF=""                   # Interfaces to listen on for DNSMASQ and Policy routing
    GLOBAL_IF=""                  # All interfaces to apply policy routing

    while getopts "s:g:" opt; do
        case "$opt" in
            s) SMART_IF="$SMART_IF $OPTARG" ;;
            g) GLOBAL_IF="$GLOBAL_IF $OPTARG" ;;
            *) log "Usage: $0 -s <smart interface1> -s <smart interface2> -g <global interface>"; clean_exit 1 ;;
        esac
    done
}

# Function to replace or add configuration entry in a config file
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

# Install necessary packages for OpenWrt
openwrt_install_necessary_packages() {
        # List of packages to check and install
    PACKAGES="coreutils-base64 nano tcpdump bind-dig bind-host"

    UPDATE_REQUIRED=0
    for pkg in $PACKAGES; do
        if ! opkg list-installed | grep -q "$pkg"; then
            UPDATE_REQUIRED=1
        fi
    done

    if [ $UPDATE_REQUIRED -eq 1 ]; then
        log "Install necessary packages."
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
            fi
        done
    else
        log "All necessary packages are already installed."
        return 0
    fi
}

# main function
main () {

    log "Starting GFW jail-break service"

    # parse arguments
    parse_args "$@"
    # Validate arguments
    if [ -z "$SMART_IF" ] && [ -z "$GLOBAL_IF" ]; then
        log "No interfaces specified. Usage:  Usage: $0 -s <smart interface1> -s <smart interface2> -g <global interface>"
        clean_exit 1
    fi
    # Trim leading space
    SMART_IF=$(echo "$SMART_IF" | sed 's/^ *//')
    GLOBAL_IF=$(echo "$GLOBAL_IF" | sed 's/^ *//')

    # Detect OS type and set default values
    os=$(detect_os_type)
    case $os in
        "OpenWrt")
            DEF_GFW_PATH="/etc/config/gfw"
            openwrt_install_necessary_packages
            ;;
        "EdgeOS")
            DEF_GFW_PATH="/config/user-data"
            ;;
        "VyOS")
            DEF_GFW_PATH="/config/user-data"
            DNSMASQ_PORT="55353"
            ;;
        *)
            log "Unsupported OS detected: $os"
            clean_exit 1
            ;;
    esac

    # update dnsmasq config file per os type
    if [ "$os" = "OpenWrt" ]; then
        # Avoid duplicate entries by using uci set (it overwrites or creates as needed)
        uci set dhcp.@dnsmasq[0].port="$DNSMASQ_PORT"
        uci set dhcp.@dnsmasq[0].confdir="$CONF_PATH"
        uci commit dhcp
    elif [ "$os" = "EdgeOS" ] || [ "$os" = "VyOS" ]; then
        # Set port option using replace_conf_entry
        replace_conf_entry "port" "$DNSMASQ_PORT" /etc/dnsmasq.conf
        replace_conf_entry "conf-dir" "$CONF_PATH" /etc/dnsmasq.conf
    fi

    /etc/init.d/dnsmasq restart
    log "Set dnsmasq port to $DNSMASQ_PORT, conf-dir to $CONF_PATH and restarted dnsmasq service."

    # make sure $DEF_GFW_PATH/conf exists and create it if missing and add a dummy dnsmasq_ipset_custom.conf file
    CONF_PATH="$DEF_GFW_PATH/conf"
    if [ ! -d "$CONF_PATH" ]; then
        mkdir -p "$CONF_PATH"
        echo "server=/google.com/$GLOBAL_DNS" >> "$CONF_PATH/dnsmasq_ipset_custom.conf"
        echo "ipset=/google.com/$GFW_IPSET" >> "$CONF_PATH/dnsmasq_ipset_custom.conf"
        log "Created directory $CONF_PATH"
    fi

    # create ip ipset LIBERTY_ADDRESS_GRP and add 8.8.8.8/8.8.4.4 to it
    if ! ipset list LIBERTY_ADDRESS_GRP > /dev/null 2>&1; then
        ipset create LIBERTY_ADDRESS_GRP hash:ip
        ipset add LIBERTY_ADDRESS_GRP 8.8.8.8
        ipset add LIBERTY_ADDRESS_GRP 8.8.4.4
        log "created ipset LIBERTY_ADDRESS_GRP."
    else
        log "ipset LIBERTY_ADDRESS_GRP already exists."
    fi 

    # add 10.255.255.254/32 to loopback interface
    if ! ip addr show dev lo | grep -q "$LOOPBACK_IP/32"; then
        ip addr add "$LOOPBACK_IP/32" dev lo
        log "Added $LOOPBACK_IP/32 to loopback interface"
    fi

    # Add policy route to forwared traffic to ipset LIBERTY_ADDRESS_GRP to gfw routing table $GFW_ROUTING_TABLE
    if ! ip rule | grep -q "from all fwmark 1 lookup $GFW_ROUTING_TABLE"; then
        ip rule add from all fwmark 1 lookup $GFW_ROUTING_TABLE
        log "Added policy route for fwmark 1 to lookup table $GFW_ROUTING_TABLE"
    fi  

    if [ -n "$GLOBAL_IF" ]; then
        # Apply DNAT rule for each global interface
        for iface in $GLOBAL_IF; do
            # DNAT to forward all DNS requests from GLOBAL_IF to GLOBAL_DNS
            if ! iptables -t nat -C PREROUTING -i "$iface" -p udp --dport 53 -j DNAT --to-destination "$GLOBAL_DNS":53 2>/dev/null; then
                iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 53 -j DNAT --to-destination "$GLOBAL_DNS":53
                log "Added DNAT rule for DNS requests on $iface to $GLOBAL_DNS"
            fi

            # mark all traffic from GLOBAL_IF to fwmark 1
            if ! iptables -t mangle -C PREROUTING -i "$iface" -j MARK --set-mark 1 2>/dev/null; then    
                iptables -t mangle -A PREROUTING -i "$iface" -j MARK --set-mark 1
                log "Marked all traffic from $iface to ipset LIBERTY_ADDRESS_GRP with fwmark 1"
            fi
        done
    fi

    if [ -n "$SMART_IF" ]; then
        # Apply DNAT rule for each smart interface
        for iface in $SMART_IF; do
            # DNAT to forward all DNS requests from SMART_IF to LOOPBACK_IP
            if ! iptables -t nat -C PREROUTING -i "$iface" -p udp --dport 53 -j DNAT --to-destination "$LOOPBACK_IP":"$DNSMASQ_PORT" 2>/dev/null; then
                iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 53 -j DNAT --to-destination "$LOOPBACK_IP":"$DNSMASQ_PORT"
                log "Added DNAT rule for DNS requests on $iface to $LOOPBACK_IP"
            fi

            # mark all traffic to ipset LIBERTY_ADDRESS_GRP from SMART_IF to fwmark 1
            if ! iptables -t mangle -C PREROUTING -i "$iface" -j MARK --set-mark 1 2>/dev/null; then
                iptables -t mangle -A PREROUTING -i "$iface" -j MARK --set-mark 1
                log "Marked all traffic from $iface to ipset LIBERTY_ADDRESS_GRP with fwmark 1"
            fi
        done
    fi  
}

main "$@"