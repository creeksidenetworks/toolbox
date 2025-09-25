#!/bin/ash

#!/bin/sh

# === Configuration Variables ===
ROUTER_ID=150
PRIVATE_KEY='MLTTqCad/qIFUEQ+onEIMcwEn4MDc6rtmPcUIZnmgFY='

echo "Starting WireGuard interface configuration..."

# Create a WireGuard zone with masquerading 
uci add firewall zone
uci set firewall.@zone[-1].name='wireguard'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci set firewall.@zone[-1].masq='1'

# And allow forwarding from LAN to WireGuard zone
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='lan'
uci set firewall.@forwarding[-1].dest='wireguard'

# Allow forwarding from guest to WireGuard zone
uci add firewall forwarding
uci set firewall.@forwarding[-1].src='guest'
uci set firewall.@forwarding[-1].dest='wireguard'

# Loop through each SD-WAN ID
for SDWAN_ID in 251 252 253; do
  
    # Set peer-specific variables based on SDWAN_ID
    case $SDWAN_ID in
        251)
        PUBLIC_KEY='zu9+zqHtZvuIZ+VE5DxqWgdiJxiDL8gTzmaYZ4O9sno='
        ENDPOINT_HOST='sdw1.creekside.network'
        ENDPOINT_PORT='52800'
        ;;
        252)
        PUBLIC_KEY='ypX70YJDR45YZhUdCdAem3uo5SAf5U4/rkFGVMZBzz8='
        ENDPOINT_HOST='sdw2.creekside.network'
        ENDPOINT_PORT='500'
        ;;
        253)
        PUBLIC_KEY='uLuDu5RyGyi3/Uxpd69RaNCGtP5Z80e2mMAxIgs/w3w='
        ENDPOINT_HOST='sdw3.creekside.network'
        ENDPOINT_PORT='52800'
        ;;
    esac

    echo "Configuring network interface wg${SDWAN_ID}..."

    # --- Configure Network Interface ---
    uci set network.wg${SDWAN_ID}='interface'
    uci set network.wg${SDWAN_ID}.proto='wireguard'
    uci set network.wg${SDWAN_ID}.private_key="${PRIVATE_KEY}"
    uci add_list network.wg${SDWAN_ID}.addresses="10.${SDWAN_ID}.255.${ROUTER_ID}/24"
    
    # --- Configure Network Peer ---
    uci add network "wireguard_wg${SDWAN_ID}"
    uci set network.@wireguard_wg${SDWAN_ID}[-1].public_key="${PUBLIC_KEY}"
    uci set network.@wireguard_wg${SDWAN_ID}[-1].allowed_ips='0.0.0.0/0'
    uci set network.@wireguard_wg${SDWAN_ID}[-1].endpoint_host="${ENDPOINT_HOST}"
    uci set network.@wireguard_wg${SDWAN_ID}[-1].endpoint_port="${ENDPOINT_PORT}"
    uci set network.@wireguard_wg${SDWAN_ID}[-1].persistent_keepalive='25'


    # --- Add interface to the existing LAN zone ---
    echo "Adding wg${SDWAN_ID} to the wireguard firewall zone..."
    uci add_list firewall.@zone[-1].network="wg${SDWAN_ID}"

done

echo "Done! All WireGuard interfaces have been configured and added to the LAN zone."

# Create ipset named LIBERTY_ADDRESS_GRP
# Create ipset LIBERTY_ADDRESS_GRP
uci add firewall ipset
uci set firewall.@ipset[-1].name='LIBERTY_ADDRESS_GRP'
uci set firewall.@ipset[-1].match='dest_ip'
uci set firewall.@ipset[-1].enabled='1'

# Policy routing: traffic from LAN zone to LIBERTY_ADDRESS_GRP uses table 100
uci add firewall rule
uci set firewall.@rule[-1].name='LAN-to-LIBERTY-PolicyRoute'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].ipset='LIBERTY_ADDRESS_GRP'
uci set firewall.@rule[-1].dest='*'
uci set firewall.@rule[-1].proto='all'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].set_mark='100'
uci set firewall.@rule[-1].target='MARK'

# Policy routing: all traffic from guest zone uses table 100
uci add firewall rule
uci set firewall.@rule[-1].name='Guest-PolicyRoute'
uci set firewall.@rule[-1].src='guest'
uci set firewall.@rule[-1].proto='all'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].set_mark='100'
uci set firewall.@rule[-1].target='MARK'

# Add policy routing configuration for table 100
uci add network rule
uci set network.@rule[-1].mark='100'
uci set network.@rule[-1].lookup='100'
uci set network.@rule[-1].priority='1000'

echo "Committing changes and reloading services..."

# Commit all changes
uci commit network
uci commit firewall

# Reload services to apply the new configuration
/etc/init.d/network reload
/etc/init.d/firewall restart

# disable ipv6
uci set network.globals.ula_prefix="disabled"
uci commit network
/etc/init.d/network restart

# Define the desired configuration
TARGET_DIR="/etc/config/gfw/conf/dnsmasq.d"

# Get the current confdir setting. The -q flag prevents errors if it doesn't exist.
CURRENT_CONFDIR=$(uci -q get dhcp.@dnsmasq[0].confdir)

# Check if the current confdir is already set to the target directory
if [ "$CURRENT_CONFDIR" = "$TARGET_DIR" ]; then
    echo "Configuration for confdir already exists. Skipping."
else
    echo "Adding confdir configuration..."
    # Add the new configuration
    uci set dhcp.@dnsmasq[0].confdir="$TARGET_DIR"
    uci commit dhcp
    echo "Restarting dnsmasq service..."
    /etc/init.d/dnsmasq restart
fi


# update Wifi

# Change all wireless interfaces to 20Mhz channel wide
uci set wireless.radio0.htmode='HT20'
uci set wireless.radio1.htmode='HT20'
uci set wireless.@wifi-device[0].disabled=0
uci set wireless.@wifi-device[1].disabled=1

# Smart WiFi 
uci set wireless.@wifi-iface[0].disabled=0

uci set wireless.@wifi-iface[0].ssid="TONGMOBILE"
uci set wireless.@wifi-iface[0].encryption="psk2"
uci set wireless.@wifi-iface[0].key="Good2Great"
uci set wireless.@wifi-iface[0].disabled=0

# Global WiFi 
uci set wireless.@wifi-iface[3].disabled=1

uci set wireless.@wifi-iface[2].ssid="TONGUSA"
uci set wireless.@wifi-iface[2].encryption="psk2"
uci set wireless.@wifi-iface[2].key="Good2Great"
uci set wireless.@wifi-iface[2].disabled=0

# Disable 2.4G radio
uci set wireless.radio1.disabled='1'

# Enable the guest interface
uci set network.guest.disabled='0'

# Commit the changes
uci commit wireless

# Reload the Wi-Fi settings
wifi reload

# Enable guest network
uci set network.guest.disabled='0'
uci commit network

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-Ping-wan'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='icmp'
uci set firewall.@rule[-1].icmp_type='echo-request'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH-wan'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].target='ACCEPT'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-HTTPS-wan'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='443'
uci set firewall.@rule[-1].family='ipv4'
uci set firewall.@rule[-1].target='ACCEPT'

uci commit firewall 
/etc/init.d/firewall restart





