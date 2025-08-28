
#!/bin/bash

# Configuration file path
CONFIG_FILE="/config/config.boot"

# Function to check if a string is a valid FQDN
is_fqdn() {
    local fqdn="$1"
    if [[ "$fqdn" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to update the WireGuard peer endpoint
update_peer_endpoint() {
    local interface="$1"
    local peer_pubkey="$2"
    local new_ip="$3"
    local listen_port="$4"

    echo "Updating peer with public key $peer_pubkey endpoint to $new_ip on port $listen_port for interface $interface"

    # Update the WireGuard peer endpoint
    sudo wg set "$interface" peer "$peer_pubkey" endpoint "$new_ip:$listen_port"
}

# Check if the file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

# Use awk to parse the file and extract the required information
peers=$(awk '
    # These variables will track our position in the file
    BEGIN {
        in_wireguard_block = 0;
        current_interface = "";
        in_peer_block = 0;
        first_peer_in_interface = 1;
    }

    # This block starts when a line begins with "wireguard"
    /^ *wireguard/ {
        # A new wireguard block is starting, store the interface name
        current_interface = $2;
        in_wireguard_block = 1;
        first_peer_in_interface = 1;
    }

    # This block starts when a line begins with "peer"
    # and we are inside a wireguard block.
    in_wireguard_block && /^ *peer/ {
        # If this is the first peer for this interface, print the header
        if (first_peer_in_interface) {
            #print "Interface: " current_interface;
            first_peer_in_interface = 0; # Set the flag so it only prints once
        }

        # Reset variables for the new peer
        peer_key = $2;
        in_peer_block = 1;
        description = "";
        endpoint = "";
    }

    # This block looks for "description" within a peer block
    in_peer_block && /^ *description/ {
        description = substr($0, index($0, "description ") + length("description "));
        gsub(/^ *| *$/, "", description);
        gsub(/^"|"$/, "", description);
    }

    # This block looks for "endpoint" within a peer block
    in_peer_block && /^ *endpoint/ {
        endpoint = $2;
        gsub(/^ *| *$/, "", endpoint);
        gsub(/^"|"$/, "", endpoint);
    }

    # This block is for the closing brace of a peer block
    in_peer_block && /^ *}/ {
        if (description != "" && endpoint != "") {
            # Print the collected information
            # Split endpoint into host/IP and port
            split(endpoint, parts, ":");
            print current_interface, peer_key, "\"" description "\"", parts[2]
        }
        # Reset the flag to signal the end of this peer block
        in_peer_block = 0;
    }
' "$CONFIG_FILE")

if [[ ! -z "$peers" ]]; then
    while IFS= read -r line; do
        interface=$(echo "$line" | awk '{print $1}')
        pubkey=$(echo "$line" | awk '{print $2}')
        description=$(echo "$line" | awk -F'"' '{print $2}')
        port=$(echo "$line" | awk '{print $NF}')

        # Check if description is a valid FQDN
        if is_fqdn "$description"; then
            # Perform DNS lookup for FQDN
            new_ip=$(host "$description" | grep 'has IPv4 address' | awk '{print $5}' )

            # get currnet IP
            current_ip=$(sudo wg show "$interface" endpoints | grep "$pubkey" | awk '{print $2}' | awk -F':' '{print $1}')

            # Update if the new IP differs from the current one
            if [[ -n $new_ip && $new_ip != $current_ip ]]; then
                update_peer_endpoint "$interface" "$pubkey" "$new_ip" "$port"
            else 
                echo "$interface" "-" "$pubkey" "$description:$port" "is currrent"
            fi
        fi
    done <<< "$peers"
fi

