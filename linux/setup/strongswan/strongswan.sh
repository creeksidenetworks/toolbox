#!/bin/bash

parse_args() {
    SSH_PORT=""  # Default SSH port

    # Process command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--port)
                SSH_PORT="$2"
                shift 2
                ;;
            *@*)
                # SSH-style user@host format
                SSH_USER="${1%@*}"
                ROUTER_HOST="${1#*@}"
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [user@hostname] [hostname] [-p <port>]"
                echo "  user@hostname  SSH connection string (e.g., user@<hostname or IP>)"
                echo "  hostname       Remote router hostname or IP"
                echo "  -p, --port     SSH port (default: 22)"
                exit 0
                ;;
            *)
                # Handle standalone hostname/IP (not user@host format)
                if [[ -z "$ROUTER_HOST" ]]; then
                    ROUTER_HOST="$1"
                else
                    echo "Unknown argument: $1"
                    echo "Use -h or --help for usage information"
                    exit 1
                fi
                shift
                ;;
        esac
    done
}

main() {

    ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CA_ROOT_DIR="$ROOT_DIR/ca"

    echo ""   
    echo "Strongswan VPN configuration generation utility v1.0"
    echo "                         (c) 2025 Creekside Networks"
    echo "----------------------------------------------------"
    echo ""

    parse_args "$@"

    # Ask user for up to 2 DNS names
    while true; do
        # Check if ROUTER_HOST is not empty and is a domain name (not IPv4 address)
        if [[ -n "$ROUTER_HOST" && ! "$ROUTER_HOST" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            read -p "Enter VPN server DNS name (default: $ROUTER_HOST): " DNS1
            DNS1="${DNS1:-$ROUTER_HOST}"
        else
            read -p "Enter VPN server DNS name (required): " DNS1
        fi
        
        if [[ -z "$DNS1" ]]; then
            echo "DNS name is required. Please enter a value."
            continue
        fi
        read -p "Enter Alternative DNS (or leave blank): " DNS2
        break
    done

    # Check for existing CAs
    CA_OPTIONS=()
    CA_PATHS=()
    CA_INDEX=0

    if [[ -d "$CA_ROOT_DIR" ]]; then
        for ca_dir in "$CA_ROOT_DIR"/*/; do
            if [[ -f "$ca_dir/ca.crt" && -f "$ca_dir/ca.key" ]]; then
                CA_NAME=$(openssl x509 -noout -subject -in "$ca_dir/ca.crt"  | awk -F '=' '{print $NF}')
                CA_OPTIONS+=("$CA_NAME")
                CA_PATHS+=("$ca_dir")
                CA_INDEX=$((CA_INDEX + 1))
            fi
        done
    fi

    EXISTING_CA_NAME=""
    if [[ ${#CA_OPTIONS[@]} -gt 0 ]]; then
        echo ""
        echo "Existing Certificate Authorities found:"
        for i in "${!CA_OPTIONS[@]}"; do
            echo "  $((i+1))) ${CA_OPTIONS[$i]}"
        done
        echo "  *) Create a new self-signed CA"

        read -p ">>> Choose a CA to use [1-$((CA_INDEX + 1))]: " CHOICE

        if [[ "$CHOICE" -le "$CA_INDEX" ]]; then
            index=$((CHOICE - 1))
            SELECTED_CA_PATH="${CA_PATHS[$index]}"
            EXISTING_CA_NAME="${CA_OPTIONS[$index]}"
            CA_KEY="$SELECTED_CA_PATH"/ca.key
            CA_CERT="$SELECTED_CA_PATH"/ca.crt
        fi
    fi

    if [ -z $EXISTING_CA_NAME ]; then
        echo ""
        read -p "Enter New VPN CA name (default: $DNS1): " NEW_CA_NAME
        NEW_CA_NAME="${NEW_CA_NAME:-$DNS1}"
    fi

   
    # Display summary of user input
    echo ""
    echo "Configuration Summary:"
    echo "====================="
    printf "%-30s: %s\n" "VPN server DNS names" "$DNS1"
    [[ $DNS2 != "" ]] &&   printf "%-30s: %s\n" " " "$DNS2"

    if [ -n "$EXISTING_CA_NAME" ]; then
        printf "%-30s: %s\n" "Selected CA" "$EXISTING_CA_NAME"
    else
        printf "%-30s: %s\n" "New self-signed CA" "$NEW_CA_NAME"
    fi
    echo ""

    # Ask for confirmation
    read -p "Proceed with these settings? (y/n): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Configuration cancelled."
        exit 0
    fi

    echo ""
    # Self sign new CA 
    if [ -n "$NEW_CA_NAME" ]; then
        # conver ca name to path by replace spaces into underscore
        CA_PATH_NAME="$NEW_CA_NAME"
        SELECTED_CA_PATH="$CA_ROOT_DIR/$CA_PATH_NAME"
        mkdir -p "$SELECTED_CA_PATH"
    
        CA_KEY="$SELECTED_CA_PATH/ca.key"
        CA_CERT="$SELECTED_CA_PATH/ca.crt"
       # Generate CA key and certificate
        openssl req -new -x509 -days 7300 -nodes \
            -subj "/CN=C$NEW_CA_NAME" \
            -keyout "$CA_KEY" -out "$CA_CERT" &> /dev/null
        echo ""
        echo "New CA certificate and key were generated"
        echo "========================================="
        #openssl x509 -text < $CA_CERT    
    fi    

    # Generate VPN server certificate
    OUTPUT_DIR="$ROOT_DIR/servers/$DNS1/ipsec.d"

    mkdir -p "$OUTPUT_DIR/cacerts"
    mkdir -p "$OUTPUT_DIR/certs"
    mkdir -p "$OUTPUT_DIR/rsa-keys"

    SERVER_CERT="$OUTPUT_DIR/certs/server.cer"
    SERVER_KEY="$OUTPUT_DIR/rsa-keys/localhost.key"
    SERVER_CSR="$OUTPUT_DIR/certs/server.csr"
    SERVER_EXT="$OUTPUT_DIR/certs/server.ext"

    cp "$CA_CERT" "$OUTPUT_DIR/cacerts/"
    # Download existing keys from router if ROUTER_HOST is provided
    if [[ -n "$ROUTER_HOST" ]]; then
        echo "Downloading existing keys from router..."
        
        # Create SSH command with proper port and user
        SCP_CMD="scp"

        if [[ -n $SSH_PORT ]]; then 
            SCP_CMD="$SCP_CMD -P $SSH_PORT"
        fi

        if [[ -n "$SSH_USER" ]]; then
            SCP_HOST="${SSH_USER}@${ROUTER_HOST}"
        else
            SCP_HOST="$ROUTER_HOST"
        fi
        
        # Download the rsa-keys directory contents
        $SCP_CMD $SCP_HOST:/config/ipsec.d/rsa-keys/localhost.key "$SERVER_KEY" 2>/dev/null
        
        # Download the certs directory contents
        if [ $? -eq 0 ]; then
            echo "Successfully downloaded existing keys from router"
        else
            echo "Warning: Could not download keys from router (may not exist yet)"
        fi
    fi

    if [ -f $SERVER_KEY ]; then 
        echo "Existing VPN certificate key will be used"
        openssl req -new -nodes \
            -subj "/CN=$DNS1" \
            -key "$SERVER_KEY" \
            -out $SERVER_CSR 
    else
        # Generate server key and CSR
        echo "Generate ne VPN certificate key"
        openssl req -new -nodes \
            -subj "/CN=$DNS1" \
            -keyout "$SERVER_KEY" \
            -out "$SERVER_CSR"
    fi

    # Create extension request
    cat > $SERVER_EXT <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=$DNS1
EOF
    [[ $DNS2 != "" ]] && echo "DNS.2=$DNS2" >> $SERVER_EXT

    echo "Sign VPN certificate"
    openssl x509 -req -days 7300 -CAcreateserial \
        -in "$SERVER_CSR" \
        -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$SERVER_CERT" \
        -extfile "$SERVER_EXT" \
        -extfile $SERVER_EXT
}

main "$@"