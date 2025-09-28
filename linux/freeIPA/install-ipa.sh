#!/bin/bash

# ==============================================================================
# FreeIPA Server and FreeRADIUS Installation Script
# ==============================================================================
# This script automates the installation of a FreeIPA server on Rocky Linux.
# It can install either a primary FreeIPA server or a replica server.
#
# For the primary server, it also installs and configures FreeRADIUS to use
# ipaNTHash for MS-CHAPv2 authentication.
#
# IMPORTANT: This script MUST be run with root privileges (e.g., `sudo`).
#
# Usage:
#   1. Make the script executable: chmod +x install_freeipa.sh
#   2. Run the script: sudo ./install_freeipa.sh
# ==============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Prequalification Checks ---
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# --- Helper Functions ---

# Function to read a value.
PROMPT_LENGTH=52
format_prompt() {
    local title=$1
    local default_value=$2
    
    if [[ -n "$default_value" ]]; then
        l2=${#default_value}
        l1=$((PROMPT_LENGTH-3-l2))
        printf "%-${l1}s [%${l2}s]" "$title" "$default_value"
    else
        printf "%-${PROMPT_LENGTH}s" "$title"
    fi
}

read_value() {
    local title=$1
    local default_value=$2
    local return_var=$3
    unset "$return_var"
    
    # get formated prompt text
    local prompt_text

    prompt_text=$(format_prompt "$title" "$default_value")

    while read -p "${prompt_text}: " value; do
        if [[ -z "$value" ]]; then
            if [[ -n "$default_value" ]]; then
                eval "$return_var=\"\$default_value\""
                break
            else
                echo "Error: This value cannot be empty." >&2
                continue
            fi
        else
            eval "$return_var=\"\$value\""
            break
        fi
    done
}

# Function to check and install necessary packages.
check_and_install_packages() {
    local packages=("$@")
    echo "Checking for necessary packages: ${packages[*]}"
    local packages_to_install=()

    for pkg in "${packages[@]}"; do
        if ! rpm -q "$pkg" &> /dev/null; then
            echo "Package '$pkg' is not installed."
            packages_to_install+=("$pkg")
        fi
    done

    if [[ ${#packages_to_install[@]} -ne 0 ]]; then
        echo "Installing missing packages: ${packages_to_install[*]}..."
        dnf install -y "${packages_to_install[@]}"
        echo "Package installation complete."
    else
        echo "All necessary packages are already installed."
    fi
}

# Function to check for a static IPv4 address on the primary network interface.
check_static_ip() {
    echo "Checking network interface configuration..."
    # Find the primary network interface.
    PRIMARY_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
    
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        echo "Error: Could not determine the primary network interface." >&2
        exit 1
    fi

    # Check for the existence of a configured IPv4 address and if it is dynamic.
    if ip addr show "$PRIMARY_INTERFACE" | grep -q "inet .*dynamic"; then
        echo "Warning: A dynamic IPv4 address was detected on the primary network interface ($PRIMARY_INTERFACE)." >&2
        echo "A static IP is required for a stable FreeIPA installation." >&2
        echo "Please reconfigure your network interface and re-run this script." >&2
        exit 1
    fi

    echo "Static IPv4 address detected on $PRIMARY_INTERFACE. Proceeding with installation."
    echo ""
}

# Function to install the FreeIPA primary server.
install_primary_server() {

    printf "\n-------- Primary Server Installation ---------\n"

    # 1. Prompt for user inputs
    read_value  "Enter the FreeIPA domain name (e.g., example.com)" "" DOMAIN
    
    # Automatically suggest realm from the domain.
    DEFAULT_REALM=$(echo "${DOMAIN}" | tr '[:lower:]' '[:upper:]')
    read_value "Enter the FreeIPA realm name" "$DEFAULT_REALM" REALM
    read_value "Enter the hostname for this server" "ipa01" HOSTNAME
    read_value "Enter the Directory Manager password: " "" DIRSRV_PASSWORD
    read_value "Enter the IPA 'admin' user password: " "" ADMIN_PASSWORD
    read_value "Enter the Freeradius client secret" "secret123" RADIUS_SECRET

    # remove domain part if provided in hostname
    HOSTNAME=${HOSTNAME%%.*}

    # 2. Confirmation step before proceeding
    echo ""
    echo "------------ Installation Summary ------------"
    printf "%-40s: %s\n" "Domain" "${DOMAIN}"
    printf "%-40s: %s\n" "Realm" "${REALM}"
    printf "%-40s: %s\n" "Hostname" "${HOSTNAME}.${DOMAIN}"
    printf "%-40s: %s\n" "Directory Manager Password" "${DIRSRV_PASSWORD}"
    printf "%-40s: %s\n" "IPA 'admin' Password" "${ADMIN_PASSWORD}"
    printf "%-40s: %s\n" "Freeradius client secret" "${RADIUS_SECRET}"
    echo "----------------------------------------------"
    read -p "Do you want to proceed with the installation? (y/n): " PROCEED
    if [[ ! "$PROCEED" =~ ^[Yy]$ ]]; then
        echo "Installation aborted by user."
        exit 1
    fi
    echo ""

    # 3. Check and install necessary packages for the primary server.
    echo "Checking and installing packages for FreeIPA primary server..."
    check_and_install_packages "bind" "bind-dyndb-ldap" "ipa-server" "ipa-server-dns" "freeipa-server-trust-ad" "freeradius" "freeradius-ldap" "freeradius-krb5" "freeradius-utils"

    # 4. Perform a pre-installation check
	echo "\n o Update local host names ${HOSTNAME}"
    sudo  hostnamectl set-hostname $HOSTNAME.$DOMAIN
 
    # Extract the primary network interface's IP address
    PRIMARY_IP=$(ip -4 addr show "$PRIMARY_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    if [[ -z "$PRIMARY_IP" ]]; then
        echo "Error: Could not determine the IP address for $PRIMARY_INTERFACE." >&2
        exit 1
    fi

    # Update /etc/hosts with the new hostname and IP
    echo "Updating /etc/hosts with $PRIMARY_IP $HOSTNAME.$DOMAIN..."
    sed -i "/[[:space:]]$HOSTNAME\.$DOMAIN/d" /etc/hosts
    echo "$PRIMARY_IP    $HOSTNAME.$DOMAIN $HOSTNAME" >> /etc/hosts
    hostnamectl set-hostname "$HOSTNAME.$DOMAIN"

    # Ensure the firewall is running and configure it.
    echo "Configuring the firewall..."
    systemctl enable --now firewalld
    firewall-cmd -q --permanent --add-service={ntp,dns,freeipa-ldap,freeipa-ldaps,freeipa-replication,freeipa-trust,radius}
    firewall-cmd -q --reload

    # 5. Run the FreeIPA server installation in unattended mode.
    echo "Starting FreeIPA server installation. This may take a while..."
    ipa-server-install\
            --ds-password=$DIRSRV_PASSWORD \
            --admin-password=$ADMIN_PASSWORD \
            --ip-address=$PRIMARY_IP \
            --domain=$PRIMARY_IP\
            --setup-adtrust\
            --realm=${REALM^^}\
            --hostname="$HOSTNAME.$DOMAIN" \
            --setup-dns \
            --mkhomedir \
            --allow-zone-overlap  \
            --auto-reverse \
            --auto-forwarders \
            --unattended
    
    echo "FreeIPA server installation complete."
}

# Function to configure FreeRADIUS for use with ipaNTHash.
configure_radius_for_nt_hash() {
    echo "--- FreeRADIUS Configuration ---"

    # 1. Configure the LDAP module
    echo "Configuring FreeRADIUS LDAP module..."
    LDAP_CONFIG_FILE="/etc/raddb/mods-available/ldap"

    # Use sed to modify the LDAP configuration file to point to IPA
    sed -i "s/^server =.*/server = \"${HOSTNAME}\"/g" "$LDAP_CONFIG_FILE"
    sed -i "s/^base_dn =.*/base_dn = \"cn=accounts,dc=${DOMAIN//./,dc=}\"/g" "$LDAP_CONFIG_FILE"
    sed -i "s/^password_attribute = userPassword/password_attribute = ipaNTHash/g" "$LDAP_CONFIG_FILE"
    sed -i "s/^identity =.*/identity = \"cn=host\/$(hostname -f),cn=services,cn=accounts,dc=${DOMAIN//./,dc=}\"/g" "$LDAP_CONFIG_FILE"
    sed -i "/^# start_tls = no/a \ \ start_tls = yes" "$LDAP_CONFIG_FILE"

    # 2. Enable the LDAP module in the default site
    echo "Enabling LDAP authentication in the default FreeRADIUS site..."
    SITES_CONFIG_FILE="/etc/raddb/sites-enabled/default"

    # Add the LDAP module to the authentication section
    sed -i "/# Auth-Type LDAP {/a \ \ \ \ \ \ \ \ ldap" "$SITES_CONFIG_FILE"
    
    # 3. Restart the FreeRADIUS service
    echo "Restarting the FreeRADIUS service..."
    systemctl enable --now radiusd
    echo "FreeRADIUS is now configured."
}

# Function to install an IPA replica server.
install_replica_server() {
    echo "--- Replica Server Installation ---"

    # Check if a replica file is provided for a traditional install.
    read -p "Do you have a replica installation file (.tar.gz)? (y/n): " HAS_REPLICA_FILE
    
    if [[ "$HAS_REPLICA_FILE" =~ ^[Yy]$ ]]; then
        read -p "Enter the full path to the replica install file (.tar.gz): " REPLICA_FILE
        
        if [[ ! -f "$REPLICA_FILE" ]]; then
            echo "Error: Replica file not found at $REPLICA_FILE." >&2
            exit 1
        fi
        
        # Check and install necessary packages for the replica.
        echo "Checking and installing packages for FreeIPA replica server..."
        check_and_install_packages "ipa-server" "freeipa-server-trust-ad" "freeradius" "freeradius-ldap" "freeradius-krb5" "freeradius-utils"
        
        echo "Starting replica installation from file. This may take a while..."
        ipa-replica-install "$REPLICA_FILE"
    else
        echo "Performing Kerberos-based replica installation."
        read -p "Enter the FQDN of the existing FreeIPA primary server: " PRIMARY_SERVER
        read -p "Enter the primary IPA server's admin username: " ADMIN_USER
        read_password "Enter the primary IPA server's admin password: " ADMIN_PASSWORD
        
        # Get a Kerberos ticket for the admin user.
        echo "Obtaining Kerberos ticket for the IPA administrator..."
        echo "$ADMIN_PASSWORD" | kinit "$ADMIN_USER"

        # Check and install necessary packages for the replica.
        echo "Checking and installing packages for FreeIPA replica server..."
        check_and_install_packages "ipa-server" "freeipa-server-trust-ad" "freeradius" "freeradius-ldap" "freeradius-krb5" "freeradius-utils"

        # Generate an unattended answer file for a clean install.
        echo "Creating unattended answer file for FreeIPA replica installation..."
        cat > /tmp/ipa-replica-answers.txt <<EOF
[global]
server=${PRIMARY_SERVER}
admin_password=${ADMIN_PASSWORD}
EOF

        # Run the FreeIPA replica installation with specified flags.
        echo "Starting FreeIPA replica installation. This may take a while..."
        ipa-replica-install --setup-adtrust --setup-ca --setup-dns --mkhomedir --allow-zone-overlap --auto-reverse --auto-forwarders --unattended --unattended-file=/tmp/ipa-replica-answers.txt
        rm /tmp/ipa-replica-answers.txt
    fi
    
    echo "Replica installation complete. You can now access the IPA domain."
    echo "Restarting the FreeRADIUS service to complete the configuration."
    systemctl enable --now radiusd
}

# --- Main Script Logic ---
echo "Welcome to the FreeIPA and FreeRADIUS setup script."
echo "----------------------------------------------------"

# Pre-installation check for static IP.
check_static_ip

# Check if the server is already enrolled in an IPA domain.
if [[ -f "/etc/ipa/default.conf" ]]; then
    echo "Warning: This server appears to be already enrolled in a FreeIPA domain."
    echo "Primary server installation is not possible. Proceeding with replica installation."
    read -p "Do you want to proceed with the installation? (y/n): " PROCEED
    if [[ ! "$PROCEED" =~ ^[Yy]$ ]]; then
        echo "Installation aborted by user."
        exit 1
    fi
    install_replica_server
else
    echo "What do you want to install?"
    echo "  1) A new FreeIPA primary server (with FreeRADIUS)"
    echo "  2) A FreeIPA replica server"

    read -p "Enter your choice (1 or 2): " CHOICE

    case "$CHOICE" in
        1)
            install_primary_server
            ;;
        2)
            install_replica_server
            ;;
        *)
            echo "Invalid choice. Please run the script again and choose 1 or 2."
            exit 1
            ;;
    esac
fi

echo "----------------------------------------------------"
echo "Installation process finished successfully."
echo "Access the FreeIPA web UI at https://$(hostname -f)"
echo "FreeRADIUS is configured for MS-CHAPv2."
echo "----------------------------------------------------"
