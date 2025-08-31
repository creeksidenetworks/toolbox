#!/bin/bash

# A script to update Rocky Linux repository mirrors.
# This version defines mirror regions as an array for easier management and extension.

# --- Prefined Mirror Regions ---
# Format: "Name|Rocky_Base_URL|EPEL_Base_URL"
# Use \$releasever and \$basearch as variables for DNF.
declare -a mirrors=(
    "Global|https://dl.rockylinux.org/pub/rocky|http://dl.fedoraproject.org/pub/epel"
    "China (USTC)|https://mirrors.ustc.edu.cn/rocky|https://mirrors.ustc.edu.cn/epel"
    # To add more regions, simply add a new line in the same format.
    # Example: "Another_Region|...|..."
)

# --- Functions ---

function show_menu() {
    clear
    echo "=========================================="
    echo "  Rocky Linux Mirror Configuration"
    echo "=========================================="
    echo "Choose a mirror region for your repositories:"
    
    # Dynamically generate the menu from the mirrors array
    for i in "${!mirrors[@]}"; do
        local mirror_name=$(echo "${mirrors[$i]}" | cut -d'|' -f1)
        echo "  $((i+1))) $mirror_name"
    done
    
    echo "=========================================="
}

function get_choice() {
    local choice
    while true; do
        read -p "Enter your choice (1 to $((${#mirrors[@]}))): " choice
        # Validate the choice against the number of available mirrors
        if [[ $choice =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#mirrors[@]} )); then
            local selected_mirror="${mirrors[choice-1]}"
            MIRROR_NAME=$(echo "$selected_mirror" | cut -d'|' -f1)
            MIRROR_BASE=$(echo "$selected_mirror" | cut -d'|' -f2)
            MIRROR_EPEL_BASE=$(echo "$selected_mirror" | cut -d'|' -f3)
            break
        else
            echo "Invalid choice. Please enter a number between 1 and $((${#mirrors[@]}))."
        fi
    done
}

function main() {
    local REPO_DIR="/etc/yum.repos.d"
    local BACKUP_DIR="${REPO_DIR}/backup_$(date +%Y-%m-%d_%H%M%S)"
    local REPO_FILE
    local base_name
    
    # Check for root privileges
    if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root or with sudo."
       exit 1
    fi
    
    show_menu
    get_choice
    
    echo ""
    echo "Selected mirror: $MIRROR_NAME"
    echo "Starting repository update process..."
    echo ""
    
    # Create a timestamped backup directory
    echo "Backing up existing repository files to $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    cp -v "$REPO_DIR"/*.repo "$BACKUP_DIR/"
    echo "Backup complete."
    echo ""
    
    # Loop through all .repo files and update them
    echo "Modifying repository configuration files..."
    for REPO_FILE in "$REPO_DIR"/*.repo; do
        base_name=$(basename "$REPO_FILE")
    
        # Check if the file is a Rocky or EPEL repository (case-insensitive for 'rocky')
        if [[ "$base_name" =~ ^([Rr]ocky|epel|epel-next|epel-testing) ]]; then
            echo "  - Processing $base_name"
    
            # Check if the file is an EPEL repository
            if [[ "$base_name" =~ ^(epel|epel-next|epel-testing)\.repo$ ]]; then
                echo "    - Detected EPEL repository. Using EPEL-specific mirrors. "
                # Disable original mirrorlist/baseurl/metalink and enable our new baseurl
                sed -i '/^metalink=/s/^/#/' "$REPO_FILE"
                sed -i 's|^#baseurl=https\?://.*epel|baseurl='"$MIRROR_EPEL_BASE"'|' "$REPO_FILE"
            else
                echo "    - Detected Rocky Linux repository."
                # Use sed to replace the mirrorlist line with the chosen baseurl
                sed -i 's|^mirrorlist=|#mirrorlist=|' "$REPO_FILE"
                #sed -i -E "s%^([[:space:]]*)#?([[:space:]]*)baseurl=http.*contentdir%baseurl=${baseos_url}%" "$repo"
                sed -i 's|^#baseurl=https\?://.*contentdir|baseurl='"$MIRROR_BASE"'|' "$REPO_FILE"
            fi
        else
            echo "  - Skipping $base_name (not a Rocky or EPEL repository)."
        fi
        
    done
    
    echo ""
    echo "Repository files updated successfully!"
    echo "Please run 'sudo dnf makecache' to refresh your package cache."
}

# Execute the main function, passing all arguments
main "$@"
