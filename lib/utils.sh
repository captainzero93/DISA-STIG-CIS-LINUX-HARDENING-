#!/bin/bash
# Utility functions for security hardening script

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --dry-run|-d)
                DRY_RUN=true
                shift
                ;;
            --profile|-p)
                PROFILE="$2"
                shift 2
                ;;
            --config|-c)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate profile selection
    if [[ ! "$PROFILE" =~ ^(basic|intermediate|advanced)$ ]]; then
        echo "Error: Invalid profile selected"
        show_help
        exit 1
    fi
}

# Function to show help message
show_help() {
    cat << EOF
Security Hardening Script v${VERSION}
Usage: ${SCRIPT_NAME} [options]

Options:
    -v, --verbose         Enable verbose output
    -d, --dry-run        Show what would be done without making changes
    -p, --profile        Select hardening profile (basic|intermediate|advanced)
    -c, --config         Specify custom configuration file
    -h, --help           Show this help message

Example:
    ${SCRIPT_NAME} --profile advanced --verbose
EOF
}

# Function to load configuration from file
load_configuration() {
    if [ -f "$CONFIG_FILE" ]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            [[ "$key" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$key" ]] && continue
            
            # Remove quotes and spaces from value
            value=$(echo "$value" | tr -d '"' | tr -d "'")
            
            # Update configuration array
            CONFIG["$key"]="$value"
        done < "$CONFIG_FILE"
    else
        log "WARNING" "Configuration file not found, using defaults"
    fi
}

# Function to install package safely
install_package() {
    local package=$1
    log "INFO" "Installing package: $package"
    
    # Check if package is already installed
    if dpkg -l | grep -q "^ii.*$package "; then
        log "INFO" "Package $package is already installed"
        return 0
    fi
    
    # Update package cache if needed
    if [[ $(find /var/cache/apt/pkgcache.bin -mtime +1) ]]; then
        sudo apt-get update || return 1
    fi
    
    # Install package
    if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"; then
        log "ERROR" "Failed to install package: $package"
        return 1
    fi
    
    return 0
}

# Function to perform system recovery
perform_recovery() {
    log "INFO" "Attempting system recovery..."
    
    # Check if backup exists
    if [ -d "$BACKUP_DIR" ]; then
        log "INFO" "Restoring from backup: $BACKUP_DIR"
        restore_backup "$BACKUP_DIR"
    else
        log "WARNING" "No backup found, cannot perform recovery"
        return 1
    fi
    
    # Restart critical services
    local critical_services=("sshd" "auditd" "ufw" "fail2ban")
    for service in "${critical_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            sudo systemctl restart "$service" || log "WARNING" "Failed to restart $service"
        fi
    done
    
    return 0
}

# Function to generate completion report
generate_completion_report() {
    local duration=$1
    local error_count=$2
    local report_file="${BACKUP_DIR}/completion_report.txt"
    
    {
        echo "Security Hardening Completion Report"
        echo "===================================="
        echo "Date: $(date)"
        echo "Duration: $duration seconds"
        echo "Error Count: $error_count"
        echo "Profile: $PROFILE"
        echo ""
        echo "System Information:"
        echo "----------------"
        uname -a
        echo ""
        echo "Installed Packages:"
        echo "-----------------"
        dpkg -l | grep "^ii" | awk '{print $2,$3}'
        echo ""
        echo "Service Status:"
        echo "--------------"
        systemctl list-units --type=service --state=active
        echo ""
        echo "Firewall Status:"
        echo "---------------"
        sudo ufw status verbose
        echo ""
        echo "Audit Status:"
        echo "-------------"
        sudo auditctl -l
    } > "$report_file"
    
    # Send report via email if configured
    if [ -n "${CONFIG[SECURITY_EMAIL]}" ]; then
        mail -s "Security Hardening Report - $(hostname)" "${CONFIG[SECURITY_EMAIL]}" < "$report_file"
    fi
}

# Function to prompt for system restart
prompt_restart() {
    local restart_needed=false
    
    # Check if kernel parameters were modified
    if [ -f "/etc/sysctl.d/99-security.conf" ]; then
        restart_needed=true
    fi
    
    # Check if security modules were loaded
    if [ -f "/etc/modules-load.d/security.conf" ]; then
        restart_needed=true
    fi
    
    if $restart_needed; then
        echo "System restart is recommended to apply all security changes."
        read -p "Would you like to restart now? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "System will restart in 1 minute..."
            sudo shutdown -r +1
        else
            log "WARNING" "Please remember to restart the system to apply all changes"
        fi
    fi
}

# Function to validate file permissions
validate_file_permissions() {
    local file=$1
    local expected_perms=$2
    local expected_owner=$3
    
    if [ ! -f "$file" ]; then
        return 1
    fi
    
    local current_perms=$(stat -c %a "$file")
    local current_owner=$(stat -c %U "$file")
    
    if [ "$current_perms" != "$expected_perms" ] || [ "$current_owner" != "$expected_owner" ]; then
        sudo chmod "$expected_perms" "$file"
        sudo chown "$expected_owner" "$file"
    fi
}

# Function to check disk encryption status
check_disk_encryption() {
    if which cryptsetup >/dev/null; then
        if sudo cryptsetup status | grep -q "active"; then
            log "INFO" "Disk encryption is active"
            return 0
        else
            log "WARNING" "Disk encryption is not active"
            return 1
        fi
    else
        log "WARNING" "cryptsetup is not installed"
        return 1
    fi
}

# Function to validate secure boot status
check_secure_boot() {
    if [ -d "/sys/firmware/efi" ]; then
        if bootctl status | grep -q "Secure Boot: enabled"; then
            log "INFO" "Secure Boot is enabled"
            return 0
        else
            log "WARNING" "Secure Boot is not enabled"
            return 1
        fi
    else
        log "INFO" "System is not UEFI-based, Secure Boot not applicable"
        return 0
    fi
}

# Function to check system entropy
check_system_entropy() {
    local min_entropy=2000
    local current_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    
    if [ "$current_entropy" -lt "$min_entropy" ]; then
        log "WARNING" "Low system entropy: $current_entropy (minimum recommended: $min_entropy)"
        
        # Install haveged if not already installed
        if ! command -v haveged >/dev/null; then
            install_package "haveged"
            sudo systemctl enable haveged
            sudo systemctl start haveged
        fi
    fi
}

# Export functions
export -f parse_arguments
export -f show_help
export -f load_configuration
export -f install_package
export -f perform_recovery
export -f generate_completion_report
export -f prompt_restart
export -f validate_file_permissions
export -f check_disk_encryption
export -f check_secure_boot
export -f check_system_entropy