#!/bin/bash
# Enhanced Utility functions for security hardening script v3.2
# Provides common functions and helpers for the main hardening script

# Global variables for utils
UTILS_VERSION="3.2"

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
            --email|-e)
                CONFIG[SECURITY_EMAIL]="$2"
                shift 2
                ;;
            --backup-dir|-b)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --skip-backup)
                CONFIG[BACKUP_ENABLED]="false"
                shift
                ;;
            --skip-firewall)
                CONFIG[FIREWALL_ENABLED]="false"
                shift
                ;;
            --skip-audit)
                CONFIG[AUDIT_ENABLED]="false"
                shift
                ;;
            --enable-ipv6)
                CONFIG[IPV6_ENABLED]="true"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version)
                echo "Security Hardening Script v${VERSION}"
                echo "Utils Library v${UTILS_VERSION}"
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
        echo "Error: Invalid profile selected: $PROFILE"
        echo "Valid profiles are: basic, intermediate, advanced"
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
    -v, --verbose           Enable verbose output
    -d, --dry-run          Show what would be done without making changes
    -p, --profile PROFILE  Select hardening profile (basic|intermediate|advanced)
    -c, --config FILE      Specify custom configuration file
    -e, --email EMAIL      Set security email for reports
    -b, --backup-dir DIR   Specify backup directory location
    --skip-backup          Skip backup creation
    --skip-firewall        Skip firewall configuration
    --skip-audit           Skip audit configuration
    --enable-ipv6          Enable IPv6 support
    --version              Show version information
    -h, --help             Show this help message

Profiles:
    basic        - Essential security hardening
    intermediate - Standard security hardening with monitoring
    advanced     - Complete security hardening with all features

Example:
    ${SCRIPT_NAME} --profile advanced --verbose --email admin@example.com
    
Configuration File Format:
    # Comments start with #
    KEY=value
    FIREWALL_ENABLED=true
    SELINUX_ENABLED=false
    
For more information, visit: https://github.com/yourgithub/security-hardening

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
            
            # Clean the key and value
            key=$(echo "$key" | xargs)
            value=$(echo "$value" | xargs)
            
            # Remove quotes from value
            value=$(echo "$value" | tr -d '"' | tr -d "'")
            
            # Update configuration array
            CONFIG["$key"]="$value"
            
            log "DEBUG" "Loaded config: $key=$value"
        done < "$CONFIG_FILE"
        
        log "INFO" "Configuration loaded successfully"
    else
        log "WARNING" "Configuration file not found: $CONFIG_FILE, using defaults"
    fi
    
    # Apply profile-specific defaults
    apply_profile_defaults
}

# Function to apply profile-specific defaults
apply_profile_defaults() {
    case "$PROFILE" in
        "basic")
            CONFIG[USB_CONTROL_ENABLED]="false"
            CONFIG[NETWORK_SEGMENTATION]="false"
            CONFIG[FILE_INTEGRITY_MONITORING]="false"
            CONFIG[CROWDSEC_ENABLED]="false"
            CONFIG[OPKSSH_ENABLED]="false"
            CONFIG[COMPLIANCE_REPORTING]="false"
            ;;
        "intermediate")
            CONFIG[NETWORK_SEGMENTATION]="false"
            CONFIG[OPKSSH_ENABLED]="false"
            ;;
        "advanced")
            # All features enabled by default
            ;;
    esac
    
    log "INFO" "Applied $PROFILE profile defaults"
}

# Enhanced package installation function
install_package() {
    local package=$1
    local retries=3
    local retry_count=0
    
    log "INFO" "Installing package: $package"
    
    # Check if package is already installed
    if dpkg -l 2>/dev/null | grep -q "^ii.*$package "; then
        log "INFO" "Package $package is already installed"
        return 0
    fi
    
    # Update package cache if needed (older than 24 hours)
    if [[ $(find /var/cache/apt/pkgcache.bin -mtime +1 2>/dev/null) ]]; then
        log "INFO" "Updating package cache..."
        sudo apt-get update || {
            log "WARNING" "Failed to update package cache"
        }
    fi
    
    # Try to install package with retries
    while [ $retry_count -lt $retries ]; do
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" 2>/dev/null; then
            log "INFO" "Successfully installed package: $package"
            return 0
        fi
        
        ((retry_count++))
        log "WARNING" "Failed to install $package, attempt $retry_count of $retries"
        sleep 2
    done
    
    log "ERROR" "Failed to install package after $retries attempts: $package"
    return 1
}

# Function to perform system recovery
perform_recovery() {
    log "INFO" "Attempting system recovery..."
    
    # Check if backup exists
    if [ -d "$BACKUP_DIR" ]; then
        log "INFO" "Restoring from backup: $BACKUP_DIR"
        
        # The restore_backup function is in the main script
        if declare -f restore_backup > /dev/null; then
            restore_backup "$BACKUP_DIR"
        else
            log "ERROR" "restore_backup function not found"
            return 1
        fi
    else
        log "WARNING" "No backup found at $BACKUP_DIR, cannot perform recovery"
        return 1
    fi
    
    # Restart critical services
    local critical_services=("sshd" "ssh" "networking" "systemd-resolved")
    for service in "${critical_services[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "${service}.service"; then
            if ! systemctl is-active --quiet "$service"; then
                sudo systemctl restart "$service" 2>/dev/null || log "WARNING" "Failed to restart $service"
            fi
        fi
    done
    
    log "INFO" "Recovery attempt completed"
    return 0
}

# Enhanced completion report generation
generate_completion_report() {
    local duration=$1
    local error_count=$2
    local report_file="${BACKUP_DIR}/completion_report.txt"
    
    log "INFO" "Generating completion report..."
    
    {
        echo "=================================="
        echo "Security Hardening Completion Report"
        echo "=================================="
        echo ""
        echo "Date: $(date)"
        echo "Duration: $duration seconds"
        echo "Error Count: $error_count"
        echo "Profile: $PROFILE"
        echo "Dry Run: $DRY_RUN"
        echo ""
        echo "System Information:"
        echo "-------------------"
        echo "Hostname: $(hostname -f)"
        echo "OS: $(lsb_release -ds 2>/dev/null || echo 'Unknown')"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo ""
        
        # Configuration summary
        echo "Configuration Summary:"
        echo "----------------------"
        for key in "${!CONFIG[@]}"; do
            echo "$key: ${CONFIG[$key]}"
        done | sort
        echo ""
        
        # Service status
        echo "Service Status:"
        echo "---------------"
        local services=("ssh" "ufw" "fail2ban" "auditd" "apparmor" "crowdsec")
        for service in "${services[@]}"; do
            if systemctl list-unit-files 2>/dev/null | grep -q "${service}.service"; then
                local status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
                echo "$service: $status"
            fi
        done
        echo ""
        
        # Firewall status
        if command -v ufw &>/dev/null; then
            echo "Firewall Status:"
            echo "----------------"
            sudo ufw status numbered 2>/dev/null | head -20 || echo "Firewall status unavailable"
            echo ""
        fi
        
        # Audit status
        if command -v auditctl &>/dev/null; then
            echo "Audit Rules Summary:"
            echo "--------------------"
            local rule_count=$(sudo auditctl -l 2>/dev/null | wc -l)
            echo "Total audit rules: $rule_count"
            echo ""
        fi
        
        # Failed services
        echo "Failed Services:"
        echo "----------------"
        systemctl list-units --state=failed --no-pager 2>/dev/null || echo "No failed services"
        echo ""
        
        # Recent security events
        echo "Recent Security Events:"
        echo "-----------------------"
        if [ -f /var/log/auth.log ]; then
            echo "Last 5 authentication failures:"
            grep "authentication failure" /var/log/auth.log 2>/dev/null | tail -5 || echo "None found"
        fi
        echo ""
        
        # Disk usage
        echo "Disk Usage:"
        echo "-----------"
        df -h / /var /tmp 2>/dev/null | grep -v "^Filesystem"
        echo ""
        
        # Recommendations
        echo "Post-Installation Recommendations:"
        echo "----------------------------------"
        echo "1. Review and test all security configurations"
        echo "2. Update all user passwords to meet new policy requirements"
        echo "3. Configure monitoring and alerting systems"
        echo "4. Schedule regular security audits"
        echo "5. Test backup and recovery procedures"
        
        if [ $error_count -gt 0 ]; then
            echo ""
            echo "⚠ WARNING: $error_count errors occurred during installation"
            echo "Please review the log file: $LOG_FILE"
        fi
        
    } > "$report_file"
    
    # Display report to console if verbose
    if $VERBOSE; then
        cat "$report_file"
    fi
    
    # Send report via email if configured
    if [ -n "${CONFIG[SECURITY_EMAIL]}" ]; then
        if command -v mail &>/dev/null; then
            mail -s "Security Hardening Report - $(hostname)" "${CONFIG[SECURITY_EMAIL]}" < "$report_file"
            log "INFO" "Report sent to ${CONFIG[SECURITY_EMAIL]}"
        else
            log "WARNING" "Mail command not available, cannot send report"
        fi
    fi
    
    log "INFO" "Completion report saved to: $report_file"
}

# Function to prompt for system restart
prompt_restart() {
    local restart_needed=false
    local restart_reasons=()
    
    # Check if kernel parameters were modified
    if [ -f "/etc/sysctl.d/99-security.conf" ] || [ -f "/etc/sysctl.d/99-advanced-security.conf" ]; then
        restart_needed=true
        restart_reasons+=("Kernel parameters modified")
    fi
    
    # Check if GRUB was modified
    if [ -f "/etc/default/grub.backup" ]; then
        restart_needed=true
        restart_reasons+=("Boot configuration updated")
    fi
    
    # Check if SELinux was enabled
    if [ "${CONFIG[SELINUX_ENABLED]}" = "true" ] && command -v getenforce &>/dev/null; then
        if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
            restart_needed=true
            restart_reasons+=("SELinux configuration changed")
        fi
    fi
    
    # Check if kernel modules were configured
    if [ -f "/etc/modules-load.d/security.conf" ]; then
        restart_needed=true
        restart_reasons+=("Kernel modules configured")
    fi
    
    if $restart_needed; then
        echo ""
        echo "========================================="
        echo "System Restart Recommended"
        echo "========================================="
        echo "The following changes require a restart:"
        for reason in "${restart_reasons[@]}"; do
            echo "  - $reason"
        done
        echo ""
        read -p "Would you like to restart now? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "System will restart in 1 minute..."
            echo "System will restart in 1 minute. Press Ctrl+C to cancel."
            sudo shutdown -r +1 "Security hardening complete - system restart"
        else
            log "WARNING" "Please remember to restart the system to apply all changes"
            echo ""
            echo "⚠ IMPORTANT: Restart required to apply all security changes"
            echo "  Run 'sudo reboot' when ready"
        fi
    else
        log "INFO" "No restart required - all changes applied successfully"
    fi
}

# Function to validate file permissions
validate_file_permissions() {
    local file=$1
    local expected_perms=$2
    local expected_owner=$3
    local expected_group=${4:-$expected_owner}
    
    if [ ! -e "$file" ]; then
        log "WARNING" "File does not exist: $file"
        return 1
    fi
    
    local current_perms=$(stat -c %a "$file" 2>/dev/null)
    local current_owner=$(stat -c %U "$file" 2>/dev/null)
    local current_group=$(stat -c %G "$file" 2>/dev/null)
    
    local changes_made=false
    
    if [ "$current_perms" != "$expected_perms" ]; then
        log "INFO" "Fixing permissions for $file: $current_perms -> $expected_perms"
        sudo chmod "$expected_perms" "$file"
        changes_made=true
    fi
    
    if [ "$current_owner" != "$expected_owner" ]; then
        log "INFO" "Fixing ownership for $file: $current_owner -> $expected_owner"
        sudo chown "$expected_owner" "$file"
        changes_made=true
    fi
    
    if [ "$current_group" != "$expected_group" ]; then
        log "INFO" "Fixing group for $file: $current_group -> $expected_group"
        sudo chgrp "$expected_group" "$file"
        changes_made=true
    fi
    
    if $changes_made; then
        log "INFO" "Permissions validated and corrected for: $file"
    fi
    
    return 0
}

# Function to check disk encryption status
check_disk_encryption() {
    log "INFO" "Checking disk encryption status..."
    
    local encrypted=false
    
    # Check for LUKS encryption
    if command -v cryptsetup &>/dev/null; then
        if lsblk -o NAME,FSTYPE 2>/dev/null | grep -q "crypto_LUKS"; then
            encrypted=true
            log "INFO" "LUKS disk encryption detected"
        fi
        
        # Check for active encrypted volumes
        if sudo cryptsetup status 2>/dev/null | grep -q "is active"; then
            encrypted=true
            log "INFO" "Active encrypted volumes detected"
        fi
    fi
    
    # Check for eCryptfs (home directory encryption)
    if [ -d "$HOME/.ecryptfs" ]; then
        encrypted=true
        log "INFO" "eCryptfs home directory encryption detected"
    fi
    
    if ! $encrypted; then
        log "WARNING" "Disk encryption is not active"
        log "WARNING" "Consider enabling full disk encryption for enhanced security"
        return 1
    fi
    
    return 0
}

# Function to validate secure boot status
check_secure_boot() {
    log "INFO" "Checking Secure Boot status..."
    
    if [ -d "/sys/firmware/efi" ]; then
        # Check using mokutil if available
        if command -v mokutil &>/dev/null; then
            local sb_state=$(mokutil --sb-state 2>/dev/null | grep "SecureBoot" | awk '{print $2}')
            if [ "$sb_state" = "enabled" ]; then
                log "INFO" "Secure Boot is enabled"
                return 0
            else
                log "WARNING" "Secure Boot is disabled or not supported"
                return 1
            fi
        fi
        
        # Fallback to bootctl if available
        if command -v bootctl &>/dev/null; then
            if bootctl status 2>/dev/null | grep -q "Secure Boot: enabled"; then
                log "INFO" "Secure Boot is enabled"
                return 0
            else
                log "WARNING" "Secure Boot is not enabled"
                return 1
            fi
        fi
        
        # Check EFI variables directly
        if [ -f "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" ]; then
            local sb_value=$(od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | awk '{print $NF}')
            if [ "$sb_value" = "1" ]; then
                log "INFO" "Secure Boot is enabled"
                return 0
            fi
        fi
        
        log "WARNING" "Unable to determine Secure Boot status"
        return 1
    else
        log "INFO" "System is not UEFI-based, Secure Boot not applicable"
        return 0
    fi
}

# Function to check system entropy
check_system_entropy() {
    local min_entropy=2000
    local current_entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
    
    log "INFO" "Current system entropy: $current_entropy bits"
    
    if [ "$current_entropy" -lt "$min_entropy" ]; then
        log "WARNING" "Low system entropy: $current_entropy (minimum recommended: $min_entropy)"
        
        # Install haveged if not already installed
        if ! command -v haveged &>/dev/null; then
            log "INFO" "Installing haveged to improve entropy..."
            if install_package "haveged"; then
                sudo systemctl enable haveged 2>/dev/null
                sudo systemctl start haveged 2>/dev/null
                
                # Wait a moment for entropy to build
                sleep 2
                
                # Check entropy again
                current_entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
                log "INFO" "Entropy after installing haveged: $current_entropy bits"
            fi
        else
            # Ensure haveged is running
            if ! systemctl is-active --quiet haveged; then
                sudo systemctl start haveged 2>/dev/null
            fi
        fi
    else
        log "INFO" "System entropy is adequate"
    fi
}

# Function to check for security updates
check_security_updates() {
    log "INFO" "Checking for security updates..."
    
    # Update package cache
    sudo apt-get update &>/dev/null
    
    # Check for security updates
    local updates=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l)
    
    if [ "$updates" -gt 0 ]; then
        log "WARNING" "$updates security updates available"
        
        if [ "${CONFIG[AUTOMATIC_UPDATES]}" = "true" ]; then
            log "INFO" "Installing security updates..."
            sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade 2>/dev/null
        else
            log "INFO" "Run 'sudo apt-get upgrade' to install updates"
        fi
    else
        log "INFO" "System is up to date"
    fi
}

# Function to verify network connectivity
verify_network_connectivity() {
    log "INFO" "Verifying network connectivity..."
    
    local test_hosts=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    local connected=false
    
    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 2 "$host" &>/dev/null; then
            connected=true
            log "INFO" "Network connectivity verified (via $host)"
            break
        fi
    done
    
    if ! $connected; then
        log "ERROR" "No network connectivity detected"
        return 1
    fi
    
    # Check DNS resolution
    if ! nslookup google.com &>/dev/null; then
        log "WARNING" "DNS resolution may not be working properly"
    fi
    
    return 0
}

# Function to create secure temporary directory
create_secure_temp_dir() {
    local temp_dir=$(mktemp -d /tmp/hardening.XXXXXX)
    
    if [ ! -d "$temp_dir" ]; then
        log "ERROR" "Failed to create temporary directory"
        return 1
    fi
    
    # Set secure permissions
    chmod 700 "$temp_dir"
    
    # Register cleanup on exit
    trap "rm -rf $temp_dir" EXIT
    
    echo "$temp_dir"
}

# Function to validate system integrity
validate_system_integrity() {
    log "INFO" "Validating system integrity..."
    
    local integrity_issues=0
    
    # Check for rootkits
    if command -v rkhunter &>/dev/null; then
        log "INFO" "Running rootkit check..."
        sudo rkhunter --check --skip-keypress --quiet 2>/dev/null
        if [ $? -ne 0 ]; then
            log "WARNING" "Potential rootkit detected - review rkhunter log"
            ((integrity_issues++))
        fi
    fi
    
    # Check for suspicious processes
    local suspicious_procs=$(ps aux | grep -E '(nc|netcat|/tmp/|/dev/shm/)' | grep -v grep | wc -l)
    if [ "$suspicious_procs" -gt 0 ]; then
        log "WARNING" "$suspicious_procs potentially suspicious processes detected"
        ((integrity_issues++))
    fi
    
    # Check for unauthorized SUID files
    local unauthorized_suid=$(find / -type f -perm -4000 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' | wc -l)
    if [ "$unauthorized_suid" -gt 0 ]; then
        log "WARNING" "$unauthorized_suid unauthorized SUID files detected"
        ((integrity_issues++))
    fi
    
    if [ $integrity_issues -eq 0 ]; then
        log "INFO" "System integrity check passed"
    else
        log "WARNING" "System integrity check found $integrity_issues issues"
    fi
    
    return $integrity_issues
}

# Function to backup critical system files
backup_critical_files() {
    local backup_dir="${1:-$BACKUP_DIR}"
    
    log "INFO" "Backing up critical system files to $backup_dir..."
    
    # Create backup directory
    sudo mkdir -p "$backup_dir"
    sudo chmod 700 "$backup_dir"
    
    # List of critical files to backup
    local critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
        "/etc/fstab"
        "/etc/hosts"
        "/etc/hostname"
        "/etc/network/interfaces"
        "/etc/netplan/"
        "/etc/systemd/resolved.conf"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -e "$file" ]; then
            local backup_path="${backup_dir}${file}"
            sudo mkdir -p "$(dirname "$backup_path")"
            sudo cp -a "$file" "$backup_path" 2>/dev/null && \
                log "DEBUG" "Backed up: $file"
        fi
    done
    
    log "INFO" "Critical files backup completed"
}

# Function to check listening services
check_listening_services() {
    log "INFO" "Checking for listening services..."
    
    if command -v ss &>/dev/null; then
        local listening_tcp=$(sudo ss -tlnp | grep LISTEN | wc -l)
        local listening_udp=$(sudo ss -ulnp | wc -l)
        
        log "INFO" "Found $listening_tcp TCP and $listening_udp UDP listening services"
        
        # Check for services on dangerous ports
        local dangerous_ports="23 135 139 445 3389"
        for port in $dangerous_ports; do
            if sudo ss -tlnp | grep -q ":$port "; then
                log "WARNING" "Service listening on potentially dangerous port: $port"
            fi
        done
    fi
}

# Function to setup log monitoring
setup_log_monitoring() {
    log "INFO" "Setting up log monitoring..."
    
    # Create log monitoring script
    cat << 'EOF' | sudo tee /usr/local/bin/security-log-monitor > /dev/null
#!/bin/bash
# Security log monitoring script

# Monitor auth logs for failures
tail -F /var/log/auth.log | while read line; do
    if echo "$line" | grep -q "authentication failure"; then
        logger -t security-monitor "Authentication failure detected: $line"
    fi
    if echo "$line" | grep -q "FAILED su"; then
        logger -t security-monitor "Failed su attempt detected: $line"
    fi
done
EOF
    
    sudo chmod +x /usr/local/bin/security-log-monitor
    
    # Create systemd service for log monitoring
    cat << 'EOF' | sudo tee /etc/systemd/system/security-log-monitor.service > /dev/null
[Unit]
Description=Security Log Monitor
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-log-monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable security-log-monitor 2>/dev/null
    sudo systemctl start security-log-monitor 2>/dev/null
    
    log "INFO" "Log monitoring configured"
}

# Export all functions
export -f parse_arguments
export -f show_help
export -f load_configuration
export -f apply_profile_defaults
export -f install_package
export -f perform_recovery
export -f generate_completion_report
export -f prompt_restart
export -f validate_file_permissions
export -f check_disk_encryption
export -f check_secure_boot
export -f check_system_entropy
export -f check_security_updates
export -f verify_network_connectivity
export -f create_secure_temp_dir
export -f validate_system_integrity
export -f backup_critical_files
export -f check_listening_services
export -f setup_log_monitoring

# Utility completed message
log "INFO" "Utility functions loaded successfully (v${UTILS_VERSION})"
