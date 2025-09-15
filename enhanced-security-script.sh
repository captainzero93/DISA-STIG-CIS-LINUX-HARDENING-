#!/bin/bash
# Enhanced Linux Security Hardening Script v3.2
# Implements DISA STIG and CIS Compliance standards with comprehensive security controls
# Added CrowdSec, Cloudflare OPKSSH SSO, and advanced security features

# Global Variables and Configuration
VERSION="3.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/security_config.conf"
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/security_hardening.log"
SCRIPT_NAME=$(basename "$0")
VERBOSE=false
DRY_RUN=false
PROFILE="advanced" # Can be basic, intermediate, or advanced

# Import utility functions
source "${SCRIPT_DIR}/lib/utils.sh" 2>/dev/null || {
    echo "Error: Unable to source utility functions"
    exit 1
}

# Configuration Defaults
declare -A CONFIG=(
    [BACKUP_ENABLED]="true"
    [FIREWALL_ENABLED]="true"
    [SELINUX_ENABLED]="false"
    [APPARMOR_ENABLED]="true"
    [IPV6_ENABLED]="false"
    [AUDIT_ENABLED]="true"
    [AUTOMATIC_UPDATES]="true"
    [PASSWORD_POLICY_STRICT]="true"
    [USB_CONTROL_ENABLED]="true"
    [NETWORK_SEGMENTATION]="true"
    [FILE_INTEGRITY_MONITORING]="true"
    [CROWDSEC_ENABLED]="true"
    [OPKSSH_ENABLED]="true"
    [CREDENTIAL_VAULT_ENABLED]="true"
    [COMPLIANCE_REPORTING]="true"
    [SECURITY_EMAIL]=""
)

# Enhanced logging function with syslog support
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_message="[$level] $timestamp: $message"

    # Log to file
    echo "$log_message" | sudo tee -a "$LOG_FILE" >/dev/null

    # Log to syslog
    logger -t "security_hardening" -p "local0.$level" "$message"

    # Display if verbose mode is enabled
    $VERBOSE && echo "$log_message"
}

# Enhanced error handling function
handle_error() {
    local error_message=$1
    local error_code=${2:-1}
    local stack_trace=$(caller)

    log "ERROR" "Error Code $error_code: $error_message at line $stack_trace"

    # Create error report
    local error_report="${BACKUP_DIR}/error_report_$(date +%s).txt"
    {
        echo "Error Report - $(date)"
        echo "Error Code: $error_code"
        echo "Error Message: $error_message"
        echo "Stack Trace: $stack_trace"
        echo "System Information:"
        uname -a
        echo "Last 10 lines of log:"
        tail -n 10 "$LOG_FILE"
    } > "$error_report"

    # Attempt recovery if possible
    if [ "$error_code" -eq 2 ]; then
        log "INFO" "Attempting recovery procedure..."
        perform_advanced_recovery "intermediate"
    fi

    exit "$error_code"
}

# Enhanced input validation function
validate_input() {
    local input="$1"
    local type="$2"
    
    case "$type" in
        "domain")
            if ! echo "$input" | grep -qE '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
                handle_error "Invalid domain format: $input" 100
            fi
            ;;
        "ip")
            if ! echo "$input" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
                handle_error "Invalid IP address format: $input" 101
            fi
            ;;
        "port")
            if ! echo "$input" | grep -qE '^[0-9]{1,5}$' || [ "$input" -gt 65535 ]; then
                handle_error "Invalid port number: $input" 102
            fi
            ;;
        "email")
            if ! echo "$input" | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
                handle_error "Invalid email format: $input" 103
            fi
            ;;
    esac
}

# Setup encrypted credential vault
setup_credential_vault() {
    if [ "${CONFIG[CREDENTIAL_VAULT_ENABLED]}" != "true" ]; then
        return 0
    fi
    
    log "INFO" "Setting up encrypted credential vault..."
    
    # Install age encryption tool
    if ! command -v age &>/dev/null; then
        wget -qO- https://github.com/FiloSottile/age/releases/latest/download/age-v1.1.1-linux-amd64.tar.gz | sudo tar xz -C /usr/local/bin age/age age/age-keygen --strip=1
        sudo chmod +x /usr/local/bin/age /usr/local/bin/age-keygen
    fi
    
    # Generate encryption key if not exists
    if [ ! -f /root/.config/security/vault.key ]; then
        sudo mkdir -p /root/.config/security
        sudo age-keygen -o /root/.config/security/vault.key 2>/dev/null
        sudo chmod 600 /root/.config/security/vault.key
    fi
    
    log "INFO" "Credential vault configured successfully"
}

# Encrypt sensitive data function
encrypt_sensitive_data() {
    local data="$1"
    local output_file="$2"
    
    if [ -f /root/.config/security/vault.key ]; then
        echo "$data" | age -r "$(age-keygen -y < /root/.config/security/vault.key 2>/dev/null)" > "$output_file"
        chmod 600 "$output_file"
    else
        # Fallback to basic protection
        echo "$data" > "$output_file"
        chmod 600 "$output_file"
    fi
}

# Configuration validation function
validate_configuration() {
    log "INFO" "Validating configuration before applying..."
    
    local validation_errors=0
    
    # Check for conflicting settings
    if [[ "${CONFIG[SELINUX_ENABLED]}" == "true" && "${CONFIG[APPARMOR_ENABLED]}" == "true" ]]; then
        log "ERROR" "Cannot enable both SELinux and AppArmor simultaneously"
        ((validation_errors++))
    fi
    
    # Validate network settings
    if [[ "${CONFIG[IPV6_ENABLED]}" == "false" ]] && ip -6 addr show 2>/dev/null | grep -q "inet6"; then
        log "WARNING" "IPv6 is disabled but IPv6 addresses are configured"
    fi
    
    # Check service dependencies
    if [[ "${CONFIG[AUDIT_ENABLED]}" == "true" ]] && ! systemctl list-unit-files 2>/dev/null | grep -q "auditd.service"; then
        log "WARNING" "Audit enabled but auditd service not available - will install"
    fi
    
    # Validate email configuration if reporting is enabled
    if [[ "${CONFIG[COMPLIANCE_REPORTING]}" == "true" && -n "${CONFIG[SECURITY_EMAIL]}" ]]; then
        validate_input "${CONFIG[SECURITY_EMAIL]}" "email"
    fi
    
    if [ $validation_errors -gt 0 ]; then
        handle_error "Configuration validation failed with $validation_errors errors" 104
    fi
    
    log "INFO" "Configuration validation passed"
}

# Function to validate system requirements
check_requirements() {
    log "INFO" "Checking system requirements..."

    # Check OS compatibility
    if ! command -v lsb_release &>/dev/null; then
        handle_error "lsb_release command not found. This script requires an Ubuntu-based system." 2
    fi

    local os_name=$(lsb_release -si)
    local os_version=$(lsb_release -sr)

    if [[ "$os_name" != "Ubuntu" && "$os_name" != "Debian" ]]; then
        handle_error "This script is designed for Ubuntu or Debian-based systems. Detected OS: $os_name" 3
    fi

    # Version check with proper version comparison
    if [[ "$os_name" == "Ubuntu" ]]; then
        if ! awk -v ver="$os_version" 'BEGIN { if (ver < 18.04) exit 1; }'; then
            handle_error "This script requires Ubuntu 18.04 or later. Detected version: $os_version" 4
        fi
    elif [[ "$os_name" == "Debian" ]]; then
        if ! awk -v ver="$os_version" 'BEGIN { if (ver < 12.0) exit 1; }'; then
            handle_error "This script requires Debian 12.0 or later. Detected version: $os_version" 5
        fi
    fi

    # Check for required tools
    local required_tools=("wget" "curl" "apt" "systemctl" "openssl" "mailutils")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            install_package "$tool"
        fi
    done

    # Check disk space
    local required_space=5120  # 5GB in MB
    local available_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt "$required_space" ]; then
        handle_error "Insufficient disk space. Required: ${required_space}MB, Available: ${available_space}MB" 7
    fi

    # Check memory
    local required_memory=1024  # 1GB in MB
    local available_memory=$(free -m | awk '/Mem:/ {print $2}')
    if [ "$available_memory" -lt "$required_memory" ]; then
        handle_error "Insufficient memory. Required: ${required_memory}MB, Available: ${available_memory}MB" 8
    fi

    # Network connectivity check
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        handle_error "No network connectivity detected" 9
    fi
    
    # Check system entropy
    check_system_entropy

    log "INFO" "System requirements check passed. OS: $os_name $os_version"
}

# Enhanced backup function with integrity verification
backup_files() {
    log "INFO" "Creating system backup..."

    # Create backup directory with secure permissions
    sudo install -d -m 0700 "$BACKUP_DIR" || handle_error "Failed to create backup directory" 10

    local files_to_backup=(
        "/etc/default/grub"
        "/etc/ssh/sshd_config"
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-auth"
        "/etc/login.defs"
        "/etc/sysctl.conf"
        "/etc/security/limits.conf"
        "/etc/audit/auditd.conf"
        "/etc/selinux/config"
        "/etc/apparmor/parser.conf"
        "/etc/default/ufw"
        "/etc/security/pwquality.conf"
    )

    # Create backup manifest
    local manifest_file="${BACKUP_DIR}/manifest.txt"
    echo "Backup created on $(date)" > "$manifest_file"
    echo "System Information:" >> "$manifest_file"
    uname -a >> "$manifest_file"

    # Backup files with checksums
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            # Create directory structure
            sudo mkdir -p "${BACKUP_DIR}$(dirname "$file")"

            # Copy file with permissions
            sudo cp -p "$file" "${BACKUP_DIR}${file}" || {
                log "WARNING" "Failed to backup $file"
                continue
            }

            # Generate checksum
            sha256sum "${BACKUP_DIR}${file}" >> "${BACKUP_DIR}/checksums.txt"

            # Add to manifest
            echo "Backed up: $file" >> "$manifest_file"
        else
            log "WARNING" "File not found, skipping backup: $file"
        fi
    done

    # Create compressed archive of backup
    sudo tar -czf "${BACKUP_DIR}.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")" || {
        handle_error "Failed to create backup archive" 11
    }

    # Generate checksum for the archive
    sha256sum "${BACKUP_DIR}.tar.gz" > "${BACKUP_DIR}.tar.gz.sha256"

    log "INFO" "Backup created successfully in $BACKUP_DIR"
    log "INFO" "Backup archive created: ${BACKUP_DIR}.tar.gz"
}

# Enhanced restore function with integrity checking
restore_backup() {
    local backup_path=$1

    if [ ! -f "${backup_path}.tar.gz" ]; then
        handle_error "Backup archive not found: ${backup_path}.tar.gz" 12
    fi

    # Verify archive checksum
    if [ -f "${backup_path}.tar.gz.sha256" ]; then
        if ! sha256sum -c "${backup_path}.tar.gz.sha256" &>/dev/null; then
            handle_error "Backup archive integrity check failed" 13
        fi
    fi

    # Extract archive
    sudo tar -xzf "${backup_path}.tar.gz" -C / || handle_error "Failed to extract backup archive" 14

    # Verify individual file checksums
    if [ -f "${backup_path}/checksums.txt" ]; then
        while IFS= read -r line; do
            local checksum=$(echo "$line" | cut -d' ' -f1)
            local file=$(echo "$line" | cut -d' ' -f3-)

            if ! echo "$checksum  $file" | sha256sum -c --quiet 2>/dev/null; then
                log "WARNING" "Checksum verification failed for: $file"
            fi
        done < "${backup_path}/checksums.txt"
    fi

    log "INFO" "System restore completed from $backup_path"
}

# Enhanced SSH hardening function
configure_ssh_hardening() {
    log "INFO" "Applying advanced SSH hardening..."
    
    # Backup original SSH config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create SSH user group if it doesn't exist
    sudo groupadd -f ssh-users
    
    # Apply hardened SSH configuration
    cat << 'EOF' | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null
# Enhanced SSH Security Configuration
# STIG/CIS Compliant Settings

# Protocol and Port
Protocol 2
Port 22

# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60

# Modern Cryptography (FIPS 140-2 compliant where possible)
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Security Features
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Access Control
AllowGroups ssh-users
DenyUsers root
MaxStartups 10:30:60
Banner /etc/ssh/banner

# Additional Security
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
RekeyLimit 1G 1h
EOF
    
    # Create SSH banner
    cat << 'EOF' | sudo tee /etc/ssh/banner > /dev/null
##############################################################
#                                                            #
#  Unauthorized access to this system is strictly prohibited #
#  All access attempts are logged and monitored             #
#  Violators will be prosecuted to the fullest extent       #
#                                                            #
##############################################################
EOF
    
    # Generate strong host keys if needed
    sudo ssh-keygen -A -f /etc/ssh
    
    # Remove weak host keys
    sudo rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key* 2>/dev/null
    
    # Set proper permissions
    sudo chmod 600 /etc/ssh/ssh_host_*_key
    sudo chmod 644 /etc/ssh/ssh_host_*_key.pub
    
    # Verify SSH configuration
    sudo sshd -t || handle_error "SSH configuration is invalid" 50
    
    # Restart SSH service
    sudo systemctl restart ssh || handle_error "Failed to restart SSH service" 51
    
    log "INFO" "SSH hardening completed successfully"
}

# Enhanced firewall configuration function
setup_firewall() {
    log "INFO" "Configuring advanced firewall settings..."

    # Install required packages
    install_package "ufw"
    install_package "iptables-persistent"

    # Basic UFW configuration
    sudo ufw default deny incoming || handle_error "Failed to set UFW default incoming policy" 15
    sudo ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy" 16

    # Configure rate limiting for SSH
    sudo ufw limit ssh comment 'Allow SSH with rate limiting' || handle_error "Failed to configure SSH in UFW" 17

    # Configure common services based on profile
    if [[ "$PROFILE" == "advanced" || "$PROFILE" == "intermediate" ]]; then
        # Allow only essential services
        sudo ufw allow 22/tcp comment 'SSH'
        sudo ufw allow 123/udp comment 'NTP'
        
        # Add HTTP/HTTPS only if needed
        read -p "Allow HTTP/HTTPS traffic? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo ufw allow 80/tcp comment 'HTTP'
            sudo ufw allow 443/tcp comment 'HTTPS'
        fi
    fi

    # Configure advanced rules
    if [ "${CONFIG[NETWORK_SEGMENTATION]}" = "true" ]; then
        # Allow internal network communication
        sudo ufw allow from 192.168.0.0/16 to any comment 'Internal network' || log "WARNING" "Failed to configure internal network rules"
        sudo ufw allow from 10.0.0.0/8 to any comment 'Private network' || log "WARNING" "Failed to configure private network rules"
    fi

    # IPv6 configuration
    if [ "${CONFIG[IPV6_ENABLED]}" = "true" ]; then
        log "INFO" "Configuring IPv6 firewall rules..."
        sudo sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
    else
        log "INFO" "Disabling IPv6 firewall rules..."
        sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
    fi

    # Enable logging
    sudo ufw logging on || handle_error "Failed to enable UFW logging" 18
    sudo ufw logging high

    # Apply rules
    if ! $DRY_RUN; then
        sudo ufw --force enable || handle_error "Failed to enable UFW" 19

        # Verify firewall status
        if ! sudo ufw status verbose | grep -q "Status: active"; then
            handle_error "Firewall is not active after configuration" 20
        fi
    fi

    log "INFO" "Firewall configuration completed"
}

# Enhanced fail2ban configuration
setup_fail2ban() {
    log "INFO" "Configuring Fail2Ban..."

    install_package "fail2ban"

    # Create custom configuration
    local f2b_config="/etc/fail2ban/jail.local"
    cat << 'EOF' | sudo tee "$f2b_config" > /dev/null
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
banaction = %(banaction_allports)s
ignoreip = 127.0.0.1/8 ::1
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 24h

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = %(sshd_log)s
maxretry = 2
bantime = 48h

[sshd-aggressive]
enabled = true
port = ssh
filter = sshd[mode=aggressive]
logpath = %(sshd_log)s
maxretry = 2
bantime = 72h

[http-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
bantime = 12h

[http-get-dos]
enabled = true
port = http,https
filter = http-get-dos
logpath = /var/log/apache2/access.log
maxretry = 100
findtime = 5m
bantime = 2h

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
bantime = 1h

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime = 168h
maxretry = 3
EOF

    # Create custom filter for HTTP DoS protection
    local dos_filter="/etc/fail2ban/filter.d/http-get-dos.conf"
    cat << 'EOF' | sudo tee "$dos_filter" > /dev/null
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

    # Create custom filter for SSH DDoS
    local ssh_ddos_filter="/etc/fail2ban/filter.d/sshd-ddos.conf"
    cat << 'EOF' | sudo tee "$ssh_ddos_filter" > /dev/null
[Definition]
failregex = ^.*sshd\[.*\]: Did not receive identification string from <HOST>$
            ^.*sshd\[.*\]: Connection from <HOST> port .* \[preauth\]$
ignoreregex =
EOF

    # Enable and start service
    sudo systemctl enable fail2ban || handle_error "Failed to enable Fail2Ban service" 21
    sudo systemctl restart fail2ban || handle_error "Failed to start Fail2Ban service" 22

    # Verify service status
    if ! sudo systemctl is-active --quiet fail2ban; then
        handle_error "Fail2Ban service is not running after configuration" 23
    fi

    log "INFO" "Fail2Ban configuration completed"
}

# Comprehensive audit configuration
setup_comprehensive_audit() {
    log "INFO" "Configuring comprehensive audit system..."

    install_package "auditd"
    install_package "audispd-plugins"

    # Configure main audit settings
    local audit_conf="/etc/audit/auditd.conf"
    cat << 'EOF' | sudo tee "$audit_conf" > /dev/null
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = EMAIL
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
distribute_network = no
EOF

    # Configure comprehensive audit rules (STIG & CIS Compliance)
    local audit_rules="/etc/audit/rules.d/audit.rules"
    cat << 'EOF' | sudo tee "$audit_rules" > /dev/null
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure Mode
-f 2

# Date and Time
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User, Group, and Password Modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Network Environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale

# System Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Login/Logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/log/auth.log -p wa -k logins

# Session Initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Discretionary Access Control
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized Access Attempts
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Privilege Escalation
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged
-w /usr/bin/sudo -p x -k privileged
-w /usr/bin/su -p x -k privileged
-w /usr/bin/passwd -p x -k privileged-passwd
-w /usr/bin/gpasswd -p x -k privileged-gpasswd
-w /usr/bin/chage -p x -k privileged-chage
-w /usr/bin/usermod -p x -k privileged-usermod
-w /usr/bin/crontab -p x -k privileged-crontab

# Module Loading/Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules

# File deletion events
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Scope creep prevention
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k scope_creep
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k scope_creep

# Container events
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker -p wa -k docker
-w /etc/docker -p wa -k docker
-w /usr/bin/containerd -p wa -k containerd

# Systemd monitoring
-w /bin/systemctl -p x -k systemd
-w /etc/systemd/ -p wa -k systemd

# Make audit config immutable
-e 2
EOF

    # Restart audit daemon
    sudo service auditd restart || handle_error "Failed to restart audit daemon" 24

    # Verify audit is working
    if ! sudo auditctl -l &>/dev/null; then
        handle_error "Audit system is not functioning properly after configuration" 25
    fi

    log "INFO" "Comprehensive audit system configured successfully"
}

# Enhanced password policy configuration (STIG & CIS Compliance)
configure_password_policy() {
    log "INFO" "Configuring password and authentication policies..."

    # Install required packages
    install_package "libpam-pwquality"
    install_package "libpam-faillock"

    # Configure PAM password quality requirements
    local pwquality_conf="/etc/security/pwquality.conf"
    cat << 'EOF' | sudo tee "$pwquality_conf" > /dev/null
# Password length and complexity (STIG/CIS compliant)
minlen = 15
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4

# Password history and reuse
remember = 24

# Password strength
difok = 8
dictcheck = 1
enforcing = 1

# Reject username in password
usercheck = 1

# Reject character sequences
maxsequence = 3

# Reject repeated characters
maxrepeat = 3

# Minimum length of different characters
maxclassrepeat = 4

# Reject simple passwords
gecoscheck = 1
EOF

    # Configure PAM password settings
    local pam_password="/etc/pam.d/common-password"
    cat << 'EOF' | sudo tee "$pam_password" > /dev/null
# PAM password configuration with enhanced security
password    requisite     pam_pwquality.so retry=3
password    required      pam_pwhistory.so remember=24 use_authtok
password    [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512 shadow remember=24
password    requisite     pam_deny.so
password    required      pam_permit.so
EOF

    # Configure account lockout
    local pam_auth="/etc/pam.d/common-auth"
    cat << 'EOF' | sudo tee "$pam_auth" > /dev/null
# PAM authentication with account lockout
auth    required      pam_env.so
auth    required      pam_faillock.so preauth silent audit deny=3 unlock_time=1800 even_deny_root root_unlock_time=1800
auth    [success=1 default=bad]  pam_unix.so
auth    [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1800 even_deny_root root_unlock_time=1800
auth    sufficient    pam_faillock.so authsucc audit deny=3 unlock_time=1800 even_deny_root root_unlock_time=1800
auth    requisite     pam_deny.so
auth    required      pam_permit.so
auth    optional      pam_cap.so
EOF

    # Configure login.defs
    local login_defs="/etc/login.defs"
    sudo cp "$login_defs" "${login_defs}.backup"
    cat << 'EOF' | sudo tee "$login_defs" > /dev/null
# Password aging controls (STIG/CIS compliant)
PASS_MAX_DAYS   60
PASS_MIN_DAYS   1
PASS_WARN_AGE   7

# Password length restrictions
PASS_MIN_LEN    15

# Password hashing
ENCRYPT_METHOD SHA512
SHA_CRYPT_MIN_ROUNDS 5000
SHA_CRYPT_MAX_ROUNDS 500000

# Account restrictions
CREATE_HOME     yes
UMASK          077
USERGROUPS_ENAB yes

# Login restrictions
LOGIN_RETRIES   3
LOGIN_TIMEOUT   60
FAILLOG_ENAB    yes
LOG_UNKFAIL_ENAB yes
SYSLOG_SU_ENAB  yes
SYSLOG_SG_ENAB  yes

# User/Group ID ranges
UID_MIN         1000
UID_MAX         60000
GID_MIN         1000
GID_MAX         60000
SYS_UID_MIN     100
SYS_UID_MAX     999
SYS_GID_MIN     100
SYS_GID_MAX     999

# Additional security
CHFN_RESTRICT   rwh
DEFAULT_HOME    no
USERDEL_CMD     /usr/sbin/userdel_local
EOF

    log "INFO" "Password and authentication policies configured successfully"
}

# Advanced kernel security configuration
configure_advanced_kernel_security() {
    log "INFO" "Configuring advanced kernel security parameters..."

    local sysctl_conf="/etc/sysctl.d/99-advanced-security.conf"
    cat << 'EOF' | sudo tee "$sysctl_conf" > /dev/null
# Advanced Kernel Security Parameters
# STIG/CIS Compliant Configuration

# Network Security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.forwarding = 0

# IPv6 Security (if enabled)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Process Security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.panic_on_oops = 1
kernel.panic = 60
kernel.sysrq = 0
kernel.unprivileged_userns_clone = 0
kernel.kexec_load_disabled = 1

# Memory Protection
kernel.exec-shield = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# File System Security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2

# Core Dump Restrictions
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false

# Process Restrictions
kernel.pid_max = 65536
kernel.threads-max = 30000
fs.file-max = 65535

# Additional Security Measures
kernel.panic_on_unrecovered_nmi = 1
kernel.panic_on_io_nmi = 1
kernel.modules_disabled = 0
EOF

    # Apply sysctl settings
    sudo sysctl -p "$sysctl_conf" || handle_error "Failed to apply sysctl settings" 26

    log "INFO" "Advanced kernel security parameters configured successfully"
}

# Function to setup USB device control
setup_usb_control() {
    if [ "${CONFIG[USB_CONTROL_ENABLED]}" != "true" ]; then
        return 0
    fi

    log "INFO" "Configuring USB device control..."

    # Install required packages
    install_package "usbguard"

    # Generate initial policy
    sudo usbguard generate-policy > /etc/usbguard/rules.conf

    # Configure USBGuard daemon
    cat << 'EOF' | sudo tee /etc/usbguard/usbguard-daemon.conf > /dev/null
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=apply-policy
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=
DeviceRulesWithPort=false
AuditBackend=FileAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
EOF

    # Create log directory
    sudo mkdir -p /var/log/usbguard
    
    # Start and enable USBGuard service
    sudo systemctl enable usbguard || handle_error "Failed to enable USBGuard service" 27
    sudo systemctl restart usbguard || handle_error "Failed to start USBGuard service" 28

    log "INFO" "USB device control configured successfully"
}

# Function to setup file integrity monitoring
setup_file_integrity() {
    if [ "${CONFIG[FILE_INTEGRITY_MONITORING]}" != "true" ]; then
        return 0
    fi

    log "INFO" "Configuring file integrity monitoring..."

    # Install AIDE
    install_package "aide"
    install_package "aide-common"

    # Configure AIDE
    cat << 'EOF' | sudo tee /etc/aide/aide.conf > /dev/null
# AIDE configuration for comprehensive file integrity monitoring
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
database_new=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# Monitoring rules
FIPSR = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha256
NORMAL = FIPSR+sha512

# Directories to monitor
/boot   NORMAL
/bin    NORMAL
/sbin   NORMAL
/lib    NORMAL
/lib64  NORMAL
/opt    NORMAL
/usr    NORMAL
/root   NORMAL
!/usr/src
!/usr/tmp

/etc    NORMAL
!/etc/mtab

# Variable files that change frequently
!/var/log
!/var/spool
!/var/tmp
!/var/cache

# Temporary directories
!/tmp
!/dev/shm
EOF

    # Initialize AIDE database
    log "INFO" "Initializing AIDE database (this may take several minutes)..."
    sudo aideinit --yes --force || handle_error "Failed to initialize AIDE database" 29

    # Setup daily integrity checks
    cat << 'EOF' | sudo tee /etc/cron.daily/aide-check > /dev/null
#!/bin/bash
# Daily AIDE integrity check

AIDE_LOG="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide

/usr/bin/aide --check > "$AIDE_LOG" 2>&1

if [ $? -ne 0 ]; then
    # Changes detected, send alert
    mail -s "AIDE Integrity Check Alert - $(hostname)" root < "$AIDE_LOG"
fi

# Rotate old logs
find /var/log/aide -name "aide-check-*.log" -mtime +30 -delete
EOF

    # Make AIDE check script executable
    sudo chmod +x /etc/cron.daily/aide-check

    # Configure AIDE log rotation
    cat << 'EOF' | sudo tee /etc/logrotate.d/aide > /dev/null
/var/log/aide/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

    log "INFO" "File integrity monitoring configured successfully"
}

# Function to setup SELinux/AppArmor
setup_mandatory_access_control() {
    log "INFO" "Configuring Mandatory Access Control..."

    if [ "${CONFIG[SELINUX_ENABLED]}" = "true" ]; then
        # Setup SELinux
        install_package "selinux-basics"
        install_package "selinux-policy-default"
        install_package "selinux-utils"

        # Configure SELinux policy
        sudo selinux-activate || handle_error "Failed to activate SELinux" 30

        # Set SELinux to enforcing mode
        sudo setenforce 1 2>/dev/null || log "WARNING" "Failed to set SELinux to enforcing mode (reboot required)"

        # Configure SELinux policy in config file
        sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

    elif [ "${CONFIG[APPARMOR_ENABLED]}" = "true" ]; then
        # Setup AppArmor
        install_package "apparmor"
        install_package "apparmor-utils"
        install_package "apparmor-profiles"
        install_package "apparmor-profiles-extra"

        # Enable AppArmor
        sudo systemctl enable apparmor || handle_error "Failed to enable AppArmor" 31
        sudo systemctl restart apparmor || handle_error "Failed to start AppArmor" 32

        # Set all profiles to enforce mode
        sudo aa-enforce /etc/apparmor.d/* 2>/dev/null || log "WARNING" "Failed to enforce some AppArmor profiles"

        # Create custom AppArmor profile for critical services
        create_custom_apparmor_profiles
    fi

    log "INFO" "Mandatory Access Control configured successfully"
}

# Function to create custom AppArmor profiles
create_custom_apparmor_profiles() {
    # Custom profile for SSH
    cat << 'EOF' | sudo tee /etc/apparmor.d/usr.sbin.sshd > /dev/null
#include <tunables/global>

profile sshd /usr/sbin/sshd {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/authentication>
    #include <abstractions/openssl>

    capability net_bind_service,
    capability chown,
    capability fowner,
    capability kill,
    capability setgid,
    capability setuid,
    capability sys_chroot,
    capability sys_resource,
    capability sys_tty_config,
    capability audit_write,
    capability dac_override,
    capability dac_read_search,

    /usr/sbin/sshd mr,
    /etc/ssh/** r,
    /etc/ssh/sshd_config r,
    /etc/ssh/ssh_host_* r,
    /var/log/auth.log w,
    /var/log/syslog w,
    /var/run/sshd.pid w,
    /var/run/sshd/** rw,
    /dev/ptmx rw,
    /dev/pts/* rw,
    /dev/urandom r,
    /etc/localtime r,
    /etc/pam.d/* r,
    /etc/security/** r,
    /proc/*/fd/ r,
    /proc/sys/kernel/ngroups_max r,
    /run/utmp rk,
    @{HOME}/.ssh/authorized_keys r,

    # Add support for OPKSSH auth helper
    /usr/local/bin/opk-ssh-auth-helper PUx,
    /etc/ssh/opk_trusted_user_ca_keys.pem r,
    /etc/opkssh/** r,

    # Allow execution of shells for user sessions
    /bin/bash PUx,
    /bin/sh PUx,
    /usr/bin/zsh PUx,
}
EOF

    # Reload AppArmor profiles
    sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd 2>/dev/null || log "WARNING" "Failed to load custom SSH AppArmor profile"
    sudo service apparmor reload 2>/dev/null || log "WARNING" "Failed to reload AppArmor profiles"
}

# Function to setup secure boot configuration
setup_secure_boot() {
    log "INFO" "Configuring secure boot settings..."

    # Check if system supports secure boot
    if [ ! -d "/sys/firmware/efi" ]; then
        log "WARNING" "System is not UEFI-based, skipping secure boot configuration"
        return 0
    fi

    # Check if GRUB is installed
    if command -v grub-install > /dev/null 2>&1; then
        # Install required packages
        install_package "grub-efi-amd64-signed"
        install_package "shim-signed"

        # Configure GRUB security settings
        local grub_config="/etc/default/grub"

        # Backup original configuration
        sudo cp "$grub_config" "${grub_config}.backup"

        # Update GRUB security parameters
        sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash module.sig_enforce=1 lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 slab_nomerge vsyscall=none"/' "$grub_config"

        # Add additional security parameters
        sudo sed -i 's/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"/' "$grub_config"

        # Set GRUB password if requested
        if [[ "$PROFILE" == "advanced" ]]; then
            echo "Setting up GRUB password protection..."
            read -s -p "Enter GRUB password (press Enter to skip): " grub_password
            echo

            if [ -n "$grub_password" ]; then
                # Generate GRUB password hash
                local password_hash
                password_hash=$(echo -e "$grub_password\n$grub_password" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/grub\.pbkdf2/ { print $NF }')

                # Add password protection to GRUB
                cat << EOF | sudo tee /etc/grub.d/40_custom > /dev/null
#!/bin/sh
exec tail -n +3 \$0

set superusers="admin"
password_pbkdf2 admin $password_hash
EOF
                sudo chmod 755 /etc/grub.d/40_custom
            fi
        fi

        # Update GRUB configuration
        sudo update-grub || handle_error "Failed to update GRUB configuration" 33

        # Secure boot directory permissions
        sudo chmod 700 /boot/grub
        sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null

        log "INFO" "Secure boot configured successfully"
    else
        log "WARNING" "System does not use GRUB, skipping secure boot configuration"
    fi
}

# Function to harden systemd services
harden_systemd_services() {
    log "INFO" "Hardening systemd services..."
    
    # Create drop-in directories for service hardening
    local services=("ssh" "cron" "rsyslog")
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "${service}.service"; then
            sudo mkdir -p "/etc/systemd/system/${service}.service.d/"
            
            # Apply security hardening
            cat << EOF | sudo tee "/etc/systemd/system/${service}.service.d/hardening.conf" > /dev/null
[Service]
# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
EOF
            
            # Service-specific configurations
            if [ "$service" = "ssh" ]; then
                echo "ReadWritePaths=/var/log /var/run" | sudo tee -a "/etc/systemd/system/${service}.service.d/hardening.conf" > /dev/null
            fi
        fi
    done
    
    sudo systemctl daemon-reload
    
    log "INFO" "Systemd services hardened successfully"
}

# Setup CrowdSec
setup_crowdsec() {
    if [ "${CONFIG[CROWDSEC_ENABLED]}" != "true" ]; then
        return 0
    fi

    log "INFO" "Configuring CrowdSec..."

    # Install CrowdSec
    if ! command -v cscli &>/dev/null; then
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
        install_package "crowdsec"
    fi

    # Install CrowdSec firewall bouncer
    install_package "crowdsec-firewall-bouncer-iptables"

    # Register with CrowdSec community
    sudo cscli capi register || log "WARNING" "Failed to register with CrowdSec community"

    # Install collections
    sudo cscli collections install crowdsecurity/linux || true
    sudo cscli collections install crowdsecurity/sshd || true
    sudo cscli collections install crowdsecurity/iptables || true

    # Configure CrowdSec for UFW
    if [ "${CONFIG[FIREWALL_ENABLED]}" = "true" ]; then
        # Generate bouncer API key
        BOUNCER_KEY=$(sudo cscli bouncers add firewall-bouncer -o raw 2>/dev/null || echo "")
        
        if [ -n "$BOUNCER_KEY" ]; then
            # Configure the bouncer
            cat << EOF | sudo tee /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml > /dev/null
mode: iptables
pid_dir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
api_url: http://localhost:8080/
api_key: ${BOUNCER_KEY}
disable_ipv6: $([ "${CONFIG[IPV6_ENABLED]}" = "false" ] && echo "true" || echo "false")
deny_action: DROP
deny_log: true
supported_decisions_types:
  - ban
EOF
        fi
    fi

    # Start services
    sudo systemctl enable crowdsec || handle_error "Failed to enable CrowdSec service" 45
    sudo systemctl restart crowdsec || handle_error "Failed to start CrowdSec service" 46
    
    if [ -n "$BOUNCER_KEY" ]; then
        sudo systemctl enable crowdsec-firewall-bouncer || handle_error "Failed to enable CrowdSec bouncer" 47
        sudo systemctl restart crowdsec-firewall-bouncer || handle_error "Failed to start CrowdSec bouncer" 48
    fi

    log "INFO" "CrowdSec configuration completed successfully"
}

# Setup Cloudflare OPKSSH SSO
setup_opkssh_auth() {
    if [ "${CONFIG[OPKSSH_ENABLED]}" != "true" ]; then
        return 0
    fi

    log "INFO" "Configuring Cloudflare OPKSSH SSO for SSH authentication..."

    # Create directory for OPKSSH
    sudo mkdir -p /etc/opkssh
    sudo chmod 755 /etc/opkssh

    # Download and install OPKSSH binaries
    log "INFO" "Downloading OPKSSH binaries..."
    if [ ! -f /usr/local/bin/opk-ssh-auth-helper ]; then
        sudo curl -sL https://github.com/cloudflare/opk/releases/latest/download/opk-ssh-auth-helper -o /usr/local/bin/opk-ssh-auth-helper
        sudo chmod +x /usr/local/bin/opk-ssh-auth-helper
    fi

    # Download Cloudflare CA keys
    log "INFO" "Downloading Cloudflare CA keys..."
    sudo curl -s https://developers.cloudflare.com/cdn-cgi/access/certificates/opk_ca_keys.pem -o /etc/ssh/opk_trusted_user_ca_keys.pem
    sudo chmod 644 /etc/ssh/opk_trusted_user_ca_keys.pem

    # Configure SSH server to use OPKSSH
    cat << 'EOF' | sudo tee /etc/ssh/sshd_config.d/60-opkssh.conf > /dev/null
# Cloudflare OPKSSH SSO configuration
AuthorizedKeysCommand /usr/local/bin/opk-ssh-auth-helper
AuthorizedKeysCommandUser nobody
TrustedUserCAKeys /etc/ssh/opk_trusted_user_ca_keys.pem
EOF

    # Prompt for Cloudflare Zero Trust configuration
    echo "Please enter your Cloudflare Zero Trust team domain (example.cloudflareaccess.com):"
    read -r team_domain
    validate_input "$team_domain" "domain"

    echo "Please enter your SSH application domain (ssh.example.com):"
    read -r app_domain
    validate_input "$app_domain" "domain"

    # Create OPKSSH configuration file
    cat << EOF | sudo tee /etc/opkssh/config.json > /dev/null
{
    "app_domain": "${app_domain}",
    "team_domain": "${team_domain}",
    "service_token_file": "/etc/opkssh/service_token",
    "log_level": "info"
}
EOF

    # Secure the configuration file
    sudo chmod 644 /etc/opkssh/config.json

    # Prompt for service token
    echo "Please enter your Cloudflare Access service token (will be hidden):"
    read -s service_token
    echo
    
    # Encrypt and store service token
    encrypt_sensitive_data "$service_token" "/etc/opkssh/service_token"

    # Verify and restart SSH
    sudo sshd -t || handle_error "SSH configuration is invalid" 50
    sudo systemctl restart ssh || handle_error "Failed to restart SSH service" 51

    log "INFO" "Cloudflare OPKSSH SSO configured successfully"
}

# Generate compliance report
generate_compliance_report() {
    if [ "${CONFIG[COMPLIANCE_REPORTING]}" != "true" ]; then
        return 0
    fi

    log "INFO" "Generating compliance report..."
    
    local report_file="${BACKUP_DIR}/compliance_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat << 'EOF' > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>Security Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .metadata { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Compliance Report</h1>
EOF
    
    # Add system information
    echo "<div class='metadata'>" >> "$report_file"
    echo "<p><strong>Hostname:</strong> $(hostname -f)</p>" >> "$report_file"
    echo "<p><strong>Report Date:</strong> $(date)</p>" >> "$report_file"
    echo "<p><strong>OS:</strong> $(lsb_release -ds)</p>" >> "$report_file"
    echo "<p><strong>Kernel:</strong> $(uname -r)</p>" >> "$report_file"
    echo "<p><strong>Profile:</strong> $PROFILE</p>" >> "$report_file"
    echo "</div>" >> "$report_file"
    
    # Add compliance summary
    echo "<div class='summary'>" >> "$report_file"
    echo "<h2>Compliance Summary</h2>" >> "$report_file"
    
    local total_checks=0
    local passed_checks=0
    
    # Add compliance checks table
    echo "<table>" >> "$report_file"
    echo "<tr><th>Control ID</th><th>Category</th><th>Description</th><th>Status</th></tr>" >> "$report_file"
    
    # SSH Configuration Checks
    check_compliance_item "SSH-1" "SSH" "SSH Protocol Version 2" "grep -q 'Protocol 2' /etc/ssh/sshd_config"
    check_compliance_item "SSH-2" "SSH" "SSH Root Login Disabled" "grep -qE '^PermitRootLogin (no|prohibit-password)' /etc/ssh/sshd_config"
    check_compliance_item "SSH-3" "SSH" "SSH Password Authentication Disabled" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"
    
    # Firewall Checks
    check_compliance_item "FW-1" "Firewall" "Firewall Enabled" "ufw status | grep -q 'Status: active'"
    check_compliance_item "FW-2" "Firewall" "Default Deny Incoming" "ufw status verbose | grep -q 'Default: deny (incoming)'"
    
    # Audit Checks
    check_compliance_item "AUD-1" "Audit" "Audit Daemon Running" "systemctl is-active auditd"
    check_compliance_item "AUD-2" "Audit" "Audit Rules Configured" "auditctl -l | grep -q time-change"
    
    # Password Policy Checks
    check_compliance_item "PWD-1" "Password" "Password Complexity Enforced" "grep -q 'minlen = 15' /etc/security/pwquality.conf"
    check_compliance_item "PWD-2" "Password" "Password History Enforced" "grep -q 'remember=24' /etc/pam.d/common-password"
    check_compliance_item "PWD-3" "Password" "Account Lockout Configured" "grep -q 'pam_faillock.so' /etc/pam.d/common-auth"
    
    # Kernel Security Checks
    check_compliance_item "KERN-1" "Kernel" "ASLR Enabled" "sysctl kernel.randomize_va_space | grep -q '= 2'"
    check_compliance_item "KERN-2" "Kernel" "SYN Cookies Enabled" "sysctl net.ipv4.tcp_syncookies | grep -q '= 1'"
    check_compliance_item "KERN-3" "Kernel" "IP Forwarding Disabled" "sysctl net.ipv4.conf.all.forwarding | grep -q '= 0'"
    
    # MAC Checks
    if [ "${CONFIG[APPARMOR_ENABLED]}" = "true" ]; then
        check_compliance_item "MAC-1" "MAC" "AppArmor Enabled" "systemctl is-active apparmor"
        check_compliance_item "MAC-2" "MAC" "AppArmor Enforcing" "aa-status | grep -q 'profiles are in enforce mode'"
    fi
    
    # File Integrity Checks
    if [ "${CONFIG[FILE_INTEGRITY_MONITORING]}" = "true" ]; then
        check_compliance_item "FIM-1" "File Integrity" "AIDE Installed" "which aide"
        check_compliance_item "FIM-2" "File Integrity" "AIDE Database Initialized" "[ -f /var/lib/aide/aide.db ]"
    fi
    
    echo "</table>" >> "$report_file"
    
    # Calculate compliance percentage
    local compliance_percentage=0
    if [ $total_checks -gt 0 ]; then
        compliance_percentage=$(( (passed_checks * 100) / total_checks ))
    fi
    
    echo "<p><strong>Total Checks:</strong> $total_checks</p>" >> "$report_file"
    echo "<p><strong>Passed:</strong> <span class='pass'>$passed_checks</span></p>" >> "$report_file"
    echo "<p><strong>Failed:</strong> <span class='fail'>$((total_checks - passed_checks))</span></p>" >> "$report_file"
    echo "<p><strong>Compliance Rate:</strong> ${compliance_percentage}%</p>" >> "$report_file"
    echo "</div>" >> "$report_file"
    
    echo "</div></body></html>" >> "$report_file"
    
    log "INFO" "Compliance report generated: $report_file"
    
    # Send report via email if configured
    if [ -n "${CONFIG[SECURITY_EMAIL]}" ]; then
        mail -a "Content-Type: text/html" -s "Security Compliance Report - $(hostname)" "${CONFIG[SECURITY_EMAIL]}" < "$report_file"
        log "INFO" "Compliance report sent to ${CONFIG[SECURITY_EMAIL]}"
    fi
}

# Helper function for compliance checks
check_compliance_item() {
    local control_id="$1"
    local category="$2"
    local description="$3"
    local check_command="$4"
    
    local status="fail"
    local status_class="fail"
    
    ((total_checks++))
    
    if eval "$check_command" &>/dev/null; then
        status="PASS"
        status_class="pass"
        ((passed_checks++))
    else
        status="FAIL"
        status_class="fail"
    fi
    
    echo "<tr><td>$control_id</td><td>$category</td><td>$description</td><td class='$status_class'>$status</td></tr>" >> "$report_file"
}

# Enhanced recovery mechanism
perform_advanced_recovery() {
    local recovery_level="${1:-basic}"
    
    log "INFO" "Initiating advanced recovery procedure (level: $recovery_level)..."
    
    case "$recovery_level" in
        "basic")
            # Restore critical services
            local critical_services=("ssh" "networking" "systemd-resolved")
            for service in "${critical_services[@]}"; do
                if ! systemctl is-active --quiet "$service"; then
                    systemctl restart "$service" 2>/dev/null || log "WARNING" "Failed to restart $service"
                fi
            done
            ;;
            
        "intermediate")
            # Restore from last known good configuration
            if [ -f "${BACKUP_DIR}.tar.gz" ]; then
                restore_backup "${BACKUP_DIR}"
            fi
            
            # Restart all security services
            local security_services=("ssh" "auditd" "ufw" "fail2ban" "apparmor" "crowdsec")
            for service in "${security_services[@]}"; do
                if systemctl list-unit-files | grep -q "${service}.service"; then
                    systemctl restart "$service" 2>/dev/null || log "WARNING" "Failed to restart $service"
                fi
            done
            ;;
            
        "full")
            # Complete system rollback
            log "INFO" "Performing full system rollback..."
            
            # Restore all backed up files
            if [ -f "${BACKUP_DIR}.tar.gz" ]; then
                restore_backup "${BACKUP_DIR}"
            fi
            
            # Reset all configurations to defaults
            local config_files=(
                "/etc/ssh/sshd_config"
                "/etc/pam.d/common-password"
                "/etc/pam.d/common-auth"
                "/etc/login.defs"
                "/etc/sysctl.conf"
                "/etc/audit/auditd.conf"
            )
            
            for file in "${config_files[@]}"; do
                if [ -f "${file}.backup" ]; then
                    sudo cp "${file}.backup" "$file"
                    log "INFO" "Restored $file from backup"
                fi
            done
            
            # Restart all services
            systemctl daemon-reload
            systemctl restart ssh
            systemctl restart auditd
            systemctl restart ufw
            ;;
    esac
    
    # Verify system state after recovery
    verify_system_state
}

# Verify system state
verify_system_state() {
    log "INFO" "Verifying system state..."
    
    local issues=0
    
    # Check critical services
    local critical_services=("ssh" "networking")
    for service in "${critical_services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log "ERROR" "Critical service not running: $service"
            ((issues++))
        fi
    done
    
    # Check network connectivity
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        log "ERROR" "No network connectivity"
        ((issues++))
    fi
    
    # Check disk space
    local available_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1024 ]; then
        log "WARNING" "Low disk space: ${available_space}MB available"
    fi
    
    if [ $issues -eq 0 ]; then
        log "INFO" "System state verification passed"
    else
        log "ERROR" "System state verification failed with $issues issues"
    fi
    
    return $issues
}

# Main execution function with error handling
main() {
    local start_time=$(date +%s)
    local error_count=0

    # Parse command line arguments and set initial configuration
    parse_arguments "$@"

    # Create backup directory with secure permissions
    sudo install -d -m 0700 "$BACKUP_DIR" || handle_error "Failed to create backup directory" 10

    # Setup credential vault early
    setup_credential_vault

    # Validate environment and requirements
    check_requirements

    # Load configuration
    load_configuration

    # Validate configuration
    validate_configuration

    # Create backup
    if [ "${CONFIG[BACKUP_ENABLED]}" = "true" ]; then
        backup_files
    fi

    # Execute security hardening functions in sequence
    if ! $DRY_RUN; then
        local functions=(
            "configure_ssh_hardening"
            "setup_secure_boot"
            "setup_firewall"
            "setup_fail2ban"
            "setup_comprehensive_audit"
            "configure_password_policy"
            "configure_advanced_kernel_security"
            "setup_usb_control"
            "setup_file_integrity"
            "setup_mandatory_access_control"
            "harden_systemd_services"
            "setup_crowdsec"
            "setup_opkssh_auth"
        )

        for func in "${functions[@]}"; do
            # Skip function if disabled in config
            local config_key="${func^^}"
            config_key="${config_key#SETUP_}"
            config_key="${config_key#CONFIGURE_}"
            config_key="${config_key}_ENABLED"

            # Special handling for functions that don't follow naming convention
            case "$func" in
                "setup_comprehensive_audit")
                    config_key="AUDIT_ENABLED"
                    ;;
                "configure_ssh_hardening"|"setup_secure_boot"|"harden_systemd_services")
                    # These are always enabled in advanced security
                    config_key=""
                    ;;
                "configure_password_policy")
                    config_key="PASSWORD_POLICY_STRICT"
                    ;;
                "configure_advanced_kernel_security")
                    # Always enabled for kernel security
                    config_key=""
                    ;;
            esac

            if [[ -n "$config_key" && "${CONFIG[$config_key]}" == "false" ]]; then
                log "INFO" "Skipping $func (disabled in configuration)"
                continue
            fi

            log "INFO" "Executing $func..."
            if ! $func; then
                log "ERROR" "Failed to execute $func"
                ((error_count++))
                if [ $error_count -gt 3 ]; then
                    handle_error "Too many failures occurred during execution" 39
                fi
            fi
        done
        
        # Generate compliance report
        generate_compliance_report
    fi

    # Calculate execution time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Generate completion report
    generate_completion_report "$duration" "$error_count"

    log "INFO" "Security hardening completed in $duration seconds with $error_count errors"

    # Prompt for system restart if needed
    if ! $DRY_RUN && [ $error_count -eq 0 ]; then
        prompt_restart
    fi
}

# Execute main function with proper error handling
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'handle_error "Script interrupted" 40' INT TERM
    main "$@"
fi
