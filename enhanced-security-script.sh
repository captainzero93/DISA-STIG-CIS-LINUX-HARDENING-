#!/bin/bash
# Enhanced Linux Security Hardening Script v3.1
# Implements DISA STIG and CIS Compliance standards with comprehensive security controls
# Added CrowdSec and Cloudflare OPKSSH SSO support

# Global Variables and Configuration
VERSION="3.1"
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
        perform_recovery
    fi

    exit "$error_code"
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
    local required_tools=("wget" "curl" "apt" "systemctl" "openssl" "auditd" "mailutils")
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
        "/etc/login.defs"
        "/etc/sysctl.conf"
        "/etc/security/limits.conf"
        "/etc/audit/auditd.conf"
        "/etc/selinux/config"
        "/etc/apparmor/parser.conf"
        "/etc/default/ufw"
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
    if ! sha256sum -c "${backup_path}.tar.gz.sha256"; then
        handle_error "Backup archive integrity check failed" 13
    fi

    # Extract archive
    sudo tar -xzf "${backup_path}.tar.gz" -C / || handle_error "Failed to extract backup archive" 14

    # Verify individual file checksums
    while IFS= read -r line; do
        local checksum=$(echo "$line" | cut -d' ' -f1)
        local file=$(echo "$line" | cut -d' ' -f3-)

        if ! echo "$checksum  $file" | sha256sum -c --quiet; then
            log "WARNING" "Checksum verification failed for: $file"
        fi
    done < "${backup_path}/checksums.txt"

    log "INFO" "System restore completed from $backup_path"
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

    # Configure common services
    declare -A services=(
        ["http"]="80"
        ["https"]="443"
        ["dns"]="53"
        ["ntp"]="123"
    )

    for service in "${!services[@]}"; do
        local port="${services[$service]}"
        sudo ufw allow "$port/tcp" comment "Allow $service" || log "WARNING" "Failed to allow $service in UFW"
    done

    # Configure advanced rules
    if [ "${CONFIG[NETWORK_SEGMENTATION]}" = "true" ]; then
        # Allow internal network communication
        sudo ufw allow from 192.168.0.0/16 to any || log "WARNING" "Failed to configure internal network rules"

        # Configure DMZ if applicable
        if [ -n "$DMZ_NETWORK" ]; then
            sudo ufw allow from "$DMZ_NETWORK" to any port 80 || log "WARNING" "Failed to configure DMZ rules"
            sudo ufw allow from "$DMZ_NETWORK" to any port 443 || log "WARNING" "Failed to configure DMZ rules"
        fi
    fi

    # IPv6 configuration
    if [ "${CONFIG[IPV6_ENABLED]}" = "true" ]; then
        log "INFO" "Configuring IPv6 firewall rules..."
        sudo ufw allow in on lo || log "WARNING" "Failed to allow IPv6 loopback traffic"
        sudo ufw allow out on lo || log "WARNING" "Failed to allow IPv6 loopback traffic"
        sudo ufw deny in from ::/0 || log "WARNING" "Failed to deny all incoming IPv6 traffic"
    else
        log "INFO" "Disabling IPv6 firewall rules..."
        sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
    fi

    # Enable logging
    sudo ufw logging on || handle_error "Failed to enable UFW logging" 18

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
    cat << EOF | sudo tee "$f2b_config" > /dev/null
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
banaction = %(banaction_allports)s
ignoreip = 127.0.0.1/8 ::1

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
EOF

    # Create custom filter for HTTP DoS protection
    local dos_filter="/etc/fail2ban/filter.d/http-get-dos.conf"
    cat << EOF | sudo tee "$dos_filter" > /dev/null
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

    # Enable and start service
    sudo systemctl enable fail2ban || handle_error "Failed to enable Fail2Ban service" 21
    sudo systemctl start fail2ban || handle_error "Failed to start Fail2Ban service" 22

    # Verify service status
    if ! sudo systemctl is-active --quiet fail2ban; then
        handle_error "Fail2Ban service is not running after configuration" 23
    fi

    log "INFO" "Fail2Ban configuration completed"
}

# Enhanced audit configuration with STIG compliance
setup_audit() {
    log "INFO" "Configuring advanced audit system..."

    install_package "auditd"

    # Configure main audit settings
    local audit_conf="/etc/audit/auditd.conf"
    cat << EOF | sudo tee "$audit_conf" > /dev/null
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
##TCP_listen_queue = 5
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF

    # Configure audit rules (STIG & CIS Compliance)
    local audit_rules="/etc/audit/rules.d/audit.rules"
    cat << EOF | sudo tee "$audit_rules" > /dev/null
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

# Network Environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# System Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Login/Logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

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
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Module Loading/Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,delete_module -k modules

# Make audit config immutable
-e 2
EOF

    # Restart audit daemon
    sudo service auditd restart || handle_error "Failed to restart audit daemon" 24

    # Verify audit is working
    if ! sudo auditctl -l &>/dev/null; then
        handle_error "Audit system is not functioning properly after configuration" 25
    fi

    log "INFO" "Audit system configured successfully"
}

# Enhanced password policy configuration (STIG & CIS Compliance)
configure_password_policy() {
    log "INFO" "Configuring password and authentication policies..."

    # Install required packages
    install_package "libpam-pwquality"

    # Configure PAM password quality requirements
    local pwquality_conf="/etc/security/pwquality.conf"
    cat << EOF | sudo tee "$pwquality_conf" > /dev/null
# Password length and complexity
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
EOF

    # Configure PAM password and authentication settings
    local pam_password="/etc/pam.d/common-password"
    cat << EOF | sudo tee "$pam_password" > /dev/null
password    requisite     pam_pwquality.so retry=3
password    required      pam_pwhistory.so remember=24
password    [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512 shadow remember=24
password    requisite     pam_deny.so
password    required      pam_permit.so
EOF

    # Configure login.defs
    local login_defs="/etc/login.defs"
    cat << EOF | sudo tee "$login_defs" > /dev/null
# Password aging controls
PASS_MAX_DAYS   60
PASS_MIN_DAYS   1
PASS_WARN_AGE   7

# Password length restrictions
PASS_MIN_LEN    15

# Password hashing
ENCRYPT_METHOD SHA512

# Account restrictions
CREATE_HOME     yes
UMASK          077
USERGROUPS_ENAB yes

# Login restrictions
LOGIN_RETRIES   3
LOGIN_TIMEOUT   60
EOF

    # Configure account lockout
    local pam_auth="/etc/pam.d/common-auth"
    cat << EOF | sudo tee "$pam_auth" > /dev/null
auth    required      pam_env.so
auth    required      pam_faillock.so preauth silent audit deny=3 unlock_time=1800
auth    [success=1 default=bad]  pam_unix.so
auth    [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1800
auth    sufficient    pam_faillock.so authsucc audit deny=3 unlock_time=1800
auth    requisite     pam_deny.so
auth    required      pam_permit.so
EOF

    log "INFO" "Password and authentication policies configured successfully"
}

# Enhanced sysctl security configuration (STIG & CIS Compliance)
configure_sysctl() {
    log "INFO" "Configuring kernel security parameters..."

    local sysctl_conf="/etc/sysctl.d/99-security.conf"
    cat << EOF | sudo tee "$sysctl_conf" > /dev/null
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

# IPv6 Security (if enabled)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Process Security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.panic_on_oops = 1
kernel.panic = 60
kernel.sysrq = 0

# File System Security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2

# Additional Security Measures
kernel.core_uses_pid = 1
kernel.panic_on_unrecovered_nmi = 1
kernel.panic_on_io_nmi = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
EOF

    # Apply sysctl settings
    sudo sysctl -p "$sysctl_conf" || handle_error "Failed to apply sysctl settings" 26

    log "INFO" "Kernel security parameters configured successfully"
}

# Function to setup USB device control
setup_usb_control() {
    log "INFO" "Configuring USB device control..."

    # Install required packages
    install_package "usbguard"

    # Generate initial policy
    sudo usbguard generate-policy > /etc/usbguard/rules.conf

    # Configure USBGuard daemon
    cat << EOF | sudo tee /etc/usbguard/usbguard-daemon.conf > /dev/null
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

    # Start and enable USBGuard service
    sudo systemctl enable usbguard || handle_error "Failed to enable USBGuard service" 27
    sudo systemctl start usbguard || handle_error "Failed to start USBGuard service" 28

    log "INFO" "USB device control configured successfully"
}

# Function to setup file integrity monitoring
setup_file_integrity() {
    log "INFO" "Configuring file integrity monitoring..."

    # Install AIDE
    install_package "aide"

    # Configure AIDE
    cat << EOF | sudo tee /etc/aide/aide.conf > /dev/null
# AIDE configuration
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
database_new=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# Monitoring rules
Selection all = R+a+sha512+xattrs+acl+selinux
Selection etc = R+a+sha512+xattrs+acl+selinux
Selection bin = R+a+sha512+xattrs+acl+selinux
Selection sbin = R+a+sha512+xattrs+acl+selinux
Selection usrbin = R+a+sha512+xattrs+acl+selinux
Selection usrsbin = R+a+sha512+xattrs+acl+selinux

# Directories to monitor
/boot   all
/bin    bin
/sbin   sbin
/usr/bin usrbin
/usr/sbin usrsbin
/etc    etc
/usr/lib all
/usr/lib64 all

# Log files (growing logfiles)
!/var/log/.*
!/var/log/aide/.*

# Temporary directories
!/tmp/.*
!/var/tmp/.*
EOF

    # Initialize AIDE database
    sudo aideinit || handle_error "Failed to initialize AIDE database" 29

    # Setup daily integrity checks
    cat << EOF | sudo tee /etc/cron.daily/aide-check > /dev/null
#!/bin/sh
/usr/bin/aide --check | mail -s "AIDE Integrity Check Report" root
EOF

# Make AIDE check script executable
sudo chmod +x /etc/cron.daily/aide-check

# Configure AIDE log rotation
cat << EOF | sudo tee /etc/logrotate.d/aide > /dev/null
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

        # Configure SELinux policy
        sudo selinux-activate || handle_error "Failed to activate SELinux" 30

        # Set SELinux to enforcing mode
        sudo setenforce 1 || log "WARNING" "Failed to set SELinux to enforcing mode"

        # Configure SELinux policy in config file
        sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

    elif [ "${CONFIG[APPARMOR_ENABLED]}" = "true" ]; then
        # Setup AppArmor
        install_package "apparmor"
        install_package "apparmor-utils"
        install_package "apparmor-profiles"

        # Enable AppArmor
        sudo systemctl enable apparmor || handle_error "Failed to enable AppArmor" 31
        sudo systemctl start apparmor || handle_error "Failed to start AppArmor" 32

        # Set all profiles to enforce mode
        sudo aa-enforce /etc/apparmor.d/* || log "WARNING" "Failed to enforce some AppArmor profiles"

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

    /usr/sbin/sshd mr,
    /etc/ssh/* r,
    /etc/ssh/sshd_config r,
    /etc/ssh/ssh_host_* r,
    /var/log/auth.log w,
    /var/log/syslog w,
    /var/run/sshd.pid w,
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
}
EOF

    # Reload AppArmor profiles
    sudo find /etc/apparmor.d/ -type f -exec grep -L '^#include' {} \; -exec sudo apparmor_parser -r {} \;
    sudo service apparmor reload  || log "WARNING" "Failed to reload AppArmor profiles"
}

# Function to setup secure boot configuration
setup_secure_boot() {
    log "INFO" "Configuring secure boot settings..."

    # Check if system is UEFI-based
    if [ -d "/sys/firmware/efi" ]; then
        # Install required packages
        install_package "grub-efi-amd64-signed"
        install_package "shim-signed"

        # Configure GRUB security settings
        local grub_config="/etc/default/grub"

        # Backup original configuration
        sudo cp "$grub_config" "${grub_config}.backup"

        # Update GRUB security parameters
        sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash module.sig_enforce=1 lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 slab_nomerge vsyscall=none"/' "$grub_config"

        # Set GRUB password
        local grub_password
        read -s -p "Enter GRUB password: " grub_password
        echo

        # Generate GRUB password hash
        local password_hash
        password_hash=$(echo -e "$grub_password\n$grub_password" | grub-mkpasswd-pbkdf2 | awk '/hash of/ {print $NF}')

        # Add password protection to GRUB
        cat << EOF | sudo tee /etc/grub.d/40_custom > /dev/null
#!/bin/sh

tail -f -n +3 \$0

set superusers="admin"
password_pbkdf2 admin $password_hash
EOF

        # Update GRUB configuration
        sudo update-grub || handle_error "Failed to update GRUB configuration" 33

        # Secure boot directory permissions
        sudo chmod 700 /boot/grub
        sudo chmod 600 /boot/grub/grub.cfg

        log "INFO" "Secure boot configured successfully"
    else
        log "WARNING" "System is not UEFI-based, skipping secure boot configuration"
    fi
}

# Function to setup network segmentation
setup_network_segmentation() {
    log "INFO" "Configuring network segmentation..."

    # Install required packages
    install_package "vlan"
    install_package "bridge-utils"

    # Load required kernel modules
    sudo modprobe 8021q || handle_error "Failed to load VLAN module" 34
    echo "8021q" | sudo tee -a /etc/modules

    # Configure network interfaces for segmentation
    cat << EOF | sudo tee /etc/network/interfaces.d/vlans > /dev/null
# Management VLAN
auto eth0.100
iface eth0.100 inet static
    address 192.168.100.1
    netmask 255.255.255.0
    vlan-raw-device eth0

# Production VLAN
auto eth0.200
iface eth0.200 inet static
    address 192.168.200.1
    netmask 255.255.255.0
    vlan-raw-device eth0

# DMZ VLAN
auto eth0.300
iface eth0.300 inet static
    address 192.168.300.1
    netmask 255.255.255.0
    vlan-raw-device eth0
EOF

    # Configure network isolation rules
    setup_network_isolation_rules

    log "INFO" "Network segmentation configured successfully"
}

# Function to setup network isolation rules
setup_network_isolation_rules() {
    # Create iptables rules for network isolation
    cat << 'EOF' | sudo tee /etc/iptables/rules.v4 > /dev/null
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow established connections
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow internal management VLAN
-A INPUT -i eth0.100 -j ACCEPT
-A FORWARD -i eth0.100 -o eth0.200 -j ACCEPT
-A FORWARD -i eth0.100 -o eth0.300 -j ACCEPT

# Restrict DMZ access
-A FORWARD -i eth0.300 -o eth0.200 -j DROP
-A FORWARD -i eth0.300 -o eth0.100 -j DROP

# Allow specific services from production to DMZ
-A FORWARD -i eth0.200 -o eth0.300 -p tcp --dport 80 -j ACCEPT
-A FORWARD -i eth0.200 -o eth0.300 -p tcp --dport 443 -j ACCEPT

COMMIT
EOF

    # Apply iptables rules
    sudo iptables-restore < /etc/iptables/rules.v4 || handle_error "Failed to apply iptables rules" 35

    # Make iptables rules persistent
    sudo netfilter-persistent save || handle_error "Failed to save iptables rules" 36
}

# Function to setup security monitoring
setup_security_monitoring() {
    log "INFO" "Configuring security monitoring..."

    # Install monitoring tools
    install_package "ossec-hids-server"
    install_package "logwatch"
    install_package "rkhunter"
    install_package "chkrootkit"

    # Configure OSSEC
    cat << EOF | sudo tee /var/ossec/etc/ossec.conf > /dev/null
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>root@localhost</email_to>
    <smtp_server>localhost</smtp_server>
    <email_from>ossec@$(hostname -f)</email_from>
  </global>

  <syscheck>
    <frequency>7200</frequency>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
  </syscheck>

  <rootcheck>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
  </rootcheck>

  <alerts>
    <log_alert_level>1</log_alert_level>
    <email_alert_level>7</email_alert_level>
  </alerts>
</ossec_config>
EOF

    # Configure rkhunter
    cat << EOF | sudo tee /etc/rkhunter.conf.local > /dev/null
MAIL-ON-WARNING=root@localhost
MAIL_CMD=mail -s "[rkhunter] Warnings found for \${HOST_NAME}"
SCRIPTWHITELIST=/usr/bin/lwp-request
ALLOWHIDDENDIR=/dev/.udev
ALLOWHIDDENDIR=/dev/.static
ALLOWHIDDENDIR=/dev/.initramfs
EOF

    # Configure automated security scans
    cat << 'EOF' | sudo tee /etc/cron.daily/security-scan > /dev/null
#!/bin/bash
# Daily security scan script

# Run rkhunter check
/usr/bin/rkhunter --check --skip-keypress --report-warnings-only

# Run chkrootkit
/usr/sbin/chkrootkit | grep -v "not infected" | grep -v "nothing found" | grep -v "nothing detected"

# Run AIDE check
/usr/bin/aide --check

# Check for failed login attempts
grep "Failed password" /var/log/auth.log | tail -n 10

# Check for modified system files
find /bin /usr/bin /sbin /usr/sbin -type f -mtime -1 -ls

# Send daily security report
/usr/sbin/logwatch --output mail --mailto root --detail high
EOF

    # Make security scan script executable
    sudo chmod +x /etc/cron.daily/security-scan

    # Start OSSEC service
    sudo systemctl enable ossec || handle_error "Failed to enable OSSEC service" 37
    sudo systemctl start ossec || handle_error "Failed to start OSSEC service" 38

    log "INFO" "Security monitoring configured successfully"
}

# Function to setup CrowdSec
setup_crowdsec() {
    log "INFO" "Configuring CrowdSec..."

    # Install CrowdSec
    log "INFO" "Installing CrowdSec..."
    if ! command -v cscli &>/dev/null; then
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
        install_package "crowdsec"
    else
        log "INFO" "CrowdSec is already installed"
    fi

    # Install CrowdSec firewall bouncer
    log "INFO" "Installing CrowdSec firewall bouncer..."
    install_package "crowdsec-firewall-bouncer"

    # Configure CrowdSec
    log "INFO" "Configuring CrowdSec..."

    # Enable community sharing
    log "INFO" "Registering with CrowdSec community..."
    sudo cscli capi register || log "WARNING" "Failed to register with CrowdSec community"

    # Install collections for common threats
    log "INFO" "Installing CrowdSec collections..."
    sudo cscli collections install crowdsecurity/linux
    sudo cscli collections install crowdsecurity/sshd
    sudo cscli collections install crowdsecurity/http-cve

    # Install parsers for common services
    log "INFO" "Installing CrowdSec parsers..."
    sudo cscli parsers install crowdsecurity/whitelists
    sudo cscli parsers install crowdsecurity/sshd
    sudo cscli parsers install crowdsecurity/nginx
    sudo cscli parsers install crowdsecurity/apache2

    # Configure CrowdSec to work with local firewall
    if [ "${CONFIG[FIREWALL_ENABLED]}" = "true" ]; then
        log "INFO" "Configuring CrowdSec with local firewall..."
        # Add a bouncer for the firewall
        BOUNCER_KEY=$(sudo cscli bouncers add firewall-bouncer -o raw)

        # Configure the bouncer
        cat << EOF | sudo tee /etc/crowdsec/bouncers/firewall-bouncer.yaml > /dev/null
api_url: http://127.0.0.1:8080/
api_key: ${BOUNCER_KEY}
update_frequency: 10s
blacklists_ipv4: /etc/crowdsec/blacklists/ipv4.deny
blacklists_ipv6: /etc/crowdsec/blacklists/ipv6.deny
daemon: true
log_mode: file
log_dir: /var/log/
log_level: info
EOF
    fi

    # Integrate with UFW if enabled
    if [ "${CONFIG[FIREWALL_ENABLED]}" = "true" ]; then
        log "INFO" "Integrating CrowdSec with UFW..."
        cat << EOF | sudo tee /etc/crowdsec/bouncers/firewall-bouncer-ufw.yaml > /dev/null
mode: ufw
piddir: /var/run/
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
EOF
    fi

    # Start and enable CrowdSec service
    sudo systemctl enable crowdsec || handle_error "Failed to enable CrowdSec service" 45
    sudo systemctl restart crowdsec || handle_error "Failed to start CrowdSec service" 46

    # Start and enable bouncer
    sudo systemctl enable cs-firewall-bouncer || handle_error "Failed to enable CrowdSec firewall bouncer" 47
    sudo systemctl restart cs-firewall-bouncer || handle_error "Failed to start CrowdSec firewall bouncer" 48

    # Verify CrowdSec status
    if ! sudo systemctl is-active --quiet crowdsec; then
        handle_error "CrowdSec service is not running after configuration" 49
    fi

    log "INFO" "CrowdSec configuration completed successfully"
}

# Function to setup Cloudflare OPKSSH SSO for SSH
setup_opkssh_auth() {
    log "INFO" "Configuring Cloudflare OPKSSH SSO for SSH authentication..."

    # Install required packages
    install_package "curl"
    install_package "openssh-server"
    install_package "jq"

    # Create directory for OPKSSH
    sudo mkdir -p /etc/opkssh
    sudo chmod 755 /etc/opkssh

    # Download and install OPKSSH binaries
    log "INFO" "Downloading OPKSSH binaries..."
    sudo curl -sL https://github.com/cloudflare/opk/releases/latest/download/opk-ssh-auth-helper -o /usr/local/bin/opk-ssh-auth-helper
    sudo chmod +x /usr/local/bin/opk-ssh-auth-helper

    # Download Cloudflare CA keys
    log "INFO" "Downloading Cloudflare CA keys..."
    sudo curl -s https://developers.cloudflare.com/cdn-cgi/access/certificates/opk_ca_keys.pem -o /etc/ssh/opk_trusted_user_ca_keys.pem
    sudo chmod 644 /etc/ssh/opk_trusted_user_ca_keys.pem

    # Configure SSH server to use OPKSSH
    log "INFO" "Configuring SSH to use OPKSSH..."
    cat << EOF | sudo tee /etc/ssh/sshd_config.d/60-opkssh.conf > /dev/null
# Cloudflare OPKSSH SSO configuration
AuthorizedKeysCommand /usr/local/bin/opk-ssh-auth-helper
AuthorizedKeysCommandUser nobody
TrustedUserCAKeys /etc/ssh/opk_trusted_user_ca_keys.pem
EOF

    # Create OPKSSH configuration
    log "INFO" "Creating OPKSSH configuration..."

    # Prompt for Cloudflare Zero Trust configuration
    echo "Please enter your Cloudflare Zero Trust team domain (example.cloudflareaccess.com):"
    read -r team_domain

    echo "Please enter your SSH application domain (ssh.example.com):"
    read -r app_domain

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
    echo "$service_token" | sudo tee /etc/opkssh/service_token > /dev/null
    sudo chmod 600 /etc/opkssh/service_token

    # Verify and restart SSH
    log "INFO" "Verifying SSH configuration..."
    sudo sshd -t || handle_error "SSH configuration is invalid" 50

    # Restart SSH service
    sudo systemctl restart ssh || handle_error "Failed to restart SSH service" 51

    log "INFO" "Cloudflare OPKSSH SSO for SSH configured successfully"
    log "INFO" "Users can now authenticate using Cloudflare Zero Trust identity"
}

# Main execution function with error handling
main() {
    local start_time=$(date +%s)
    local error_count=0

    # Parse command line arguments and set initial configuration
    parse_arguments "$@"

    # Create backup directory with secure permissions
    sudo install -d -m 0700 "$BACKUP_DIR" || handle_error "Failed to create backup directory" 10

    # Validate environment and requirements
    check_requirements

    # Create backup
    backup_files

    # Load configuration
    load_configuration

    # Execute security hardening functions in sequence
    if ! $DRY_RUN; then
        local functions=(
            "setup_firewall"
            "setup_fail2ban"
            "setup_audit"
            "configure_password_policy"
            "configure_sysctl"
            "setup_usb_control"
            "setup_file_integrity"
            "setup_mandatory_access_control"
            "setup_secure_boot"
            "setup_network_segmentation"
            "setup_security_monitoring"
            "setup_crowdsec"
            "setup_opkssh_auth"
        )

        for func in "${functions[@]}"; do
            # Skip function if disabled in config
            local config_key="${func^^}"
            config_key="${config_key#SETUP_}"
            config_key="${config_key}_ENABLED"

            if [[ -n "${CONFIG[$config_key]}" && "${CONFIG[$config_key]}" == "false" ]]; then
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
