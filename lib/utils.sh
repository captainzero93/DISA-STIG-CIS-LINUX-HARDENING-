#!/bin/bash
# Provides common functions and helpers for the main hardening script

VERBOSE=false
DRY_RUN=false

# Function to check if the script is run as root
is_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root."
    exit 1
  fi
}

# Function to validate input
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

# Function to create a secure temporary directory
create_secure_temp_dir() {
  local temp_dir=$(mktemp -d /tmp/hardening.XXXXXX)
  if [ ! -d "$temp_dir" ]; then
    log ERROR "Failed to create temporary directory"
    return 1
  fi

  # Set secure permissions
  chmod 700 "$temp_dir"

  # Register cleanup on exit
  trap "rm -rf $temp_dir" EXIT

  echo "$temp_dir"
}

# Function to check system entropy
check_system_entropy() {
  local min_entropy=2000
  local current_entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)

  log INFO "Current system entropy: $current_entropy bits"

  if [ "$current_entropy" -lt "$min_entropy" ]; then
    log WARNING "Low system entropy: $current_entropy (minimum recommended: $min_entropy)"

    # Install haveged if not already installed
    if ! command -v haveged &>/dev/null; then
      log INFO "Installing haveged to improve entropy..."
      if install_package "haveged"; then
        sudo systemctl enable haveged 2>/dev/null
        sudo systemctl start haveged 2>/dev/null

        # Wait a moment for entropy to build
        sleep 2

        # Check entropy again
        current_entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo 0)
        log INFO "Entropy after installing haveged: $current_entropy bits"
      fi
    else
      # Ensure haveged is running
      if ! systemctl is-active --quiet haveged; then
        sudo systemctl start haveged 2>/dev/null
      fi
    fi
  else
    log INFO "System entropy is adequate"
  fi
}

# Configuration validation function
validate_configuration() {
  log INFO "Validating configuration before applying..."

  local validation_errors=0

  # Check for conflicting settings
  if [[ "${CONFIG[SELINUX_ENABLED]}" == "true" && "${CONFIG[APPARMOR_ENABLED]}" == "true" ]]; then
    log ERROR "Cannot enable both SELinux and AppArmor simultaneously"
    ((validation_errors++))
  fi

  # Validate network settings
  if [[ "${CONFIG[IPV6_ENABLED]}" == "false" ]] && ip -6 addr show 2>/dev/null | grep -q "inet6"; then
    log WARNING "IPv6 is disabled but IPv6 addresses are configured"
  fi

  # Check service dependencies
  if [[ "${CONFIG[AUDIT_ENABLED]}" == "true" ]] && ! systemctl list-unit-files 2>/dev/null | grep -q "auditd.service"; then
    log WARNING "Audit enabled but auditd service not available - will install"
  fi

  # Validate email configuration if reporting is enabled
  if [[ "${CONFIG[COMPLIANCE_REPORTING]}" == "true" && -n "${CONFIG[SECURITY_EMAIL]}" ]]; then
    validate_input "${CONFIG[SECURITY_EMAIL]}" "email"
  fi

  if [ $validation_errors -gt 0 ]; then
    handle_error "Configuration validation failed with $validation_errors errors" 104
  fi

  log INFO "Configuration validation passed"
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
      log INFO "System will restart in 1 minute..."
      echo "System will restart in 1 minute. Press Ctrl+C to cancel."
      sudo shutdown -r +1 "Security hardening complete - system restart"
    else
      log WARNING "Please remember to restart the system to apply all changes"
      echo ""
      echo "⚠ IMPORTANT: Restart required to apply all security changes"
      echo "  Run 'sudo reboot' when ready"
    fi
  else
    log INFO "No restart required - all changes applied successfully"
  fi
}

# Function to validate file permissions
validate_file_permissions() {
  local file=$1
  local expected_perms=$2
  local expected_owner=$3
  local expected_group=${4:-$expected_owner}

  if [ ! -e "$file" ]; then
    log WARNING "File does not exist: $file"
    return 1
  fi

  local current_perms=$(stat -c %a "$file" 2>/dev/null)
  local current_owner=$(stat -c %U "$file" 2>/dev/null)
  local current_group=$(stat -c %G "$file" 2>/dev/null)

  local changes_made=false

  if [ "$current_perms" != "$expected_perms" ]; then
    log INFO "Fixing permissions for $file: $current_perms -> $expected_perms"
    sudo chmod "$expected_perms" "$file"
    changes_made=true
  fi

  if [ "$current_owner" != "$expected_owner" ]; then
    log INFO "Fixing ownership for $file: $current_owner -> $expected_owner"
    sudo chown "$expected_owner" "$file"
    changes_made=true
  fi

  if [ "$current_group" != "$expected_group" ]; then
    log INFO "Fixing group for $file: $current_group -> $expected_group"
    sudo chgrp "$expected_group" "$file"
    changes_made=true
  fi

  if $changes_made; then
    log INFO "Permissions validated and corrected for: $file"
  fi

  return 0
}

# Function to check for security updates
check_security_updates() {
  log INFO "Checking for security updates..."

  # Update package cache
  sudo apt-get update &>/dev/null

  # Check for security updates
  local updates=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l)

  if [ "$updates" -gt 0 ]; then
    log WARNING "$updates security updates available"

    if [ "${CONFIG[AUTOMATIC_UPDATES]}" = "true" ]; then
      log INFO "Installing security updates..."
      sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade 2>/dev/null
    else
      log INFO "Run 'sudo apt-get upgrade' to install updates"
    fi
  else
    log INFO "System is up to date"
  fi
}

# Function to verify network connectivity
verify_network_connectivity() {
  log INFO "Verifying network connectivity..."

  local test_hosts=("8.8.8.8" "1.1.1.1" "9.9.9.9")
  local connected=false

  for host in "${test_hosts[@]}"; do
    if ping -c 1 -W 2 "$host" &>/dev/null; then
      connected=true
      log INFO "Network connectivity verified (via $host)"
      break
    fi
  done

  if ! $connected; then
    log ERROR "No network connectivity detected"
    return 1
  fi

  # Check DNS resolution
  if ! nslookup google.com &>/dev/null; then
    log WARNING "DNS resolution may not be working properly"
  fi

  return 0
}

# Function to validate system integrity
validate_system_integrity() {
  log INFO "Validating system integrity..."

  local integrity_issues=0

  # Check for rootkits
  if command -v rkhunter &>/dev/null; then
    log INFO "Running rootkit check..."
    sudo rkhunter --check --skip-keypress --quiet 2>/dev/null
    if [ $? -ne 0 ]; then
      log WARNING "Potential rootkit detected - review rkhunter log"
      ((integrity_issues++))
    fi
  fi

  # Check for suspicious processes
  local suspicious_procs=$(ps aux | grep -E '(nc|netcat|/tmp/|/dev/shm/)' | grep -v grep | wc -l)
  if [ "$suspicious_procs" -gt 0 ]; then
    log WARNING "$suspicious_procs potentially suspicious processes detected"
    ((integrity_issues++))
  fi

  # Check for unauthorized SUID files
  local unauthorized_suid=$(find / -type f -perm -4000 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' | wc -l)
  if [ "$unauthorized_suid" -gt 0 ]; then
    log WARNING "$unauthorized_suid unauthorized SUID files detected"
    ((integrity_issues++))
  fi

  if [ $integrity_issues -eq 0 ]; then
    log INFO "System integrity check passed"
  else
    log WARNING "System integrity check found $integrity_issues issues"
  fi

  return $integrity_issues
}
