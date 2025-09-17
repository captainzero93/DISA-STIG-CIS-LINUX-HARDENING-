#!/bin/bash
# system recovery

# Function to perform system recovery
perform_recovery() {
  log INFO "Attempting system recovery..."

  # Check if backup exists
  if [ -d "$BACKUP_DIR" ]; then
    log INFO "Restoring from backup: $BACKUP_DIR"

    if declare -f restore_backup >/dev/null; then
      restore_backup "$BACKUP_DIR"
    else
      log ERROR "restore_backup function not found"
      return 1
    fi
  else
    log WARNING "No backup found at $BACKUP_DIR, cannot perform recovery"
    return 1
  fi

  # Restart critical services
  local critical_services=("sshd" "ssh" "networking" "systemd-resolved")

  for service in "${critical_services[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "${service}.service"; then
      if ! systemctl is-active --quiet "$service"; then
        systemctl restart "$service" 2>/dev/null || log WARNING "Failed to restart $service"
      fi
    fi
  done

  log INFO "Recovery attempt completed"
  return 0
}

# Function to perform advanced recovery
perform_advanced_recovery() {
  local recovery_level="${1:-basic}"

  log INFO "Initiating advanced recovery procedure (level: $recovery_level)..."

  case "$recovery_level" in
  "basic")
    # Restore critical services
    local critical_services=("ssh" "networking" "systemd-resolved")

    for service in "${critical_services[@]}"; do
      if ! systemctl is-active --quiet "$service"; then
        systemctl restart "$service" 2>/dev/null || log WARNING "Failed to restart $service"
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
        systemctl restart "$service" 2>/dev/null || log WARNING "Failed to restart $service"
      fi
    done
    ;;
  "full")
    # Complete system rollback
    log INFO "Performing full system rollback..."

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
        cp "${file}.backup" "$file"
        log INFO "Restored $file from backup"
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
