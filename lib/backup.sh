#!/bin/bash
# backup and restore

# Function to create backup directory
create_backup_dir() {
  install -d -m 0700 "$BACKUP_DIR" || handle_error "Failed to create backup directory" 10
}

# Function to backup critical files
backup_critical_files() {
  local backup_dir="${1:-$BACKUP_DIR}"

  log INFO "Backing up critical system files to $backup_dir..."

  # Create backup directory
  mkdir -p "$backup_dir"
  chmod 700 "$backup_dir"

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
      mkdir -p "$(dirname "$backup_path")"
      cp -a "$file" "$backup_path" 2>/dev/null &&
        log DEBUG "Backed up: $file"
    fi
  done

  log INFO "Critical files backup completed"
}

# Enhanced backup function with integrity verification
backup_files() {
  log INFO "Creating system backup..."

  # Cleanup previous backups directory
  rm -rf "${BACKUP_DIR}"

  # Create backup directory with secure permissions
  install -d -m 0700 "$BACKUP_DIR" || handle_error "Failed to create backup directory" 10

  local files_to_backup=(
    "/etc/default/grub"
    "/etc/ssh/sshd_config"
    "/etc/pam.d/"
    "/etc/login.defs"
    "/etc/sysctl.conf"
    "/etc/sysctl.d/"
    "/etc/security/"
    "/etc/audit/"
    "/etc/modprobe.d/"
    "/etc/systemd/"
    "/etc/apparmor.d/"
    "/etc/fail2ban/"
    "/etc/ufw/"
    "/etc/sudoers"
    "/etc/sudoers.d/"
    "/etc/fstab"
    "/etc/hosts"
    "/etc/hosts.allow"
    "/etc/hosts.deny"
    "/etc/issue"
    "/etc/issue.net"
    "/etc/selinux/config"
    "/etc/apparmor/parser.conf"
    "/etc/default/ufw"
  )

  # Create backup manifest
  local manifest_file="${BACKUP_DIR}/manifest.txt"
  cat >"${manifest_file}" <<EOF
Backup Date: $(date)
Script Version: ${VERSION}
Profile: ${PROFILE}
System: $(lsb_release -ds)
Kernel: $(uname -r)
System Information: $(uname -a)
-------------------------------
EOF

  for item in "${files_to_backup[@]}"; do
    if [[ -e "${item}" ]]; then
      log DEBUG "Backing up ${item} in $BACKUP_DIR"
      cp -a "${item}" "${BACKUP_DIR}/" 2>/dev/null ||
        log WARNING "Failed to backup ${item}"

      # Generate checksum
      if [ -f "${BACKUP_DIR}${item}" ]; then
        log DEBUG "Generating checksum for ${BACKUP_DIR}${item}"
        sha256sum "${BACKUP_DIR}${item}" >>"${BACKUP_DIR}/checksums.txt"
      else
        log DEBUG "Generating checksum for file in ${BACKUP_DIR}/$(basename $item)"
        find "${BACKUP_DIR}/$(basename $item)" -type f -exec sha256sum {} \; >>"${BACKUP_DIR}/checksums.txt"
      fi

      # Add to manifest
      echo "Backed up: $item" >>"$manifest_file"
    fi
  done

  # Save current service states
  systemctl list-unit-files --state=enabled >"${BACKUP_DIR}/enabled_services.txt"
  sha256sum "${BACKUP_DIR}/enabled_services.txt" >>"${BACKUP_DIR}/checksums.txt"

  # Save installed packages
  dpkg -l >"${BACKUP_DIR}/installed_packages.txt"
  sha256sum "${BACKUP_DIR}/installed_packages.txt" >>"${BACKUP_DIR}/checksums.txt"

  # Save iptables rules
  sudo iptables-save >"${BACKUP_DIR}/iptables.rules" 2>/dev/null && sha256sum "${BACKUP_DIR}/iptables.rules" >>"${BACKUP_DIR}/checksums.txt" || true
  sudo ip6tables-save >"${BACKUP_DIR}/ip6tables.rules" 2>/dev/null && sha256sum "${BACKUP_DIR}/ip6tables.rules" >>"${BACKUP_DIR}/checksums.txt" || true

  # Create compressed archive of backup
  tar -czf "${BACKUP_DIR}.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")" ||
    handle_error "Failed to create backup archive" 11

  # Generate checksum for the archive
  sha256sum "${BACKUP_DIR}.tar.gz" >"${BACKUP_DIR}.tar.gz.sha256"

  log INFO "Backup created successfully in $BACKUP_DIR"
  log INFO "Backup archive created: ${BACKUP_DIR}.tar.gz"
}

# Restore from backup
restore_backup() {
  local backup_file

  if [[ -n "${1:-}" ]]; then
    backup_file="$1"
  else
    # Find most recent backup
    if [[ "$BACKUP_DIR" == "/root/security_backup_"* ]]; then
      backup_file=$(ls -t /root/security_backup_*.tar.gz 2>/dev/null | head -1)
    else
      backup_file="${BACKUP_DIR}.tar.gz"
    fi
  fi

  if [[ ! -f "${backup_file}" ]]; then
    log ERROR "No backup file found"
    return 1
  fi

  # Verify archive checksum
  if [ -f "${backup_file}.sha256" ]; then
    if ! sha256sum -c "${backup_file}.sha256" &>/dev/null; then
      handle_error "Backup archive integrity check failed" 13
    fi
  fi

  log INFO "Restoring from ${backup_file}..."

  local temp_dir=$(mktemp -d)
  tar -xzf "${backup_file}" -C "${temp_dir}" || handle_error "Failed to extract backup archive" 14

  # Verify individual file checksums
  if [ -f "${temp_dir}/checksums.txt" ]; then
    while IFS= read -r line; do
      local checksum=$(echo "$line" | cut -d' ' -f1)
      local file=$(echo "$line" | cut -d' ' -f3-)

      if ! echo "$checksum  $file" | sha256sum -c --quiet 2>/dev/null; then
        log WARNING "Checksum verification failed for: $file"
      fi
    done <"${temp_dir}/checksums.txt"
  fi

  local backup_source=$(find "${temp_dir}" -maxdepth 1 -type d -name "$(basename $BACKUP_DIR)" | head -1)

  if [[ -z "${backup_source}" ]]; then
    log ERROR "Invalid backup file structure"
    rm -rf "${temp_dir}"
    return 1
  fi

  # Restore files
  cp -a "${backup_source}"/etc/* /etc/ 2>/dev/null || true

  # Restore iptables rules
  if [[ -f "${backup_source}/iptables.rules" ]]; then
    iptables-restore <"${backup_source}/iptables.rules" 2>/dev/null || true
  fi

  if [[ -f "${backup_source}/ip6tables.rules" ]]; then
    ip6tables-restore <"${backup_source}/ip6tables.rules" 2>/dev/null || true
  fi

  rm -rf "${temp_dir}"

  log INFO "System restored from backup"
  log INFO "You may need to restart services for changes to take effect"
}
