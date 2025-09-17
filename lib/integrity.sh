#!/bin/bash
# file integrity monitoring

# Function to setup file integrity monitoring
setup_file_integrity() {
  if [ "${CONFIG[FILE_INTEGRITY_MONITORING]}" != "true" ]; then
    return 0
  fi

  log INFO "Configuring file integrity monitoring..."

  # Install AIDE
  install_package "aide"
  install_package "aide-common"

  # Configure AIDE
  cat <<'EOF' | tee /etc/aide/aide.conf >/dev/null
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
  log INFO "Initializing AIDE database (this may take several minutes)..."
  aideinit --yes --force || handle_error "Failed to initialize AIDE database" 29

  # Setup daily integrity checks
  cat <<'EOF' | tee /etc/cron.daily/aide-check >/dev/null
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
  chmod +x /etc/cron.daily/aide-check

  # Configure AIDE log rotation
  cat <<'EOF' | tee /etc/logrotate.d/aide >/dev/null
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

  log INFO "File integrity monitoring configured successfully"
}
