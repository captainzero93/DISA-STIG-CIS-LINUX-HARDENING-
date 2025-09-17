 #!/bin/bash

# Function to harden systemd services
harden_systemd_services() {
  log INFO "Hardening systemd services..."

  # Create drop-in directories for service hardening
  local services=("ssh" "cron" "rsyslog")

  for service in "${services[@]}"; do
    if systemctl list-unit-files | grep -q "${service}.service"; then
      sudo mkdir -p "/etc/systemd/system/${service}.service.d/"

      # Apply security hardening
      cat <<EOF | sudo tee "/etc/systemd/system/${service}.service.d/hardening.conf" >/dev/null
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
        echo "ReadWritePaths=/var/log /var/run" | sudo tee -a "/etc/systemd/system/${service}.service.d/hardening.conf" >/dev/null
      fi
    fi
  done

  sudo systemctl daemon-reload

  log INFO "Systemd services hardened successfully"
}

# Function to verify system state
verify_system_state() {
  log INFO "Verifying system state..."
  local issues=0

  # Check critical services
  local critical_services=("ssh" "networking")

  for service in "${critical_services[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
      log ERROR "Critical service not running: $service"
      ((issues++))
    fi
  done

  # Check network connectivity
  if ! ping -c 1 8.8.8.8 &>/dev/null; then
    log ERROR "No network connectivity"
    ((issues++))
  fi

  # Check disk space
  local available_space=$(df -m / | awk 'NR==2 {print $4}')

  if [ "$available_space" -lt 1024 ]; then
    log WARNING "Low disk space: ${available_space}MB available"
  fi

  if [ $issues -eq 0 ]; then
    log INFO "System state verification passed"
  else
    log ERROR "System state verification failed with $issues issues"
  fi

  return $issues
}

# Function to check listening services
check_listening_services() {
  log INFO "Checking for listening services..."

  if command -v ss &>/dev/null; then
    local listening_tcp=$(sudo ss -tlnp | grep LISTEN | wc -l)
    local listening_udp=$(sudo ss -ulnp | wc -l)

    log INFO "Found $listening_tcp TCP and $listening_udp UDP listening services"

    # Check for services on dangerous ports
    local dangerous_ports="23 135 139 445 3389"
    for port in $dangerous_ports; do
      if sudo ss -tlnp | grep -q ":$port "; then
        log WARNING "Service listening on potentially dangerous port: $port"
      fi
    done
  fi
}
