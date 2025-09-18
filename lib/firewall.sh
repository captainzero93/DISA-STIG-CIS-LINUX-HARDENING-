#!/bin/bash
# firewall setup and hardening

# Function to setup firewall
setup_firewall() {
  log INFO "Configuring advanced firewall settings..."

  # Install required packages
  install_package "ufw"
  install_package "iptables-persistent"

  # Basic UFW configuration
  ufw default deny incoming || handle_error "Failed to set UFW default incoming policy" 15
  ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy" 16

  # Configure rate limiting for SSH
  ufw limit ssh comment 'Allow SSH with rate limiting' || handle_error "Failed to configure SSH in UFW" 17

  # Configure common services based on profile
  if [[ "$PROFILE" == "advanced" || "$PROFILE" == "intermediate" ]]; then
    # Allow only essential services
    ufw allow 22/tcp comment 'SSH'
    ufw allow 123/udp comment 'NTP'

    # Add HTTP/HTTPS only if needed
    read -p "Allow HTTP/HTTPS traffic? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      ufw allow 80/tcp comment 'HTTP'
      ufw allow 443/tcp comment 'HTTPS'
    fi
  fi

  # Configure advanced rules
  if [ "${CONFIG[NETWORK_SEGMENTATION]}" = "true" ]; then
    # Allow internal network communication
    ufw allow from 192.168.0.0/16 to any comment 'Internal network' || log WARNING "Failed to configure internal network rules"
    ufw allow from 10.0.0.0/8 to any comment 'Private network' || log WARNING "Failed to configure private network rules"
  fi

  # IPv6 configuration
  if [ "${CONFIG[IPV6_ENABLED]}" = "true" ]; then
    log INFO "Configuring IPv6 firewall rules..."
    sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
  else
    log INFO "Disabling IPv6 firewall rules..."
    sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
  fi

  # Enable logging
  ufw logging on || handle_error "Failed to enable UFW logging" 18
  ufw logging high

  # Apply rules
  if ! $DRY_RUN; then
    ufw --force enable || handle_error "Failed to enable UFW" 19

    # Verify firewall status
    if !ufw status verbose | grep -q "Status: active"; then
      handle_error "Firewall is not active after configuration" 20
    fi
  fi

  log INFO "Firewall configuration completed"
}
