#!/bin/bash
# CrowdSec setup

# Function to setup CrowdSec
setup_crowdsec() {
  if [ "${CONFIG[CROWDSEC_ENABLED]}" != "true" ]; then
    return 0
  fi

  log INFO "Configuring CrowdSec..."

  # Install CrowdSec
  if ! command -v cscli &>/dev/null; then
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    install_package "crowdsec"
  fi

  # Install CrowdSec firewall bouncer
  install_package "crowdsec-firewall-bouncer-iptables"

  # Register with CrowdSec community
  cscli capi register || log WARNING "Failed to register with CrowdSec community"

  # Install collections
  cscli collections install crowdsecurity/linux || true
  cscli collections install crowdsecurity/sshd || true
  cscli collections install crowdsecurity/iptables || true

  # Configure CrowdSec for UFW
  if [ "${CONFIG[FIREWALL_ENABLED]}" = "true" ]; then
    # Generate bouncer API key
    BOUNCER_KEY=$(sudo cscli bouncers add firewall-bouncer -o raw 2>/dev/null || echo "")
    if [ -n "$BOUNCER_KEY" ]; then
      # Configure the bouncer
      cat <<EOF | tee /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml >/dev/null
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
  systemctl enable crowdsec || handle_error "Failed to enable CrowdSec service" 45
  systemctl restart crowdsec || handle_error "Failed to start CrowdSec service" 46

  if [ -n "$BOUNCER_KEY" ]; then
    systemctl enable crowdsec-firewall-bouncer || handle_error "Failed to enable CrowdSec bouncer" 47
    systemctl restart crowdsec-firewall-bouncer || handle_error "Failed to start CrowdSec bouncer" 48
  fi

  log INFO "CrowdSec configuration completed successfully"
}
