#!/bin/bash

# Enhanced fail2ban configuration
setup_fail2ban() {
  log INFO "Configuring Fail2Ban..."

  install_package "fail2ban"

  # Create custom configuration
  local f2b_config="/etc/fail2ban/jail.local"
  cat <<'EOF' | sudo tee "$f2b_config" >/dev/null
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
  cat <<'EOF' | sudo tee "$dos_filter" >/dev/null
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

  # Create custom filter for SSH DDoS
  local ssh_ddos_filter="/etc/fail2ban/filter.d/sshd-ddos.conf"
  cat <<'EOF' | sudo tee "$ssh_ddos_filter" >/dev/null
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

  log INFO "Fail2Ban configuration completed"
}
