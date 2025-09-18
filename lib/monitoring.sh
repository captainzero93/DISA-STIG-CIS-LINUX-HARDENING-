 #!/bin/bash

# Function to setup log monitoring
setup_log_monitoring() {
  log INFO "Setting up log monitoring..."

  # Create log monitoring script
  cat <<'EOF' | sudo tee /usr/local/bin/security-log-monitor >/dev/null
#!/bin/bash
# Security log monitoring script

# Monitor auth logs for failures
tail -F /var/log/auth.log | while read line; do
    if echo "$line" | grep -q "authentication failure"; then
        logger -t security-monitor "Authentication failure detected: $line"
    fi
    if echo "$line" | grep -q "FAILED su"; then
        logger -t security-monitor "Failed su attempt detected: $line"
    fi
done
EOF

  sudo chmod +x /usr/local/bin/security-log-monitor

  # Create systemd service for log monitoring
  cat <<'EOF' | sudo tee /etc/systemd/system/security-log-monitor.service >/dev/null
[Unit]
Description=Security Log Monitor
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-log-monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable security-log-monitor 2>/dev/null
  sudo systemctl start security-log-monitor 2>/dev/null

  log INFO "Log monitoring configured"
}
