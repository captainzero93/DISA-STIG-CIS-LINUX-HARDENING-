#!/bin/bash
# compliance reporting

# Function to generate compliance report
generate_compliance_report() {
  if [ "${CONFIG[COMPLIANCE_REPORTING]}" != "true" ]; then
    return 0
  fi

  log INFO "Generating compliance report..."
  local report_file="${BACKUP_DIR}/compliance_report_$(date +%Y%m%d_%H%M%S).html"

  cat <<'EOF' >"$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>Security Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .metadata { color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Compliance Report</h1>
EOF

  # Add system information
  echo "<div class='metadata'>" >>"$report_file"
  echo "<p><strong>Hostname:</strong> $(hostname -f)</p>" >>"$report_file"
  echo "<p><strong>Report Date:</strong> $(date)</p>" >>"$report_file"
  echo "<p><strong>OS:</strong> $(lsb_release -ds)</p>" >>"$report_file"
  echo "<p><strong>Kernel:</strong> $(uname -r)</p>" >>"$report_file"
  echo "<p><strong>Profile:</strong> $PROFILE</p>" >>"$report_file"
  echo "</div>" >>"$report_file"

  # Add compliance summary
  echo "<div class='summary'>" >>"$report_file"
  echo "<h2>Compliance Summary</h2>" >>"$report_file"
  local total_checks=0
  local passed_checks=0

  # Add compliance checks table
  echo "<table>" >>"$report_file"
  echo "<tr><th>Control ID</th><th>Category</th><th>Description</th><th>Status</th></tr>" >>"$report_file"

  # SSH Configuration Checks
  check_compliance_item "SSH-1" "SSH" "SSH Protocol Version 2" "grep -q 'Protocol 2' /etc/ssh/sshd_config"
  check_compliance_item "SSH-2" "SSH" "SSH Root Login Disabled" "grep -qE '^PermitRootLogin (no|prohibit-password)' /etc/ssh/sshd_config"
  check_compliance_item "SSH-3" "SSH" "SSH Password Authentication Disabled" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"

  # Firewall Checks
  check_compliance_item "FW-1" "Firewall" "Firewall Enabled" "ufw status | grep -q 'Status: active'"
  check_compliance_item "FW-2" "Firewall" "Default Deny Incoming" "ufw status verbose | grep -q 'Default: deny (incoming)'"

  # Audit Checks
  check_compliance_item "AUD-1" "Audit" "Audit Daemon Running" "systemctl is-active auditd"
  check_compliance_item "AUD-2" "Audit" "Audit Rules Configured" "auditctl -l | grep -q time-change"

  # Password Policy Checks
  check_compliance_item "PWD-1" "Password" "Password Complexity Enforced" "grep -q 'minlen = 15' /etc/security/pwquality.conf"
  check_compliance_item "PWD-2" "Password" "Password History Enforced" "grep -q 'remember=24' /etc/pam.d/common-password"
  check_compliance_item "PWD-3" "Password" "Account Lockout Configured" "grep -q 'pam_faillock.so' /etc/pam.d/common-auth"

  # Kernel Security Checks
  check_compliance_item "KERN-1" "Kernel" "ASLR Enabled" "sysctl kernel.randomize_va_space | grep -q '= 2'"
  check_compliance_item "KERN-2" "Kernel" "SYN Cookies Enabled" "sysctl net.ipv4.tcp_syncookies | grep -q '= 1'"
  check_compliance_item "KERN-3" "Kernel" "IP Forwarding Disabled" "sysctl net.ipv4.conf.all.forwarding | grep -q '= 0'"

  # MAC Checks
  if [ "${CONFIG[APPARMOR_ENABLED]}" = "true" ]; then
    check_compliance_item "MAC-1" "MAC" "AppArmor Enabled" "systemctl is-active apparmor"
    check_compliance_item "MAC-2" "MAC" "AppArmor Enforcing" "aa-status | grep -q 'profiles are in enforce mode'"
  fi

  # File Integrity Checks
  if [ "${CONFIG[FILE_INTEGRITY_MONITORING]}" = "true" ]; then
    check_compliance_item "FIM-1" "File Integrity" "AIDE Installed" "which aide"
    check_compliance_item "FIM-2" "File Integrity" "AIDE Database Initialized" "[ -f /var/lib/aide/aide.db ]"
  fi

  echo "</table>" >>"$report_file"

  # Calculate compliance percentage
  local compliance_percentage=0
  if [ $total_checks -gt 0 ]; then
    compliance_percentage=$(((passed_checks * 100) / total_checks))
  fi

  echo "<p><strong>Total Checks:</strong> $total_checks</p>" >>"$report_file"
  echo "<p><strong>Passed:</strong> <span class='pass'>$passed_checks</span></p>" >>"$report_file"
  echo "<p><strong>Failed:</strong> <span class='fail'>$((total_checks - passed_checks))</span></p>" >>"$report_file"
  echo "<p><strong>Compliance Rate:</strong> ${compliance_percentage}%</p>" >>"$report_file"
  echo "</div>" >>"$report_file"
  echo "</div></body></html>" >>"$report_file"

  log INFO "Compliance report generated: $report_file"

  # Send report via email if configured
  if [ -n "${CONFIG[SECURITY_EMAIL]}" ]; then
    mail -a "Content-Type: text/html" -s "Security Compliance Report - $(hostname)" "${CONFIG[SECURITY_EMAIL]}" <"$report_file"
    log INFO "Compliance report sent to ${CONFIG[SECURITY_EMAIL]}"
  fi
}

# Helper function for compliance checks
check_compliance_item() {
  local control_id="$1"
  local category="$2"
  local description="$3"
  local check_command="$4"
  local status="fail"
  local status_class="fail"

  ((total_checks++))

  if eval "$check_command" &>/dev/null; then
    status="PASS"
    status_class="pass"
    ((passed_checks++))
  else
    status="FAIL"
    status_class="fail"
  fi

  echo "<tr><td>$control_id</td><td>$category</td><td>$description</td><td class='$status_class'>$status</td></tr>" >>"$report_file"
}
