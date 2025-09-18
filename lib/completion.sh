#!/bin/bash

# Enhanced completion report generation
generate_completion_report() {
  local duration=$1
  local error_count=$2
  local report_file="${BACKUP_DIR}/completion_report.txt"

  log INFO "Generating completion report..."

  {
    echo "=================================="
    echo "Security Hardening Completion Report"
    echo "=================================="
    echo ""
    echo "Date: $(date)"
    echo "Duration: $duration seconds"
    echo "Error Count: $error_count"
    echo "Profile: $PROFILE"
    echo "Dry Run: $DRY_RUN"
    echo ""
    echo "System Information:"
    echo "-------------------"
    echo "Hostname: $(hostname -f)"
    echo "OS: $(lsb_release -ds 2>/dev/null || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo ""

    # Configuration summary
    echo "Configuration Summary:"
    echo "----------------------"
    for key in "${!CONFIG[@]}"; do
      echo "$key: ${CONFIG[$key]}"
    done | sort
    echo ""

    # Service status
    echo "Service Status:"
    echo "---------------"
    local services=("ssh" "ufw" "fail2ban" "auditd" "apparmor" "crowdsec")
    for service in "${services[@]}"; do
      if systemctl list-unit-files 2>/dev/null | grep -q "${service}.service"; then
        local status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
        echo "$service: $status"
      fi
    done
    echo ""

    # Firewall status
    if command -v ufw &>/dev/null; then
      echo "Firewall Status:"
      echo "----------------"
      sudo ufw status numbered 2>/dev/null | head -20 || echo "Firewall status unavailable"
      echo ""
    fi

    # Audit status
    if command -v auditctl &>/dev/null; then
      echo "Audit Rules Summary:"
      echo "--------------------"
      local rule_count=$(sudo auditctl -l 2>/dev/null | wc -l)
      echo "Total audit rules: $rule_count"
      echo ""
    fi

    # Failed services
    echo "Failed Services:"
    echo "----------------"
    systemctl list-units --state=failed --no-pager 2>/dev/null || echo "No failed services"
    echo ""

    # Recent security events
    echo "Recent Security Events:"
    echo "-----------------------"
    if [ -f /var/log/auth.log ]; then
      echo "Last 5 authentication failures:"
      grep "authentication failure" /var/log/auth.log 2>/dev/null | tail -5 || echo "None found"
    fi
    echo ""

    # Disk usage
    echo "Disk Usage:"
    echo "-----------"
    df -h / /var /tmp 2>/dev/null | grep -v "^Filesystem"
    echo ""

    # Recommendations
    echo "Post-Installation Recommendations:"
    echo "----------------------------------"
    echo "1. Review and test all security configurations"
    echo "2. Update all user passwords to meet new policy requirements"
    echo "3. Configure monitoring and alerting systems"
    echo "4. Schedule regular security audits"
    echo "5. Test backup and recovery procedures"

    if [ $error_count -gt 0 ]; then
      echo ""
      echo "⚠ WARNING: $error_count errors occurred during installation"
      echo "Please review the log file: $LOG_FILE"
    fi

  } >"$report_file"

  # Display report to console if verbose
  if $VERBOSE; then
    cat "$report_file"
  fi

  # Send report via email if configured
  if [ -n "${CONFIG[SECURITY_EMAIL]}" ]; then
    if command -v mail &>/dev/null; then
      mail -s "Security Hardening Report - $(hostname)" "${CONFIG[SECURITY_EMAIL]}" <"$report_file"
      log INFO "Report sent to ${CONFIG[SECURITY_EMAIL]}"
    else
      log WARNING "Mail command not available, cannot send report"
    fi
  fi

  log INFO "Completion report saved to: $report_file"
}
