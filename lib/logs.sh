#!/bin/bash

# Function to log messages
log() {
  local level=$1
  local message=$2
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  local log_message="[$level] $timestamp: $message"

  # Log to file
  echo "$log_message" | tee -a "$LOG_FILE" >/dev/null

  # Log to syslog
  logger -t "security_hardening" -p "local0.$level" "$message"

  # Display if verbose mode is enabled
  $VERBOSE && echo "$log_message"
}

# Function to handle errors
handle_error() {
  local error_message=$1
  local error_code=${2:-1}
  local report_file="${3:-$BACKUP_DIR/error_report_$(date +%s).txt}"
  local stack_trace=$(caller)
  log ERROR "Error Code $error_code: $error_message at line $stack_trace"

  # Create error report
  cat >"$report_file" <<EOF
Error Report - $(date)
Error Code: $error_code
Error Message: $error_message
Stack Trace: $stack_trace
System Information:
$(uname -a)
Last 10 lines of log:
$(tail -n 10 "$LOG_FILE")
EOF

  # Attempt recovery if possible
  if [ "$error_code" -eq 2 ]; then
    log INFO "Attempting recovery procedure..."
    perform_advanced_recovery "intermediate"
  fi

  exit "$error_code"
}
