#!/bin/bash
# Enhanced Linux Security Hardening Script v3.2
# Implements DISA STIG and CIS Compliance standards with comprehensive security controls
# Added CrowdSec, Cloudflare OPKSSH SSO, and advanced security features

set -euo pipefail # Exit on error, undefined variables, and pipe failures

# Global variables
readonly VERSION="3.2"

SCRIPT_NAME=$(basename "$0")
if [ "$SCRIPT_NAME" = "main.sh" ]; then
  readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  readonly LIB_DIR="$SCRIPT_DIR/lib"
  readonly DEPENDENCIES_FILE="$SCRIPT_DIR/dependencies.txt"
  readonly BACKUP_DIR="$SCRIPT_DIR/backups"
  readonly LOG_FILE="$SCRIPT_DIR/security_hardening.log"
  readonly CONFIG_FILE="$SCRIPT_DIR/conf/security_config.conf"
else
  readonly SCRIPT_DIR="/opt/security-hardening"
  readonly LIB_DIR="/opt/security-hardening/lib"
  readonly DEPENDENCIES_FILE="/opt/security-hardening/dependencies.txt"
  readonly BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
  readonly LOG_FILE="/var/log/security_hardening.log"
  readonly CONFIG_FILE="/etc/security-hardening/security_config.conf"
fi

# Default values
PROFILE="advanced" # Can be basic, intermediate, or advanced

# Loading dependencies
for file in $LIB_DIR/*.sh; do
  source "$file" 2>/dev/null || {
    echo "Error: Unable to source $file"
    exit 1
  }
done

# Main execution function
main() {
  local start_time=$(date +%s)
  local error_count=0

  # Check if running as root
  is_root

  # Parse command line arguments and set initial configuration
  parse_arguments "$@"

  # Create backup directory with secure permissions
  create_backup_dir

  # Setup credential vault early
  setup_credential_vault

  # Validate environment and requirements
  check_requirements

  # Load configuration
  load_configuration

  # Validate configuration
  validate_configuration

  # Create backup
  if [ "${CONFIG[BACKUP_ENABLED]}" = "true" ]; then
    backup_files
  fi

  # Execute security hardening functions in sequence
  if ! $DRY_RUN; then
    local functions=(
      "configure_ssh_hardening"
      "setup_secure_boot"
      "setup_firewall"
      "setup_fail2ban"
      "setup_comprehensive_audit"
      "configure_password_policy"
      "configure_advanced_kernel_security"
      "setup_usb_control"
      "setup_file_integrity"
      "setup_mandatory_access_control"
      "harden_systemd_services"
      "setup_crowdsec"
      "setup_opkssh_auth"
    )

    for func in "${functions[@]}"; do
      # Skip function if disabled in config
      local config_key="${func^^}"
      config_key="${config_key#SETUP_}"
      config_key="${config_key#CONFIGURE_}"
      config_key="${config_key}_ENABLED"

      # Special handling for functions that don't follow naming convention
      case "$func" in
      "setup_comprehensive_audit")
        config_key="AUDIT_ENABLED"
        ;;
      "configure_ssh_hardening" | "setup_secure_boot" | "harden_systemd_services")
        # These are always enabled in advanced security
        config_key=""
        ;;
      "configure_password_policy")
        config_key="PASSWORD_POLICY_STRICT"
        ;;
      "configure_advanced_kernel_security")
        # Always enabled for kernel security
        config_key=""
        ;;
      esac

      if [[ -n "$config_key" && "${CONFIG[$config_key]}" == "false" ]]; then
        log INFO "Skipping $func (disabled in configuration)"
        continue
      fi

      log INFO "Executing $func..."
      if ! $func; then
        log ERROR "Failed to execute $func"
        ((error_count++))
        if [ $error_count -gt 3 ]; then
          handle_error "Too many failures occurred during execution" 39
        fi
      fi
    done

    # Generate compliance report
    generate_compliance_report
  fi

  # Calculate execution time
  local end_time=$(date +%s)
  local duration=$((end_time - start_time))

  # Generate completion report
  generate_completion_report "$duration" "$error_count"

  log INFO "Security hardening completed in $duration seconds with $error_count errors"

  # Prompt for system restart if needed
  if ! $DRY_RUN && [ $error_count -eq 0 ]; then
    prompt_restart
  fi
}

# Execute main function with proper error handling
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  trap 'handle_error "Script interrupted" 40' INT TERM
  main "$@"
fi
