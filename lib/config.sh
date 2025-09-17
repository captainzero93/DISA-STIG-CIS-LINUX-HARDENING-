#!/bin/bash
# handles command-line arguments, configuration loading, and profile management

# Default configuration
declare -A CONFIG=(
  [BACKUP_ENABLED]="true"
  [FIREWALL_ENABLED]="true"
  [SELINUX_ENABLED]="false"
  [APPARMOR_ENABLED]="true"
  [IPV6_ENABLED]="false"
  [AUDIT_ENABLED]="true"
  [AUTOMATIC_UPDATES]="true"
  [PASSWORD_POLICY_STRICT]="true"
  [USB_CONTROL_ENABLED]="true"
  [NETWORK_SEGMENTATION]="true"
  [FILE_INTEGRITY_MONITORING]="true"
  [CROWDSEC_ENABLED]="true"
  [OPKSSH_ENABLED]="true"
  [CREDENTIAL_VAULT_ENABLED]="true"
  [COMPLIANCE_REPORTING]="true"
  [SECURITY_EMAIL]=""
)

# Function to parse command line arguments
parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case $1 in
    --verbose | -v)
      VERBOSE=true
      shift
      ;;
    --dry-run | -d)
      DRY_RUN=true
      shift
      ;;
    --profile | -p)
      PROFILE="$2"
      shift 2
      ;;
    --config | -c)
      CONFIG_FILE="$2"
      shift 2
      ;;
    --email | -e)
      CONFIG[SECURITY_EMAIL]="$2"
      shift 2
      ;;
    --backup-dir | -b)
      BACKUP_DIR="$2"
      shift 2
      ;;
    --skip-backup | -sb)
      CONFIG[BACKUP_ENABLED]="false"
      shift
      ;;
    --skip-firewall | -sf)
      CONFIG[FIREWALL_ENABLED]="false"
      shift
      ;;
    --skip-audit | -sa)
      CONFIG[AUDIT_ENABLED]="false"
      shift
      ;;
    --enable-ipv6 | -6)
      CONFIG[IPV6_ENABLED]="true"
      shift
      ;;
    --restore | -r)
      if [ -n "${2:-}" ]; then
        if [ -e "$2" ]; then
          log DEBUG "Restoring backup $2"
          restore_backup "$2" || handle_error "Failed to restore backup $2" 1 "$SCRIPT_DIR/restore_security_hardening.log"
        else
          log DEBUG "Restoring default backup"
          restore_backup || handle_error "Failed to restore default backup" 1 "$SCRIPT_DIR/restore_security_hardening.log"
        fi
      fi
      exit $?
      ;;
    --help | -h)
      show_help
      exit 0
      ;;
    --version)
      echo "Security Hardening Script v${VERSION}"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
    esac
  done

  # Validate profile selection
  if [[ ! "$PROFILE" =~ ^(basic|intermediate|advanced)$ ]]; then
    echo "Error: Invalid profile selected: $PROFILE"
    echo "Valid profiles are: basic, intermediate, advanced"
    show_help
    exit 1
  fi
}

# Function to show help message
# TODO: add option to only generate report
show_help() {
  cat <<EOF
Security Hardening Script v${VERSION}
Usage: ${SCRIPT_NAME} [options]
Options:
    -v,  --verbose          Enable verbose output
    -d,  --dry-run          Show what would be done without making changes
    -p,  --profile PROFILE  Select hardening profile (basic|intermediate|advanced)
    -c,  --config FILE      Specify custom configuration file
    -e,  --email EMAIL      Set security email for reports
    -b,  --backup-dir DIR   Specify backup directory location
    -sb, --skip-backup      Skip backup creation
    -sf, --skip-firewall    Skip firewall configuration
    -sa, --skip-audit       Skip audit configuration
    -6,  --enable-ipv6      Enable IPv6 support
    -r,  --restore          Restore backup from specified directory or default
    --version               Show version information
    -h, --help              Show this help message
Profiles:
    basic        - Essential security hardening
    intermediate - Standard security hardening with monitoring
    advanced     - Complete security hardening with all features
Example:
    ${SCRIPT_NAME} --profile advanced --verbose --email admin@example.com
Configuration File Format:
    # Comments start with #
    KEY=value
    FIREWALL_ENABLED=true
    SELINUX_ENABLED=false
For more information, visit: ${REPO_URL}
EOF
}

# Function to load configuration from file
load_configuration() {
  if [ -f "$CONFIG_FILE" ]; then
    log INFO "Loading configuration from $CONFIG_FILE"
    while IFS='=' read -r key value; do
      # Skip comments and empty lines
      [[ "$key" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$key" ]] && continue

      # Clean the key and value
      key=$(echo "$key" | xargs)
      value=$(echo "$value" | xargs)

      # Remove quotes from value
      value=$(echo "$value" | tr -d '"' | tr -d "'")

      # Update configuration array
      CONFIG["$key"]="$value"
      log DEBUG "Loaded config: $key=$value"
    done <"$CONFIG_FILE"
    log INFO "Configuration loaded successfully"
  else
    log WARNING "Configuration file not found: $CONFIG_FILE, using defaults"
  fi

  # Apply profile-specific defaults
  apply_profile_defaults
}

# Function to apply profile-specific defaults
apply_profile_defaults() {
  case "$PROFILE" in
  "basic")
    CONFIG[USB_CONTROL_ENABLED]="false"
    CONFIG[NETWORK_SEGMENTATION]="false"
    CONFIG[FILE_INTEGRITY_MONITORING]="false"
    CONFIG[CROWDSEC_ENABLED]="false"
    CONFIG[OPKSSH_ENABLED]="false"
    CONFIG[COMPLIANCE_REPORTING]="false"
    ;;
  "intermediate")
    CONFIG[NETWORK_SEGMENTATION]="false"
    CONFIG[OPKSSH_ENABLED]="false"
    ;;
  "advanced")
    # All features enabled by default
    ;;
  esac
  log INFO "Applied $PROFILE profile defaults"
}
