#!/bin/bash

# Function to check disk encryption status
check_disk_encryption() {
  log INFO "Checking disk encryption status..."

  local encrypted=false

  # Check for LUKS encryption
  if command -v cryptsetup &>/dev/null; then
    if lsblk -o NAME,FSTYPE 2>/dev/null | grep -q "crypto_LUKS"; then
      encrypted=true
      log INFO "LUKS disk encryption detected"
    fi

    # Check for active encrypted volumes
    if sudo cryptsetup status 2>/dev/null | grep -q "is active"; then
      encrypted=true
      log INFO "Active encrypted volumes detected"
    fi
  fi

  # Check for eCryptfs (home directory encryption)
  if [ -d "$HOME/.ecryptfs" ]; then
    encrypted=true
    log INFO "eCryptfs home directory encryption detected"
  fi

  if ! $encrypted; then
    log WARNING "Disk encryption is not active"
    log WARNING "Consider enabling full disk encryption for enhanced security"
    return 1
  fi

  return 0
}

# Setup encrypted credential vault
setup_credential_vault() {
  if [ "${CONFIG[CREDENTIAL_VAULT_ENABLED]}" != "true" ]; then
    return 0
  fi

  log INFO "Setting up encrypted credential vault..."

  # Install age encryption tool
  if ! command -v age &>/dev/null; then
    wget -qO- https://github.com/FiloSottile/age/releases/download/v1.2.1/age-v1.2.1-linux-amd64.tar.gz | tar xz -C /usr/local/bin age/age age/age-keygen --strip=1
    chmod +x /usr/local/bin/age /usr/local/bin/age-keygen
  fi

  # Generate encryption key if not exists
  if [ ! -f /root/.config/security/vault.key ]; then
    mkdir -p /root/.config/security
    age-keygen -o /root/.config/security/vault.key 2>/dev/null
    chmod 600 /root/.config/security/vault.key
  fi

  log INFO "Credential vault configured successfully"
}

# Encrypt sensitive data function
encrypt_sensitive_data() {
  local data="$1"
  local output_file="$2"

  if [ -f /root/.config/security/vault.key ]; then
    echo "$data" | age -r "$(age-keygen -y </root/.config/security/vault.key 2>/dev/null)" >"$output_file"
    chmod 600 "$output_file"
  else
    # Fallback to basic protection
    echo "$data" >"$output_file"
    chmod 600 "$output_file"
  fi
}
