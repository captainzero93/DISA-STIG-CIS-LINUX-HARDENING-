#!/bin/bash
# Cloudflare OPKSSH SSO setup

# Function to setup Cloudflare OPKSSH SSO
setup_opkssh_auth() {
  if [ "${CONFIG[OPKSSH_ENABLED]}" != "true" ]; then
    return 0
  fi

  log INFO "Configuring Cloudflare OPKSSH SSO for SSH authentication..."

  # Create directory for OPKSSH
  mkdir -p /etc/opkssh
  chmod 755 /etc/opkssh

  # Download and install OPKSSH binaries
  log INFO "Downloading OPKSSH binaries..."
  if [ ! -f /usr/local/bin/opk-ssh-auth-helper ]; then
    curl -sL https://github.com/cloudflare/opk/releases/latest/download/opk-ssh-auth-helper -o /usr/local/bin/opk-ssh-auth-helper
    chmod +x /usr/local/bin/opk-ssh-auth-helper
  fi

  # Download Cloudflare CA keys
  log INFO "Downloading Cloudflare CA keys..."
  curl -s https://developers.cloudflare.com/cdn-cgi/access/certificates/opk_ca_keys.pem -o /etc/ssh/opk_trusted_user_ca_keys.pem
  chmod 644 /etc/ssh/opk_trusted_user_ca_keys.pem

  # Configure SSH server to use OPKSSH
  cat <<'EOF' | tee /etc/ssh/sshd_config.d/60-opkssh.conf >/dev/null
# Cloudflare OPKSSH SSO configuration
AuthorizedKeysCommand /usr/local/bin/opk-ssh-auth-helper
AuthorizedKeysCommandUser nobody
TrustedUserCAKeys /etc/ssh/opk_trusted_user_ca_keys.pem
EOF

  # Prompt for Cloudflare Zero Trust configuration
  echo "Please enter your Cloudflare Zero Trust team domain (example.cloudflareaccess.com):"
  read -r team_domain
  validate_input "$team_domain" "domain"

  echo "Please enter your SSH application domain (ssh.example.com):"
  read -r app_domain
  validate_input "$app_domain" "domain"

  # Create OPKSSH configuration file
  cat <<EOF | tee /etc/opkssh/config.json >/dev/null
{
    "app_domain": "${app_domain}",
    "team_domain": "${team_domain}",
    "service_token_file": "/etc/opkssh/service_token",
    "log_level": "info"
}
EOF

  # Secure the configuration file
  chmod 644 /etc/opkssh/config.json

  # Prompt for service token
  echo "Please enter your Cloudflare Access service token (will be hidden):"
  read -s service_token
  echo

  # Encrypt and store service token
  encrypt_sensitive_data "$service_token" "/etc/opkssh/service_token"

  # Verify and restart SSH
  sshd -t || handle_error "SSH configuration is invalid" 50
  systemctl restart ssh || handle_error "Failed to restart SSH service" 51

  log INFO "Cloudflare OPKSSH SSO configured successfully"
}
