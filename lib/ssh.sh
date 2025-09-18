#!/bin/bash

# Function to apply advanced SSH hardening
configure_ssh_hardening() {
  log INFO "Applying advanced SSH hardening..."

  # Backup original SSH config
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

  # Create SSH user group if it doesn't exist
  groupadd -f ssh-users

  # Apply hardened SSH configuration
  cat <<'EOF' | tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null
# Enhanced SSH Security Configuration
# STIG/CIS Compliant Settings
# Protocol and Port
Protocol 2
Port 22
# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60
# Modern Cryptography (FIPS 140-2 compliant where possible)
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
# Security Features
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
# Logging
SyslogFacility AUTH
LogLevel VERBOSE
# Access Control
AllowGroups ssh-users
DenyUsers root
MaxStartups 10:30:60
Banner /etc/ssh/banner
# Additional Security
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
RekeyLimit 1G 1h
EOF

  # Create SSH banner
  cat <<'EOF' | tee /etc/ssh/banner >/dev/null
##############################################################
#                                                            #
#  Unauthorized access to this system is strictly prohibited #
#  All access attempts are logged and monitored             #
#  Violators will be prosecuted to the fullest extent       #
#                                                            #
##############################################################
EOF

  # Generate strong host keys if needed
  ssh-keygen -A -f /etc/ssh

  # Remove weak host keys
  rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key* 2>/dev/null

  # Set proper permissions
  chmod 600 /etc/ssh/ssh_host_*_key
  chmod 644 /etc/ssh/ssh_host_*_key.pub

  # Verify SSH configuration
  sshd -t || handle_error "SSH configuration is invalid" 50

  # Restart SSH service
  systemctl restart ssh || handle_error "Failed to restart SSH service" 51

  log INFO "SSH hardening completed successfully"
} 
