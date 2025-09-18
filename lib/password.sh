#!/bin/bash

# Enhanced password policy configuration (STIG & CIS Compliance)
configure_password_policy() {
  log INFO "Configuring password and authentication policies..."

  # Install required packages
  install_package "libpam-pwquality"
  install_package "libpam-faillock"

  # Configure PAM password quality requirements
  local pwquality_conf="/etc/security/pwquality.conf"
  cat <<'EOF' | sudo tee "$pwquality_conf" >/dev/null
# Password length and complexity (STIG/CIS compliant)
minlen = 15
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 4

# Password history and reuse
remember = 24

# Password strength
difok = 8
dictcheck = 1
enforcing = 1

# Reject username in password
usercheck = 1

# Reject character sequences
maxsequence = 3

# Reject repeated characters
maxrepeat = 3

# Minimum length of different characters
maxclassrepeat = 4

# Reject simple passwords
gecoscheck = 1
EOF

  # Configure PAM password settings
  local pam_password="/etc/pam.d/common-password"
  cat <<'EOF' | sudo tee "$pam_password" >/dev/null
# PAM password configuration with enhanced security
password    requisite     pam_pwquality.so retry=3
password    required      pam_pwhistory.so remember=24 use_authtok
password    [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512 shadow remember=24
password    requisite     pam_deny.so
password    required      pam_permit.so
EOF

  # Configure account lockout
  local pam_auth="/etc/pam.d/common-auth"
  cat <<'EOF' | sudo tee "$pam_auth" >/dev/null
# PAM authentication with account lockout
auth    required      pam_env.so
auth    required      pam_faillock.so preauth silent audit deny=3 unlock_time=1800 even_deny_root root_unlock_time=1800
auth    [success=1 default=bad]  pam_unix.so
auth    [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1800 even_deny_root root_unlock_time=1800
auth    sufficient    pam_faillock.so authsucc audit deny=3 unlock_time=1800 even_deny_root root_unlock_time=1800
auth    requisite     pam_deny.so
auth    required      pam_permit.so
auth    optional      pam_cap.so
EOF

  # Configure login.defs
  local login_defs="/etc/login.defs"
  sudo cp "$login_defs" "${login_defs}.backup"
  cat <<'EOF' | sudo tee "$login_defs" >/dev/null
# Password aging controls (STIG/CIS compliant)
PASS_MAX_DAYS   60
PASS_MIN_DAYS   1
PASS_WARN_AGE   7

# Password length restrictions
PASS_MIN_LEN    15

# Password hashing
ENCRYPT_METHOD SHA512
SHA_CRYPT_MIN_ROUNDS 5000
SHA_CRYPT_MAX_ROUNDS 500000

# Account restrictions
CREATE_HOME     yes
UMASK          077
USERGROUPS_ENAB yes

# Login restrictions
LOGIN_RETRIES   3
LOGIN_TIMEOUT   60
FAILLOG_ENAB    yes
LOG_UNKFAIL_ENAB yes
SYSLOG_SU_ENAB  yes
SYSLOG_SG_ENAB  yes

# User/Group ID ranges
UID_MIN         1000
UID_MAX         60000
GID_MIN         1000
GID_MAX         60000
SYS_UID_MIN     100
SYS_UID_MAX     999
SYS_GID_MIN     100
SYS_GID_MAX     999

# Additional security
CHFN_RESTRICT   rwh
DEFAULT_HOME    no
USERDEL_CMD     /usr/sbin/userdel_local
EOF

  log INFO "Password and authentication policies configured successfully"
}
