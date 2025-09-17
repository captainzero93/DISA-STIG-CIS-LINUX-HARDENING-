#!/bin/bash
# SELinux and AppArmor configuration
# NOTE: mac for mandatory access control

# Function to setup mandatory access control
setup_mandatory_access_control() {
  log INFO "Configuring Mandatory Access Control..."

  if [ "${CONFIG[SELINUX_ENABLED]}" = "true" ]; then
    # Setup SELinux
    install_package "selinux-basics"
    install_package "selinux-policy-default"
    install_package "selinux-utils"

    # Configure SELinux policy
    selinux-activate || handle_error "Failed to activate SELinux" 30

    # Set SELinux to enforcing mode
    setenforce 1 2>/dev/null || log WARNING "Failed to set SELinux to enforcing mode (reboot required)"

    # Configure SELinux policy in config file
    sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

  elif [ "${CONFIG[APPARMOR_ENABLED]}" = "true" ]; then
    # Setup AppArmor
    install_package "apparmor"
    install_package "apparmor-utils"
    install_package "apparmor-profiles"
    install_package "apparmor-profiles-extra"

    # Enable AppArmor
    systemctl enable apparmor || handle_error "Failed to enable AppArmor" 31
    systemctl restart apparmor || handle_error "Failed to start AppArmor" 32

    # Set all profiles to enforce mode
    aa-enforce /etc/apparmor.d/* 2>/dev/null || log WARNING "Failed to enforce some AppArmor profiles"

    # Create custom AppArmor profile for critical services
    create_custom_apparmor_profiles
  fi

  log INFO "Mandatory Access Control configured successfully"
}

# Function to create custom AppArmor profiles
create_custom_apparmor_profiles() {
  # Custom profile for SSH
  cat <<'EOF' | tee /etc/apparmor.d/usr.sbin.sshd >/dev/null
#include <tunables/global>
profile sshd /usr/sbin/sshd {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/authentication>
    #include <abstractions/openssl>
    capability net_bind_service,
    capability chown,
    capability fowner,
    capability kill,
    capability setgid,
    capability setuid,
    capability sys_chroot,
    capability sys_resource,
    capability sys_tty_config,
    capability audit_write,
    capability dac_override,
    capability dac_read_search,
    /usr/sbin/sshd mr,
    /etc/ssh/** r,
    /etc/ssh/sshd_config r,
    /etc/ssh/ssh_host_* r,
    /var/log/auth.log w,
    /var/log/syslog w,
    /var/run/sshd.pid w,
    /var/run/sshd/** rw,
    /dev/ptmx rw,
    /dev/pts/* rw,
    /dev/urandom r,
    /etc/localtime r,
    /etc/pam.d/* r,
    /etc/security/** r,
    /proc/*/fd/ r,
    /proc/sys/kernel/ngroups_max r,
    /run/utmp rk,
    @{HOME}/.ssh/authorized_keys r,
    # Add support for OPKSSH auth helper
    /usr/local/bin/opk-ssh-auth-helper PUx,
    /etc/ssh/opk_trusted_user_ca_keys.pem r,
    /etc/opkssh/** r,
    # Allow execution of shells for user sessions
    /bin/bash PUx,
    /bin/sh PUx,
    /usr/bin/zsh PUx,
}
EOF

  # Reload AppArmor profiles
  apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd 2>/dev/null || log WARNING "Failed to load custom SSH AppArmor profile"
  service apparmor reload 2>/dev/null || log WARNING "Failed to reload AppArmor profiles"
}
