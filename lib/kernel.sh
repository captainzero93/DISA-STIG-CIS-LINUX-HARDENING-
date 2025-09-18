#!/bin/bash
# kernel security configuration

# Function to configure advanced kernel security
configure_advanced_kernel_security() {
  log INFO "Configuring advanced kernel security parameters..."

  local sysctl_conf="/etc/sysctl.d/99-advanced-security.conf"
  cat <<'EOF' | tee "$sysctl_conf" >/dev/null
# Advanced Kernel Security Parameters
# STIG/CIS Compliant Configuration
# Network Security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.forwarding = 0
# IPv6 Security (if enabled)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# Process Security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.panic_on_oops = 1
kernel.panic = 60
kernel.sysrq = 0
kernel.unprivileged_userns_clone = 0
kernel.kexec_load_disabled = 1
# Memory Protection
kernel.exec-shield = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# File System Security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
# Core Dump Restrictions
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false
# Process Restrictions
kernel.pid_max = 65536
kernel.threads-max = 30000
fs.file-max = 65535
# Additional Security Measures
kernel.panic_on_unrecovered_nmi = 1
kernel.panic_on_io_nmi = 1
kernel.modules_disabled = 0
EOF

  # Apply sysctl settings
  sysctl -p "$sysctl_conf" || handle_error "Failed to apply sysctl settings" 26

  log INFO "Advanced kernel security parameters configured successfully"
}
