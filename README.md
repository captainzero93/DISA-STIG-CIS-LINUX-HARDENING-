# Linux Security Hardening Script (Enhanced)

## Overview
This project provides a comprehensive, configurable security hardening solution for Ubuntu and Debian-based systems. It implements **DISA STIG** and **CIS Benchmark** controls while offering advanced features for intrusion prevention, access control, compliance reporting, and recovery.

**Version 3.2** introduces a modular structure, improved error handling with automatic recovery, credential vault integration, and built-in compliance reporting — making the script more robust, auditable, and enterprise-ready.

## Features
- Comprehensive system hardening aligned with DISA STIG & CIS standards  
- Advanced firewall configuration with network segmentation and DMZ support  
- Intrusion prevention with Fail2Ban and CrowdSec  
- Enhanced logging (local and syslog) with detailed error reports  
- Automated backup with checksum validation and integrity-verified restore  
- USB device control with USBGuard  
- Strong password policies and account lockouts  
- Credential Vault integration for secure secret handling  
- Automated compliance reporting and drift detection  
- Modular structure (`lib/utils.sh`) for maintainability  

## Requirements
- Ubuntu 18.04+ or Debian 12.0+  
- Minimum 5GB free disk space, 1GB RAM  
- Root or sudo access  
- Active internet connection  

## Quick Start

# Clone the repository
git clone https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-.git

# Change to the script directory
cd DISA-STIG-CIS-LINUX-HARDENING-

# Make the script executable
chmod +x enhanced-security-script.sh

# Run with default settings
sudo ./enhanced-security-script.sh

Optional flags:

    --verbose: Enable detailed output

    --dry-run: Preview changes without applying

    --restore: Restore from a backup

Configuration

The script uses a configuration file (security_config.conf) for customization. Example configurations for stricter and user-friendly setups are included in the repository.

Key options include:

CROWDSEC_ENABLED="true"          # Enable CrowdSec intrusion prevention
OPKSSH_ENABLED="true"            # Enable Cloudflare OPKSSH SSO
CREDENTIAL_VAULT_ENABLED="true"  # Store secrets securely
COMPLIANCE_REPORTING="true"      # Generate daily compliance reports
FILE_INTEGRITY_MONITORING="true" # Enable AIDE with scheduled checks
APPARMOR_ENABLED="true"          # Enable AppArmor (default)
SELINUX_ENABLED="false"          # Enable SELinux (alternative)

Security Highlights

    System Hardening: kernel parameters, service lockdown, filesystem protections

    Access Control: AppArmor/SELinux profiles, strict PAM policies, account lockouts

    Network Security: UFW + iptables-persistent, rate limiting, IPv6 hardening

    Monitoring & Auditing: Auditd (STIG rules), AIDE, CrowdSec, Fail2Ban

    Recovery: secure backups with checksums, integrity verification, one-command restore

Version History

    v3.2: Modular utilities, credential vault, compliance reporting, improved input validation and error handling, advanced recovery.

    v3.1: CrowdSec integration, Cloudflare OPKSSH, improved backups, stricter firewall/audit/password rules.

    v3.0: Enhanced features, new configuration system, STIG/CIS compliance.

    v2.0: Added network segmentation, monitoring improvements.

    v1.0: Initial release.
