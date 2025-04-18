# Linux Security Hardening Script (Enhanced) 

## Overview
This project provides a (somewhat) comprehensive security hardening solution for Ubuntu and Debian-based Linux systems, implementing DISA STIG and CIS Compliance standards. V3.1 includes enhanced features, improved error handling, and configurable security controls.

## Features
- Comprehensive system hardening aligned with STIG/CIS standards
- Advanced firewall configuration with network segmentation
- Intrusion detection and prevention (Fail2Ban, OSSEC)
- Detailed logging and monitoring
- Automated backup and recovery
- USB device control
- Network isolation and VLAN support
- Security reporting and compliance checking

## Requirements
- Ubuntu 18.04+ or Debian 12.0+
- Minimum 5GB free disk space
- Root or sudo access
- Active internet connection

## Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-.git

# Change to the script directory

cd DISA-STIG-CIS-LINUX-HARDENING-

# Make the script executable
chmod +x enhanced-security-script.sh
```

### Basic Usage
```bash
# Run with default settings
sudo ./enhanced-security-script.sh

# Run with verbose output
sudo ./enhanced-security-script.sh --verbose

# Test run without making changes
sudo ./enhanced-security-script.sh --dry-run
```

## Configuration
The script uses a configuration file (`security_config.conf`) for customization. A default configuration file is provided in the repository. However you will want to use less strict settings for a Home machine ( see user_friendly_example.conf in the Repo for an example ).

### Configuration File Setup
The configuration file is automatically loaded from the same directory as the script. You can modify the settings before running the script:

```bash
# Review and modify configuration
sudo nano security_config.conf

# Secure the configuration file
sudo chmod 600 security_config.conf
sudo chown root:root security_config.conf
```

### Key Configuration Options
```bash
# Basic security options
BACKUP_ENABLED="true"
FIREWALL_ENABLED="true"
AUDIT_ENABLED="true"

# Access control
SELINUX_ENABLED="false"
APPARMOR_ENABLED="true"

# Network security
IPV6_ENABLED="false"
NETWORK_SEGMENTATION="true"

# Authentication
PASSWORD_POLICY_STRICT="true"
ACCOUNT_LOCKOUT_THRESHOLD="3"

# Monitoring
FILE_INTEGRITY_MONITORING="true"
OSSEC_ENABLED="true"
```

## Command Line Options
- `--help`: Display usage information
- `--version`: Show script version
- `--verbose`: Enable detailed output
- `--dry-run`: Preview changes without applying them
- `--restore`: Restore from backup

## Security Features

### System Hardening
- Kernel parameter optimization
- Service hardening
- File system security
- Process accounting
- Secure boot configuration

### Access Control
- Mandatory Access Control (AppArmor/SELinux)
- Strong password policies
- Account lockout protection
- USB device control

### Network Security
- Advanced firewall rules
- Network segmentation
- DMZ configuration
- Rate limiting
- IPv6 security measures

### Monitoring & Auditing
- File integrity monitoring (AIDE)
- System auditing
- OSSEC HIDS
- Daily security scans
- Automated reporting

## Backup and Recovery
The script automatically creates backups before making changes:

```bash
# Restore from backup
sudo ./enhanced-security-script.sh --restore

# Backup location
/root/security_backup_YYYYMMDD_HHMMSS/
```

## Logging
- Main log: `/var/log/security_hardening.log`
- Audit log: `/var/log/audit/audit.log`
- OSSEC logs: `/var/ossec/logs/`
- Fail2Ban log: `/var/log/fail2ban.log`

## Compliance

### DISA STIG Controls
Implements critical controls from DISA STIG guidelines including:
- Account and Authentication Security (V-230234, V-230236)
- Audit Configuration (V-230445)
- Network Security (V-230484, V-230485)

### CIS Benchmark Implementation
- Level 1 Server Controls (Sections 1-6)
- Automated scoring against CIS profiles

### Daily Compliance Reports
- Detailed compliance status reports
- Configuration drift detection
- Failed control notifications

## Troubleshooting

### Common Issues
1. Script fails to start:
   - Check permissions
   - Verify system requirements
   - Ensure configuration file exists

2. Network issues:
   - Verify internet connectivity
   - Check DNS resolution
   - Review firewall rules

3. Service failures:
   - Check service status
   - Review error logs
   - Verify dependencies

### Debug Mode
```bash
# Enable verbose logging
sudo ./enhanced-security-script.sh --verbose

# Check logs
tail -f /var/log/security_hardening.log
```

## Best Practices
1. Always run `--dry-run` first ( sudo ./enhanced-security-script.sh --dry-run )
2. Review configuration before running
3. Maintain regular backups
4. Monitor logs after implementation
5. Regularly update security policies

## License
See the LICENSE file for details.

## Acknowledgments
- DISA STIG Guidelines
- CIS Benchmarks
- Debian/Ubuntu Security Team
- Open Source Security Community

## Version History
- v 3.1: added crowdsec and fixed a bunch of errors.
- v3.0: Enhanced security features, improved configuration, STIG/CIS compliance.
- v2.0: Added network segmentation, improved monitoring.
- v1.0: Initial release


