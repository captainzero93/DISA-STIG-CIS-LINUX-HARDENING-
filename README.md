# Linux Security Hardening Suite v3.2

OLD see https://github.com/captainzero93/security_harden_linux


A comprehensive, enterprise-grade security hardening solution for Ubuntu and Debian-based systems, implementing DISA STIG, CIS Benchmark, and NSA guidelines.

## Features

### Core Security Features

- **SSH Hardening**: Modern cryptography, key-based authentication, rate limiting
- **Firewall Configuration**: UFW with advanced rules and rate limiting
- **Kernel Hardening**: Sysctl security parameters, module restrictions
- **Password Policies**: STIG/CIS compliant complexity and aging requirements
- **Audit System**: Comprehensive auditd rules for compliance
- **File Integrity Monitoring**: AIDE configuration and automated checks
- **Mandatory Access Control**: AppArmor or SELinux support
- **USB Device Control**: USBGuard implementation
- **Secure Boot**: GRUB password protection and secure boot configuration

### Advanced Features (v3.2)

- **Encrypted Credential Vault**: Secure storage for sensitive data using age encryption
- **CrowdSec Integration**: Community-based threat intelligence and blocking
- **Cloudflare OPKSSH SSO**: Zero Trust SSH authentication support
- **Compliance Reporting**: HTML reports with STIG/CIS control validation
- **Advanced Recovery**: Multi-level recovery mechanisms with integrity checking
- **Service Hardening**: Systemd service security restrictions
- **Network Segmentation**: VLAN configuration support

## Requirements

### System Requirements

- **OS**: Ubuntu 18.04+ or Debian 12.0+
- **Architecture**: x86_64 (amd64)
- **Memory**: Minimum 1GB RAM
- **Disk Space**: Minimum 5GB free space
- **Network**: Internet connectivity for package installation
- **Privileges**: Root or sudo access required

### Dependencies (automatically installed)

- wget, curl, git
- openssl, mailutils
- auditd, ufw, fail2ban
- aide, apparmor-utils
- Additional tools based on enabled features

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-.git
cd DISA-STIG-CIS-LINUX-HARDENING-

# Make installer executable id needed
chmod +x install.sh

# Run installer as root
sudo ./install.sh
```

### Manual Installation

```bash
# Create directories
sudo mkdir -p /opt/security-hardening/lib
sudo mkdir -p /etc/security-hardening
sudo mkdir -p /var/log/security-hardening

# Copy files
sudo cp enhanced_security_hardening.sh /opt/security-hardening/
sudo cp -r lib/*.sh /opt/security-hardening/lib/
sudo cp dependencies.txt /opt/security-hardening/lib/
sudo cp conf/security_config.conf /etc/security-hardening/

# Set permissions
sudo chmod 755 /opt/security-hardening/enhanced_security_hardening.sh
sudo chmod -R 644 /opt/security-hardening/lib

# Create symlink
sudo ln -s /opt/security-hardening/enhanced_security_hardening.sh /usr/local/bin/security-hardening
```

## Usage

### Basic Usage

```bash
# Run with default (advanced) profile
sudo security-hardening

# Run with specific profile
sudo security-hardening --profile basic
sudo security-hardening --profile intermediate
sudo security-hardening --profile advanced

# Dry run (preview changes without applying)
sudo security-hardening --dry-run --verbose

# Use custom configuration
sudo security-hardening --config /path/to/config.conf
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-d, --dry-run` | Preview changes without applying |
| `-p, --profile PROFILE` | Select profile (basic/intermediate/advanced) |
| `-c, --config FILE` | Use custom configuration file |
| `-e, --email EMAIL` | Set email for security reports |
| `-b, --backup-dir DIR` | Custom backup directory |
| `-sb, --skip-backup` | Skip backup creation |
| `-sf, --skip-firewall` | Skip firewall configuration |
| `-sa, --skip-audit` | Skip audit configuration |
| `-6, --enable-ipv6` | Enable IPv6 support |
| `-r, --restore` | Restore backup from specified directory or default |
| `-h, --help` | Show help message |

## Security Profiles

### Basic Profile

Essential security hardening for general-purpose systems:

- SSH hardening
- Basic firewall rules
- Password policies
- Kernel security parameters
- Audit logging

### Intermediate Profile

Standard security for production environments:

- Everything from Basic
- Fail2ban intrusion prevention
- File integrity monitoring (AIDE)
- AppArmor mandatory access control
- CrowdSec threat intelligence

### Advanced Profile

Maximum security for high-risk environments:

- Everything from Intermediate
- USB device control
- Network segmentation support
- Cloudflare OPKSSH SSO
- Encrypted credential vault
- Comprehensive compliance reporting
- Service hardening

## Configuration

### Configuration File

Edit `/etc/security-hardening/security_config.conf`:

```bash
# Core settings
SECURITY_EMAIL="admin@example.com"
AUTOMATIC_UPDATES=true
BACKUP_ENABLED=true

# Security features
FIREWALL_ENABLED=true
AUDIT_ENABLED=true
PASSWORD_POLICY_STRICT=true
FILE_INTEGRITY_MONITORING=true

# Advanced features
CROWDSEC_ENABLED=true
OPKSSH_ENABLED=false
CREDENTIAL_VAULT_ENABLED=true
COMPLIANCE_REPORTING=true

# Network settings
IPV6_ENABLED=false
NETWORK_SEGMENTATION=false
```

### Email Notifications

Configure email for security reports:

```bash
sudo security-hardening --email admin@example.com --profile advanced
```

### Automated Execution

Enable weekly security checks:

```bash
# Enable systemd timer
sudo systemctl enable --now security-hardening.timer

# Check timer status
sudo systemctl status security-hardening.timer

# View timer schedule
sudo systemctl list-timers security-hardening.timer
```

## Validation

### Check Applied Settings

```bash
# Verify firewall status
sudo ufw status verbose

# Check audit rules
sudo auditctl -l

# Verify SSH configuration
sudo sshd -T | grep -E "permitrootlogin|passwordauthentication"

# Check fail2ban status
sudo fail2ban-client status

# View AppArmor profiles
sudo aa-status

# Check kernel parameters
sudo sysctl -a | grep -E "net.ipv4|kernel"
```

### Compliance Report

Generate HTML compliance report:

```bash
sudo security-hardening --profile advanced --email admin@example.com
# Report saved to /root/security_backup_*/compliance_report_*.html
```

## Troubleshooting

### Common Issues

#### SSH Access Lost

1. Boot into recovery mode
2. Mount root filesystem as read-write
3. Restore SSH configuration:

   ```bash
   cp /root/security_backup_*/etc/ssh/sshd_config /etc/ssh/
   systemctl restart ssh
   ```

#### Firewall Blocking Services

```bash
# Temporarily disable firewall
sudo ufw disable

# Add required rules
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Re-enable firewall
sudo ufw enable
```

#### System Won't Boot

1. Boot from live USB
2. Mount system partition
3. Restore GRUB configuration:

   ```bash
   cp /mnt/root/security_backup_*/etc/default/grub /mnt/etc/default/
   chroot /mnt update-grub
   ```

### Recovery Options

```bash
# Basic recovery (restart services)
sudo /opt/security-hardening/enhanced_security_hardening.sh --recovery basic

# Intermediate recovery (restore from backup)
sudo /opt/security-hardening/enhanced_security_hardening.sh --recovery intermediate

# Full recovery (complete rollback)
sudo /opt/security-hardening/enhanced_security_hardening.sh --recovery full
```

### Log Files

- Main log: `/var/log/security_hardening.log`
- Audit logs: `/var/log/audit/audit.log`
- Firewall logs: `/var/log/ufw.log`
- Fail2ban logs: `/var/log/fail2ban.log`
- CrowdSec logs: `/var/log/crowdsec.log`

## Compliance Standards

This suite implements controls from:

- **DISA STIG**: Defense Information Systems Agency Security Technical Implementation Guides
- **CIS Benchmarks**: Center for Internet Security Benchmarks
- **NSA Guidelines**: National Security Agency Hardening Guidelines
- **NIST 800-53**: Security and Privacy Controls
- **PCI DSS**: Payment Card Industry Data Security Standard (relevant controls)

## Updates and Maintenance

### Update the Suite

```bash
cd DISA-STIG-CIS-LINUX-HARDENING-
git pull origin main
sudo ./install.sh
```

### Regular Maintenance

1. Review logs weekly: `/var/log/security_hardening.log`
2. Update AIDE database monthly: `sudo aideinit --yes --force`
3. Review compliance reports quarterly
4. Test recovery procedures semi-annually
5. Update CrowdSec collections: `sudo cscli hub update && sudo cscli hub upgrade`

## Important Warnings

1. **Always test in a non-production environment first**
2. **Ensure you have console/physical access before running**
3. **Create backups before applying hardening**
4. **Some changes require system restart**
5. **SSH settings may lock you out if misconfigured**
6. **Review all settings in dry-run mode first**

## Customization

### Adding Custom Audit Rules

Edit `/etc/audit/rules.d/audit.rules` and add your rules:

```bash
-w /etc/custom/app -p wa -k custom_app
-w /var/www/html -p wa -k web_content
```

### Custom AppArmor Profiles

Create profiles in `/etc/apparmor.d/`:

```bash
sudo aa-genprof /usr/bin/custom-app
sudo aa-enforce /etc/apparmor.d/usr.bin.custom-app
```

### Firewall Exceptions

Add custom UFW rules:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 3306
sudo ufw allow 8080/tcp comment 'Custom web app'
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Acknowledgments

- DISA for STIG guidelines
- CIS for security benchmarks
- NSA for hardening guides
- The open-source security community

## Version History

### v3.2 (Current)

- Added encrypted credential vault
- Enhanced SSH hardening with modern cryptography
- Improved compliance reporting
- Advanced recovery mechanisms
- Service hardening with systemd

### v3.1

- CrowdSec integration
- Cloudflare OPKSSH SSO support
- Enhanced audit rules

### v3.0

- Initial public release
- Core hardening features
- Three-tier profile system
