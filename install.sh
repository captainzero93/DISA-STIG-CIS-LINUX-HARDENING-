#!/bin/bash
# Security Hardening Suite Installation Script
# Version 3.2

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation directories
INSTALL_DIR="/opt/security-hardening"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/security-hardening"
LOG_DIR="/var/log/security-hardening"
LIB_DIR="$INSTALL_DIR/lib"

# Script files
MAIN_SCRIPT="enhanced_security_hardening.sh"
UTILS_SCRIPT="utils.sh"
CONFIG_FILE="security_config.conf"

echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}   Security Hardening Suite Installation${NC}"
echo -e "${GREEN}================================================${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This installer must be run as root${NC}"
    exit 1
fi

# Check OS compatibility
if ! command -v lsb_release &>/dev/null; then
    echo -e "${RED}Error: lsb_release not found. Please install lsb-release package${NC}"
    exit 1
fi

OS_NAME=$(lsb_release -si)
OS_VERSION=$(lsb_release -sr)

if [[ "$OS_NAME" != "Ubuntu" && "$OS_NAME" != "Debian" ]]; then
    echo -e "${RED}Error: This script is designed for Ubuntu or Debian systems${NC}"
    echo -e "${RED}Detected: $OS_NAME $OS_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} System compatibility check passed: $OS_NAME $OS_VERSION"

# Create installation directories
echo -e "${YELLOW}Creating installation directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$LIB_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$INSTALL_DIR"
chmod 755 "$CONFIG_DIR"
chmod 755 "$LOG_DIR"

# Copy script files
echo -e "${YELLOW}Installing script files...${NC}"

# Check if scripts exist in current directory
if [ ! -f "$MAIN_SCRIPT" ]; then
    echo -e "${RED}Error: $MAIN_SCRIPT not found in current directory${NC}"
    exit 1
fi

if [ ! -f "lib/$UTILS_SCRIPT" ]; then
    echo -e "${RED}Error: lib/$UTILS_SCRIPT not found${NC}"
    exit 1
fi

# Copy main script
cp "$MAIN_SCRIPT" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/$MAIN_SCRIPT"

# Copy utils library
cp "lib/$UTILS_SCRIPT" "$LIB_DIR/"
chmod 644 "$LIB_DIR/$UTILS_SCRIPT"

# Copy configuration file
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$CONFIG_DIR/"
    chmod 644 "$CONFIG_DIR/$CONFIG_FILE"
    echo -e "${GREEN}✓${NC} Configuration file installed"
else
    echo -e "${YELLOW}⚠${NC} No configuration file found, using defaults"
fi

# Create symbolic link for easy execution
ln -sf "$INSTALL_DIR/$MAIN_SCRIPT" "$BIN_DIR/security-hardening"
echo -e "${GREEN}✓${NC} Created command: security-hardening"

# Install dependencies
echo -e "${YELLOW}Installing required dependencies...${NC}"
apt-get update >/dev/null 2>&1

DEPENDENCIES=(
    "wget"
    "curl"
    "git"
    "openssl"
    "mailutils"
    "lsb-release"
    "net-tools"
    "iptables"
)

for dep in "${DEPENDENCIES[@]}"; do
    if ! dpkg -l | grep -q "^ii.*$dep "; then
        echo -e "  Installing $dep..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$dep" >/dev/null 2>&1
    fi
done

echo -e "${GREEN}✓${NC} Dependencies installed"

# Create systemd service for automated hardening checks
echo -e "${YELLOW}Creating systemd service...${NC}"
cat << 'EOF' > /etc/systemd/system/security-hardening.service
[Unit]
Description=Security Hardening Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/security-hardening --profile advanced --config /etc/security-hardening/security_config.conf
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer for weekly execution
cat << 'EOF' > /etc/systemd/system/security-hardening.timer
[Unit]
Description=Weekly Security Hardening Check
Requires=security-hardening.service

[Timer]
OnCalendar=weekly
OnBootSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd service created"

# Create log rotation configuration
echo -e "${YELLOW}Configuring log rotation...${NC}"
cat << EOF > /etc/logrotate.d/security-hardening
$LOG_DIR/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF
echo -e "${GREEN}✓${NC} Log rotation configured"

# Create uninstall script
echo -e "${YELLOW}Creating uninstall script...${NC}"
cat << 'EOF' > "$INSTALL_DIR/uninstall.sh"
#!/bin/bash
# Security Hardening Suite Uninstaller

echo "Uninstalling Security Hardening Suite..."

# Stop and disable services
systemctl stop security-hardening.timer 2>/dev/null
systemctl disable security-hardening.timer 2>/dev/null
systemctl stop security-hardening.service 2>/dev/null
systemctl disable security-hardening.service 2>/dev/null

# Remove systemd files
rm -f /etc/systemd/system/security-hardening.service
rm -f /etc/systemd/system/security-hardening.timer
systemctl daemon-reload

# Remove symbolic link
rm -f /usr/local/bin/security-hardening

# Remove log rotation
rm -f /etc/logrotate.d/security-hardening

# Ask about removing configuration and logs
read -p "Remove configuration files? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/security-hardening
fi

read -p "Remove log files? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /var/log/security-hardening
fi

# Remove installation directory
rm -rf /opt/security-hardening

echo "Security Hardening Suite has been uninstalled"
EOF
chmod 755 "$INSTALL_DIR/uninstall.sh"
echo -e "${GREEN}✓${NC} Uninstall script created"

# Display installation summary
echo
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo
echo -e "${GREEN}Installation Summary:${NC}"
echo -e "  • Main script: $INSTALL_DIR/$MAIN_SCRIPT"
echo -e "  • Configuration: $CONFIG_DIR/$CONFIG_FILE"
echo -e "  • Logs: $LOG_DIR/"
echo -e "  • Command: security-hardening"
echo
echo -e "${GREEN}Usage Examples:${NC}"
echo -e "  • Run with basic profile:"
echo -e "    ${YELLOW}security-hardening --profile basic${NC}"
echo
echo -e "  • Run with advanced profile (recommended):"
echo -e "    ${YELLOW}security-hardening --profile advanced${NC}"
echo
echo -e "  • Dry run to see what would be changed:"
echo -e "    ${YELLOW}security-hardening --profile advanced --dry-run${NC}"
echo
echo -e "  • Run with custom configuration:"
echo -e "    ${YELLOW}security-hardening --config /etc/security-hardening/security_config.conf${NC}"
echo
echo -e "${GREEN}Automated Execution:${NC}"
echo -e "  • Enable weekly automated checks:"
echo -e "    ${YELLOW}systemctl enable --now security-hardening.timer${NC}"
echo
echo -e "${GREEN}Configuration:${NC}"
echo -e "  • Edit configuration file:"
echo -e "    ${YELLOW}nano $CONFIG_DIR/$CONFIG_FILE${NC}"
echo
echo -e "${GREEN}Uninstall:${NC}"
echo -e "  • To uninstall, run:"
echo -e "    ${YELLOW}$INSTALL_DIR/uninstall.sh${NC}"
echo
echo -e "${YELLOW}⚠ Important:${NC}"
echo -e "  1. Review the configuration file before running"
echo -e "  2. Test with --dry-run first"
echo -e "  3. Ensure you have console access before running"
echo -e "  4. Some changes require a system restart"
echo
echo -e "${GREEN}Next Steps:${NC}"
echo -e "  1. ${YELLOW}cd $CONFIG_DIR${NC}"
echo -e "  2. ${YELLOW}nano security_config.conf${NC} (edit configuration)"
echo -e "  3. ${YELLOW}security-hardening --profile advanced --dry-run${NC} (test)"
echo -e "  4. ${YELLOW}security-hardening --profile advanced${NC} (apply)"
echo
