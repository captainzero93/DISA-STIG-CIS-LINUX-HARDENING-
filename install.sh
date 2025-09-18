#!/bin/bash
# Security Hardening Suite Installation Script
# Version 3.2

set -e

# Runtime variables
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_URL="$(git remote get-url origin 2>/dev/null | sed 's/git@github.com:/https:\/\/github.com\//; s/\.git$//' 2>/dev/null)"

# Installation directories
readonly INSTALL_DIR="/opt/security-hardening"
readonly BIN_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/security-hardening"
readonly LOG_DIR="/var/log/security-hardening"
readonly LIB_DIR="$INSTALL_DIR/lib"
readonly DEPENDENCIES_FILE="$SCRIPT_DIR/dependencies.txt"

# Script files
readonly MAIN_SCRIPT="enhanced_security_hardening.sh"
readonly CONFIG_FILE="security_config.conf"

IMPORTS=(
  "$SCRIPT_DIR/lib/dependencies.sh"
  "$SCRIPT_DIR/lib/utils.sh"
  "$SCRIPT_DIR/lib/color.sh"
)
# Imports
for file in "${IMPORTS[@]}"; do
  source "$file" 2>/dev/null || {
    echo "Error: Unable to source $file"
    exit 1
  }
done

# Import utilities functions
source "$SCRIPT_DIR/lib/utils.sh" 2>/dev/null || {
  echo "Error: Unable to source dependencies.sh"
  exit 1
}

# Check if running as root
is_root

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
if [ ! -f "$SCRIPT_DIR/main.sh" ]; then
  echo -e "${RED}Error: main.sh not found in current directory${NC}"
  exit 1
fi

# Copy main script
cp "$SCRIPT_DIR/main.sh" "$INSTALL_DIR/$MAIN_SCRIPT"
chmod 755 "$INSTALL_DIR/$MAIN_SCRIPT"

# Copy utils library
cp -r "$SCRIPT_DIR/lib" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/dependencies.txt" "$INSTALL_DIR/"
echo "REPO_URL=\"$REPO_URL\"" >>"$INSTALL_DIR/lib/config.sh"
chmod -R 644 "$LIB_DIR/"

# Copy configuration file
if [ -f "$SCRIPT_DIR/conf/$CONFIG_FILE" ]; then
  # -n (--no-clobber) option to avoid overwriting existing file
  cp -n "$SCRIPT_DIR/conf/$CONFIG_FILE" "$CONFIG_DIR/"
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

verify_dependencies || install_dependencies
echo -e "${GREEN}✓${NC} Dependencies installed"

# Create systemd service for automated hardening checks
echo -e "${YELLOW}Creating systemd service...${NC}"
cat <<'EOF' >/etc/systemd/system/security-hardening.service
[Unit]
Description=Security Hardening Service
After=network.target

[Service]
Type=oneshot
ExecStart=${BIN_DIR}/security-hardening --profile advanced --config ${CONFIG_DIR}/security_config.conf
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer for weekly execution
cat <<'EOF' >/etc/systemd/system/security-hardening.timer
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
cat <<EOF >/etc/logrotate.d/security-hardening
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
cat <<'EOF' >"$INSTALL_DIR/uninstall.sh"
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
rm -f ${BIN_DIR}/security-hardening

# Remove log rotation
rm -f /etc/logrotate.d/security-hardening

# Ask about removing configuration and logs
read -p "Remove configuration files? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf ${CONFIG_DIR}
fi

read -p "Remove log files? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf ${LOG_DIR}
fi

# Remove installation directory
rm -rf ${INSTALL_DIR}

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
