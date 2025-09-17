#!/bin/bash
# USB device control

# Function to setup USB device control
setup_usb_control() {
  if [ "${CONFIG[USB_CONTROL_ENABLED]}" != "true" ]; then
    return 0
  fi

  log INFO "Configuring USB device control..."

  # Install required packages
  install_package "usbguard"

  # Generate initial policy
  usbguard generate-policy >/etc/usbguard/rules.conf

  # Configure USBGuard daemon
  cat <<'EOF' | tee /etc/usbguard/usbguard-daemon.conf >/dev/null
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=apply-policy
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=
DeviceRulesWithPort=false
AuditBackend=FileAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
EOF

  # Create log directory
  mkdir -p /var/log/usbguard

  # Start and enable USBGuard service
  systemctl enable usbguard || handle_error "Failed to enable USBGuard service" 27
  systemctl restart usbguard || handle_error "Failed to start USBGuard service" 28

  log INFO "USB device control configured successfully"
}
