 #!/bin/bash

# Function to setup secure boot configuration
setup_secure_boot() {
  log INFO "Configuring secure boot settings..."

  # Check if system supports secure boot
  if [ ! -d "/sys/firmware/efi" ]; then
    log WARNING "System is not UEFI-based, skipping secure boot configuration"
    return 0
  fi

  # Check if GRUB is installed
  if command -v grub-install >/dev/null 2>&1; then
    # Install required packages
    install_package "grub-efi-amd64-signed"
    install_package "shim-signed"

    # Configure GRUB security settings
    local grub_config="/etc/default/grub"

    # Backup original configuration
    sudo cp "$grub_config" "${grub_config}.backup"

    # Update GRUB security parameters
    sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash module.sig_enforce=1 lockdown=confidentiality init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 slab_nomerge vsyscall=none"/' "$grub_config"

    # Add additional security parameters
    sudo sed -i 's/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"/' "$grub_config"

    # Set GRUB password if requested
    if [[ "$PROFILE" == "advanced" ]]; then
      echo "Setting up GRUB password protection..."
      read -s -p "Enter GRUB password (press Enter to skip): " grub_password
      echo

      if [ -n "$grub_password" ]; then
        # Generate GRUB password hash
        local password_hash
        password_hash=$(echo -e "$grub_password\n$grub_password" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/grub\.pbkdf2/ { print $NF }')

        # Add password protection to GRUB
        cat <<EOF | sudo tee /etc/grub.d/40_custom >/dev/null
#!/bin/sh
exec tail -n +3 \$0

set superusers="admin"
password_pbkdf2 admin $password_hash
EOF
        sudo chmod 755 /etc/grub.d/40_custom
      fi
    fi

    # Update GRUB configuration
    sudo update-grub || handle_error "Failed to update GRUB configuration" 33

    # Secure boot directory permissions
    sudo chmod 700 /boot/grub
    sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null

    log INFO "Secure boot configured successfully"
  else
    log WARNING "System does not use GRUB, skipping secure boot configuration"
  fi
}

# Function to validate secure boot status
check_secure_boot() {
  log INFO "Checking Secure Boot status..."

  if [ -d "/sys/firmware/efi" ]; then
    # Check using mokutil if available
    if command -v mokutil &>/dev/null; then
      local sb_state=$(mokutil --sb-state 2>/dev/null | grep "SecureBoot" | awk '{print $2}')
      if [ "$sb_state" = "enabled" ]; then
        log INFO "Secure Boot is enabled"
        return 0
      else
        log WARNING "Secure Boot is disabled or not supported"
        return 1
      fi
    fi

    # Fallback to bootctl if available
    if command -v bootctl &>/dev/null; then
      if bootctl status 2>/dev/null | grep -q "Secure Boot: enabled"; then
        log INFO "Secure Boot is enabled"
        return 0
      else
        log WARNING "Secure Boot is not enabled"
        return 1
      fi
    fi

    # Check EFI variables directly
    if [ -f "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" ]; then
      local sb_value=$(od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | awk '{print $NF}')
      if [ "$sb_value" = "1" ]; then
        log INFO "Secure Boot is enabled"
        return 0
      fi
    fi

    log WARNING "Unable to determine Secure Boot status"
    return 1
  else
    log INFO "System is not UEFI-based, Secure Boot not applicable"
    return 0
  fi
}
