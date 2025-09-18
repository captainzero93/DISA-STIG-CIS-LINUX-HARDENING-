#!/bin/bash

# Function to install all packages in one go
install_dependencies() {
  if [ ! -f "$DEPENDENCIES_FILE" ]; then
    echo "Error: Dependencies file $DEPENDENCIES_FILE not found."
    exit 1
  fi

  # Extract non-comment, non-empty lines from the file
  local packages=()
  while IFS= read -r package || [ -n "$package" ]; do
    # Skip comments and empty lines
    if [[ "$package" =~ ^[[:space:]]*# ]] || [[ -z "$package" ]]; then
      continue
    fi
    packages+=("$package")
  done <"$DEPENDENCIES_FILE"

  if [ ${#packages[@]} -eq 0 ]; then
    echo "No packages to install."
    return 0
  fi

  echo "Installing packages: ${packages[*]}..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

# Function to verify all packages are installed
verify_dependencies() {
  if [ ! -f "$DEPENDENCIES_FILE" ]; then
    echo "Error: Dependencies file $DEPENDENCIES_FILE not found."
    exit 1
  fi

  local missing_dependencies=0
  while IFS= read -r package || [ -n "$package" ]; do
    # Skip comments and empty lines
    if [[ "$package" =~ ^[[:space:]]*# ]] || [[ -z "$package" ]]; then
      continue
    fi
    # Verify the package
    if ! dpkg -l | grep -q "^ii.*$package "; then
      echo "Error: $package is not installed."
      ((missing_dependencies++))
    fi
  done <"$DEPENDENCIES_FILE"

  if [ "$missing_dependencies" -gt 0 ]; then
    echo "Error: $missing_dependencies dependencies are missing."
    return 1
  else
    echo "All dependencies are installed."
  fi
}

# Enhanced package installation function
install_package() {
  local package=$1
  local retries=3
  local retry_count=0

  log INFO "Installing package: $package"

  # Check if package is already installed
  if dpkg -l 2>/dev/null | grep -q "^ii.*$package "; then
    log INFO "Package $package is already installed"
    return 0
  fi

  # Update package cache if needed (older than 24 hours)
  if [[ $(find /var/cache/apt/pkgcache.bin -mtime +1 2>/dev/null) ]]; then
    log INFO "Updating package cache..."
    sudo apt-get update || {
      log WARNING "Failed to update package cache"
    }
  fi

  # Try to install package with retries
  while [ $retry_count -lt $retries ]; do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" 2>/dev/null; then
      log INFO "Successfully installed package: $package"
      return 0
    fi

    ((retry_count++))
    log WARNING "Failed to install $package, attempt $retry_count of $retries"
    sleep 2
  done

  log ERROR "Failed to install package after $retries attempts: $package"
  return 1
}

# Function to validate system requirements
check_requirements() {
  log INFO "Checking system requirements..."

  # Check OS compatibility
  if ! command -v lsb_release &>/dev/null; then
    handle_error "lsb_release command not found. This script requires an Ubuntu-based system." 2
  fi

  local os_name=$(lsb_release -si)
  local os_version=$(lsb_release -sr)

  if [[ "$os_name" != "Ubuntu" && "$os_name" != "Debian" ]]; then
    handle_error "This script is designed for Ubuntu or Debian-based systems. Detected OS: $os_name" 3
  fi

  # Version check with proper version comparison
  if [[ "$os_name" == "Ubuntu" ]]; then
    if ! awk -v ver="$os_version" 'BEGIN { if (ver < 18.04) exit 1; }'; then
      handle_error "This script requires Ubuntu 18.04 or later. Detected version: $os_version" 4
    fi
  elif [[ "$os_name" == "Debian" ]]; then
    if ! awk -v ver="$os_version" 'BEGIN { if (ver < 12.0) exit 1; }'; then
      handle_error "This script requires Debian 12.0 or later. Detected version: $os_version" 5
    fi
  fi

  # Check for required tools
  local required_tools=("wget" "curl" "apt" "systemctl" "openssl" "mailutils")
  for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      install_package "$tool"
    fi
  done

  # Check disk space
  local required_space=5120 # 5GB in MB
  local available_space=$(df -m / | awk 'NR==2 {print $4}')
  if [ "$available_space" -lt "$required_space" ]; then
    handle_error "Insufficient disk space. Required: ${required_space}MB, Available: ${available_space}MB" 7
  fi

  # Check memory
  local required_memory=1024 # 1GB in MB
  local available_memory=$(free -m | awk '/Mem:/ {print $2}')
  if [ "$available_memory" -lt "$required_memory" ]; then
    handle_error "Insufficient memory. Required: ${required_memory}MB, Available: ${available_memory}MB" 8
  fi

  # Network connectivity check
  if ! ping -c 1 8.8.8.8 &>/dev/null; then
    handle_error "No network connectivity detected" 9
  fi

  # Check system entropy
  check_system_entropy

  log INFO "System requirements check passed. OS: $os_name $os_version"
}

