#!/bin/bash

set -euo pipefail
error() {
  echo -e "\033[0;31mTest failed\033[0m"
}
trap error ERR

source ./lib/color.sh 2>/dev/null || {
  echo -e "${RED}Error: Unable to source color.sh${NC}"
  exit 1
}

echo -e "${YELLOW}Testing installation${NC}"
./install.sh
echo -e "${GREEN}Test: success${NC}"

echo -e "${YELLOW}Testing main script dry run${NC}"
./main.sh --dry-run --verbose
./main.sh --verbose --restore ./backup.tar.gz
echo -e "${GREEN}Test: success${NC}"

echo -e "${YELLOW}Testing installed script dry run${NC}"
security-hardening --dry-run --verbose
security-hardening --verbose --restore
echo -e "${GREEN}Test: success${NC}"

echo -e "${YELLOW}Testing installed script default${NC}"
security-hardening --verbose
security-hardening --verbose --restore
echo -e "${GREEN}Test: success${NC}"

echo -e "${YELLOW}Testing uninstall${NC}"
/opt/security-hardening/uninstall.sh
echo -e "${GREEN}Test: success${NC}"
