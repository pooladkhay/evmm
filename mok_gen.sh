#!/bin/bash

# MOK Key Generation Script
# This script generates and enrolls custom MOK keys for Secure Boot

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}MOK Key Generation and Enrollment${NC}"
echo -e "${GREEN}with Secure Boot Support${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Please do not run this script as root. It will use sudo when needed.${NC}"
    exit 1
fi

# Check Secure Boot status
echo -e "${YELLOW}Checking Secure Boot status...${NC}"
if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
    echo -e "${GREEN}✓ Secure Boot is enabled${NC}\n"
else
    echo -e "${YELLOW}Warning: Secure Boot status unclear or disabled${NC}"
    echo -e "Continuing anyway...\n"
fi

# Install required tools
echo -e "${YELLOW}Installing required tools...${NC}"
sudo dnf install -y openssl mokutil
echo -e "${GREEN}✓ Required tools installed${NC}\n"

# Generate MOK key
echo -e "${YELLOW}Generating MOK (Machine Owner Key)...${NC}"
MOK_DIR="$HOME/.mok"
MOK_NAME="dev-signing-key"
mkdir -p "$MOK_DIR"
if [ ! -f "$MOK_DIR/$MOK_NAME.priv" ]; then
    openssl req -new -x509 -newkey rsa:2048 -keyout "$MOK_DIR/$MOK_NAME.priv" -outform DER -out "$MOK_DIR/$MOK_NAME.der" -nodes -days 36500 -subj "/CN=Custom Development Key/"
    echo -e "${GREEN}✓ MOK key generated at $MOK_DIR/$MOK_NAME.der${NC}\n"
else
    echo -e "${GREEN}✓ MOK key already exists at $MOK_DIR/$MOK_NAME.der${NC}\n"
fi

echo -e "${YELLOW}Enrolling MOK key for Secure Boot...${NC}"
echo -e "${YELLOW}You will be prompted to create a password.${NC}"
echo -e "${YELLOW}REMEMBER THIS PASSWORD - you'll need it on the next boot!${NC}\n"

sudo mokutil --import "$MOK_DIR/$MOK_NAME.der"

echo -e "${GREEN}✓ MOK key enrollment initiated${NC}\n"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Initialization Complete!${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${YELLOW}IMPORTANT NEXT STEPS:${NC}"
echo -e "1. Reboot your system: ${GREEN}sudo reboot${NC}"
echo -e "2. During boot, you'll see the MOK Manager (blue screen)"
echo -e "3. Select: ${GREEN}Enroll MOK${NC}"
echo -e "4. Select: ${GREEN}Continue${NC}"
echo -e "5. Select: ${GREEN}Yes${NC}"
echo -e "6. Enter the password you just created"
echo -e "7. Select: ${GREEN}Reboot${NC}\n"

read -p "Would you like to reboot now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Rebooting...${NC}"
    sudo reboot
else
    echo -e "${YELLOW}Please reboot manually when ready: sudo reboot${NC}"
fi
