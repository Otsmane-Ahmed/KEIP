#!/bin/bash

# setup.sh - Install dependencies for KEIP
# Supports Debian/Ubuntu (apt)

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

echo -e "${GREEN}[*] KEIP Setup Script${NC}"

# Check for Root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Error: Must run as root${NC}"
  exit 1
fi

# Update Apt
echo -e "${GREEN}[*] Updating package lists...${NC}"
apt-get update

# Install Kernel Headers & Tools
KERNEL_VERSION=$(uname -r)
echo -e "${GREEN}[*] Installing dependencies...${NC}"

apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool \
    python3-pip \
    python3-bpfcc

# Set up Python Virtual Environment
echo -e "${GREEN}[*] Configuring Python environment...${NC}"
apt-get install -y python3-venv

if [ ! -d "keip-env" ]; then
    python3 -m venv keip-env
    echo -e "${GREEN}[+] Virtual environment 'keip-env' created.${NC}"
fi

# Activate and install deps
source keip-env/bin/activate
pip install --upgrade pip setuptools wheel

echo -e "${GREEN}[+] Setup complete${NC}"
echo -e "Run: ${GREEN}sudo ./run_keip.sh${NC}"
