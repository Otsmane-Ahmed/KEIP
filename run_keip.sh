#!/bin/bash

# run_keip.sh - Launcher for KEIP Pip Monitor

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Check for Root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] KEIP requires root privileges (eBPF).${NC}"
  echo -e "Please run: ${GREEN}sudo ./run_keip.sh${NC}"
  exit 1
fi

# Check for Config
if [ ! -f "src/config.json" ]; then
    echo -e "${RED}[!] Warning: src/config.json not found.${NC}"
    echo "Using default hardcoded whitelist."
fi

# Virtual Environment
if [ -f "keip-env/bin/activate" ]; then
    source keip-env/bin/activate
else
    echo -e "${RED}[!] Virtual environment not found. Please run ./setup.sh first.${NC}"
    exit 1
fi

# Run Monitor
echo -e "${GREEN}[*] Starting KEIP Pip Monitor...${NC}"
echo -e "Logs will be displayed below. Press Ctrl+C to stop."
echo ""

python3 src/keip_pip_monitor.py
