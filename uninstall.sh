#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "------------------------------------------"
echo " KEIP Uninstallation Script"
echo "------------------------------------------"

if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Error: Must run as root${NC}"
  exit 1
fi

echo -e "${YELLOW}[*] Stopping any running KEIP monitors...${NC}"
pkill -f "keip-python.*keip_pip_monitor.py" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Stopped KEIP monitor${NC}"
else
    echo -e "${YELLOW}[!] No running KEIP monitor found${NC}"
fi

echo -e "\n${YELLOW}[*] Checking for attached eBPF programs...${NC}"
if command -v bpftool &> /dev/null; then
    bpf_progs=$(bpftool prog list | grep -i "lsm" | wc -l)
    if [ "$bpf_progs" -gt 0 ]; then
        echo -e "${YELLOW}[!] Found $bpf_progs LSM BPF programs${NC}"
        echo -e "${YELLOW}    Note: These will be automatically cleaned up on reboot${NC}"
        echo -e "${YELLOW}    Or detached when the monitor process exits${NC}"
    else
        echo -e "${GREEN}[+] No LSM BPF programs currently attached${NC}"
    fi
else
    echo -e "${YELLOW}[!] bpftool not found, cannot check BPF programs${NC}"
fi

echo -e "\n${YELLOW}[*] Removing system-wide installation...${NC}"
if [ -f "/usr/local/bin/keip" ]; then
    rm -f /usr/local/bin/keip
    echo -e "${GREEN}[+] Removed /usr/local/bin/keip${NC}"
else
    echo -e "${YELLOW}[!] Global keip command not found${NC}"
fi

if [ -d "/opt/keip" ]; then
    rm -rf /opt/keip
    echo -e "${GREEN}[+] Removed /opt/keip${NC}"
else
    echo -e "${YELLOW}[!] /opt/keip directory not found${NC}"
fi

echo -e "\n${YELLOW}[*] Removing virtual environment...${NC}"
if [ -d "keip-env" ]; then
    rm -rf keip-env
    echo -e "${GREEN}[+] Virtual environment removed${NC}"
else
    echo -e "${YELLOW}[!] Virtual environment not found${NC}"
fi

echo -e "\n${YELLOW}[?] Remove results and logs? (y/N): ${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    if [ -d "keip_phase5_results" ]; then
        rm -rf keip_phase5_results
        echo -e "${GREEN}[+] Results directory removed${NC}"
    fi
    if [ -d "phase5_samples" ]; then
        rm -rf phase5_samples
        echo -e "${GREEN}[+] Samples directory removed${NC}"
    fi
else
    echo -e "${YELLOW}[!] Keeping results and logs${NC}"
fi

echo -e "\n${GREEN}------------------------------------------${NC}"
echo -e "${GREEN}[+] KEIP uninstallation complete${NC}"
echo -e "${GREEN}------------------------------------------${NC}"
echo ""
echo "To remove system dependencies (optional):"
echo "  sudo apt remove python3-bpfcc bpftool"
echo ""
echo "To completely remove KEIP project directory:"
echo "  cd .. && rm -rf KEIP/"
