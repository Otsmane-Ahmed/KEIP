#!/bin/bash
# check_compat.sh
# Checks if the system meets requirements for KEIP (Kernel version, BPF support)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "-----------------------------------------"
echo " KEIP System Compatibility Check"
echo "-----------------------------------------"

# Check Kernel Version
KERNEL_VERSION=$(uname -r)
MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo -n "[*] Checking Kernel Version ($KERNEL_VERSION)... "
if [ "$MAJOR" -ge 5 ] && [ "$MINOR" -ge 8 ]; then
    echo -e "${GREEN}OK (>= 5.8)${NC}"
else
    echo -e "${RED}FAIL (Need >= 5.8 for LSM BPF)${NC}"
    echo -e "${YELLOW}  Upgrade your kernel to use KEIP.${NC}"
    exit 1
fi

# Check for LSM BPF Support
echo -n "[*] Checking for LSM BPF Support... "
if [ -f "/sys/kernel/security/lsm" ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if [[ "$LSM_LIST" == *"bpf"* ]]; then
        echo -e "${GREEN}OK (bpf in active LSMs)${NC}"
    else
        echo -e "${YELLOW}WARNING (bpf not in active LSMs)${NC}"
        echo -e "  You might need to add 'lsm=...,bpf' to your kernel boot parameters (GRUB)."
    fi
else
    echo -e "${YELLOW}UNKNOWN (cannot read /sys/kernel/security/lsm)${NC}"
fi

# Check for Python 3
echo -n "[*] Checking Python 3... "
if command -v python3 &> /dev/null; then
    PY_VER=$(python3 --version)
    echo -e "${GREEN}OK ($PY_VER)${NC}"
else
    echo -e "${RED}FAIL (Python 3 not found)${NC}"
    exit 1
fi

# Check for BCC tools
echo -n "[*] Checking for BCC tools... "
if python3 -c "import bcc" &> /dev/null; then
    echo -e "${GREEN}OK (bcc python module found)${NC}"
else
    echo -e "${YELLOW}MISSING (bcc python module)${NC}"
    echo -e "  Run ./setup.sh to install dependencies."
fi

echo "-----------------------------------------"
echo -e "${GREEN}[+] System check complete.${NC}"
echo "    If all checks passed, you are ready to use KEIP."
