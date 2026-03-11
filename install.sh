#!/bin/bash

# install.sh - Install KEIP system-wide
# Makes 'keip' command available globally

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     KEIP System-Wide Installation               ║${NC}"
echo -e "${GREEN}╚═════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Error: Must run as root${NC}"
  echo -e "    Run: ${YELLOW}sudo ./install.sh${NC}"
  exit 1
fi

# Install directory
INSTALL_DIR="/opt/keip"

echo -e "${GREEN}[*] Installing KEIP to $INSTALL_DIR...${NC}"

# Remove old installation if exists
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Removing previous installation...${NC}"
    rm -rf "$INSTALL_DIR"
fi

# Create directory
mkdir -p "$INSTALL_DIR"

# Copy files
echo -e "${GREEN}[*] Copying KEIP files...${NC}"
cp -r src "$INSTALL_DIR/"
cp check_compat.sh "$INSTALL_DIR/"

# Setup Python binary with capabilities
echo -e "${GREEN}[*] Setting up dedicated Python binary with capabilities...${NC}"
KEIP_PYTHON="$INSTALL_DIR/keip-python"
cp $(which python3) "$KEIP_PYTHON"
chmod 755 "$KEIP_PYTHON"
chown root:root "$KEIP_PYTHON"
# Set capabilities (requires libcap2-bin)
setcap 'cap_bpf,cap_sys_admin,cap_perfmon,cap_dac_read_search=ep' "$KEIP_PYTHON" || echo -e "${YELLOW}[!] Warning: Failed to set capabilities. You may need to install libcap2-bin.${NC}"

# Create global keip command
echo -e "${GREEN}[*] Creating 'keip' command in /usr/local/bin...${NC}"
cat > /usr/local/bin/keip << 'WRAPPER'
#!/bin/bash

# KEIP Global Command Wrapper

KEIP_DIR="/opt/keip"
KEIP_PYTHON="$KEIP_DIR/keip-python"

# Find the user's active python (venv or system)
find_user_python() {
    USER_PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
    if [ -z "$USER_PYTHON" ]; then
        echo "[!] Error: No python3 found in your PATH."
        exit 1
    fi
    echo "$USER_PYTHON"
}

case "$1" in
    install)
        shift
        USER_PYTHON=$(find_user_python)
        "$USER_PYTHON" "$KEIP_DIR/src/pth_audit.py" install "$@"
        ;;
    scan)
        USER_PYTHON=$(find_user_python)
        "$USER_PYTHON" "$KEIP_DIR/src/pth_audit.py" scan
        ;;
    python)
        shift
        USER_PYTHON=$(find_user_python)
        "$USER_PYTHON" "$KEIP_DIR/src/pth_audit.py" python "$@"
        ;;
    *)
        # eBPF monitor needs the privileged keip-python binary
        cd "$KEIP_DIR"
        "$KEIP_PYTHON" src/keip_pip_monitor.py "$@"
        ;;
esac
WRAPPER

chmod +x /usr/local/bin/keip

echo ""
echo -e "${GREEN}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   KEIP installed successfully!                  ║${NC}"
echo -e "${GREEN}╚═════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Usage:"
echo -e "  ${YELLOW}keip${NC}                         # Start eBPF monitor"
echo -e "  ${YELLOW}keip --quiet${NC}                  # Quiet mode (CI/CD)"
echo -e "  ${YELLOW}keip install <package>${NC}        # Install with .pth audit"
echo -e "  ${YELLOW}keip scan${NC}                     # Scan for malicious .pth files"
echo -e "  ${YELLOW}keip python <script>${NC}          # Safe python execution"
echo -e "  ${YELLOW}keip --help${NC}                   # Show all options"
echo ""
