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

# Create global keip command
echo -e "${GREEN}[*] Creating 'keip' command in /usr/local/bin...${NC}"
cat > /usr/local/bin/keip << 'EOF'
#!/bin/bash

# KEIP Global Command Wrapper

if [ "$EUID" -ne 0 ]; then 
  echo "╔═════════════════════════════════════════════════╗"
  echo "║  KEIP requires root privileges (eBPF hooks)     ║"
  echo "╚═════════════════════════════════════════════════╝"
  echo ""
  echo "Run: sudo keip [options]"
  exit 1
fi

cd /opt/keip
python3 src/keip_pip_monitor.py "$@"
EOF

chmod +x /usr/local/bin/keip

echo ""
echo -e "${GREEN}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ KEIP installed successfully!                 ║${NC}"
echo -e "${GREEN}╚═════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Usage:"
echo -e "  ${YELLOW}sudo keip${NC}          # Start monitoring"
echo -e "  ${YELLOW}sudo keip --quiet${NC}  # Quiet mode (CI/CD)"
echo -e "  ${YELLOW}sudo keip --help${NC}   # Show all options"
echo ""
