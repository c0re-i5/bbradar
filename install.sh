#!/usr/bin/env bash
# BBRadar install script for Kali Linux
# Run: chmod +x install.sh && ./install.sh

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo -e "${BOLD}  BBRadar — Bug Bounty Hunting Platform${NC}"
echo -e "${BOLD}═══════════════════════════════════════${NC}"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 10 ]]; then
    echo -e "${RED}Error: Python 3.10+ required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION detected"

# Install Python dependencies
echo -e "\n${BOLD}Installing Python dependencies...${NC}"
pip3 install --user -e ".[dev]" 2>/dev/null || pip3 install -e ".[dev]"
echo -e "${GREEN}✓${NC} Python packages installed"

# Initialize BBRadar
echo -e "\n${BOLD}Initializing BBRadar...${NC}"
python3 -m bbradar init
echo -e "${GREEN}✓${NC} BBRadar initialized"

# Check for common Kali tools
echo -e "\n${BOLD}Checking Kali Linux tools...${NC}"
TOOLS=(nmap subfinder amass httpx nuclei ffuf gobuster nikto whatweb sqlmap)
MISSING=()
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${YELLOW}○${NC} $tool (not found — optional)"
        MISSING+=("$tool")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}Note:${NC} Some tools are not installed. You can install them with:"
    echo "  sudo apt install ${MISSING[*]}"
    echo "  or use 'go install' for Go-based tools (subfinder, httpx, nuclei, etc.)"
fi

echo -e "\n${BOLD}${GREEN}BBRadar installation complete!${NC}"
echo ""
echo "Quick start:"
echo "  bb init                            — Initialize the database"
echo "  bb wizard project                  — Create a project (guided)"
echo "  bb wizard vuln                     — Log a finding (guided)"
echo "  bb report generate --project 1     — Generate a report"
echo ""
echo "Run 'bb --help' for full command reference."
