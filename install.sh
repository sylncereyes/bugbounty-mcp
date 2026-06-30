#!/bin/bash
# StealthVision-MCP Installer
# Installs dependencies and sets up the browser automation environment

set -e

echo "=== StealthVision-MCP Installer ==="

# Check if running in project directory
if [ ! -f "server.py" ]; then
    echo "Error: Run this script from the bugbounty-mcp directory"
    exit 1
fi

# Create venv if not exists
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install --quiet playwright httpx python-dotenv

# Install Playwright browsers
echo "[*] Installing Playwright browsers..."
playwright install chromium

# Check for external tools
echo "[*] Checking external tools..."
TOOLS=("subfinder" "httpx" "nuclei" "katana" "naabu")

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "  ✅ $tool found"
    else
        echo "  ⚠ $tool not found - install from https://github.com/projectdiscovery/$tool"
    fi
done

echo ""
echo "=== Installation Complete ==="
echo "To run: source venv/bin/activate && python server.py"