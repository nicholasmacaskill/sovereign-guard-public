#!/bin/bash

# Sovereign Guard - One-Line Installer
# Usage: curl -sL https://raw.githubusercontent.com/nicholasmacaskill/python-sovereign-guard/main/install.sh | bash

set -e

INSTALL_DIR="$HOME/.sovereign-guard"
REPO_URL="https://github.com/nicholasmacaskill/python-sovereign-guard.git"
BIN_DIR="/usr/local/bin"

echo "🛡️  Installing Sovereign Guard..."

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required."
    exit 1
fi

# 2. Clone/Update Repo
if [ -d "$INSTALL_DIR" ]; then
    echo "   Existing installation found. Updating..."
    cd "$INSTALL_DIR"
    git pull origin main
else
    echo "   Cloning repository to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# 2.5 Unlock Proprietary Core (The Moat)
echo ""
echo "🔐 Sovereign Guard Pro / Enterprise"
echo "   The core logic of this repository is encrypted to protect IP."
echo "   Public tools (CLI, Dashboard) are free. The Engine requires a license."
echo ""

if ! command -v git-crypt &> /dev/null; then
    echo "⚠️  git-crypt not found. Installing via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install git-crypt
    else
        echo "❌ Error: Homebrew not found. Please install 'git-crypt' manually."
        exit 1
    fi
fi

# Check if already unlocked
if grep -q "sovereign_core.py" .git/git-crypt/keys/* 2>/dev/null; then
    echo "   ✅ Core is already unlocked."
else
    echo -n "🔑 Enter path to your Sovereign License Key (.key file): "
    read LICENSE_KEY_PATH
    
    if [ -f "$LICENSE_KEY_PATH" ]; then
        echo "   Unlocking Core Engine..."
        git-crypt unlock "$LICENSE_KEY_PATH"
        echo "   ✅ Moat Unlocked. Proprietary assets utilized."
    else
        echo "   ❌ Invalid Key Path. Installing Public Shell ONLY."
        echo "   (The monitor will fail to start without the core engine)"
    fi
fi

# 3. Setup Virtual Environment
echo "   Setting up isolated environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# 4. Install Dependencies
echo "   Installing dependencies..."
./venv/bin/pip install -q psutil plyer

# 5. Link Binary
echo "   Linking 'sovereign' command..."
# Use a wrapper script to run in the correct venv
cat <<EOF > "$INSTALL_DIR/sovereign-wrapper"
#!/bin/bash
cd "$INSTALL_DIR"
./venv/bin/python3 src/sovereign_ctl.py "\$@"
EOF

chmod +x "$INSTALL_DIR/sovereign-wrapper"

# Attempt to symlink to /usr/local/bin or alias in .zshrc
if [ -w "$BIN_DIR" ]; then
    ln -sf "$INSTALL_DIR/sovereign-wrapper" "$BIN_DIR/sovereign"
    echo "   ✅ Installed to $BIN_DIR/sovereign"
else
    # Fallback if no sudo access (add to PATH)
    SHELL_RC="$HOME/.zshrc"
    if [ -f "$HOME/.bashrc" ]; then SHELL_RC="$HOME/.bashrc"; fi
    
    if ! grep -q "sovereign-guard" "$SHELL_RC"; then
        echo "" >> "$SHELL_RC"
        echo "# Sovereign Guard CLI" >> "$SHELL_RC"
        echo "alias sovereign='$INSTALL_DIR/sovereign-wrapper'" >> "$SHELL_RC"
        echo "   ⚠️  Added alias to $SHELL_RC. Restart your terminal to use 'sovereign'."
    else
        echo "   ✅ Alias already exists in $SHELL_RC"
    fi
fi

echo ""
echo "=================================================="
echo "🛡️  Sovereign Guard Installed Successfully."
echo "=================================================="
echo "Run: 'sovereign setup' to initialize protection."
echo "Run: 'sovereign start' to activate the monitor."
echo "=================================================="
