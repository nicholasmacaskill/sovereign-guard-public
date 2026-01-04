#!/bin/bash

echo "==========================================="
echo "   Initializing Sovereign Guard Suite      "
echo "==========================================="

# check python installation
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 could not be found. Please install Python 3."
    exit 1
fi

echo "[*] Setting up Python Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "    [OK] Virtual environment created."
else
    echo "    [OK] Virtual environment already exists."
fi

echo "[*] Installing Python dependencies into venv..."
# Install psutil and plyer into the virtual environment
./venv/bin/pip install psutil plyer

if [ $? -eq 0 ]; then
    echo "[PASS] Dependencies installed successfully."
else
    echo "[FAIL] Failed to install dependencies."
    exit 1
fi

echo "[*] Checking for ClamAV (malware scanner)..."
if ! command -v clamscan &> /dev/null; then
    echo "    [INFO] ClamAV not found. Installing via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install clamav
        echo "    [INFO] Updating virus definitions (this may take a moment)..."
        freshclam
        echo "    [PASS] ClamAV installed and updated."
    else
        echo "    [WARN] Homebrew not found. Install ClamAV manually: brew install clamav"
    fi
else
    echo "    [OK] ClamAV already installed."
fi

# Make scripts executable
chmod +x tools/audit_system.py
chmod +x src/guard_monitor.py
chmod +x src/watchdog.py
chmod +x sovereign

echo "[*] Setting up Launch Agent for Process Monitor (macOS)..."

# Define the LaunchAgent plist
PLIST_PATH="$HOME/Library/LaunchAgents/com.sovereign.watchdog.plist"
SCRIPT_PATH="$(pwd)/src/watchdog.py"
PYTHON_PATH="$(pwd)/venv/bin/python3"

cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sovereign.watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_PATH</string>
        <string>$SCRIPT_PATH</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$(pwd)/logs/guard_watchdog.err</string>
    <key>StandardOutPath</key>
    <string>$(pwd)/logs/guard_watchdog.out</string>
</dict>
</plist>
EOF

echo "    [INFO] Created plist at $PLIST_PATH"
echo "    [NOTE] To activate, run: launchctl load $PLIST_PATH"

echo "[*] Installing Command Line Interface..."
# Source files are now in src/
# CLI is now a pre-existing root script developed by Antigravity
chmod +x sovereign
echo "    [PASS] CLI configured as './sovereign'"

echo "==========================================="
echo "   Setup Complete.                         "
echo "   Run './venv/bin/python3 tools/audit_system.py' to verify OS."
echo "==========================================="
