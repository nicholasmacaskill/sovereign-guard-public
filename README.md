# Sovereign Guard Suite

## Overview
Sovereign Guard is a **read-only monitoring system** designed to detect browser session hijacking attempts on your local machine. It **does not interfere** with your active Chrome sessions, tabs, or browsing activity—it only watches for malicious processes attempting to exploit your browser.

## What This Protects Against

### Chrome's Device Bound Session Credentials (DBSC) - And Its Gaps

In 2024-2025, Google introduced **Device Bound Session Credentials (DBSC)** to combat session theft. DBSC binds your login sessions to your specific hardware, making stolen cookies useless on another machine.

**However, DBSC has critical gaps:**

1. **Remote Debugging Bypass**: Attackers can launch Chrome with `--remote-debugging-port` on *your own machine* to bypass hardware binding and extract live session tokens.
2. **Malicious Extensions**: Extensions loaded via `--load-extension` can intercept credentials before DBSC protects them.
3. **Local Privilege Escalation**: Malware running locally can spawn Chrome instances that inherit your hardware signature but operate under attacker control.

**Sovereign Guard closes these gaps** by detecting when Chrome is launched with these exploit flags—something DBSC cannot prevent on its own.

## How It Works (Non-Invasive Monitoring)

### Read-Only Process Scanning
The monitor uses `psutil` to **read** the list of running processes and their command-line arguments. It does **not**:
- Modify any processes
- Inject code into Chrome
- Access your browsing data
- Interfere with active tabs or sessions
- Require admin/root privileges

### What It Detects
When a Chrome process starts with dangerous flags, the monitor:
1. **Logs the event** to `guard_monitor.log`
2. **Sends a desktop notification** with threat details
3. **Runs automatic diagnostics**:
   - Scans for suspicious LaunchAgents
   - Checks for active remote debugging ports
   - Lists recent app installations

### Your Active Sessions Are Safe
- **Normal Chrome usage**: Completely unaffected. Browse, login, use extensions as usual.
- **Existing tabs**: Never touched or modified.
- **Cookies/sessions**: Not accessed or read by the monitor.
- **Performance**: Minimal CPU usage (checks every 2 seconds).

## The Session Theft Attack Vector

### How Attackers Exploit DBSC Gaps

Even with DBSC enabled, an attacker with local access (via malware, phishing, or supply chain attack) can:

```bash
# Attacker launches Chrome with remote debugging on YOUR machine
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/stolen-profile
```

This allows them to:
- **Bypass DBSC**: The process runs on your hardware, so DBSC sees it as legitimate.
- **Extract live sessions**: Use Chrome DevTools Protocol to dump cookies, tokens, and credentials.
- **Hijack accounts**: Replay your sessions on their own machine (DBSC can't distinguish the source).

**Sovereign Guard detects this immediately** and alerts you before damage occurs.

## Installation & Usage

### Quick Start
```bash
cd /Users/nicholasmacaskill/Desktop/python-sovereign-guard/
./setup.sh
```

### Run the Monitor
```bash
./venv/bin/python3 guard_monitor.py
```

### Enable Auto-Start (Persistent Protection)
```bash
launchctl load ~/Library/LaunchAgents/com.sovereign.guard_monitor.plist
```

## Alert Response

When you receive a **"CRITICAL: BROWSER HIJACK RISK"** notification:

1. **Immediate**: Close the flagged Chrome process (PID shown in alert)
   ```bash
   kill -9 [PID]
   ```

2. **Investigate**: Review the automatic diagnostics in your terminal
   - Check for suspicious LaunchAgents
   - Verify no external debuggers are connected
   - Review recent app installations

3. **Scan**: Run a malware scan
   ```bash
   brew install clamav
   freshclam
   clamscan -r ~/
   ```

## Peace of Mind Guarantees

✅ **No Session Interference**: Your active Chrome sessions remain untouched  
✅ **No Data Access**: The monitor never reads cookies, passwords, or browsing history  
✅ **No Performance Impact**: Lightweight scanning with minimal resource usage  
✅ **No Admin Required**: Runs with standard user permissions  
✅ **Open Source**: All code is visible and auditable in this repository  

## Additional Security Tools

### OS Hardening Audit
Check your system's security posture:
```bash
./venv/bin/python3 audit_system.py
```

Verifies:
- macOS Lockdown Mode status
- DBSC support in your browser
- Core Isolation (Windows) / HVCI settings

### Authentication Policy (For Developers)
If you're building web applications, use the included `auth_middleware.ts` to enforce hardware-key-only authentication (FIDO2/WebAuthn) and block SMS/TOTP for admin routes.

## Technical Details

### Monitored Flags
- `--remote-debugging-port`: Enables Chrome DevTools Protocol access
- `--load-extension`: Loads unpacked extensions (common malware vector)

### Diagnostic Checks (Automatic)
- **LaunchAgents**: Scans `~/Library/LaunchAgents/` for Chrome-related persistence
- **Network Ports**: Detects listening debugger ports (9222, 1337, etc.)
- **Recent Installs**: Lists apps installed in the last 7 days

### Log Files
- `guard_monitor.log`: All detections and diagnostics
- `guard_monitor.err`: Error output (if running as LaunchAgent)

## Why This Matters

DBSC is a major step forward, but it assumes attackers only steal cookies remotely. **Local exploitation** remains a blind spot. Sovereign Guard fills that gap by detecting when your own machine is being used against you.

## Support & Contribution

This is a security tool built for transparency. Review the code, suggest improvements, or report issues.

**Stay Sovereign. Stay Secure.**
