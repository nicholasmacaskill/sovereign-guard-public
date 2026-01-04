# 🔍 Sovereign Guard: Audit & Verification Guide

> **Trust, but verify.** This guide shows you how to audit Sovereign Guard's behavior and confirm it works as advertised.

---

## 1. Code Transparency Audit

### What's Public (Read the Source)
The following files are **unencrypted** on GitHub for full transparency:
- `sovereign` - Main CLI wrapper
- `sovereign_ctl.py` - Control logic (start/stop/commands)
- `sovereign_dashboard.py` - Threat visualization dashboard
- `audit_system.py` - System integrity checker
- `bootstrap_discovery.py` - Learning engine initialization
- `test_suite.py` - Threat simulation suite

**How to audit:**
```bash
# Clone and inspect public source
git clone https://github.com/nicholasmacaskill/python-sovereign-guard.git
cd python-sovereign-guard

# Read the control logic
cat sovereign_ctl.py sovereign_dashboard.py
```

**What to verify:**
- ✅ No network calls or telemetry
- ✅ All data stays on your machine
- ✅ Only reads/writes to local log files

---

## 2. Runtime Behavior Verification

### Monitor What It's Actually Doing
```bash
# Check CPU/Memory footprint (should be minimal)
ps aux | grep guard_monitor

# Verify file access (should only touch logs and configs)
lsof -p $(cat guard_monitor.pid)

# Confirm zero outbound network connections from Sovereign Guard
lsof -i | grep -i python
```

**Expected behavior:**
- CPU usage: <5% on average
- Memory: ~20-50MB
- Network: **Zero connections** (it only monitors, doesn't phone home)

---

## 3. Log File Inspection

All activity is logged in plaintext. Nothing is hidden.

```bash
# Real-time threat detection log
tail -f guard_monitor.log

# Learning observations (what it trusts)
cat .learning_log.json | jq '.observations | .[-10:]'

# System status
./sovereign status
```

**What to look for:**
- Timestamps match actual events
- Detections align with your actions
- No unexpected entries or external IPs

---

## 4. Threat Simulation Tests

Run the built-in test suite to verify detections work:

```bash
# Activate virtual environment
source venv/bin/activate

# Run comprehensive threat simulations
python3 test_suite.py
```

**Tests include:**
- Clipboard poisoning (crypto addresses, API keys)
- Command injection patterns
- Suspicious process flags (`--remote-debugging-port`)
- Network activity from untrusted processes

**Expected result:** All threats should be detected and logged immediately.

---

## 5. Trust Model for Encrypted Components

The following are **encrypted** on GitHub to protect proprietary IP:
- `sovereign_core.py` - Threat detection algorithms
- `guard_monitor.py` - Core monitoring engine
- `SovereignNative/` - Native macOS UI
- AI forensics and learning models

**How to verify encrypted components:**
1. **Behavioral Evidence**: Does it detect what it claims? Run the test suite.
2. **Public Fingerprint**: Check the [immutable proof of creation](https://gist.github.com/nicholasmacaskill) showing code existed on Jan 3, 2026.
3. **Reputation**: Track GitHub issues, community feedback, and my public commits.

**This is standard for security tools.** Commercial EDR vendors (CrowdStrike, SentinelOne) also keep detection logic proprietary—you trust them based on outcomes, not by reading their source.

---

## 6. Network Isolation Test

Sovereign Guard is **100% local-first**. Verify this:

```bash
# Disconnect from the internet
sudo ifconfig en0 down

# Sovereign Guard should still work perfectly
./sovereign status
./sovereign scan

# Reconnect
sudo ifconfig en0 up
```

**Expected:** All features work offline. No errors about "can't reach server."

---

## 7. Uninstall Verification

Want to remove it completely?

```bash
./sovereign stop
rm -rf ~/Desktop/python-sovereign-guard
```

**Verify cleanup:**
- No background processes: `ps aux | grep sovereign`
- No network listeners: `lsof -i | grep sovereign`
- Your system is exactly as it was before installation

---

## 🛡️ Questions or Concerns?

If you find behavior that contradicts this guide, **open a GitHub issue immediately**:
[https://github.com/nicholasmacaskill/python-sovereign-guard/issues](https://github.com/nicholasmacaskill/python-sovereign-guard/issues)

Security tools require trust. This guide exists so you don't have to take my word for it—**verify everything yourself**.
