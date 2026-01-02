# 🛡️ Sovereign Guard Suite (2026 Edition)

> **"Your hardware is secure, but is your session?"**

Sovereign Guard is a high-fidelity, zero-trust security perimeter designed to protect modern workstations against the 2026 threat landscape. While 2024-era protections like **Device Bound Session Credentials (DBSC)** secured cookies to hardware, they left a massive blind spot: **Local Environment Exploitation.**

Sovereign Guard fills that gap by monitoring the integrity of your browser's execution and the sanctity of your clipboard.

## 💎 Value Proposition: Session Sovereignty

Sovereign Guard solves a specific security gap that standard tools (like Antivirus or YubiKeys) do not address: **Local Environment Exploitation.**

*   **The Problem**: Modern security protects the *Login*. Once logged in, your "Session Cookie" is vulnerable. Malware can launch hidden "Shadow Sessions" or swap your clipboard content in milliseconds.
*   **The Solution**: Sovereign Guard assumes your environment is hostile and actively polices it.
    *   **Anti-Hijack**: Kills browsers attempting to run in "Debug Mode" or from hidden locations.
    *   **Clipboard Sentry**: Detects and neutralizes "Copy/Paste Attacks" (crypto swappers).
    *   **Double-Lock Resilience**: Military-grade process supervision ensures the monitor cannot be disabled by user-space malware.

---

## ⚡️ The 2026 Threat Landscape

In 2026, account hijacking has evolved beyond simple cookie theft. Attackers now leverage:

### 1. DBSC "Inside-Out" Bypasses
DBSC binds your session to your TPM/Secure Enclave. However, malware running on your machine can launch a **legitimate, hardware-signed browser** with `--remote-debugging-port`. The session is "securely bound" to your machine, but the attacker controls it remotely via the DevTools Protocol.

### 2. Advanced Clipboard "Clippers"
Sophisticated malware now monitors your clipboard in real-time. When it detects a high-value address (BTC/ETH) or a sensitive command (`curl | bash`), it swaps the content in the milliseconds between **Copy** and **Paste**.

### 3. "Shadow Session" & Profile Cloning
Attackers do not need to hijack your *active* browser window. Instead, they launch a **parallel, invisible Chrome instance** (`--headless`) that points to your existing user profile data.
*   **The Threat**: To you, your browser looks normal. In the background, a second "Shadow Chrome" is running with your logged-in sessions, controlled remotely via the DevTools Protocol.
*   **The Mitigation**: Sovereign Guard monitors *every* process. Even if your main window is safe, if a background process attempts to launch a secondary instance with debugging or a cloned profile, it is instantly terminated.

---

## 🛡️ Mitigation Strategies

Sovereign Guard neutralizes these threats through multi-layered, low-latency monitoring.

### 🏗️ Execution Integrity (Anti-Hijack)
*   **Watchdog Supervisor**: A dedicated `watchdog.py` process acts as a supervisor, instantly resurrecting the monitor if it is killed by malware.
*   **Flag Neutralization**: Kills any browser process launched with dangerous flags (`--remote-debugging-port`, `--load-extension`) that allow external control or unvetted code execution.
*   **Path Enforcement**: Rejects any browser binary running from untrusted locations. Chrome must run from `/Applications/` or it is considered a compromise.
*   **Origin Tracing**: Every event logs the **Parent Process**, unmasking the hidden scripts or agents that attempted the launch.

### 📋 Clipboard Sentry (Anti-Virus)
*   **Strict Neutralization**: Detects and overwrites "Instructional Threats" (command injections like `curl | bash`) and "Script Droppers" (`eval(atob)`) the moment they enter the clipboard.
*   **Swap-Mode Protection**: Actively monitors financial addresses. If a background process attempts to swap your copied BTC address for an attacker's, the system detects the delta and resets it to a safety warning.
*   **Exposure Prevention**: Alerts you if sensitive keys (RSA, AWS Secrets) are copied while suspicious background activity is detected.

### ⚡️ Active Counter-Response (Honeypotting)
*   **Attacker Identification**: If a remote hijack is detected via a debug port, the system automatically traces the **Remote IP address** of the attacker.
*   **Forensic Scare Messages**: Instead of a generic warning, the system overwrites the clipboard with a targeted message: `[SOVEREIGN_SEC_LOG]: ATTACKER IP [IP] LOGGED. WE HAVE YOUR FINGERPRINT.`
*   **Aggressive Alerts**: Vocalizes a severe warning: *"Active hijack confirmed. Attacker location traced. Forensic counter-measures initiated."*
When a threat is neutralized, the system automatically initiates a deep-dive audit:
*   **Persistence Audit**: Scans `~/Library/LaunchAgents` for malicious persistence.
*   **Network Sentry**: Scans for listening debugger ports that bypassed process checks.
*   **Malware Pulse**: Triggers an automated `clamscan` of high-risk directories (`~/Downloads`, `/tmp`).

---

## 🚀 Quick Start (For Novices)

**Just run this command.** It automates everything:
```bash
./setup.sh
```
This script will:
1.  Install the necessary "brains" (Python dependencies).
2.  Set up the **Double-Lock** supervisor (see below).
3.  Launch the protection immediately.

You will hear: *"Sovereign Guard online. Verification active."* 
You will hear: *"Sovereign Guard online. Verification active."* 
That's it. You are secure.

## ⚠️ Important: "Core Logic" Requirement
**Note for GitHub Users**: This repository contains the **Public Shell** (`guard_monitor.py`) and a **Demo Core** (`sovereign_core_example.py`).
The proprietary detection logic (`sovereign_core.py`) is **not included** in this public release.

To run the system in **Demo Mode**:
1.  Rename the example file:
    ```bash
    mv sovereign_core_example.py sovereign_core.py
    ```
2.  Run the setup script.

*To obtain the full commercial license with heuristics and zero-day detection, contact the developer.*

> **Developer Note**: This repo uses `git-crypt`. If you are the owner, unlock the core matching your key:
> `git-crypt unlock ./my-sovereign-key.key`

---

## 🏗️ The "Double-Lock" Architecture (Bulletproof)

Sovereign Guard uses a military-grade "Two-Man Rule" specifically designed to be resilient against malware attempts to kill it:

1.  **The Watchdog (Supervisor)**: This process does nothing but watch the monitor. If the monitor dies or is killed, the Watchdog resurrects it in `< 0.1s`.
2.  **The OS Daemon (Launchd)**: The macOS system itself watches the Watchdog. If you kill the Watchdog, macOS restarts it instantly.

**Result**: To stop Sovereign Guard, an attacker would need **Root/Administrator** access to unload the system daemon. User-space malware cannot kill it.

---

## ⚙️ Manual Configuration (Optional)

### 1. Configure Your Secret
Sovereign Guard uses a secret key to authorize "Safe Mode" and prevent malware from disabling the monitor.
```bash
cp .env.example .env.sovereign
# Edit .env.sovereign and set a strong SOVEREIGN_SECRET (Default is fine for testing)
nano .env.sovereign
```

### 2. Run the Initializer
(If you didn't use the Quick Start command above)
```bash
./setup.sh
```

### 3. Verify OS Hardening
Run the audit tool to ensure your macOS settings are optimized.
```bash
./sovereign scan
```

---

## ⚡️ Quick Controls

Use the `sovereign` CLI to manage your perimeter.

| Command | Action |
| :--- | :--- |
| `./sovereign start` | Launch the background monitor |
| `./sovereign status` | View perimeter health and active mode |
| `./sovereign dev` | Enable **Safe Mode** (Suspends auto-kill for debugging) |
| `./sovereign secure`| Re-arm the **Active Defense** |
| `./sovereign scan` | Perform a one-time security audit |
| `./sovereign stop` | Disable the monitor |

---

## 📜 Technical Details & Whitelist

### 🛡️ Whitelisted System Processes
Sovereign Guard ignores specific developer tools and system daemons to prevent false positives. The following processes are **EXEMPT** from termination:
*   **Developer Tools**: `code`, `vscode`, `node`, `npm`, `git`, `docker`, `iterm2`, `terminal`, `warp`
*   **System Daemons**: `spotlight`, `launchd`, `finder`, `dock`, `softwareupdated`, `taskgated`
*   **Intelligence Agents**: `knowledge-agent`, `spotlightknowledged`

### 📊 Logs & Diagnostics
*   **Audit Trail**: All events are logged to `guard_monitor.log` (JSON-structured for parsing).
*   **Watcher Logs**: Supervisor events are found in `guard_watchdog.out`.
*   **Feedback**: Uses macOS native `say` for vocal alerts (Samantha voice) and `osascript` for desktop notifications.

**Stay Sovereign. Stay Secure.**
