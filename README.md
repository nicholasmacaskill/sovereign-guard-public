# 🛡️ Sovereign Guard Suite (2026 Enterprise Edition)

> **"Your hardware is secure, but is your session?"**

Sovereign Guard is a high-fidelity, zero-trust security perimeter designed to protect modern workstations against the 2026 threat landscape. While 2024-era protections like **Device Bound Session Credentials (DBSC)** secured cookies to hardware, they left a massive blind spot: **Local Environment Exploitation.**

**Sovereign Guard fills that gap.** It assumes your local environment is hostile and actively polices process execution, clipboard integrity, and network telemetry in real-time.

---

## 💎 The "Glass" Architecture

Sovereign Guard is built on a **"Glass" Philosophy**: Transparency where it matters, opacity where it's needed.

*   **Public Shell (Open Source)**: The wrapper scripts, monitoring loops, and CLI tools (`src/guard_monitor.py`, `sovereign_ctl`) are fully open-source. You can verify exactly *how* the system watches you.
*   **Encrypted Core (Proprietary)**: The advanced heuristic engines (`src/sovereign_engine/`)—which detect zero-day anomalies, counter-adversarial behavior, and AI forensics—are **encrypted** in this repository. This protects the detection IP while allowing the community to audit the orchestration logic.

---

## ⚡️ The 2026 Threat Landscape

In 2026, account hijacking has evolved beyond simple cookie theft. Attackers now leverage:

1.  **"Inside-Out" Bypasses**: Malware launching legitimate Chrome instances with `--remote-debugging-port` to bypass hardware-bound sessions.
2.  **Smart Clippers**: Malware that swaps crypto addresses or sensitive secrets in the milliseconds between Copy and Paste.
3.  **Shadow Sessions**: Headless browser instances running in the background, cloning your session state.

Sovereign Guard neutralizes these threats instantly.

---

## 🚀 Key Features

### 🛡️ Active Defense
-   **Anti-Hijack Sentry**: Instantly terminates browsers launching with debug flags or suspicious extensions.
-   **Clipboard Fortress**: Detects and reverts malicious address swaps (BTC/ETH) and sanitized command injections.
-   **Reverse Shell Terminator**: Kills unauthorized shells connecting to non-trusted IPs.
-   **Persistence Monitor**: Watches `LaunchAgents` and `~/.ssh` for unauthorized backdoors.

### 🧠 AI-Native Intelligence
-   **Learning Mode**: A 7-day adaptive phase that learns your specific workflow.
-   **Bootstrap Acceleration**: Skip the wait—instantly scan your system to build a Trusted Baseline in seconds.
-   **Trust Score**: A real-time `0-100` health metric visible on your dashboard.
-   **Supply Chain Sentinel**: Scans for "typosquatting" packages in your dev environment.

### 🔐 Sovereign Identity
-   **Rubicon 2FA**: Enforce hardware-key (YubiKey) or TOTP verification for sensitive commands (`stop`, `off`).
-   **Double-Lock Resilience**: A "Watchdog" supervisor ensures the monitor cannot be disabled by user-space malware.

---

## 🚀 Quick Start

**1. Install & Setup**
```bash
./setup.sh
```
This installs dependencies, configures the environment, and launches the daemon.

**2. Bootstrap (Skip Learning)**
Instead of waiting 7 days, instantly learn your current environment:
```bash
./sovereign bootstrap
```

**3. Check Status**
```bash
./sovereign status
```

---

## 🕹️ Command Center

Use the `sovereign` CLI to control your perimeter:

| Command | Description |
| :--- | :--- |
| `./sovereign start` | Launch the active monitor |
| `./sovereign status` | View Trust Score, Mode, and Health |
| `./sovereign logs` | **NEW**: View today's security alerts |
| `./sovereign bootstrap` | **NEW**: Instantly learn current system state |
| `./sovereign dev` | Enable Safe Mode (Pause auto-kill) |
| `./sovereign 2fa` | Setup Rubicon (TOTP/Hardware Lock) |
| `./sovereign scan` | Run a one-time forensic audit |

---

## ⚙️ Configuration Modes

Sovereign Guard operates in three modes, controlled by `.env.sovereign`:

1.  **LEARN (Days 1-7)**: Observes behavior, builds whitelist. No blocking.
2.  **WARN (Days 8-14)**: Alerts on threats but does not kill. User review required.
3.  **PROTECT (Day 15+)**: **Ruthless.** Any unknown process or anomaly is terminated instantly.

**Manual Override:**
```bash
# Force Full Protection Immediately
echo 'PROTECTION_MODE="protect"' >> .env.sovereign
./sovereign restart
```

---

## � Security Note

This repository contains **encrypted binaries** (via `git-crypt`) for the `sovereign_engine`.
To unlock the full detection logic, you must possess the authorized GPG key.

*   **Public**: `src/guard_monitor.py`, `tools/`, `sovereign_ctl`
*   **Encrypted**: `src/sovereign_engine/`, `docs/MARKETING_COPY.md`

**Stay Sovereign.**
