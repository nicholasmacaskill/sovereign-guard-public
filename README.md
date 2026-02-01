# 🛡️ Sovereign Guard Suite (2026 Enterprise Edition)

**"Your hardware is secure, but is your session?"**

Sovereign Guard is a high-fidelity, zero-trust security perimeter designed to protect modern workstations against the 2026 threat landscape. While 2024-era protections like **Device Bound Session Credentials (DBSC)** secured cookies to hardware, they left a massive blind spot: **Local Environment Exploitation.**

Sovereign Guard fills that gap by policing the *execution context* rather than just the *credential*. It ensures that even if an attacker has physical or remote access to your machine, they cannot hijack your active sessions or exfiltrate sensitive data.

---

## System Architecture

Sovereign Guard operates as a multi-layered defensive shell around your sensitive applications. It combines real-time process monitoring, forensic directory auditing, and deep browser introspection.

```mermaid
graph TD
    User([User Workflow]) -- Safe --> Apps[Standard Applications]
    User -- Interaction --> Buffer[System Clipboard]
    
    subgraph SG [Sovereign Guard Perimeter]
        Watchdog[Watchdog Supervisor] --> Monitor[Guard Monitor]
        Monitor --> Scanners[Modular Scanners]
        Scanners -- Scan --> OS[Process Table / LaunchAgents / Network]
        Scanners -- Protect --> Buffer
        Scanners -- Audit --> Browsers[Chrome / Brave / Arc / Edge]
    end
    
    Apps -. Unauthorized Access .-> Buffer
    Apps -. Persistence .-> OS
    SG -- Terminate / Revert --> Apps
```

### Core Components
-   **Watchdog Supervisor**: A resilient background process that ensures the Guard Monitor is always running and tampered-proof.
-   **Guard Monitor**: The central engine that orchestrates the scanning loop, handles alerts, and executes protection maneuvers.
-   **Modular Scanners**: Plug-and-play forensic modules targeting specific attack vectors (Persistence, Clipboard, Network, Browser).

---

## 🛡️ Key Features & Protections

### 1. Anti-Hijack Sentry
Modern session hijacking often involves launching a legitimate browser with the `--remote-debugging-port` flag.
-   **Sentry Logic**: Instantly terminates any browser process launched with dangerous debug flags or by untrusted parent processes.
-   **Sandbox Enforcement**: Flags and blocks browsers running without a sandbox (`--no-sandbox`).

### 2. Smart Clipboard Fortress
Protects against **Pastejacking** and **Crypto Clippers**.
-   **Pastejacking Protection**: Sanitizes the clipboard to remove hidden, malicious terminal commands (e.g., ANSI escape sequences or `curl | sh` pipes).
-   **Crypto Restoration**: Specifically monitors for the replacement of BTC/ETH addresses in the clipboard and reverts them to the original intended address.

### 3. "Ghost" Persistence Monitor
Attacks in 2026 rely on **Shadow Persistence** via Service Workers and Hosted Apps.
-   **Service Worker Audit**: Monitors browser internal directories for new Service Worker registrations.
-   **Smart Whitelisting**: Resolves the origin (URL) of new Service Workers via internal LevelDB analysis. If the origin is a high-trust domain (Google, GitHub, etc.), it is automatically whitelisted to reduce noise.
-   **Extension Sentry**: Scans the `manifest.json` of all installed extensions for high-risk permissions like `<all_urls>`, `debugger`, and `webRequestBlocking`.

### 4. Active Tab & Link Detection
Real-time monitoring of your active browsing environment.
-   **Tab Monitoring**: Uses AppleScript (on macOS) to query the active tab's URL across all supported browsers (Arc, Brave, Chrome, Edge, Safari).
-   **Malicious Link Block**: Warns you instantly if you navigate to a known malicious domain or attempt to download high-risk file types (.scr, .dmg, .pkg, .zip) from untrusted sources.

### 5. Advanced Injection Defense (New for 2026)
Protects against sophisticated malware running *inside* your trusted applications.
-   **Process Memory Scanner**: Periodically scans browser memory for injected executable code (RWX regions, suspicious eval(), or shellcode).
-   **Binary Code Integrity**: Verifies SHA-256 hashes of browser binaries every 5 minutes to detect tampering or "trojanized" updates.
-   **Module Verification**: Blocks the loading of unsigned or untrusted dynamic libraries (.dylib/.dll) into the browser process space.
-   **Launch Services Monitor**: (macOS) Detects if the default browser handler has been silently hijacked by a malicious wrapper.
-   **Keychain Anomaly Detection**: Uses behavioral analysis to flag processes accessing keychain items at superhuman speeds (>50 reads/min).

---

## The 2026 Threat Landscape

In 2026, account hijacking has evolved beyond simple cookie theft. Sovereign Guard is built to neutralize:
1.  **"Inside-Out" Bypasses**: Malware launching legitimate browsers to clone user sessions remotely.
2.  **Smart Clippers**: Highly optimized scripts that swap secrets in the milliseconds between Copy and Paste.
3.  **Shadow Persistence**: Malicious background scripts that "haunt" browser profiles long after a site is closed.

---

## ✅ Verification & Trust

Sovereign Guard is **Audit-Proven.** Our Playwright-based E2E audit suite verifies the system's effectiveness against real attack simulations.

| Attack Vector | Guard Response | Result |
| :--- | :--- | :--- |
| **Debug Hijack** | Browser Termination | ✅ BLOCK |
| **Process Injection** | Memory Kill | ✅ NEUTRALIZE |
| **Pastejacking** | Buffer Sanitation | ✅ CLEAN |
| **Crypto Clipper** | Address Restoration | ✅ PROTECT |
| **Reverse Shell** | Connection Severed | ✅ KILL |
| **Shadow Persistence**| Entry Purged | ✅ CLEAN |
| **Browser Tampering** | Integrity Alert | ✅ DETECT |
| **Malicious Links** | Active Notification | ✅ WARN |

> [!IMPORTANT]
> **Source Redaction Layer**: To protect our proprietary threat intelligence, this public repository uses a "Redacted Core" model. The scanning logic is fully transparent, but specific malware domain lists and signature patterns are replaced with `REDACTED` placeholders. For the full, unredacted intelligence suite, authorized users should refer to the [Private Repository](https://github.com/nicholasmacaskill/sovereign-guard-private).

---

## 🚀 Quick Start

### Installation
1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/nicholasmacaskill/python-sovereign-guard.git
    cd python-sovereign-guard
    ```
2.  **Initialize Environment**:
    ```bash
    ./setup.sh
    ```
3.  **Bootstrap the Baseline**:
    Let the Guard scan your current clean state to build a "Trust Profile":
    ```bash
    ./sovereign bootstrap
    ```

### Command Center
| Command | Description |
| :--- | :--- |
| `./sovereign start` | Launch the active monitor supervisor |
| `./sovereign stop` | Gracefully shut down the security perimeter |
| `./sovereign status` | View Trust Score, Mode, and Health |
| `./sovereign logs` | View real-time security alerts and blocked threats |
| `./sovereign scan` | Perform a deep, manual forensic audit |
| `./sovereign dev` | Enter "Safe Mode" (Alerts only, no active blocking) |

---

## 🛠️ Development & Auditing

Sovereign Guard includes a comprehensive E2E audit suite powered by Playwright. To run the security simulations:
```bash
./venv/bin/python -m pytest tests/e2e/
```

**Stay Sovereign.**
