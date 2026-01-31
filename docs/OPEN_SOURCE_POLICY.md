# Sovereign Guard: Open Source & Redaction Policy

## Our Philosophy

Sovereign Guard follows a **"Transparent Defense"** model. We believe that security software should be open to audit, but proprietary threat intelligence (the "Moat") must be protected to maintain effectiveness.

## Component Tiers

### 1. The Public Shell (Open Source)
The following orchestration and monitoring logic is fully unencrypted and open for audit:
- `guard_monitor.py`: The main detection loop.
- `scanners.py`: Logic for supply chain and hardware monitoring.
- `persistence.py`: Logic for detection Service Workers and LaunchAgents.
- `sovereign_ctl`: Control CLI and watchdog supervisor.

### 2. The Redacted Core (Proprietary)
To protect our users and intellectual property, specific threat signatures in `patterns.py` have been **redacted** in this public repository. 
- **Redacted Items**: Known malicious URLs, specific file hashes, and proprietary forensic heuristics.
- **Goal**: Allow developers to see HOW we detect threats without providing a roadmap for attackers to bypass the specific signatures.

### 3. The Sealed Vault (Hardware Boundary)
Components in `SovereignNative/` and `sovereign_core.py` interact with hardware-bound credentials (DBSC) and are maintained as proprietary modules.

## Contribution
We welcome audits and logic improvements. If you identify a bug in the monitoring loop, please submit a PR.

**Stay Sovereign.**
