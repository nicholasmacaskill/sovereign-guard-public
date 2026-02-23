import psutil
import re
import time
import sys
import os
import socket
import logging
import subprocess
import platform
import hmac
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from plyer import notification
import path_utils

# IMPORT PROPRIETARY CORE
try:
    import sovereign_core as core
except ImportError:
    print("CRITICAL: 'sovereign_core' module not found.")
    sys.exit(1)

# Session domain learner (passive, no-fail)
try:
    import session_learner
    _SESSION_LEARNER_AVAILABLE = True
except ImportError:
    _SESSION_LEARNER_AVAILABLE = False

try:
    from sovereign_engine import tripwire
    _TRIPWIRE_AVAILABLE = True
except ImportError:
    _TRIPWIRE_AVAILABLE = False

# Global State & Constants
LAST_SPOKEN_TIME = 0
VOICE_COOLDOWN = 5 
SAFE_MODE_FILE = path_utils.get_config_file("developer_mode.lock")
ENV_FILE = path_utils.get_config_file(".env.sovereign")
AUTO_MALWARE_SCAN = True
SCAN_PATHS = [
    os.path.expanduser('~/Downloads'),
    os.path.expanduser('~/Library/LaunchAgents'),
    '/tmp'
]

# Configure logging
log_path = path_utils.get_log_file('guard_monitor.log')
handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=2)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def notify_alert(title, message, sound=None):
    """Triggers a desktop notification."""
    try:
        if sys.platform == "darwin":
            safe_title = title.replace('\\', '\\\\').replace('"', '\\"')
            safe_message = message.replace('\\', '\\\\').replace('"', '\\"')
            sound_str = f'sound name "{sound}"' if sound else 'sound name ""'
            script = f'display notification "{safe_message}" with title "{safe_title}" {sound_str}'
            subprocess.run(["osascript", "-e", script], check=False)
            return

        notification.notify(title=title, message=message, app_name='Sovereign Guard', timeout=10)
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

def speak(text):
    """Speaks text using a calm female voice (macOS), with debounce. [MUTED]"""
    # Vocal warnings disabled - using silent notifications instead
    pass


def enforce_debug_port_firewall():
    """Blocks TCP port 9222 (Chrome DevTools Protocol) via pf at startup.
    Prevents session theft even if the guard is slow to kill a flagged process.
    No-op when Developer Mode is active.
    """
    if check_safe_mode():
        logger.info("Developer Mode active — skipping port 9222 pf block.")
        return
    try:
        # Check if rule already exists to avoid duplicates
        existing = subprocess.run(['pfctl', '-sr'], capture_output=True, text=True, timeout=3)
        if existing.returncode == 0 and '9222' in (existing.stdout or ''):
            logger.info("Port 9222 pf rule already active.")
            return

        rule = 'block drop quick proto tcp from any to any port 9222\n'
        proc = subprocess.run(
            ['pfctl', '-ef', '-'],
            input=rule, capture_output=True, text=True, timeout=5
        )
        if proc.returncode == 0 or 'pf enabled' in (proc.stderr or '').lower():
            msg = "🔒 PORT 9222 BLOCKED: Chrome DevTools Protocol sealed via pf firewall."
            print(msg)
            logger.info(msg)
        else:
            logger.warning(f"pf rule for port 9222 may have failed: {proc.stderr.strip()}")
    except FileNotFoundError:
        logger.warning("pfctl not found — cannot block port 9222 via pf.")
    except Exception as e:
        logger.warning(f"Could not enforce debug port firewall: {e}")


def scan_launchagent_plists():
    """Scans LaunchAgent and LaunchDaemon plists for entries that launch Chrome
    with --remote-debugging-port. This is how the Feb 2 attacker persisted.
    Returns a list of suspicious plist paths.
    """
    suspicious = []
    plist_dirs = [
        os.path.expanduser('~/Library/LaunchAgents'),
        '/Library/LaunchAgents',
        '/Library/LaunchDaemons',
    ]
    for d in plist_dirs:
        if not os.path.isdir(d):
            continue
        try:
            entries = os.listdir(d)
        except PermissionError:
            continue
        for fname in entries:
            if not fname.endswith('.plist'):
                continue
            fpath = os.path.join(d, fname)
            try:
                result = subprocess.run(
                    ['plutil', '-convert', 'json', '-o', '-', fpath],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode == 0 and '--remote-debugging-port' in result.stdout:
                    suspicious.append(fpath)
                    
                    # QUARANTINE LOGIC (Active Defense)
                    quarantine_dir = path_utils.get_config_dir("quarantine")
                    os.makedirs(quarantine_dir, exist_ok=True)
                    q_path = os.path.join(quarantine_dir, f"{os.path.basename(fpath)}.quarantine")
                    
                    msg = f"🚨 MALICIOUS PERSISTENCE NEUTRALIZED: {fpath}"
                    print(f"\n{msg}")
                    logger.critical(msg)
                    
                    # Unload and move the file
                    try:
                        subprocess.run(['launchctl', 'unload', fpath], capture_output=True, check=False)
                        os.rename(fpath, q_path)
                        logger.info(f"Quarantined malicious plist to: {q_path}")
                    except Exception as e:
                        logger.error(f"Failed to quarantine {fpath}: {e}")

                    notify_alert(
                        "🔒 Threat Neutralized",
                        f"A malicious LaunchAgent was found and quarantined:\n{os.path.basename(fpath)}",
                        sound="Basso"
                    )
                    speak("Active Defense engaged. Malicious persistence detected and neutralized.")
            except Exception:
                continue
    return suspicious


def check_debug_port_activity():
    """Detects any process listening or connected on port 9222 (Chrome DevTools).
    The pf rule blocks inbound connections, but the port may still be OPEN on the
    process side — we log who opened it so there's a forensic trail.
    """
    try:
        result = subprocess.run(
            ['lsof', '-iTCP:9222', '-sTCP:LISTEN,ESTABLISHED', '-n', '-P'],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode != 0 or not result.stdout.strip():
            return

        for line in result.stdout.strip().splitlines():
            if 'COMMAND' in line:
                continue  # header row
            parts = line.split()
            if len(parts) < 2:
                continue
            proc_name = parts[0]
            pid = parts[1]
            state = parts[-1] if parts else 'UNKNOWN'
            msg = (
                f"🔍 PORT 9222 ACTIVITY: '{proc_name}' (PID: {pid}) has the "
                f"Chrome DevTools port {state} — connection blocked by pf"
            )
            print(f"\n{msg}")
            logger.warning(msg)
            notify_alert(
                "⚠️ Debug Port Activity Logged",
                f"'{proc_name}' (PID: {pid}) opened port 9222. Connection sealed by firewall.",
                sound="Basso"
            )
    except Exception as e:
        logger.debug(f"Port 9222 activity monitor error: {e}")


def check_linkedin_session_activity():
    """Flags non-browser processes making established HTTPS connections to LinkedIn.
    Uses lsof to find active TCP:443 connections then reverse-resolves the remote IP.
    If a non-browser process is calling linkedin.com, that's session exfiltration risk.
    """
    try:
        result = subprocess.run(
            ['lsof', '-iTCP:443', '-sTCP:ESTABLISHED', '-n', '-P'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0 or not result.stdout.strip():
            return

        for line in result.stdout.strip().splitlines():
            if 'COMMAND' in line:
                continue
            parts = line.split()
            # lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            # NAME for TCP: local->remote
            if len(parts) < 9:
                continue
            proc_name = parts[0]
            pid = parts[1]
            name_field = parts[8]

            # Skip whitelisted browser processes
            if any(b in proc_name.lower() for b in core.SESSION_MONITOR_BROWSERS):
                continue

            # Extract remote IP from the local->remote field
            if '->' not in name_field:
                continue
            remote = name_field.split('->')[1]
            remote_ip = remote.rsplit(':', 1)[0]  # Handle IPv6 brackets

            # Reverse-resolve to catch LinkedIn IPs
            try:
                hostname = socket.gethostbyaddr(remote_ip)[0]
            except (socket.herror, socket.gaierror):
                continue

            if any(d in hostname for d in core.PROTECTED_SESSION_DOMAINS):
                msg = (
                    f"🚨 LINKEDIN SESSION RISK: Non-browser process '{proc_name}' "
                    f"(PID: {pid}) has an active HTTPS connection to {hostname} ({remote_ip})"
                )
                print(f"\n{msg}")
                logger.warning(msg)
                notify_alert(
                    "🔐 LinkedIn Session Access by Non-Browser",
                    f"'{proc_name}' (PID: {pid}) → {hostname}\nThis process should not have access to your session.",
                    sound="Basso"
                )
    except Exception as e:
        logger.debug(f"LinkedIn session monitor error: {e}")


def check_safe_mode():
    """Checks if Developer Mode is active and VERIFIES the authorization secret."""
    if not os.path.exists(SAFE_MODE_FILE): return False
    try:
        secret = path_utils.get_secret()
        if not secret: return False
        with open(SAFE_MODE_FILE, 'r') as f:
            sig = f.read().strip()
            return hmac.compare_digest(sig, secret)
    except: return False

def get_clipboard_content():
    """Gets current clipboard content using pbpaste on macOS."""
    try:
        if platform.system() == 'Darwin':
            return subprocess.check_output(['pbpaste'], text=True, stderr=subprocess.DEVNULL)
    except: pass
    return None

def set_clipboard_content(text):
    """Overwrites clipboard content using pbcopy on macOS."""
    try:
        if platform.system() == 'Darwin':
            process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            process.communicate(input=text.encode('utf-8'))
            return True
    except: pass
    return False

def check_clipboard_sentry(last_val, safe_mode=False):
    """Monitors for suspicious clipboard content and NEUTRALIZES threats using Core Logic."""
    current_val = get_clipboard_content()
    if not current_val: return current_val, None
    
    # If user is in Safe Mode (Developer Mode), don't purge.
    if safe_mode:
        return current_val, None
        
    detected_threats = []
    
    # 0. Global Safe List Check (Prevent False Positives for common things)
    is_whitelisted = False
    for whitelist_pattern in getattr(core, 'CLIPBOARD_WHITELIST', []):
        if re.search(whitelist_pattern, current_val, re.IGNORECASE):
            is_whitelisted = True
            break
    
    if not is_whitelisted:
        # Use threat patterns from CORE
        for threat_name, pattern in core.THREAT_PATTERNS.items():
            match = pattern.search(current_val)
            if match:
                if threat_name in core.STRICT_MODE_THREATS:
                    detected_threats.append((threat_name, match.group(0)))
                elif threat_name == "SENSITIVE_EXPOSURE":
                     detected_threats.append((threat_name, "[REDACTED_SENSITIVE_KEY]"))
    
    # Check for Crypto Swaps
    crypto_match = core.THREAT_PATTERNS["CRYPTO_SWAP"].search(current_val)
    last_crypto_match = core.THREAT_PATTERNS["CRYPTO_SWAP"].search(last_val) if last_val else None
    
    if crypto_match and last_crypto_match:
        curr_addr = crypto_match.group(0)
        prev_addr = last_crypto_match.group(0)
        if curr_addr != prev_addr:
            detected_threats.append(("CRYPTO_SWAP", f"{prev_addr[:10]}... -> {curr_addr[:10]}..."))

    if detected_threats:
        threat_types = [t[0] for t in detected_threats]
        threat_desc = "; ".join([f"{t[0]}: {t[1]}" for t in detected_threats])
        
        # 1. IMMEDIATE NEUTRALIZATION using Core Intelligence
        attacker_ip = None
        for p in psutil.process_iter(['pid', 'name']):
            try:
                # Basic check here, core has deep logic if we need it
                if any(b in (p.info['name'] or "").lower() for b in ['chrome', 'brave', 'edge']):
                     # Calls Core to get IP
                     ip = core.get_attacker_ip(p.info['pid'])
                     if ip: attacker_ip = ip
            except: continue

        if attacker_ip:
            scare_msg = f"[SOVEREIGN_SEC_LOG]: ENCRYPTION KEY MASKED. REMOTE IP {attacker_ip} LOGGED. WE HAVE YOUR FINGERPRINT."
            set_clipboard_content(scare_msg)
            speak("Active hijack confirmed. Attacker location traced.")
        else:
            # LEARN MODE CHECK
            try:
                from learning_engine import get_protection_mode
                mode = get_protection_mode()
            except:
                mode = 'protect'
                
            if mode == 'learn':
                # Just log and move on, don't overwrite clipboard
                logger.info(f"[LEARN] Clipboard threat observed (not neutralized): {threat_desc}")
                return current_val, None
                
            set_clipboard_content("⚠️ SOVEREIGN GUARD: CLIPBOARD VIRUS DETECTED! DO NOT PASTE. ⚠️")
        
        # 2. AUDIT AND KILL via Core
        alert_msg = f"❌ CLIPBOARD THREAT NEUTRALIZED!\n    Detections: {threat_desc}"
        if attacker_ip: alert_msg += f"\n    🚨 ATTACKER TRACED: {attacker_ip}"

        audit_result = core.audit_clipboard_hijacker()
        alert_msg += f"\n    Result: {audit_result}"
        
        if not attacker_ip:
            speak("Clipboard threat detected and neutralized.")
            
        return "⚠️ SOVEREIGN GUARD: CLIPBOARD THREAT DETECTED", alert_msg

    return current_val, None

def handle_safe_mode_transitions(is_safe_mode, was_safe_mode):
    """Processes entry/exit of Safe Mode with UI feedback."""
    if is_safe_mode and not was_safe_mode:
        print("\n⚠️  DEVELOPER MODE ACTIVE: Auto-Kill Disabled.")
        speak("Developer mode enabled.")
        return True
    elif not is_safe_mode and was_safe_mode:
        print("\n🛡️  DEVELOPER MODE DEACTIVATED: Auto-Kill Re-armed.")
        speak("Developer mode disabled.")
        return False
    return was_safe_mode

def run_multimedia_sequence():
    """Checks for unauthorized camera/mic/screen access."""
    threats = core.check_multimedia_access()
    if threats:
        for t in threats:
            msg = f"\n🚨 MULTIMEDIA ALERT: {t['process']} (PID: {t['pid']}) is accessing hardware."
            print(msg)
            logger.warning(msg)
            speak(f"Warning. Unauthorized {t['process']} is accessing your camera or microphone.")
        return True
    
    if core.check_screen_sharing():
        msg = "\n🚨 SCREEN SHARING ALERT: Active screen sharing detected."
        print(msg)
        logger.warning(msg)
        speak("Warning. Screen sharing is active.")
        return True
    return False

def run_clipboard_sequence(last_clipboard, is_safe_mode):
    """Orchestrates clipboard monitoring and neutralization."""
    current_clipboard, cb_alert = check_clipboard_sentry(last_clipboard, safe_mode=is_safe_mode)
    if cb_alert:
        print(f"\n{cb_alert}")
        logger.warning(cb_alert)
        speak("Warning. Clipboard hijack attempt detected.")
    return current_clipboard

def run_persistence_sequence(baseline):
    """Checks for persistence threats against a baseline."""
    new_baseline, threats = core.check_persistence(last_files=baseline)
    if threats:
        for t in threats:
            msg = f"\n{t['title']}: {t['summary']}"
            print(msg)
            logger.warning(msg)
            speak(f"Warning. {t['type']} detected at {os.path.basename(t['path'])}.")
    return new_baseline

def run_browser_persistence_sequence(baseline):
    """Checks for browser persistence threats."""
    new_baseline, threats = core.check_browser_persistence()
    if threats:
        for t in threats:
            msg = f"\n{t['title']}: {t['summary']}"
            print(msg)
            logger.warning(msg)
            speak(f"Security Alert. New browser persistence module detected in {os.path.basename(os.path.dirname(t['path']))}.")
    return new_baseline

def scan_single_process(proc, is_safe_mode, current_mode, seen_pids, scanned_pids, run_memory_scan=False):
    """Performs deep security analysis on a single process."""
    try:
        pid = proc.pid
        name = proc.name()
        
        if pid in scanned_pids: return 0
        scanned_pids.add(pid)
        
        # Injection Defense: Memory Scanning (only when triggered)
        if run_memory_scan and core.ENABLE_MEMORY_SCANNING:
            memory_threat = core.scan_process_memory(proc)
            if memory_threat:
                msg = f"\n{memory_threat['title']}: {memory_threat['summary']}"
                print(msg)
                logger.critical(msg)
                notify_alert(memory_threat['title'], memory_threat['summary'], sound="Basso")
                speak("Security alert. Possible memory injection detected in browser.")
                if not is_safe_mode:
                    # Browsers are prone to JIT false positives; we log and alert but don't kill 
                    # unless it's a known non-browser or in aggressive mode.
                    if any(b in name.lower() for b in ['chrome', 'brave', 'edge', 'arc', 'safari']):
                        print(f"    [!] LOGGED: Suspected injection in '{name}' (PID: {pid}). Termination skipped to prevent work loss.")
                        logger.warning(f"Injection termination skipped for browser: {name}")
                    else:
                        try:
                            proc.kill()
                            print(f"    [!] NEUTRALIZED: '{name}' (PID: {pid}) terminated due to injection.")
                        except: pass
        
        # Module/Library Verification
        if run_memory_scan and core.ENABLE_MEMORY_SCANNING:
            module_threat = core.verify_process_modules(proc)
            if module_threat:
                msg = f"\n{module_threat['title']}: {module_threat['summary']}"
                print(msg)
                logger.warning(msg)
                notify_alert(module_threat['title'], module_threat['summary'])
        
        # 1. Vault Guard
        vault_threat = core.check_vault_access(proc)
        if vault_threat:
            msg = f"\n{vault_threat['title']}: {vault_threat['summary']}"
            print(msg)
            logger.warning(msg)
            speak(f"Security Alert. Unauthorized access to your {os.path.basename(os.path.dirname(vault_threat['path']))} vault.")
            if not is_safe_mode and current_mode == 'protect':
                try: proc.kill(); print(f"    [!] NEUTRALIZED: '{name}' killed.")
                except: pass

        # 2. Whitelist Bypass
        name_lower = name.lower()
        if any(safe in name_lower for safe in core.SAFE_LIST_PROCESSES):
            return 0
            
        if pid in seen_pids: return 0
        seen_pids.add(pid)
        
        # 3. Deep Core Check
        alert = core.check_process(proc, mode=current_mode, safe_mode=is_safe_mode)
        if alert:
            print(f"\n{alert['summary']}")
            logger.warning(alert['summary'])
            notify_alert(alert['title'], alert['summary'])
            if not is_safe_mode and alert['critical']:
                try:
                    proc.kill()
                    speak("Critical threat detected. Process neutralized.")
                except: pass
        
        # 4. Network Monitor
        if any(t in name_lower for t in ['chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi', 'chromium']):
            network_threat = core.check_network_activity(proc, mode=current_mode)
            if network_threat:
                print(f"\n{network_threat['summary']}")
                logger.warning(f"[NETWORK] {network_threat['summary']}")
                if network_threat['critical'] or current_mode != 'learn':
                    notify_alert(network_threat['title'], network_threat['summary'])
                if not is_safe_mode and network_threat['critical']:
                    try:
                        proc.kill()
                        speak("Reverse shell detected and neutralized.")
                    except: pass
        return 1
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0

def run_mitm_sequence():
    """Checks for MITM vulnerabilities (ARP spoofing, authorized proxies)."""
    try:
        from sovereign_engine.analyzer import check_mitm_vulnerabilities
        threats = check_mitm_vulnerabilities()
        if threats:
            for t in threats:
                msg = f"\n🚨 MITM ALERT: {t['summary']}"
                print(msg)
                logger.warning(msg)
                speak(f"Security Warning. Potential Man in the Middle vulnerability detected. {t['type'].replace('_', ' ')}")
            return True
    except Exception as e:
        logger.error(f"MITM Check failed: {e}")
    return False

def monitor_loop():
    print("Sovereign Guard Monitor Active (Public Shell)...")
    logger.info("Monitor started.")
    speak("Sovereign Guard online. Verification active.")

    # ── Startup Hardening ──────────────────────────────────────────────────────
    enforce_debug_port_firewall()   # Seal port 9222 via pf immediately
    scan_launchagent_plists()       # Check for malicious LaunchAgents at boot
    
    if _TRIPWIRE_AVAILABLE:
        tripwire.deploy_bait()      # Deploy decoy files
    # ──────────────────────────────────────────────────────────────────────────

    core.start_trigger_thread()

    seen_pids = set()
    last_heartbeat = time.time()
    last_hourly_notify = time.time()
    last_clipboard = get_clipboard_content()

    # Initialize Hardening Baselines
    persistence_baseline, _ = core.check_persistence(last_files=None)
    browser_persistence_baseline, _ = core.check_browser_persistence()
    last_persistence_check = time.time()
    last_mitm_check = time.time()
    last_tab_check = time.time()
    last_plist_scan = time.time()         # LaunchAgent plist scan timer
    last_debug_port_check = time.time()   # Port 9222 activity monitor
    last_linkedin_check = time.time()     # LinkedIn session monitor
    last_ca_scan = time.time()           # Root CA monitor timer

    # Initialize Injection Defense Timers
    last_memory_scan = time.time()
    last_integrity_check = time.time()
    last_launch_services_check = time.time()
    last_keychain_check = time.time()

    was_safe_mode = False
    
    try:
        from learning_engine import get_protection_mode
    except:
        def get_protection_mode(): return os.getenv('PROTECTION_MODE', 'protect')

    try:
        while True:
            # 1. State Caching (Efficiency)
            is_safe_mode = check_safe_mode()
            current_mode = get_protection_mode()
            was_safe_mode = handle_safe_mode_transitions(is_safe_mode, was_safe_mode)

            # 2. Sequential Security Checks
            last_clipboard = run_clipboard_sequence(last_clipboard, is_safe_mode)
            run_multimedia_sequence()
            
            if time.time() - last_persistence_check > 30:
                persistence_baseline = run_persistence_sequence(persistence_baseline)
                browser_persistence_baseline = run_browser_persistence_sequence(browser_persistence_baseline)
                last_persistence_check = time.time()

            if time.time() - last_mitm_check > 60:
                run_mitm_sequence()
                last_mitm_check = time.time()

            # LaunchAgent Plist Scan (every 5 minutes)
            if time.time() - last_plist_scan > 300:
                scan_launchagent_plists()
                last_plist_scan = time.time()

            # Port 9222 Activity Monitor (every 10 seconds)
            if time.time() - last_debug_port_check > 10:
                check_debug_port_activity()
                last_debug_port_check = time.time()

            # LinkedIn Session Monitor + Domain Learner (every 30 seconds)
            if time.time() - last_linkedin_check > 30:
                check_linkedin_session_activity()
                if _SESSION_LEARNER_AVAILABLE:
                    session_learner.scan_browser_session_domains()
                last_linkedin_check = time.time()

            # Root CA Monitor (every 15 minutes)
            if time.time() - last_ca_scan > 900:
                ca_threats = core.scan_root_cas()
                for t in ca_threats:
                    print(f"\n{t['title']}: {t['summary']}")
                    logger.critical(f"Root CA: {t['summary']}")
                    notify_alert(t['title'], t['summary'], sound="Basso")
                    speak("Security Alert. A rogue root certificate was detected in your system keychain. Potential Man in the Middle hijacking.")
                last_ca_scan = time.time()

            # DISABLED: Active Tab Monitoring (Uses AppleScript which auto-launches Safari)
            # if time.time() - last_tab_check > 10:
            #     active_tab_threats = core.check_active_tabs()
            #     for t in active_tab_threats:
            #         print(f"\n{t['title']}: {t['summary']}")
            #         logger.warning(f"Active Tab Threat: {t['summary']}")
            #         notify_alert(t['title'], t['summary'])
            #     last_tab_check = time.time()

            # 2.5 Injection Defense Sequences
            # Binary Integrity Check (every 5 minutes)
            if core.ENABLE_BINARY_VERIFICATION and time.time() - last_integrity_check > core.INTEGRITY_CHECK_INTERVAL:
                integrity_threats = core.verify_binary_integrity()
                for t in integrity_threats:
                    print(f"\n{t['title']}: {t['summary']}")
                    logger.critical(f"Binary Integrity: {t['summary']}")
                    notify_alert(t['title'], t['summary'], sound="Basso")
                    speak("Critical security alert. Browser binary has been tampered with.")
                last_integrity_check = time.time()
            
            # Launch Services Monitor (every 2 minutes)
            if core.ENABLE_LAUNCH_SERVICES_MONITOR and time.time() - last_launch_services_check > core.LAUNCH_SERVICES_CHECK_INTERVAL:
                ls_threats = core.check_launch_services()
                for t in ls_threats:
                    print(f"\n{t['title']}: {t['summary']}")
                    logger.warning(f"Launch Services: {t['summary']}")
                    notify_alert(t['title'], t['summary'])
                last_launch_services_check = time.time()
            
            # Keychain Access Monitor (every 30 seconds)
            # Keychain Access Monitor (every 30 seconds)
            if core.ENABLE_KEYCHAIN_MONITORING and time.time() - last_keychain_check > core.KEYCHAIN_MONITOR_INTERVAL:
                keychain_threats = core.monitor_keychain_access()
                for t in keychain_threats:
                    print(f"\n{t['title']}: {t['summary']}")
                    logger.warning(f"Keychain Access: {t['summary']}")
                    notify_alert(t['title'], t['summary'], sound="Ping")
                last_keychain_check = time.time()

            # Honey-Cookie Tripwire (every 5 seconds)
            if _TRIPWIRE_AVAILABLE:
                traps = tripwire.check_traps()
                for t in traps:
                    msg = f"\n{t['title']}: {t['summary']}"
                    print(msg)
                    logger.critical(msg)
                    notify_alert(t['title'], t['summary'], sound="Basso")
                    # Immediate Neutralization
                    try:
                        p = psutil.Process(t['pid'])
                        p.kill()
                        print(f"    [!] NEUTRALIZED: '{t['process']}' (PID: {t['pid']}) killed for touching bait.")
                    except: pass
            
            # Active Defense: File Monitor (TEMPORARILY DISABLED - causes Safari launch)
            # TODO: Fix lsof Safari trigger issue
            # active_response_mode = 'aggressive' if os.getenv('SOVEREIGN_AGGRESSIVE_MODE') == '1' else 'safe'
            # file_threats = core.monitor_sensitive_files(active_response_level=active_response_mode)
            # for t in file_threats:
            #     print(f"\n{t['title']}: {t['summary']}")
            #     logger.critical(f"File Monitor: {t['summary']}")
            #     sound = "Basso" if t.get('action') == "KILLED" else "Glass"
            #     notify_alert(t['title'], t['summary'], sound=sound)
            #     if t.get('action') == "KILLED":
            #         speak("Active Defense engaged. Unauthorized access terminated.")

            # 3. Process & Network Scan
            scanned_pids = set()
            scanned_count = 0
            
            # Determine if we should run memory scans this iteration
            run_memory_scan = core.ENABLE_MEMORY_SCANNING and (time.time() - last_memory_scan > core.MEMORY_SCAN_INTERVAL)
            if run_memory_scan:
                last_memory_scan = time.time()
            
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        scanned_count += scan_single_process(proc, is_safe_mode, current_mode, seen_pids, scanned_pids, run_memory_scan)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        continue
            except Exception as e:
                logger.error(f"Process iteration error: {e}")

            # 4. Heartbeat & Diagnostics
            if time.time() - last_heartbeat > 60:
                mode_str = "DEV MODE" if is_safe_mode else "PROTECT"
                if current_mode == 'learn': mode_str = "LEARN"
                print(f"🛡️  [{time.strftime('%H:%M:%S')}] {mode_str} | Scanned: {scanned_count}")
                last_heartbeat = time.time()

            # 5. Hourly Maintenance
            if time.time() - last_hourly_notify > 3600:
                try:
                    from learning_engine import rotate_logs
                    rotate_logs()
                except: pass
                
                # Hourly Forensic Scan
                history_threats = core.scan_browser_history()
                if history_threats:
                     for t in history_threats:
                         print(f"\n{t['title']}: {t['summary']}")
                         logger.warning(f"History Threat: {t['summary']}")
                         notify_alert(t['title'], t['summary'])

                extension_threats = core.scan_extensions()
                if extension_threats:
                    for t in extension_threats:
                        msg = f"🛡️ RISKY EXTENSION: {t['name']} ({t['id']})"
                        print(f"\n{msg}")
                        logger.warning(msg)
                        notify_alert("Risky Browser Extension", f"{t['name']} has sensitive permissions: {t['risks']}")

                         

                         
                notify_alert("Sovereign Guard Status", f"Guard active in {current_mode} mode.")
                last_hourly_notify = time.time()

            time.sleep(2.0)
            
    except KeyboardInterrupt:
        print("\nStopping Monitor.")
        sys.exit(0)

if __name__ == "__main__":
    monitor_loop()

