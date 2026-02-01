import psutil
import re
import time
import sys
import os
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


def notify_alert(title, message):
    """Triggers a desktop notification."""
    try:
        if sys.platform == "darwin":
            safe_title = title.replace('\\', '\\\\').replace('"', '\\"')
            safe_message = message.replace('\\', '\\\\').replace('"', '\\"')
            script = f'display notification "{safe_message}" with title "{safe_title}"'
            subprocess.run(["osascript", "-e", script], check=False)
            return

        notification.notify(title=title, message=message, app_name='Sovereign Guard', timeout=10)
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

def speak(text):
    """Speaks text using a calm female voice (macOS), with debounce."""
    global LAST_SPOKEN_TIME
    try:
        now = time.time()
        if now - LAST_SPOKEN_TIME < VOICE_COOLDOWN:
            return
        subprocess.Popen(['say', '-v', 'Samantha', '-r', '160', text])
        LAST_SPOKEN_TIME = now
    except:
        pass

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
    new_baseline, threats = core.check_browser_persistence(last_state=baseline)
    if threats:
        for t in threats:
            msg = f"\n{t['title']}: {t['summary']}"
            print(msg)
            logger.warning(msg)
            speak(f"Security Alert. New browser persistence module detected in {os.path.basename(os.path.dirname(t['path']))}.")
    return new_baseline

def scan_single_process(proc, is_safe_mode, current_mode, seen_pids, scanned_pids):
    """Performs deep security analysis on a single process."""
    try:
        pid = proc.pid
        name = proc.name()
        
        if pid in scanned_pids: return 0
        scanned_pids.add(pid)
        
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
    
    core.start_trigger_thread()

    seen_pids = set()
    last_heartbeat = time.time()
    last_hourly_notify = time.time()
    last_clipboard = get_clipboard_content()
    
    # Initialize Hardening Baselines
    persistence_baseline, _ = core.check_persistence(last_files=None)
    browser_persistence_baseline, _ = core.check_browser_persistence(last_state=None)
    last_persistence_check = time.time()
    last_mitm_check = time.time()
    last_tab_check = time.time()
    
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

            if time.time() - last_tab_check > 10:
                active_tab_threats = core.check_active_tabs()
                for t in active_tab_threats:
                    print(f"\n{t['title']}: {t['summary']}")
                    logger.warning(f"Active Tab Threat: {t['summary']}")
                    notify_alert(t['title'], t['summary'])
                last_tab_check = time.time()

            # 3. Process & Network Scan
            scanned_pids = set()
            scanned_count = 0
            
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        scanned_count += scan_single_process(proc, is_safe_mode, current_mode, seen_pids, scanned_pids)
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

