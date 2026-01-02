import psutil
import time
import sys
import os
import logging
import subprocess
import platform
import hmac
from datetime import datetime
from plyer import notification
from logging.handlers import RotatingFileHandler

# IMPORT PROPRIETARY CORE
# If this fails, the user needs the 'sovereign_core.py' file (Sold Separately)
try:
    import sovereign_core as core
except ImportError:
    print("CRITICAL: 'sovereign_core' module not found.")
    print("Please ensure sovereign_core.py is present.")
    sys.exit(1)

# Global state for voice debounce
LAST_SPOKEN_TIME = 0
VOICE_COOLDOWN = 5 # Seconds

# Configure logging
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'guard_monitor.log')
handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=2)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Mitigation Configuration
SAFE_MODE_FILE = "developer_mode.lock" 
ENV_FILE = ".env.sovereign"
AUTO_MALWARE_SCAN = True
SCAN_PATHS = [
    os.path.expanduser('~/Downloads'),
    os.path.expanduser('~/Library/LaunchAgents'),
    '/tmp'
]

def get_secret():
    """Reads the sovereign secret from the env file."""
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'r') as f:
            for line in f:
                if line.startswith('SOVEREIGN_SECRET='):
                    return line.split('=', 1)[1].strip()
    return None

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
        secret = get_secret()
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

def check_clipboard_sentry(last_val):
    """Monitors for suspicious clipboard content and NEUTRALIZES threats using Core Logic."""
    current_val = get_clipboard_content()
    if not current_val: return current_val, None
        
    detected_threats = []
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

def monitor_loop():
    print("Sovereign Guard Monitor Active (Public Shell)...")
    logger.info("Monitor started.")
    speak("Sovereign Guard online. Verification active.")

    seen_pids = set()
    last_heartbeat = time.time()
    last_clipboard = get_clipboard_content()
    was_safe_mode = False

    try:
        while True:
            # 1. Clipboard Sentry
            last_clipboard, cb_alert = check_clipboard_sentry(last_clipboard)
            if cb_alert:
                print(f"\n{cb_alert}")
                logger.warning(cb_alert)
                speak("Warning. Clipboard hijack attempt detected.")

            # Dev Mode Logic
            is_safe_mode = check_safe_mode()
            if is_safe_mode and not was_safe_mode:
                print("\n⚠️  DEVELOPER MODE ACTIVE: Auto-Kill Disabled.")
                speak("Developer mode enabled.")
                was_safe_mode = True
            elif not is_safe_mode and was_safe_mode:
                print("\n🛡️  DEVELOPER MODE DEACTIVATED: Auto-Kill Re-armed.")
                speak("Developer mode disabled.")
                was_safe_mode = False

            current_pids = set()
            scanned_count = 0
            
            # Main Monitoring Loop
            scanned_pids = set()  # Track already-scanned PIDs this iteration
            
            # 2. Process Scanning (Uses Core Logic)
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    
                    # Performance: Skip if already scanned this iteration
                    if pid in scanned_pids:
                        continue
                    scanned_pids.add(pid)
                    
                    # Skip if whitelisted process (no need to check details)
                    name_lower = name.lower()
                    is_safe = False
                    for safe in core.SAFE_LIST_PROCESSES:
                        if name_lower == safe or name_lower.startswith(f"{safe} ") or name_lower.startswith(f"{safe}."):
                            is_safe = True
                            break
                    
                    if is_safe:
                        current_pids.add(pid)
                        continue
                    
                    scanned_count += 1
                    
                    # Detailed Core Check
                    alert = core.check_process(proc, safe_mode=is_safe_mode)
                    if alert:
                        # Handle the alert returned by core
                        print(f"\n{alert['summary']}")
                        logger.warning(alert['summary'])
                        
                        # Diagnostics
                        diagnostics = core.run_threat_diagnostics()
                        for d in diagnostics: print(f"  {d}")
                        
                        # Malware Scan (if enabled)
                        scan_results = []
                        if AUTO_MALWARE_SCAN:
                             scan_results = core.run_malware_scan(SCAN_PATHS)
                             
                        notify_alert(alert['title'], alert['summary'])
                        
                        # REMEDIATION (Kill Logic lives here, Decision lives in Core)
                        if not is_safe_mode and alert['critical']:
                            try:
                                proc.kill()
                                print("⚡️ THREAT AUTOMATICALLY NEUTRALIZED (Process Killed)")
                                speak("Critical threat detected. Process neutralized.")
                            except:
                                print("❌ Failed to auto-kill.")
                        elif is_safe_mode:
                            speak("Threat detected. Intervention suspended.")
                    
                    # Network Activity Check (Only for browsers and unknown processes)
                    # Performance: Skip network check for safe system processes
                    is_browser = any(t in name_lower for t in ['chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi', 'chromium'])
                    should_check_network = is_browser or not is_safe
                    
                    if should_check_network:
                        network_threat = core.check_network_activity(proc)
                        if network_threat:
                            print(f"\n{network_threat['summary']}")
                            logger.warning(f"[NETWORK] {network_threat['summary']}")
                            
                            notify_alert(network_threat['title'], network_threat['summary'])
                            
                            # Kill reverse shells immediately
                            if not is_safe_mode and network_threat['critical']:
                                try:
                                    proc.kill()
                                    print("⚡️ REVERSE SHELL NEUTRALIZED (Process Killed)")
                                    speak("Reverse shell detected and neutralized.")
                                except:
                                    print("❌ Failed to kill reverse shell.")
                            elif not network_threat['critical']:
                                # Just warn for suspicious connections
                                speak("Suspicious network connection detected.")
                    
                    current_pids.add(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if time.time() - last_heartbeat > 10:
                mode_str = "DEV MODE (SAFE)" if is_safe_mode else "ACTIVE DEFENSE"
                print(f"🛡️  [{time.strftime('%H:%M:%S')}] {mode_str} | Scanned: {scanned_count}")
                last_heartbeat = time.time()

            time.sleep(0.5) 
            
    except KeyboardInterrupt:
        print("\nStopping Monitor.")
        sys.exit(0)

if __name__ == "__main__":
    monitor_loop()
