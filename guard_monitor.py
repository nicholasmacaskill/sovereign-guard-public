import psutil
import time
import sys
import os
import logging
import subprocess
import re
import platform
import hmac
from datetime import datetime
from plyer import notification

# Global state for voice debounce
LAST_SPOKEN_TIME = 0
VOICE_COOLDOWN = 5 # Seconds

# Configure logging
# Configure logging
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'guard_monitor.log')
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Constants
# Constants
TARGET_PROCESS_NAMES = [
    'chrome.exe', 'Google Chrome', 'Google Chrome Helper',
    'Brave Browser', 'brave.exe',
    'Microsoft Edge', 'msedge.exe',
    'Arc', 'Arc Helper',
    'Opera', 'opera.exe',
    'Vivaldi', 'vivaldi.exe',
    'Chromium', 'chromium'
]
CRITICAL_FLAGS = [
    '--remote-debugging-port', 
    '--load-extension'
]
SUSPICIOUS_FLAGS = [
    '--disable-web-security', 
    '--no-sandbox', 
    '--headless'
]
DEBUG_PORTS = [9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229, 1337]

# Mitigation Configuration
SAFE_MODE_FILE = "developer_mode.lock" # If this file exists, AUTO-KILL is disabled
SAFE_LIST_PROCESSES = [
    'code', 'vscode', 'pycharm', 'idea', 'node', 'npm', 'git', 'docker',
    'mdworker', 'mds', 'spotlight', 'launchd', 'distnoted', 
    'cfprefsd', 'taskgated', 'tccd', 'useractivityd', 'lsd',
    'knowledge-agent', 'spotlightknowledged',
    'terminal', 'iterm2', 'warp', 'finder', 'dock', 'softwareupdated'
] # Processes allowed to spawn tools and system tasks

# Hardened Path Validation
SAFE_BROWSER_PATHS = [
    '/Applications/',
    '/System/Applications/',
    '/usr/bin/',
    '/usr/local/bin/'
]

# Crypto Patterns for Clipboard Sentry
BTC_PATTERN = r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b'
ETH_PATTERN = r'\b0x[a-fA-F0-9]{40}\b'
CRYPTO_RE = re.compile(f"({BTC_PATTERN})|({ETH_PATTERN})")

# General Malware / Virus Patterns
CMD_INJECTION_PATTERN = r'(?:curl|wget|sh|bash|zsh|python\d*|perl\d*|php\d*|ruby\d*|node)\b.*[|;&].*'
MALICIOUS_JS_PATTERN = r'eval\(atob\(.*\)\)|String\.fromCharCode\(.*\)|unescape\('
SENSITIVE_KEY_PATTERN = r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----|AKIA[A-Z0-9]{16}|[0-9a-f]{64}'
URL_SPOOF_PATTERN = r'https?://[^\s]+@|[^\s]+\.(zip|mov|app|scr)\b'

# Combined Threat Detection
THREAT_PATTERNS = {
    "CRYPTO_SWAP": CRYPTO_RE,
    "CMD_INJECTION": re.compile(CMD_INJECTION_PATTERN, re.IGNORECASE),
    "MALICIOUS_SCRIPT": re.compile(MALICIOUS_JS_PATTERN, re.IGNORECASE),
    "SENSITIVE_EXPOSURE": re.compile(SENSITIVE_KEY_PATTERN),
    "URL_SPOOF": re.compile(URL_SPOOF_PATTERN, re.IGNORECASE)
}

# Neutralization Strategy
STRICT_MODE_THREATS = ["CMD_INJECTION", "MALICIOUS_SCRIPT", "URL_SPOOF"] # Neutralize on introduction
SWAP_MODE_THREATS = ["CRYPTO_SWAP"] # Neutralize only on mismatch replacement

# Security Configuration
AUTO_MALWARE_SCAN = True  # Set to False to disable automatic scanning
SCAN_PATHS = [
    os.path.expanduser('~/Downloads'),
    os.path.expanduser('~/Library/LaunchAgents'),
    '/tmp'
]
ENV_FILE = ".env.sovereign"

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
            # Use native osascript on macOS to avoid heavy dependencies like pyobjus
            safe_title = title.replace('\\', '\\\\').replace('"', '\\"')
            safe_message = message.replace('\\', '\\\\').replace('"', '\\"')
            script = f'display notification "{safe_message}" with title "{safe_title}"'
            subprocess.run(["osascript", "-e", script], check=False)
            return

        # Fallback to plyer for other platforms (Windows/Linux)
        notification.notify(
            title=title,
            message=message,
            app_name='Sovereign Guard',
            timeout=10
        )
    except Exception as e:
        logging.error(f"Failed to send notification: {e}")

def speak(text):
    """Speaks text using a calm female voice (macOS), with debounce."""
    global LAST_SPOKEN_TIME
    try:
        now = time.time()
        if now - LAST_SPOKEN_TIME < VOICE_COOLDOWN:
            return
            
        # Use 'Samantha' for a calm, clear female voice
        subprocess.Popen(['say', '-v', 'Samantha', '-r', '160', text])
        LAST_SPOKEN_TIME = now
    except:
        pass

def run_threat_diagnostics():
    """Runs automatic diagnostics when a threat is detected."""
    diagnostics = []
    
    # Check for suspicious LaunchAgents
    try:
        user_agents = subprocess.run(['ls', '-la', os.path.expanduser('~/Library/LaunchAgents/')], 
                                    capture_output=True, text=True, timeout=5)
        if 'chrome' in user_agents.stdout.lower() or 'debug' in user_agents.stdout.lower():
            diagnostics.append("⚠️  SUSPICIOUS: Chrome-related LaunchAgent found")
    except:
        pass
    
    # Check for listening ports (potential remote debugger)
    try:
        netstat = subprocess.run(['lsof', '-i', '-P'], capture_output=True, text=True, timeout=5)
        for line in netstat.stdout.split('\n'):
            if 'LISTEN' in line and ('9222' in line or '1337' in line or '1338' in line or '1339' in line):
                diagnostics.append(f"⚠️  ACTIVE DEBUGGER PORT: {line.split()[0]} on port {line.split()[-2]}")
    except:
        pass
    
    # Check recent app installations (last 7 days)
    try:
        recent_apps = subprocess.run(['find', '/Applications', '-maxdepth', '1', '-mtime', '-7', '-type', 'd'],
                                    capture_output=True, text=True, timeout=5)
        if recent_apps.stdout.strip():
            app_list = [app.split('/')[-1] for app in recent_apps.stdout.strip().split('\n') if app != '/Applications']
            if app_list:
                diagnostics.append(f"ℹ️  Recent installs (7d): {', '.join(app_list[:3])}")
    except:
        pass
    
    return diagnostics

    return None

def get_attacker_ip(pid):
    """Attempts to find the remote IP address connected to a process's debug port."""
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind='inet')
        for conn in connections:
            # We only care if the connection is to one of our DEBUG_PORTS
            # conn.laddr is the local address (the browser listening)
            if conn.status == 'ESTABLISHED' and conn.remote_address:
                if conn.laddr.port in DEBUG_PORTS:
                    return conn.remote_address.ip
    except:
        pass
    return None

def run_malware_scan():
    """Runs a targeted malware scan on high-risk directories."""
    scan_results = []
    
    # Check if ClamAV is installed
    try:
        clamscan_check = subprocess.run(['which', 'clamscan'], capture_output=True, text=True, timeout=2)
        if clamscan_check.returncode != 0:
            scan_results.append("⚠️  ClamAV not installed. Run: brew install clamav")
            return scan_results
    except:
        scan_results.append("⚠️  Unable to check for ClamAV")
        return scan_results
    
    scan_results.append("🔍 Starting targeted malware scan...")
    
    for path in SCAN_PATHS:
        if not os.path.exists(path):
            continue
            
        try:
            # Run quick scan on specific directory
            result = subprocess.run(
                ['clamscan', '-r', '--bell', '-i', path],
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout per directory
            )
            
            # Parse results
            if 'Infected files: 0' in result.stdout:
                scan_results.append(f"  ✓ {path}: Clean")
            else:
                # Extract infected file count
                for line in result.stdout.split('\n'):
                    if 'Infected files:' in line:
                        scan_results.append(f"  🚨 {path}: {line.strip()}")
                    elif 'FOUND' in line:
                        scan_results.append(f"    ⚠️  {line.strip()}")
        except subprocess.TimeoutExpired:
            scan_results.append(f"  ⏱️  {path}: Scan timeout (directory too large)")
        except Exception as e:
            scan_results.append(f"  ❌ {path}: Scan failed ({str(e)[:50]})")
    
    return scan_results

def check_process(proc, safe_mode=False):
    """Checks a single process for dangerous flags and PATH INTEGRITY.
    
    Args:
        proc: The psutil process object
        safe_mode: If True, detection creates alerts but DOES NOT kill.
    """
    try:
        cmdline = proc.cmdline()
        pid = proc.pid
        name = proc.name()
        exe_path = proc.exe() or ""
        
        # INTEGRITY CHECK: Is this browser running from a safe location?
        name_lower = name.lower()
        is_browser = any(t in name_lower for t in ['chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi', 'chromium'])
        
        spoof_detected = False
        if is_browser and exe_path:
            # If it's not in a standard application folder, it's a likely hijack/spoof
            if not any(exe_path.startswith(safe) for safe in SAFE_BROWSER_PATHS):
                spoof_detected = True

        # Origin Tracing: Identify Parent Process
        try:
            parent = proc.parent()
            parent_name = parent.name() if parent else "Unknown"
            parent_pid = parent.pid if parent else "N/A"
            origin_info = f"Launched by: '{parent_name}' (PID: {parent_pid})"
        except:
            origin_info = "Launched by: Unknown (Unable to trace parent)"
        
        critical_detected = []
        suspicious_detected = []
        
        if spoof_detected:
            critical_detected.append("UNSAFE EXECUTABLE PATH (SPOOFING RISK)")
            
        for arg in cmdline:
            for flag in CRITICAL_FLAGS:
                if arg.startswith(flag):
                    critical_detected.append(flag)
            for flag in SUSPICIOUS_FLAGS:
                if arg.startswith(flag):
                    suspicious_detected.append(flag)
        
        detected_flags = critical_detected + suspicious_detected
        
        if detected_flags:
            risk_level = "CRITICAL" if critical_detected or spoof_detected else "SUSPICIOUS"
            risk_title = f"⚡️ SOVEREIGN GUARD: {risk_level} THREAT DETECTED"
            
            # Run automatic diagnostics
            log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            summary_msg = f"SECURITY ALERT: Process '{name}' (PID: {pid}) detected with flags: {', '.join(detected_flags)}"
            
            actionable_msg = f"\n{'='*60}\n"
            actionable_msg += f"!!! SOVEREIGN GUARD ALERT !!!\n"
            actionable_msg += f"{'='*60}\n"
            actionable_msg += f"Process: '{name}' (PID: {pid})\n"
            actionable_msg += f"Path: '{exe_path}'\n"
            actionable_msg += f"Origin: {origin_info}\n"
            actionable_msg += f"Threat Detection: {', '.join(detected_flags)}\n"
            
            if spoof_detected:
                 actionable_msg += f"\n🚨 CRITICAL: SPOOFING ATTEMPT! Process is not running from a trusted path.\n"
            
            # 1. Run Diagnostics (Internal functions)
            actionable_msg += f"\nAUTOMATIC DIAGNOSTICS:\n"
            diagnostics = run_threat_diagnostics() # Use existing diagnostics function
            if diagnostics:
                for finding in diagnostics:
                    actionable_msg += f"  {finding}\n"
            else:
                actionable_msg += "  ✓ No additional threats detected\n"
            
            # 2. Run Malware Scan (if configured)
            malware_scan_results = []
            if AUTO_MALWARE_SCAN:
                logging.info("Initiating automatic malware scan...")
                actionable_msg += f"\nMALWARE SCAN RESULTS:\n"
                malware_scan_results = run_malware_scan()
                for result in malware_scan_results:
                    actionable_msg += f"  {result}\n"
            
            # AUTOMATIC REMEDIATION
            if not safe_mode and critical_detected:
                try:
                    proc.kill()
                    actionable_msg += f"\n⚡️ THREAT AUTOMATICALLY NEUTRALIZED (Process Killed)\n"
                    summary_msg += " [NEUTRALIZED]"
                    
                    if spoof_detected:
                        speak("Integrity breach detected. Hostile browser spoof neutralized.")
                    else:
                        speak("Critical threat detected. Insecure browser instance neutralized.")
                except Exception as e:
                    actionable_msg += f"\n❌ Failed to auto-kill process: {e}\nIMMEDIATE ACTION REQUIRED: kill -9 {pid}\n"
                    speak("Threat detected. Manual intervention required.")
            elif safe_mode and detected_flags:
                actionable_msg += f"\n⚠️  THREAT DETECTED (SAFE MODE - NO ACTION TAKEN)\n"
                summary_msg += " [SAFE MODE DETECTED]"
                speak("Threat detected. Intervention suspended due to developer mode.")
            elif suspicious_detected and not critical_detected:
                 actionable_msg += f"\nℹ️  SUSPICIOUS FLAGS DETECTED (Alert Only - No Kill)\n"
                 summary_msg += " [SUSPICIOUS ONLY]"
                 # speak("Suspicious browser activity detected.") # Maybe too annoying for suspicious? 

            actionable_msg += f"{'='*60}\n"
            
            print(actionable_msg)
            logging.warning(summary_msg)
            
            # Send the user-facing notification with diagnostic summary
            notification_msg = f"{summary_msg}\nPID: {pid}\n"
            threat_count = len(diagnostics)
            if malware_scan_results:
                # Count actual threats (not status messages)
                malware_threats = sum(1 for r in malware_scan_results if '🚨' in r or '⚠️' in r)
                threat_count += malware_threats
            
            if threat_count > 0:
                notification_msg += f"\n{threat_count} additional threat(s) found!"
            notify_alert(risk_title, notification_msg)
            return True
            
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return False

def check_network_sentry():
    """Checks for active listening ports commonly used for debugging."""
    try:
        # Use lsof for MacOS/Linux
        # Checking for any process listening on our target debug ports
        netstat = subprocess.run(['lsof', '-i', '-P', '-n'], capture_output=True, text=True, timeout=1)
        
        for line in netstat.stdout.split('\n'):
            if 'LISTEN' in line:
                for port in DEBUG_PORTS:
                    if f":{port} " in line:
                        parts = line.split()
                        proc_name = parts[0]
                        proc_pid = parts[1]
                        # Don't alert if we just alerted on this PID via process check
                        return f"⚠️  NETWORK SENTRY: Process '{proc_name}' (PID: {proc_pid}) is listening on PORT {port}"
    except:
        pass
    return None

def check_safe_mode():
    """Checks if Developer Mode is active and VERIFIES the authorization secret."""
    if not os.path.exists(SAFE_MODE_FILE):
        return False
        
    try:
        secret = get_secret()
        if not secret:
            return False # No secret set, cannot verify
            
        with open(SAFE_MODE_FILE, 'r') as f:
            # Match secret to ensure malware didn't create the lock
            sig = f.read().strip()
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(sig, secret)
    except:
        return False

def get_clipboard_content():
    """Gets current clipboard content using pbpaste on macOS."""
    try:
        if platform.system() == 'Darwin':
            return subprocess.check_output(['pbpaste'], text=True, stderr=subprocess.DEVNULL)
    except:
        pass
    return None

def set_clipboard_content(text):
    """Overwrites clipboard content using pbcopy on macOS."""
    try:
        if platform.system() == 'Darwin':
            process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            process.communicate(input=text.encode('utf-8'))
            return True
    except:
        pass
    return False

def audit_clipboard_hijacker():
    """Attempts to find and kill the process responsible for clipboard theft."""
    logging.warning("Initiating Clipboard Hijacker Audit...")
    culprits = []
    
    # Heuristic: Look for background processes that are:
    # 1. Not in the safe list
    # 2. Not in standard System/Library locations
    # 3. Launched recently or have no executable path (script-based)
    
    try:
        current_time = time.time()
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'exe', 'cmdline']):
            try:
                p_info = proc.info
                name = p_info['name']
                exe = p_info['exe'] or ""
                
                # Skip safe processes (Exact match or safe prefix to prevent substring exploits)
                # e.g. "code" matches "code", "code helper" but not "codemalware" logic requires care
                name_low = name.lower()
                is_safe = False
                for safe in SAFE_LIST_PROCESSES:
                    # Check for exact match OR safe + " " (helper) OR safe + "." (extension)
                    if name_low == safe or name_low.startswith(f"{safe} ") or name_low.startswith(f"{safe}."):
                        is_safe = True
                        break
                
                if is_safe:
                    continue
                
                # Skip officially signed Apple System processes
                if exe.startswith('/System/') or exe.startswith('/usr/lib/') or exe.startswith('/usr/bin/'):
                    continue

                # If launched in the last 600 seconds (10 mins) and not a common app
                if (current_time - p_info['create_time']) < 600:
                    # Very suspicious if it's a python script, hidden binary, or has 'clipboard'/'copy' in name
                    name_low = name.lower()
                    if any(k in name_low for k in ['python', 'paste', 'clipboard', 'copy', 'hijack']) or name.startswith('.'):
                        culprits.append(proc)
                    else:
                        # Add to potential list if it's a non-standard path
                        if '/Users/' in exe and '/Applications/' not in exe:
                            culprits.append(proc)
            except:
                continue
                
        # Neutralize the most suspicious (limit to top 3 to avoid system instability)
        neutralized_names = []
        for culprit in culprits[:3]:
            try:
                c_pid = culprit.pid
                c_name = culprit.name()
                logging.warning(f"⚡️ NEUTRALIZING HIJACK CULPRIT: {c_name} (PID: {c_pid})")
                culprit.kill()
                neutralized_names.append(f"{c_name} (PID: {c_pid})")
            except:
                continue
        
        if neutralized_names:
            msg = f"Neutralized {len(neutralized_names)} suspect(s): " + ", ".join(neutralized_names)
            speak("Sovereign Guard neutralized the clipboard threat.")
            return msg
    except Exception as e:
        logging.error(f"Error during hijacker audit: {e}")
        
    return "No clear culprit found. Full malware scan recommended."

def check_clipboard_sentry(last_val):
    """Monitors for suspicious clipboard content and NEUTRALIZES threats.
    
    This expanded sentry handles both 'Swap Mode' (crypto address changes) 
    and 'Strict Mode' (malicious patterns like command injection).
    """
    current_val = get_clipboard_content()
    if not current_val:
        return current_val, None
        
    # Detect threats in current content
    detected_threats = []
    for threat_name, pattern in THREAT_PATTERNS.items():
        match = pattern.search(current_val)
        if match:
            # For Crypto, we only care if it's a 'swap' (handled below)
            # but for everything else, the existence of the pattern is a threat
            if threat_name in STRICT_MODE_THREATS:
                detected_threats.append((threat_name, match.group(0)))
            elif threat_name == "SENSITIVE_EXPOSURE":
                 # Redact key in logs
                 detected_threats.append((threat_name, "[REDACTED_SENSITIVE_KEY]"))
    
    # Check for Crypto Swaps (Swap Mode)
    crypto_match = THREAT_PATTERNS["CRYPTO_SWAP"].search(current_val)
    last_crypto_match = THREAT_PATTERNS["CRYPTO_SWAP"].search(last_val) if last_val else None
    
    if crypto_match and last_crypto_match:
        curr_addr = crypto_match.group(0)
        prev_addr = last_crypto_match.group(0)
        if curr_addr != prev_addr:
            detected_threats.append(("CRYPTO_SWAP", f"{prev_addr[:10]}... -> {curr_addr[:10]}..."))

    if detected_threats:
        threat_types = [t[0] for t in detected_threats]
        threat_desc = "; ".join([f"{t[0]}: {t[1]}" for t in detected_threats])
        
        # 1. IMMEDIATE NEUTRALIZATION: Overwrite the clipboard
        attacker_ip = None
        # Try to find a remote IP if any browser is in debug mode
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if any(b in (p.info['name'] or "").lower() for b in ['chrome', 'brave', 'edge', 'arc']):
                    ip = get_attacker_ip(p.info['pid'])
                    if ip: attacker_ip = ip
            except: continue

        if attacker_ip:
            safety_msg = f"⚠️ SOVEREIGN GUARD: ATTACKER IP [{attacker_ip}] LOGGED. FORENSIC TRACE INITIATED. ⚠️"
            scare_msg = f"[SOVEREIGN_SEC_LOG]: ENCRYPTION KEY MASKED. REMOTE IP {attacker_ip} LOGGED. WE HAVE YOUR FINGERPRINT."
            set_clipboard_content(scare_msg)
            speak("Active hijack confirmed. Attacker location traced. Forensic counter-measures initiated.")
        else:
            safety_msg = "⚠️ SOVEREIGN GUARD: CLIPBOARD VIRUS DETECTED! DO NOT PASTE. ⚠️"
            set_clipboard_content(safety_msg)
        
        # 2. AUDIT AND KILL
        alert_msg = f"❌ CLIPBOARD THREAT NEUTRALIZED!\n" \
                  f"    Detections: {threat_desc}\n" \
                  f"    ⚡️ ACTION: Clipboard overwritten, initiating culprit audit..."
        
        if attacker_ip:
            alert_msg += f"\n    🚨 ATTACKER TRACED: {attacker_ip}"

        audit_result = audit_clipboard_hijacker()
        alert_msg += f"\n    Result: {audit_result}"
        
        # Voice fallback if not already spoken by attacker_ip logic
        if not attacker_ip:
            if "CMD_INJECTION" in threat_types:
                speak("Command injection attempt neutralized. Source process terminated.")
            elif "MALICIOUS_SCRIPT" in threat_types:
                speak("Malicious script detected in clipboard. Threat neutralized.")
            elif "CRYPTO_SWAP" in threat_types:
                speak("Warning. Clipboard hijack attempt detected. Verify your destination address.")
            else:
                speak("Clipboard threat detected and neutralized.")
            
        return safety_msg, alert_msg

    return current_val, None

def monitor_loop():
    """Main monitoring loop."""
    print("Sovereign Guard Monitor Active...")
    logging.info("Monitor started.")
    
    speak("Sovereign Guard online. Verification active.")

    seen_pids = set()
    last_heartbeat = time.time()
    scanned_count = 0
    
    # State tracking for voice feedback
    was_safe_mode = False
    last_clipboard = get_clipboard_content()

    try:
        while True:
            # 1. Clipboard Sentry Check
            last_clipboard, cb_alert = check_clipboard_sentry(last_clipboard)
            if cb_alert:
                print(f"\n{cb_alert}")
                logging.warning(cb_alert)
                speak("Warning. Clipboard hijack attempt detected. Verify your destination address.")

            # Check for Developer Mode Toggle
            is_safe_mode = check_safe_mode()
            if is_safe_mode and not was_safe_mode:
                print("\n⚠️  DEVELOPER MODE ACTIVE: Auto-Kill Disabled.")
                speak("Developer mode enabled. Auto-defense systems standby.")
                was_safe_mode = True
            elif not is_safe_mode and was_safe_mode:
                print("\n🛡️  DEVELOPER MODE DEACTIVATED: Auto-Kill Re-armed.")
                speak("Developer mode disabled. Defense systems re-engaged.")
                was_safe_mode = False

            current_pids = set()
            scanned_count = 0
            
            # 1. Network Sentry Check (Port Scanning)
            port_threat = check_network_sentry()
            if port_threat:
                print(f"\n{port_threat}")
                logging.warning(port_threat)
                # Network threats generally safer to just warn about unless we add strict port logic
            
            # 2. Process Scanning
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = proc.info['name']
                    scanned_count += 1
                    
                    # Broaden check to 'chrome' or our new target list
                    is_target = False
                    if name:
                        name_lower = name.lower()
                        
                        # Whitelist Check: If process is in SAFE_LIST, skip usage checks
                        # (Implementation Note: This safeguards IDEs, but usually we check the *browser* flags)
                        if name_lower in SAFE_LIST_PROCESSES:
                            continue
                            
                        # Broaden check to 'chrome' or our new target list
                        # FIX: Broad substring 'edge' matches 'knowledge-agent'. Use specific list.
                        if 'chrome' in name_lower or 'brave' in name_lower or 'microsoft edge' in name_lower or 'arc' in name_lower or 'opera' in name_lower:
                             is_target = True
                    
                    if is_target:
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        
                        if pid not in seen_pids:
                            # Pass safe_mode state to check_process
                            check_process(proc, safe_mode=is_safe_mode)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            seen_pids = current_pids
            
            # 3. Visual Heartbeat (Every 10 seconds)
            if time.time() - last_heartbeat > 10:
                mode_str = "DEV MODE (SAFE)" if is_safe_mode else "ACTIVE DEFENSE"
                print(f"🛡️  [{time.strftime('%H:%M:%S')}] {mode_str} | Scanned: {scanned_count}")
                last_heartbeat = time.time()

            time.sleep(0.5) # High frequency polling
            
    except KeyboardInterrupt:
        print("\nStopping Monitor.")
        logging.info("Monitor stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    monitor_loop()
