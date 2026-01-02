import psutil
import time
import sys
import os
import logging
import subprocess
import re
import platform
from plyer import notification

# Configure logging
logging.basicConfig(
    filename='guard_monitor.log',
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
    'code', 'vscode', 'pycharm', 'idea', 'node', 'npm', 
    'mdworker', 'mds', 'spotlight', 'launchd', 'distnoted', 
    'cfprefsd', 'taskgated', 'tccd', 'useractivityd', 'lsd'
] # Processes allowed to spawn tools and system tasks

# Crypto Patterns for Clipboard Sentry
BTC_PATTERN = r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b'
ETH_PATTERN = r'\b0x[a-fA-F0-9]{40}\b'
CRYPTO_RE = re.compile(f"{BTC_PATTERN}|{ETH_PATTERN}")

# Security Configuration
AUTO_MALWARE_SCAN = True  # Set to False to disable automatic scanning
SCAN_PATHS = [
    os.path.expanduser('~/Downloads'),
    os.path.expanduser('~/Library/LaunchAgents'),
    '/tmp'
]

def notify_alert(title, message):
    """Triggers a desktop notification."""
    try:
        if sys.platform == "darwin":
            # Use native osascript on macOS to avoid heavy dependencies like pyobjus
            safe_title = title.replace('"', '\\"')
            safe_message = message.replace('"', '\\"')
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
    """Speaks text using a calm female voice (macOS)."""
    try:
        # Use 'Samantha' for a calm, clear female voice
        subprocess.Popen(['say', '-v', 'Samantha', '-r', '160', text])
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
    """Checks a single process for dangerous flags.
    
    Args:
        proc: The psutil process object
        safe_mode: If True, detection creates alerts but DOES NOT kill.
    """
    try:
        cmdline = proc.cmdline()
        pid = proc.pid
        name = proc.name()
        
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
        for arg in cmdline:
            for flag in CRITICAL_FLAGS:
                if arg.startswith(flag):
                    critical_detected.append(flag)
            for flag in SUSPICIOUS_FLAGS:
                if arg.startswith(flag):
                    suspicious_detected.append(flag)
        
        detected_flags = critical_detected + suspicious_detected
        
        if detected_flags:
            # Run automatic diagnostics
            diagnostics = run_threat_diagnostics()
            
            # Run malware scan if enabled
            malware_scan_results = []
            if AUTO_MALWARE_SCAN:
                logging.info("Initiating automatic malware scan...")
                malware_scan_results = run_malware_scan()
            
            # Enhanced Alert Messaging
            risk_title = "CRITICAL: BROWSER HIJACK RISK"
            summary_msg = f"Chrome detected with INSECURE flags: {', '.join(detected_flags)}"
            
            # Detailed actionable advice for the log
            actionable_msg = (
                f"\n{'='*60}\n"
                f"!!! SOVEREIGN GUARD ALERT !!!\n"
                f"{'='*60}\n"
                f"Process: '{name}' (PID: {pid})\n"
                f"Origin: {origin_info}\n"
                f"Threat Detection: {', '.join(detected_flags)}\n"
                f"\nAUTOMATIC DIAGNOSTICS:\n"
            )
            
            if diagnostics:
                for finding in diagnostics:
                    actionable_msg += f"  {finding}\n"
            else:
                actionable_msg += "  ✓ No additional threats detected\n"
            
            # Add malware scan results
            if malware_scan_results:
                actionable_msg += f"\nMALWARE SCAN RESULTS:\n"
                for result in malware_scan_results:
                    actionable_msg += f"  {result}\n"
            
            # AUTOMATIC REMEDIATION
            if not safe_mode and critical_detected:
                try:
                    proc.kill()
                    actionable_msg += f"\n⚡️ THREAT AUTOMATICALLY NEUTRALIZED (Process Killed)\n"
                    summary_msg += " [NEUTRALIZED]"
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
            logging.warning(f"{risk_title} - {summary_msg} - PID: {pid}")
            
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
    """Checks if Developer Mode is active (prevents auto-kill)."""
    return os.path.exists(SAFE_MODE_FILE)

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
                
                # Skip safe processes
                if any(safe in name.lower() for safe in SAFE_LIST_PROCESSES):
                    continue
                
                # Skip officially signed Apple System processes
                if exe.startswith('/System/') or exe.startswith('/usr/lib/') or exe.startswith('/usr/bin/'):
                    continue

                # If launched in the last 300 seconds (5 mins) and not a common app
                if (current_time - p_info['create_time']) < 300:
                    # Very suspicious if it's a python script or a hidden binary
                    if 'python' in name.lower() or name.startswith('.'):
                        culprits.append(proc)
                    else:
                        # Add to potential list if it's a non-standard path
                        if '/Users/' in exe:
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
    """Monitors for suspicious crypto address replacement and NEUTRALIZES the threat."""
    current_val = get_clipboard_content()
    if not current_val or current_val == last_val:
        return current_val, None

    # Check if current content is a crypto address
    current_match = CRYPTO_RE.search(current_val)
    last_match = CRYPTO_RE.search(last_val) if last_val else None

    if current_match:
        curr_addr = current_match.group(0)
        
        # Scenario: User had a crypto address in clipboard, and it was replaced by a DIFFERENT one
        if last_match:
            prev_addr = last_match.group(0)
            if curr_addr != prev_addr:
                # Potential Hijack Detected
                alert_msg = f"❌ CLIPBOARD HIJACK DETECTED!\n" \
                          f"    Address replaced: {prev_addr[:10]}... -> {curr_addr[:10]}...\n" \
                          f"    ⚡️ NEUTRALIZING: Overwriting clipboard with safety warning."
                
                # 1. IMMEDIATE NEUTRALIZATION: Overwrite the clipboard
                safety_msg = "⚠️ SOVEREIGN GUARD: CLIPBOARD HIJACK DETECTED! DO NOT PASTE. ⚠️"
                set_clipboard_content(safety_msg)
                
                # 2. AUDIT AND KILL
                audit_result = audit_clipboard_hijacker()
                alert_msg += f"\n    Result: {audit_result}"
                
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
                        # A better check is: If Parent is in Safe List -> Do not kill?
                        # For now, we keep strictly to browser binaries.
                        
                        if 'chrome' in name_lower or 'brave' in name_lower or 'edge' in name_lower or 'arc' in name_lower or 'opera' in name_lower:
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
