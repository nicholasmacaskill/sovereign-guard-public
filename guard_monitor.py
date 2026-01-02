import psutil
import time
import sys
import os
import logging
import subprocess
from plyer import notification

# Configure logging
logging.basicConfig(
    filename='guard_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Constants
TARGET_PROCESS_NAMES = ['chrome.exe', 'Google Chrome']
DANGEROUS_FLAGS = ['--remote-debugging-port', '--load-extension']

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

def check_process(proc):
    """Checks a single process for dangerous flags."""
    try:
        cmdline = proc.cmdline()
        pid = proc.pid
        name = proc.name()
        
        detected_flags = []
        for arg in cmdline:
            for flag in DANGEROUS_FLAGS:
                if arg.startswith(flag):
                    detected_flags.append(flag)
        
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
            try:
                proc.kill()
                actionable_msg += f"\n⚡️ THREAT AUTOMATICALLY NEUTRALIZED (Process Killed)\n"
                summary_msg += " [NEUTRALIZED]"
                speak("Threat detected. Insecure browser instance neutralized.")
            except Exception as e:
                actionable_msg += f"\n❌ Failed to auto-kill process: {e}\nIMMEDIATE ACTION REQUIRED: kill -9 {pid}\n"
                speak("Threat detected. Manual intervention required.")

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

def monitor_loop():
    """Main monitoring loop."""
    print("Sovereign Guard Monitor Active...")
    logging.info("Monitor started.")
    
    # TEST NOTIFICATION ON STARTUP
    notify_alert("Guard Active", "The Sovereign Guard monitor has started successfully.")
    speak("Sovereign Guard initialized. The perimeter is secure.")

    seen_pids = set()

    try:
        while True:
            current_pids = set()
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    name = proc.info['name']
                    # Broaden check to case-insensitive 'chrome'
                    if name and 'chrome' in name.lower():
                        pid = proc.info['pid']
                        current_pids.add(pid)
                        
                        if pid not in seen_pids:
                            # Debug print
                            # print(f"[DEBUG] Checking process: {name} (PID: {pid})")
                            if check_process(proc):
                                 pass
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            seen_pids = current_pids
            time.sleep(0.5) # High frequency polling
            
    except KeyboardInterrupt:
        print("\nStopping Monitor.")
        logging.info("Monitor stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    monitor_loop()
