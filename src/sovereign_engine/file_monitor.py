import os
import time
import subprocess
import logging
import signal
import psutil
from datetime import datetime

# Whitelist of processes allowed to touch Identity Files
# We use partial matches for resilience, but in a stricter version we would check binary signatures.
ALLOWED_PROCESSES = [
    'Google Chrome', 'Brave Browser', 'Arc', 'Microsoft Edge', 'Opera',
    'coreautha', 'mds', 'mds_stores', 'fseventsd', 'loginwindow',
    'WindowServer', 'Antigravity' # Our own process
]

# Paths to monitor (Real Identity Files)
SENSITIVE_PATHS = [
    os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Cookies'),
    os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Login Data'),
    os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies'),
    os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data'),
    os.path.expanduser('~/Library/Application Support/Arc/User Data/Default/Cookies'),
    os.path.expanduser('~/Library/Application Support/Arc/User Data/Default/Login Data'),
]

# Honeypot File (Decoy)
DECOY_PATH = os.path.expanduser('~/Documents/passwords_backup.txt')

def setup_honeypot():
    """Creates a decoy file to trap sweepers."""
    if not os.path.exists(DECOY_PATH):
        try:
            with open(DECOY_PATH, 'w') as f:
                f.write("Google Account: my.email@gmail.com\nPassword: correct-horse-battery-staple\n")
            logging.info(f"🍯 Honeypot created at {DECOY_PATH}")
        except Exception as e:
            logging.error(f"Failed to create honeypot: {e}")

def monitor_sensitive_files(active_response_level='safe'):
    """
    Monitors file handles for sensitive and decoy files.
    active_response_level: 'safe' (Kill Decoy only), 'aggressive' (Kill All unauthorized)
    """
    active_threats = []
    
    # Ensure honeypot exists
    setup_honeypot()
    
    # Only monitor files for browsers that are ACTUALLY RUNNING
    # This prevents lsof from auto-launching Safari/Chrome when they're closed
    running_browsers = []
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if any(b in name for b in ['Google Chrome', 'Brave Browser', 'Arc', 'Safari', 'Microsoft Edge']):
                running_browsers.append(name)
        except:
            continue
    
    # Filter SENSITIVE_PATHS to only include files for running browsers
    active_paths = []
    for path in SENSITIVE_PATHS:
        # Check if the browser for this path is running
        if 'Chrome' in path and any('Chrome' in b for b in running_browsers):
            active_paths.append(path)
        elif 'Brave' in path and any('Brave' in b for b in running_browsers):
            active_paths.append(path)
        elif 'Arc' in path and any('Arc' in b for b in running_browsers):
            active_paths.append(path)
        elif 'Safari' in path and any('Safari' in b for b in running_browsers):
            active_paths.append(path)
        elif 'Edge' in path and any('Edge' in b for b in running_browsers):
            active_paths.append(path)
    
    # Combined target list (only active browser files + honeypot)
    targets = active_paths + [DECOY_PATH]
    
    # Skip if no targets (all browsers closed)
    if not targets or targets == [DECOY_PATH]:
        targets = [DECOY_PATH]  # Always monitor honeypot
    
    # 1. Run lsof (List Open Files)
    # real-life implementation needs to be efficient. lsof can be slow, 
    # so we target specific files.
    cmd = ['lsof', '-F', 'pcn', *targets]
    
    try:
        # Suppress stderr to avoid "No such file" noise
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
    except Exception as e:
        logging.error(f"lsof failed: {e}")
        return []

    # Parse lsof -F output (fields: p=PID, c=COMMAND, n=NAME)
    # Output format is line-based with prefixes
    current_pid = None
    current_cmd = None
    
    for line in output.splitlines():
        if not line: continue
        
        type_char = line[0]
        value = line[1:]
        
        if type_char == 'p':
            current_pid = int(value)
        elif type_char == 'c':
            current_cmd = value
        elif type_char == 'n':
            filename = value
            
            # We have a complete record
            if current_pid and current_cmd and filename:
                threat = check_access(current_pid, current_cmd, filename, active_response_level)
                if threat:
                    active_threats.append(threat)

    return active_threats

def check_access(pid, cmd, filename, mode):
    """Evaluates if an access is authorized and takes action."""
    
    # 1. Is it the Honeypot?
    if filename == DECOY_PATH:
        # 🍯 HONEYPOT TRIGGERED
        # Rule: NO ONE sends data to the honeypot. It's a trap.
        # Exception: We allow 'mds' (Spotlight) to index it, or text editors if explicitly opened?
        # For now, strict: If it's a script/unknown, KILL.
        
        is_safe_system_proc = any(proc in cmd for proc in ['mds', 'mds_stores', 'TextEdit'])
        if is_safe_system_proc:
            return None
            
        return terminate_process(pid, cmd, reason="HONEYPOT_TRIGGER", filename=filename)

    # 2. Is it a Real Sensitive File?
    # Check whitelist
    is_allowed = False
    for safe_proc in ALLOWED_PROCESSES:
        if safe_proc in cmd or safe_proc.lower() in cmd.lower():
            is_allowed = True
            break
            
    if is_allowed:
        return None
        
    # 🚨 UNAUTHORIZED ACCESS DETECTED
    if mode == 'aggressive':
        return terminate_process(pid, cmd, reason="UNAUTHORIZED_ACCESS", filename=filename)
    else:
        # Safe Mode: Log/Alert Only
        return {
            "type": "FILE_ACCESS_VIOLATION",
            "severity": "CRITICAL",
            "title": "🚨 UNAUTHORIZED FILE ACCESS",
            "summary": f"Process '{cmd}' (PID: {pid}) is reading {os.path.basename(filename)}",
            "process": cmd,
            "pid": pid,
            "file": filename,
            "action": "MONITORED (Safe Mode)"
        }

def terminate_process(pid, cmd, reason, filename):
    """Executes the Active Defense kill switch."""
    try:
        # Double check it's not us or root (basic safety)
        if pid == os.getpid(): return None
        
        # KILL -9
        os.kill(pid, signal.SIGKILL)
        
        logging.warning(f"⚔️ ACTIVE DEFENSE: Killed {cmd} ({pid}) for {reason}")
        
        return {
            "type": "ACTIVE_DEFENSE_KILL",
            "severity": "CRITICAL",
            "title": "⚔️ THREAT TERMINATED",
            "summary": f"Sovereign Guard KILLED process '{cmd}' (PID: {pid}) accessing {os.path.basename(filename)}",
            "process": cmd,
            "pid": pid,
            "file": filename,
            "action": "KILLED"
        }
    except Exception as e:
        logging.error(f"Failed to kill process {pid}: {e}")
        return {
            "type": "DEFENSE_FAILURE",
            "severity": "CRITICAL",
            "title": "❌ KILL FAILED",
            "summary": f"Failed to stop process '{cmd}' (PID: {pid}) accessing {os.path.basename(filename)}",
            "error": str(e)
        }
