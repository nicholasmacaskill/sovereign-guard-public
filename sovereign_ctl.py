#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import signal

# Configuration
MONITOR_SCRIPT = "watchdog.py" # Point to the supervisor
PID_FILE = "guard_supervisor.pid" # Track supervisor PID
SAFE_MODE_FILE = "developer_mode.lock"
VENV_PYTHON = "./venv/bin/python3"
ENV_FILE = ".env.sovereign"

def get_secret():
    """Reads the sovereign secret from the env file."""
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'r') as f:
            for line in f:
                if line.startswith('SOVEREIGN_SECRET='):
                    return line.split('=', 1)[1].strip()
    return None

def get_pid():
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            return None
    return None

def is_running(pid):
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True

def start():
    pid = get_pid()
    if is_running(pid):
        print(f"[-] Supervisor is already running (PID: {pid})")
        return

    print("[-] Starting Sovereign Guard (Watchdog Supervisor)...")
    try:
        # Launch independently
        with open("guard_watchdog.out", "a") as out, open("guard_watchdog.err", "a") as err:
            proc = subprocess.Popen(
                [VENV_PYTHON, MONITOR_SCRIPT],
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                cwd=os.getcwd()
            )
        
        # Save PID
        with open(PID_FILE, 'w') as f:
            f.write(str(proc.pid))
            
        print(f"[+] Sovereign Guard Supervisor started (PID: {proc.pid})")
        print("    Usage logs: tail -f guard_watchdog.out")
    except Exception as e:
        print(f"[!] Failed to start supervisor: {e}")

def stop():
    pid = get_pid()
    if not is_running(pid):
        print("[-] Monitor is not running.")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return

    print(f"[-] Stopping Sovereign Guard (PID: {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
        # Wait for shutdown
        for _ in range(10):
            if not is_running(pid):
                break
            time.sleep(0.1)
        
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        print("[+] Monitor stopped.")
    except Exception as e:
        print(f"[!] Pending stop failed: {e}")
        print("    Try manual kill: kill -9 <pid>")

def status():
    pid = get_pid()
    if is_running(pid):
        print(f"✅ Sovereign Guard: ACTIVE (PID: {pid})")
        
        if os.path.exists(SAFE_MODE_FILE):
            print("⚠️  Mode: DEVELOPER (Safe Mode Active)")
        else:
            print("🛡️  Mode: SECURE (Auto-Kill Active)")
    else:
        print("❌ Sovereign Guard: STOPPED")
        
        if os.path.exists(SAFE_MODE_FILE):
            print("⚠️  Config: Developer Mode ENABLED (Will not kill on start)")

def dev_mode():
    secret = get_secret()
    if not secret:
        print("[!] Error: SOVEREIGN_SECRET not found in .env.sovereign. Run setup.sh.")
        return

    if not os.path.exists(SAFE_MODE_FILE):
        with open(SAFE_MODE_FILE, 'w') as f:
            # Write the secret to the lock file as a signature
            f.write(secret)
        print("⚠️  [DEVELOPER MODE ENABLED]")
        print("    Auto-Kill defense disabled. Authorization signature verified.")
    else:
        print("[-] Developer mode is already active.")

def secure_mode():
    if os.path.exists(SAFE_MODE_FILE):
        os.remove(SAFE_MODE_FILE)
        print("🛡️  [SECURE MODE ENABLED]")
        print("    Auto-Kill defense re-armed. Perimeter secure.")
    else:
        print("[-] Already in Secure Mode.")

def scan_now():
    """Performs a one-time synchronous scan of the system."""
    print("🔍 Scanning all active processes...")
    try:
        # We run the monitor script with a special flag or just parse its output?
        # Simpler: We'll import the logic directly or run a one-off check script.
        # For robustness/separation, let's run the monitor script with a 'scan-once' flag.
        # But monitor script acts as a daemon. 
        # Let's verify via the PID logs if a threat was *just* detected, 
        # OR better: run a dedicated audit script. 
        
        # Let's run a quick custom scan using psutil directly here for speed
        import psutil
        threats = []
        suspicious = []
        
        target_names = ['chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi']
        critical_flags = ['--remote-debugging-port', '--load-extension']
        suspicious_flags = ['--disable-web-security', '--no-sandbox', '--headless']
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name']
                if not name: continue
                
                if any(t in name.lower() for t in target_names):
                    cmdline = proc.cmdline()
                    for arg in cmdline:
                        if any(flag in arg for flag in critical_flags):
                            threats.append(f"{name} (PID: {proc.info['pid']}) -> {arg}")
                        elif any(flag in arg for flag in suspicious_flags):
                            suspicious.append(f"{name} (PID: {proc.info['pid']}) -> {arg}")
            except:
                continue
                
        if threats:
            print("\n❌ COMPROMISED: Active threats detected!")
            for t in threats:
                print(f"   - {t}")
            sys.exit(1)
        elif suspicious:
            print("\n⚠️  SECURE (With Warnings): No critical threats, but suspicious activity detected.")
            for s in suspicious:
                print(f"   - {s}")
            sys.exit(0)
        else:
            print("\n✅ SECURE: No hostile browser processes found.")
            sys.exit(0)
            
    except ImportError:
        print("[!] psutil not found in system python. Run via ./venv/bin/python3")

def clean_logs():
    """Wipes log files."""
    for log in ["guard_monitor.log", "guard_monitor.out", "guard_monitor.err", "guard_watchdog.out", "guard_watchdog.err"]:
        if os.path.exists(log):
            open(log, 'w').close()
    print("✨ Logs cleaned.")

def uninstall():
    """Removes the LaunchAgent and cleans up."""
    print("🗑️  Uninstalling Sovereign Guard...")
    stop()
    
    plist_path = os.path.expanduser("~/Library/LaunchAgents/com.sovereign.watchdog.plist")
    if os.path.exists(plist_path):
        print("    [-] Unloading LaunchAgent...")
        subprocess.run(["launchctl", "unload", plist_path], stderr=subprocess.DEVNULL)
        os.remove(plist_path)
        print("    [+] LaunchAgent removed.")
    else:
        print("    [-] No LaunchAgent found.")
        
    print("    [-] Cleaning logs...")
    clean_logs()
    print("✅ Uninstallation complete. (Virtual environment remains in ./venv)")

def main():
    if len(sys.argv) < 2:
        print("Usage: ./sovereign {start|stop|restart|status|dev|secure|scan|clean|uninstall}")
        sys.exit(1)
        
    cmd = sys.argv[1].lower()
    
    if cmd == 'start':
        start()
    elif cmd == 'stop':
        stop()
    elif cmd == 'restart':
        stop()
        time.sleep(1)
        start()
    elif cmd == 'status':
        status()
    elif cmd == 'dev':
        dev_mode()
    elif cmd == 'secure':
        secure_mode()
    elif cmd == 'scan':
        # Re-launch scan using the VENV python where psutil lives
        if sys.executable != os.path.abspath(VENV_PYTHON):
            # We are likely running as system python (via wrapper), relaunch inside venv
            try:
                subprocess.check_call([VENV_PYTHON, __file__, "scan"])
            except subprocess.CalledProcessError:
                sys.exit(1)
        else:
            scan_now()
    elif cmd == 'clean':
        clean_logs()
    elif cmd == 'uninstall':
        uninstall()
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: ./sovereign {start|stop|restart|status|dev|secure|scan|clean|uninstall}")

if __name__ == "__main__":
    main()
