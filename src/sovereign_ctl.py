#!/usr/bin/env python3
import sys
import os
import subprocess
import time
import signal
from datetime import datetime

import path_utils

# Configuration
MONITOR_SCRIPT = os.path.join(path_utils.get_project_root(), "src", "watchdog.py")
PID_FILE = path_utils.get_run_file("guard_supervisor.pid")
SAFE_MODE_FILE = path_utils.get_run_file("developer_mode.lock")
VENV_PYTHON = os.path.join(path_utils.get_project_root(), "venv", "bin", "python3")
ENV_FILE = os.path.join(path_utils.get_project_root(), ".env.sovereign")


def get_pid():
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                return int(f.read().strip())
        except:
            return None
    return None

def is_running(pid):
    if pid is None: return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def authorize_action():
    """Enforces Hardware Key or Backup Code authorization."""
    is_enforced = False
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'r') as f:
            for line in f:
                if line.startswith('RUBICON_ENFORCED='):
                    is_enforced = (line.split('=', 1)[1].strip().lower() == 'true')
                    break
    
    if not is_enforced: return True

    try:
        import sovereign_core as core
        if core.verify_hardware_key():
            print("🔑 Hardware Key Authorized.")
            return True
            
        print("🔒 AUTHENTICATION REQUIRED\n   Touch YubiKey or enter Backup Code to proceed.")
        code = input("   Code: ").strip()
        if core.verify_backup_code(code):
             print("✅ Authorized.")
             return True
        print("❌ ACCESS DENIED.")
        return False
    except ImportError:
        secret = path_utils.get_secret()
        return input("Enter Sovereign Secret: ") == secret

def start():
    pid = get_pid()
    if is_running(pid):
        print(f"[-] Supervisor is already running (PID: {pid})")
        return

    print("[-] Starting Sovereign Guard (Watchdog Supervisor)...")
    try:
        out_log = path_utils.get_log_file("guard_watchdog.out")
        err_log = path_utils.get_log_file("guard_watchdog.err")
        with open(out_log, "a") as out, open(err_log, "a") as err:
            proc = subprocess.Popen([VENV_PYTHON, MONITOR_SCRIPT], stdout=out, stderr=err, stdin=subprocess.DEVNULL, cwd=path_utils.get_project_root())
        with open(PID_FILE, 'w') as f:
            f.write(str(proc.pid))
        print(f"[+] Sovereign Guard Supervisor started (PID: {proc.pid})\n    Usage logs: tail -f {out_log}")
    except Exception as e:
        print(f"[!] Failed to start supervisor: {e}")

def stop():
    if not authorize_action(): return
    pid = get_pid()
    if not is_running(pid):
        print("[-] Monitor is not running.")
        if os.path.exists(PID_FILE): os.remove(PID_FILE)
        return

    print(f"[-] Stopping Sovereign Guard (PID: {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            if not is_running(pid): break
            time.sleep(0.1)
        if os.path.exists(PID_FILE): os.remove(PID_FILE)
        print("[+] Monitor stopped.")
    except Exception as e:
        print(f"[!] Stop failed: {e}")

def status():
    pid = get_pid()
    if is_running(pid):
        print(f"✅ Sovereign Guard: ACTIVE (PID: {pid})")
        if os.path.exists(SAFE_MODE_FILE):
            print("⚠️  Mode: DEVELOPER (Safe Mode Active)")
        else:
            try:
                from learning_engine import get_protection_mode, analyze_learnings
                mode = get_protection_mode()
                s = analyze_learnings()
                if mode == 'learn':
                    print(f"📘 Mode: LEARN (Day {s.get('days_elapsed', 0)+1}/7)\n    Observed: {s.get('total_observations', 0)} processes")
                else:
                    print(f"🛡️  Mode: {mode.upper()}")
            except:
                print("🛡️  Mode: SECURE")
    else:
        print("❌ Sovereign Guard: STOPPED")

def dev_mode():
    if not authorize_action(): return
    secret = path_utils.get_secret()
    if not os.path.exists(SAFE_MODE_FILE):
        with open(SAFE_MODE_FILE, 'w') as f: f.write(secret or "")
        print("⚠️  [DEVELOPER MODE ENABLED]")
    else:
        print("[-] Already in Developer Mode.")

def secure_mode():
    if os.path.exists(SAFE_MODE_FILE):
        os.remove(SAFE_MODE_FILE)
        print("🛡️  [SECURE MODE ENABLED]")
    else:
        print("[-] Already in Secure Mode.")

def scan_now():
    print("🔍 Scanning all active processes...")
    import psutil
    import sovereign_core as core
    threats = []
    
    # 1. Process Scan
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            alert = core.check_process(proc, mode='protect')
            if alert and alert.get('critical'):
                threats.append(f"{proc.name()} (PID: {proc.pid})")
        except: continue
            
    if threats:
        print(f"\n❌ COMPROMISED: {len(threats)} threats detected!")
        for t in threats: print(f"   - {t}")
        sys.exit(1)
        
    # 2. Scanners
    print("📦 Auditing Supply Chain & Extensions...")
    sc_threats = core.scan_supply_chain(".")
    ext_threats = core.scan_extensions()
    mm_threats = core.check_multimedia_access()
    
    if sc_threats or mm_threats:
        print("\n⚠️  WARNING: Vulnerabilities detected.")
        for t in sc_threats: print(f"   [!] Supply Chain: {t['package']}")
        for t in mm_threats: print(f"   [!] Hardware: {t['process']} using Camera/Mic")
    else:
        print("\n✅ SECURE: No active threats found.")

def setup_2fa():
    print("🔐 SOVEREIGN GUARD // 2FA SETUP")
    import sovereign_core as core
    import base64, secrets
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    print(f"\n📱 1. SETUP AUTHENTICATOR APP\n   KEY:  {totp_secret}\n")
    codes, hashes = core.generate_backup_codes(count=10)
    print("📝 2. SAVE EMERGENCY BACKUP CODES")
    for i, c in enumerate(codes): print(f"   [{str(i+1).zfill(2)}] {c}")
    
    env_path = ".env.sovereign"
    if os.path.exists(env_path):
        with open(env_path, 'r') as f: lines = f.readlines()
        lines = [l for l in lines if not l.startswith('RUBICON_BACKUP_HASHES=') and not l.startswith('SOVEREIGN_2FA_SECRET=')]
        lines.append(f"RUBICON_BACKUP_HASHES={','.join(hashes)}\n")
        lines.append(f"SOVEREIGN_2FA_SECRET={totp_secret}\n")
        with open(env_path, 'w') as f: f.writelines(lines)
        print("\n✅ 2FA Configured & Saved.")
        
def view_logs():
    """Views today's security alerts"""
    log_file = path_utils.get_log_file('guard_monitor.log')
    today = datetime.now().strftime('%Y-%m-%d')
    print(f"📊 SEARCHING ALERTS FOR: {today}")
    print("=" * 50)
    
    if os.path.exists(log_file):
        found = False
        with open(log_file, 'r') as f:
            for line in f:
                if today in line and any(x in line for x in ["THREAT", "SUSPICIOUS", "CRITICAL", "NEUTRALIZED"]):
                    print(line.strip())
                    found = True
        if not found:
            print("   [i] No critical alerts detected today.")
    else:
        print("   [!] Log file not found.")

def main():
    COMMANDS = {
        'start': start, 'stop': stop, 'status': status, 'dev': dev_mode,
        'secure': secure_mode, 'scan': scan_now, '2fa': setup_2fa,
        'restart': lambda: (stop(), time.sleep(1), start()),
        'logs': view_logs,
        'clean': lambda: [os.remove(path_utils.get_log_file(l)) for l in ["guard_monitor.log", "guard_watchdog.out", "guard_monitor.out", "guard_monitor.err", "guard_watchdog.err"] if os.path.exists(path_utils.get_log_file(l))]
    }
    
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(f"Usage: ./sovereign {{{'|'.join(COMMANDS.keys())}}}")
        sys.exit(1)
        
    COMMANDS[sys.argv[1]]()

if __name__ == "__main__":
    main()
