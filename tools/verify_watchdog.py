import psutil
import time
import os
import sys

def verify_watchdog():
    print("--- Watchdog Verification ---")
    
    # 1. Find Monitor
    monitor_proc = None
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'guard_monitor.py' in (p.info['cmdline'] or []):
                monitor_proc = p
                break
        except:
            continue
            
    if not monitor_proc:
        print("❌ FAILURE: guard_monitor.py not found initially.")
        return False
        
    print(f"✅ Found Monitor PID: {monitor_proc.pid}")
    
    # 2. Kill Monitor
    print(f"⚡️ Killing Monitor (PID: {monitor_proc.pid})...")
    monitor_proc.kill()
    
    # 3. Wait for resurrection
    time.sleep(2)
    
    # 4. Check for new Monitor
    new_monitor = None
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'guard_monitor.py' in (p.info['cmdline'] or []) and p.pid != monitor_proc.pid:
                new_monitor = p
                break
        except:
            continue
            
    if new_monitor:
        print(f"✅ SUCCESS: Watchdog resurrected Monitor as PID {new_monitor.pid}")
        return True
    else:
        print("❌ FAILURE: Monitor did not restart.")
        return False

if __name__ == "__main__":
    if verify_watchdog():
        sys.exit(0)
    else:
        sys.exit(1)

