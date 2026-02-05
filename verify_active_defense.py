import os
import time
import subprocess
import signal

# Paths (Matching file_monitor.py)
REAL_COOKIE_PATH = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Cookies')
DECOY_PATH = os.path.expanduser('~/Documents/passwords_backup.txt')

def test_safe_mode_access():
    print(f"\n[TEST 1] Testing Safe Mode Access to Real Cookies...")
    print(f"Opening {REAL_COOKIE_PATH} with 'cat'...")
    try:
        # We assume Chrome connects are monitored.
        # This simulates a "thief" reading the file.
        # Since we are in SAFE MODE, this should trigger an ALERT but NOT KILL US.
        proc = subprocess.Popen(['cat', REAL_COOKIE_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        if proc.poll() is None:
            print("✅ Process survived (Expected in Safe Mode). Check logs for ALERT.")
            proc.terminate()
        else:
            print("❌ Process was killed! (Unexpected for Safe Mode on Real File)")
    except Exception as e:
        print(f"Test failed: {e}")

def test_honeypot_access():
    print(f"\n[TEST 2] Testing Honeypot Access (DEATH TRAP)...")
    print(f"Opening {DECOY_PATH}...")
    
    # Create decoy if missing for test
    if not os.path.exists(DECOY_PATH):
        with open(DECOY_PATH, 'w') as f: f.write("trap")

    # This process SHOULD be killed by Sovereign Guard
    # We spawn a discrete child process to touch the file
    script = f"import time; f=open('{DECOY_PATH}', 'r'); print('Opened honeypot'); time.sleep(10)"
    
    try:
        proc = subprocess.Popen(['python3', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Spawned Thief PID: {proc.pid}")
        
        # Wait a few seconds for Monitor to catch it
        for i in range(5):
            if proc.poll() is not None:
                print(f"💀 thief_process was KILLED at click {i}! (SUCCESS)")
                return
            time.sleep(1)
            print(".")
            
        print("❌ Thief survived for 5 seconds. Active Defense failed?")
        proc.terminate()
        
    except Exception as e:
        print(f"Test failed: {e}")

if __name__ == "__main__":
    print("⚠️  Ensure 'guard_monitor.py' is RUNNING in another terminal!")
    input("Press Enter to start tests...")
    test_safe_mode_access()
    test_honeypot_access()
