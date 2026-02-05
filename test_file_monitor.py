#!/usr/bin/env python3
"""
Standalone test for file_monitor module.
This directly calls monitor_sensitive_files() to test the logic.
"""
import sys
import os
import time
import subprocess

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import sovereign_core as core

def run_test():
    print("🧪 Testing File Monitor in Safe Mode...")
    print("="*50)
    
    # 1. Create honeypot
    decoy = os.path.expanduser('~/Documents/passwords_backup.txt')
    if not os.path.exists(decoy):
        with open(decoy, 'w') as f:
            f.write("TRAP")
        print(f"✅ Created honeypot: {decoy}")
    
    # 2. Spawn a thief touching the honeypot
    script = f"import time; f=open('{decoy}', 'r'); time.sleep(10)"
    thief = subprocess.Popen(['python3', '-c', script])
    print(f"👾 Spawned thief PID {thief.pid} touching honeypot...")
    
    # 3. Give it 1 second to open the file
    time.sleep(1)
    
    # 4. Run file monitor (Safe Mode)
    print("\n🛡️  Running monitor_sensitive_files(active_response_level='safe')...")
    threats = core.monitor_sensitive_files(active_response_level='safe')
    
    print(f"\n📊 Detected {len(threats)} threat(s):\n")
    for t in threats:
        print(f"  • {t['title']}")
        print(f"    {t['summary']}")
        print(f"    Action: {t.get('action', 'N/A')}")
        print()
    
    # 5. Check if thief was killed
    time.sleep(1)
    if thief.poll() is None:
        print("❌ Thief still alive! Kill switch failed.")
        thief.terminate()
    else:
        print("✅ Thief was terminated by Active Defense!")

if __name__ == "__main__":
    run_test()
