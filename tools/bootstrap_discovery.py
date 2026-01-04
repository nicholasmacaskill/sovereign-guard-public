import os
import json
import subprocess
import psutil
from datetime import datetime
from learning_engine import log_process, log_network_connection, LEARNING_LOG, NETWORK_LOG

def bootstrap_system_discovery():
    """
    Scans the system for installed applications and common developer tools
    to pre-seed the whitelist.
    """
    print("🚀 Initializing System Discovery Bootstrap...")
    found_count = 0
    
    # 1. Scan /Applications and /System/Applications
    search_paths = ['/Applications', '/System/Applications', '/usr/bin', '/usr/local/bin']
    
    for base_path in search_paths:
        if not os.path.exists(base_path):
            continue
            
        print(f"[-] Scanning {base_path}...")
        try:
            for item in os.listdir(base_path):
                # We mainly want .app folders or binaries
                name = item.replace('.app', '')
                full_path = os.path.join(base_path, item)
                
                # Mock a process observation to seed the engine
                # We use a dummy timestamp from '3 days ago' to trick the transition logic
                # Actually, better to just log them with current time but mark them as 'Trusted'
                log_process(name, full_path, [full_path])
                found_count += 1
        except Exception as e:
            print(f" [!] Skip {base_path}: {e}")

    # 2. Migration: Pull from Legacy Logs if they exist
    legacy_log = '.learning_log.json.legacy'
    if os.path.exists(legacy_log):
        print(f"[-] Migrating legacy data from {legacy_log}...")
        try:
            with open(legacy_log, 'r') as f:
                data = json.load(f)
                observations = data.get('observations', [])
                for obs in observations:
                    log_process(obs['name'], obs.get('exe_path', ''), obs.get('cmdline', []))
                    found_count += 1
            print(f" [+] Migrated {len(observations)} legacy observations.")
        except Exception as e:
            print(f" [!] Migration failed: {e}")

    print(f"✅ Bootstrap complete. Integrated {found_count} system observations.")
    return found_count

if __name__ == "__main__":
    bootstrap_system_discovery()
