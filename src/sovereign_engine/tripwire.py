import os
import subprocess
import logging
import psutil
from datetime import datetime

logger = logging.getLogger(__name__)

BAIT_FILES = [
    os.path.expanduser('~/Desktop/LinkedIn_Session_Vault.txt'),
    os.path.expanduser('~/Library/Application Support/Sovereign_Bkp.sql')
]

# We whitelist some processes that might legitimately crawl the disk 
# (though they shouldn't be opening these specific decoy files)
TRIPWIRE_WHITELIST = ['mdworker', 'mds', 'backupd', 'Spotlight']

def deploy_bait():
    """Creates decoy files to act as tripwires."""
    for fpath in BAIT_FILES:
        if not os.path.exists(fpath):
            try:
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, 'w') as f:
                    f.write("SOVEREIGN_SESSION_KEY_DEBUG_PRIMARY=0923-4923-1029-4923\n")
                    f.write("This is a bait file. Do not edit.\n")
                # Set permissions to read-only for current user
                os.chmod(fpath, 0o400)
                logger.info(f"Honey-Cookie bait deployed: {fpath}")
            except Exception as e:
                logger.error(f"Failed to deploy bait {fpath}: {e}")

def check_traps():
    """
    Checks if any process has opened the bait files.
    Returns: list of suspicious processes {pid, name, file}
    """
    threats = []
    for fpath in BAIT_FILES:
        if not os.path.exists(fpath):
            continue
            
        try:
            # Use lsof to see who has the file open
            result = subprocess.run(
                ['lsof', '-t', fpath],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().splitlines()
                for pid_str in pids:
                    try:
                        pid = int(pid_str)
                        proc = psutil.Process(pid)
                        name = proc.name()
                        
                        # Check whitelist
                        if any(w in name for w in TRIPWIRE_WHITELIST):
                            continue
                            
                        threats.append({
                            "type": "TRAP_SPRUNG",
                            "severity": "CRITICAL",
                            "title": "🚨 TRAP SPRUNG: HONEY-COOKIE ACCESSED",
                            "summary": f"Process '{name}' (PID: {pid}) accessed decoy session file: {os.path.basename(fpath)}",
                            "pid": pid,
                            "process": name,
                            "file": fpath
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                        continue
        except Exception as e:
            logger.error(f"Tripwire check failed for {fpath}: {e}")
            
    return threats
