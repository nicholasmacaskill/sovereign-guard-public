
import pytest
import subprocess
import time
import os
import signal

def test_reverse_shell_termination(guard_process):
    """
    System Integrity: Tests that a reverse shell (nc to external IP) is killed.
    """
    # 1. Start a "Reverse Shell"
    # We use 'nc' to connect to a public DNS server (safe, reliable).
    # This establishes a TCP connection to a non-private IP.
    # The Guard should see this as a shell process ('nc') connecting to untrusted IP.
    
    cmd = ["nc", "1.1.1.1", "80"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = proc.pid
    
    # 2. Wait for Kill
    killed = False
    for _ in range(10):
        if proc.poll() is not None:
            killed = True
            break
        try:
             os.kill(pid, 0)
        except OSError:
             killed = True
             break
        time.sleep(0.5)
        
    if not killed:
        proc.terminate()
        
    assert killed, "Reverse shell (nc 1.1.1.1) was NOT killed by Sovereign Guard."
