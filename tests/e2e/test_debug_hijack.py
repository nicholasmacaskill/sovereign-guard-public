
import pytest
import subprocess
import time
import os
import signal

def test_debug_port_hijack_prevention(mock_server, guard_process):
    """
    Legacy Feature Audit: Tests that launching Chrome with --remote-debugging-port 
    results in immediate termination.
    """
    # 1. Launch a "Malicious" Chrome Instance
    # We use a dummy command or actual chrome executable if available.
    # Since this is macOS, we can point to the actual binary.
    
    chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not os.path.exists(chrome_path):
        pytest.skip("Google Chrome not found in standard location")
        
    cmd = [
        chrome_path,
        "--remote-debugging-port=9222",
        "--headless", # Run headless to disable UI noise
        "about:blank"
    ]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = proc.pid
    
    # 2. Wait for Sovereign Guard to Kill it
    # Should be instant, but give it 5 seconds
    killed = False
    for _ in range(10):
        if proc.poll() is not None:
            killed = True
            break
        # Also check psutil manually in case Popen state is lagging
        try:
            os.kill(pid, 0) 
        except OSError:
            killed = True
            break
        time.sleep(0.5)
        
    # Cleanup if it survived
    if not killed:
        proc.terminate()
        
    assert killed, "Browser with --remote-debugging-port was NOT killed by Sovereign Guard."
