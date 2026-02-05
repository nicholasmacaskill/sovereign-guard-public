
import pytest
import os
import time

def test_browser_persistence_detection(browser_context, mock_server, guard_process):
    """
    Simulates a Service Worker simulation and verifies Sovereign Guard detection.
    """
    page = browser_context.new_page()
    
    # 1. Clean logs before test
    log_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../logs/guard_monitor.log'))
    start_size = 0
    if os.path.exists(log_file):
        start_size = os.path.getsize(log_file)
        
    # 2. Visit page that installs Service Worker
    # Note: Service Workers usually require HTTPS or localhost. Our mock_server is localhost.
    page.goto(f"{mock_server}/service_worker.html")
    
    # Wait for installation
    expect_text = page.locator("body")
    # We might need to reload or interact to trigger the SW persistence check in the background
    time.sleep(5) 
    
    # Sovereign Guard checks persistence every ~30 seconds. 
    # Validating this in a short E2E test is tricky without mocking the time logic in the monitor.
    # However, the monitor is running in a subprocess.
    # We can check if the monitor logged the event.
    
    # Let's wait up to 35 seconds to be safe (since loop is 30s)
    # This makes the test slow, but accurate for an "E2E Audit".
    print("\n[INFO] Waiting 35s for background persistence scan...")
    time.sleep(35)
    
    # 3. Check Logs for Detection
    found_alert = False
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            f.seek(start_size)
            new_logs = f.read()
            if "BROWSER GHOST DETECTED" in new_logs:
                found_alert = True
            if "Service Worker" in new_logs:
                found_alert = True
                
    assert found_alert, "Sovereign Guard did not log the new Service Worker persistence."
