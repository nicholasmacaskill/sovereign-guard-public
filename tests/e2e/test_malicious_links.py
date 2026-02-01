import pytest
import time
from playwright.sync_api import sync_playwright
import os
import subprocess
from sovereign_engine import scanners

def test_active_tab_detection(guard_process):
    """
    Verifies that Sovereign Guard detects a malicious URL in an active browser tab.
    """
    with sync_playwright() as p:
        # We need to use a browser that osascript can talk to.
        # Use channel="chrome" to use the installed Google Chrome app.
        browser = p.chromium.launch(headless=False, channel="chrome") 
        context = browser.new_context()
        page = context.new_page()
        
        # Use one of the patterns we added to MALICIOUS_LINKS
        malicious_url = "http://malicious-site.com/login"
        print(f"Navigating to {malicious_url}")
        
        try:
            page.goto(malicious_url, wait_until="commit")
            time.sleep(3)
            
            # DEBUG: See what is actually running
            procs = subprocess.run(['ps', '-ax'], capture_output=True, text=True).stdout
            if "Chromium" in procs or "Google Chrome" in procs:
                print("Found browser process in ps -ax")
            else:
                print("Did NOT find browser process in ps -ax. Searching for play:")
                print("\n".join([l for l in procs.splitlines() if "play" in l.lower() or "chrom" in l.lower()][:10]))
            
            # Now trigger the scanner manually to verify it sees it
            # (The background monitor will also see it, but this is a direct unit-style test)
            threats = scanners.check_active_tabs()
            
            found = False
            for t in threats:
                if "malicious-site.com" in t['url']:
                    found = True
                    break
            
            assert found, f"Scanner failed to detect active tab with URL: {malicious_url}"
            print("Successfully detected malicious active tab!")
            
        finally:
            browser.close()

if __name__ == "__main__":
    # For manual testing
    # Requires a running Chromium/Chrome window with the URL open
    print(scanners.check_active_tabs())
