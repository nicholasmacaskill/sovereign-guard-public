
import pytest
import pyperclip
import time

def test_regression_safety(guard_process):
    """
    Ensures that legitimate workflows are NOT blocked (False Positive Check).
    """
    
    # 1. Git Clone Command (Legitimate)
    # Should NOT be blocked by Pastejacking logic or Command Injection logic
    # because it is a common dev command and doesn't use masking/piping to sh (usually).
    
    safe_cmd = "git clone https://github.com/nicholasmacaskill/python-sovereign-guard.git"
    pyperclip.copy(safe_cmd)
    
    time.sleep(2)
    
    content = pyperclip.paste()
    assert content == safe_cmd, "Safe 'git clone' command was wrongly blocked!"
    
    # 2. Localhost connection (Legitimate)
    # Should not trigger Reverse Shell logic
    # We can't easily test this without a listener, but we can verify clipboard didn't flag other things.
    
    # 3. Standard URL
    safe_url = "https://google.com/search?q=test"
    pyperclip.copy(safe_url)
    time.sleep(1)
    content = pyperclip.paste()
    assert content == safe_url, "Safe URL was blocked."
