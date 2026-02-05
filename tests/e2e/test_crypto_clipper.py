
import pytest
import time
import pyperclip
import os

def test_crypto_clipper_detection(guard_process):
    """
    Legacy Feature Audit: Tests protection against Crypto Address Swapping.
    Behavior: guard_monitor should revert unauthorized changes to crypto addresses?
    Actually, per code:
    - If a crypto address is swapped (prev != curr), it alerts/neutralizes.
    """
    
    # 1. Set Clipboard to Valid BTC Address (Simulate User Copy)
    valid_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" # Satoshi's address
    pyperclip.copy(valid_btc)
    time.sleep(1) # Let Guard see it
    
    # 2. Simulate Malware Swapping it (Simulate Attack)
    # We act as the malware here
    malicious_btc = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    pyperclip.copy(malicious_btc)
    
    # 3. Wait for Reaction
    time.sleep(3)
    
    # 4. Verify Reaction
    # Sovereign Guard logic:
    # If CRYPTO_SWAP detected -> Neutralizes (Overwrites with warning)
    
    final_content = pyperclip.paste()
    print(f"\n[DEBUG] Final Content: {final_content}")
    
    assert malicious_btc not in final_content, "Crypto Swap was successful! Guard failed to revert."
    assert "SOVEREIGN GUARD" in final_content or "CLIPBOARD THREAT" in final_content, \
        "Guard did not leave a warning message after swap."
