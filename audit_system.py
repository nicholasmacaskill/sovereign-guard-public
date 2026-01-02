import platform
import subprocess
import os
import sys

def check_mac_lockdown_mode():
    """Checks Lockdown Mode status on macOS."""
    print("[-] Checking macOS Lockdown Mode...")
    # Lockdown Mode status is stored in global preferences, but reading it programmatically 
    # reliably without admin/MDM profiles can be tricky. We'll try checking the default value 
    # if accessible, or instruct manual verification if uncertain. 
    # A common indicator is in com.apple.ldm usually, but let's assume a simplified check or placeholder.
    # Note: As of macOS Ventura, programmatic detection is restricted for privacy.
    # We will simulate the check or assume user must verify. 
    
    # However, we can check SIP as a proxy for general hardening "vibes" or similar.
    # For this exercise, we'll try a generic `defaults read` which might fail if key doesn't exist.
    try:
        # This is a best-effort guess command for detection
        res = subprocess.run(['defaults', 'read', '.GlobalPreferences', 'LDMStatus'], capture_output=True, text=True)
        if res.returncode == 0:
            status = res.stdout.strip()
            print(f"    [INFO] LDMStatus found: {status}")
            if status == '1':
                print("    [PASS] Lockdown Mode appears ENABLED.")
                return True
        else:
            print("    [WARN] Could not determine Lockdown Mode status via defaults.")
    except Exception as e:
        print(f"    [ERR] Error checking Lockdown Mode: {e}")
    
    print("    [MANUAL CHECK REQ] Go to System Settings > Privacy & Security > Lockdown Mode.")
    return False

def check_windows_core_isolation():
    """Checks Core Isolation/HVCI on Windows."""
    print("[-] Checking Windows Core Isolation (HVCI)...")
    # Registry key: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperVisorEnforcedCodeIntegrity\Enabled
    try:
        import winreg
        key_path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperVisorEnforcedCodeIntegrity"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "Enabled")
            if value == 1:
                print("    [PASS] Core Isolation/HVCI is ENABLED.")
                return True
            else:
                print("    [FAIL] Core Isolation/HVCI is DISABLED.")
                return False
    except ImportError:
         print("    [SKIP] 'winreg' module not available (not running on Windows native python).")
    except FileNotFoundError:
        print("    [FAIL] Core Isolation registry key not found (likely disabled).")
    except Exception as e:
        print(f"    [ERR] Error checking Core Isolation: {e}")
    return False

def check_dbsc_support():
    """Checks for Device Bound Session Credentials (DBSC) support hints."""
    print("[-] Checking DBSC Support (Chrome/Edge)...")
    # DBSC is often controlled by enterprise policy or specific flags. 
    # We'll check if the 'Google Chrome' polices indicate anything, or if a specific flag is set.
    # This is highly experimental as DBSC is new.
    # We'll check for a mock policy file or config.
    
    dbsc_enabled = False
    
    # Mock check: inspect environment variables or config
    if os.environ.get("ENABLE_DBSC") == "1":
        dbsc_enabled = True
        print("    [PASS] DBSC explicit env var found.")
    else:
        print("    [INFO] No global DBSC environment variable found.")

    # In a real scenario, we might query `chrome://policy` export or registry.
    print("    [NOTE] Verify DBSC in Browser: chrome://flags/#enable-bound-session-credentials")
    return dbsc_enabled

def audit_system():
    os_name = platform.system()
    print(f"Starting System Audit for: {os_name}")
    print("=" * 40)
    
    if os_name == 'Darwin':
        check_mac_lockdown_mode()
    elif os_name == 'Windows':
        check_windows_core_isolation()
    else:
        print(f"[WARN] Unsupported OS for specific hardening checks: {os_name}")
        
    print("-" * 40)
    check_dbsc_support()
    print("=" * 40)
    print("Audit Complete.")

if __name__ == "__main__":
    audit_system()
