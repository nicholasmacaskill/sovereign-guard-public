
import sys
import os
import logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
import sovereign_core as core

# Setup simple logging
logging.basicConfig(level=logging.ERROR)

def run_forensic_audit():
    print("🔎 STARTING FORENSIC AUDIT...")
    print("--------------------------------")
    
    threats_found = False
    
    # 1. Check Browser History for Infostealer Domains
    print("\n[1/3] Scanning Browser History for known Stealer Domains...")
    history_threats = core.scan_browser_history()
    if history_threats:
        threats_found = True
        for t in history_threats:
            print(f"  🚨 MATCH: {t['summary']}")
            print(f"     URL: {t.get('url', 'N/A')}")
    else:
        print("  ✅ No known infostealer domains found in history.")

    # 2. Check Browser Persistence (Service Workers)
    print("\n[2/3] Scanning for 'Shadow Persistence' (Service Workers)...")
    _, persistence_threats = core.check_browser_persistence()
    if persistence_threats:
        threats_found = True
        for t in persistence_threats:
            print(f"  🚨 SUSPICIOUS: {t['summary']}")
            print(f"     Path: {t.get('path', 'N/A')}")
    else:
        print("  ✅ No suspicious Service Workers / Hosted Apps detected.")

    # 3. Check Extensions
    print("\n[3/3] Scanning Browser Extensions...")
    extension_threats = core.scan_extensions()
    if extension_threats:
        threats_found = True
        for t in extension_threats:
            print(f"  🚨 RISK: {t['name']} ({t['id']})")
            print(f"     Risks: {t['risks']}")
    else:
        print("  ✅ No high-risk extensions found.")

    print("\n--------------------------------")
    if threats_found:
        print("⚠️  POTENTIAL COMPROMISE INDICATORS FOUND.")
    else:
        print("✅  Clean forensic scan. No obvious indicators of compromise found.")

if __name__ == "__main__":
    run_forensic_audit()
