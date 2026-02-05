import sys
import os
# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

from sovereign_engine.persistence import check_browser_persistence

# We need to simulate "last state" effectively being empty or missing this file
# so that the function treats it as NEW.
# But check_browser_persistence logic is: 
# iterate all files, if not in last_state -> check whitelist -> if not whitelist -> THREAT.

print("Running check_browser_persistence...")
current_state, threats = check_browser_persistence(last_state={})

# We are looking for threats related to our dummy file
found_dummy_threat = False
for t in threats:
    if "aaaaaaaaaaaaaaaa_0" in t['path']:
        print(f"FAIL: Threat detected for dummy file: {t['summary']}")
        found_dummy_threat = True

if not found_dummy_threat:
    print("SUCCESS: No threats detected for dummy file.")
    # Optional: print total threats to see if other things are noisy
    # print(f"Total other threats: {len(threats)}")

# Cleanup
try:
    os.remove("/Users/nicholasmacaskill/Library/Application Support/Google/Chrome/Default/Service Worker/ScriptCache/aaaaaaaaaaaaaaaa_0")
    print("Cleaned up dummy file.")
except:
    pass
