import os
import re
import platform
import subprocess
import logging
import sqlite3
import shutil
import tempfile
from . import patterns

def scan_supply_chain(target_path="."):
    """Scans package.json or requirements.txt for typosquatting attacks."""
    TYPOSQUAT_DB = {}
    threats = []
    files_to_check = [os.path.join(target_path, 'requirements.txt'), os.path.join(target_path, 'package.json')] if os.path.isdir(target_path) else [target_path]
    
    for file_path in files_to_check:
        if not os.path.exists(file_path): continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            found_deps = []
            if file_path.endswith('.txt') or 'requirements' in file_path:
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    pkg = re.split(r'[=<>~]', line)[0].strip().lower()
                    if pkg: found_deps.append(pkg)
            elif 'package.json' in file_path:
                import json
                data = json.loads(content)
                found_deps = list(data.get('dependencies', {}).keys()) + list(data.get('devDependencies', {}).keys())
            
            for dep in found_deps:
                for legitimate, bad_variants in TYPOSQUAT_DB.items():
                    if dep.lower() in bad_variants:
                        threats.append({"type": "SUPPLY_CHAIN_TYPO", "severity": "HIGH", "package": dep, "legitimate_guess": legitimate})
        except: continue
    return threats

def scan_extensions():
    """Scans browser extensions for high-risk permissions."""
    risky_extensions = []
    
    for base_path in patterns.BROWSER_EXTENSION_PATHS:
        if not os.path.exists(base_path): continue
        try:
            for ext_id in os.listdir(base_path):
                ext_dir = os.path.join(base_path, ext_id)
                if not os.path.isdir(ext_dir): continue
                versions = sorted(os.listdir(ext_dir))
                if not versions: continue
                manifest_path = os.path.join(ext_dir, versions[-1], 'manifest.json')
                if not os.path.exists(manifest_path): continue
                with open(manifest_path, 'r') as f:
                    import json
                    manifest = json.load(f)
                perms = manifest.get('permissions', [])
                for cs in manifest.get('content_scripts', []): perms.extend(cs.get('matches', []))
                found_risks = [p for p in perms if p in patterns.RISKY_EXTENSION_PERMISSIONS]
                if found_risks:
                    risky_extensions.append({
                        "type": "EXTENSION_RISK", 
                        "severity": "HIGH",
                        "name": manifest.get('name', 'Unknown'), 
                        "id": ext_id, 
                        "risks": list(set(found_risks)),
                        "path": manifest_path
                    })
        except: continue
    return risky_extensions

def check_multimedia_access():
    """Checks for unauthorized camera/mic access."""
    MULTIMEDIA_WHITELIST = [
        'Antigravity', 'Google Chrome', 'Brave Browser', 'Arc', 'Microsoft Edge',
        'Safari', 'Zoom', 'Slack', 'Discord', 'FaceTime', 'Skype', 'WhatsApp',
        'callservicesd', 'AudioComponentRegistrar', 'PowerChime', 'say', 'corespeechd'
    ]
    threats = []
    if platform.system() != 'Darwin': return threats
    try:
        cmd = "lsof -n -w | grep -Ei 'VDC|AppleCamera|CoreAudio'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            seen_pids = set()
            import psutil
            for line in lines:
                parts = re.split(r'\s+', line)
                if len(parts) < 2: continue
                proc_name, pid = parts[0], parts[1]
                if pid in seen_pids: continue
                seen_pids.add(pid)
                is_safe = any(safe.lower() in proc_name.lower() or proc_name.lower() in safe.lower() for safe in MULTIMEDIA_WHITELIST)
                
                # Double check with psutil for system paths
                if not is_safe:
                    try:
                        p = psutil.Process(int(pid))
                        exe = p.exe()
                        if exe.startswith('/System/'):
                            is_safe = True
                    except: pass

                if not is_safe and not proc_name.startswith('com.apple.'):
                    threats.append({"type": "MULTIMEDIA_ACCESS", "process": proc_name, "pid": pid})
    except: pass
    return threats

def check_screen_sharing():
    """Detects active screen sharing/recording."""
    SCREEN_SHARING_AGENTS = []
    import psutil
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in SCREEN_SHARING_AGENTS: return True
    except: pass

def scan_browser_history():
    """Scans browser history for visits to known infostealer domains."""
    threats = []
    
    # Browsers lock the history DB, so we copy it to temp
    browser_histories = [
        os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/History'),
        os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Default/History'),
        os.path.expanduser('~/Library/Application Support/Arc/User Data/Default/History'),
        os.path.expanduser('~/Library/Application Support/Microsoft Edge/Default/History')
    ]
    
    if os.environ.get('SOVEREIGN_TEST_BROWSER_DIR'):
        # Playwright usually puts History in Default/History ?? Or just History?
        # Persistent Context: User Data Dir -> Default -> History
        test_dir = os.environ.get('SOVEREIGN_TEST_BROWSER_DIR')
        # Check both likely locations
        browser_histories.append(os.path.join(test_dir, 'History'))
        browser_histories.append(os.path.join(test_dir, 'Default', 'History'))

    for db_path in browser_histories:
        if not os.path.exists(db_path): continue
        try:
            # Create a temp copy
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, "History_Copy")
            shutil.copy2(db_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Simple query for URL
            for row in cursor.execute("SELECT url, title, last_visit_time FROM urls"):
                url = row[0]
                for pattern in patterns.KNOWN_INFOSTEALERS:
                    if re.search(pattern, url, re.IGNORECASE):
                        threats.append({
                             "type": "INFOSTEALER_HISTORY",
                             "severity": "CRITICAL",
                             "title": "🕵️ INFOSTEALER DOMAIN VISITED",
                             "summary": f"History record found for known stealer domain: {url}",
                             "url": url,
                             "source": db_path
                        })
                        break # One hit per URL is enough
            
            conn.close()
            shutil.rmtree(temp_dir)
        except Exception as e:
            # logging.error(f"Failed to scan history {db_path}: {e}")
            pass
            
    return threats

def check_active_tabs():
    """
    Checks active tabs in major browsers for malicious URLs via AppleScript (macOS only).
    """
    threats = []
    if platform.system() != 'Darwin': return threats
    
    scripts = {
        "Google Chrome": 'tell application "Google Chrome" to get URL of active tab of first window',
        "Chromium": 'tell application "Chromium" to get URL of active tab of first window',
        "Brave Browser": 'tell application "Brave Browser" to get URL of active tab of first window',
        "Safari": 'tell application "Safari" to get URL of current tab of front window',
        "Microsoft Edge": 'tell application "Microsoft Edge" to get URL of active tab of first window',
        "Arc": 'tell application "Arc" to get URL of active tab of first window'
    }
    
    for browser, script in scripts.items():
        try:
            # Check if browser is running first
            # We check both the full name and the first word (e.g. "Brave", "Chrome")
            short_name = browser.replace(" Browser", "").replace("Google ", "")
            check_running = subprocess.run(['pgrep', '-if', f"^{short_name}"], capture_output=True)
            if check_running.returncode != 0 and browser != "Safari":
                continue

            res = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                url = res.stdout.strip()
                if not url: continue
                
                for pattern in patterns.MALICIOUS_LINKS:
                    if re.search(pattern, url, re.IGNORECASE):
                        threats.append({
                            "type": "MALICIOUS_LINK",
                            "severity": "CRITICAL",
                            "title": "🚨 MALICIOUS LINK DETECTED",
                            "summary": f"You are currently viewing a known malicious site in {browser}: {url}",
                            "url": url,
                            "browser": browser
                        })
                        break
        except:
            continue
            
    return threats
