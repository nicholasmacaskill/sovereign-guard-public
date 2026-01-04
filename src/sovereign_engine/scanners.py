import os
import re
import platform
import subprocess
import logging
from . import patterns

def scan_supply_chain(target_path="."):
    """Scans package.json or requirements.txt for typosquatting attacks."""
    TYPOSQUAT_DB = {
        'requests': ['reqests', 'request', 'requesst', 'rquests'],
        'numpy': ['numy', 'nump', 'numpp'],
        'pandas': ['padas', 'pandda', 'pndas'],
        'flask': ['fask', 'flakk', 'flaks'],
        'django': ['djago', 'djanog', 'djanga'],
        'tensorflow': ['tensorflw', 'tnsorflow', 'tensoflow'],
        'discord.py': ['discord.p', 'dicord.py', 'discordpy'],
        'selenium': ['selenum', 'seleium', 'sylenium'],
        'dotenv': ['python-dotenv', 'dontenv'],
        'cryptography': ['crytography', 'cryptogprahy'],
        'colors': ['clors', 'colour'], 
        'dateutil': ['dateutils'] 
    }
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
    EXTENSION_PATHS = [
        os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/Extensions"),
        os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
        os.path.expanduser("~/Library/Application Support/Arc/User Data/Default/Extensions")
    ]
    RISKY_PERMISSIONS = ['<all_urls>', 'http://*/*', 'https://*/*', 'clipboardRead', 'clipboardWrite', 'desktopCapture', 'tabCapture', 'cookies']
    risky_extensions = []
    
    for base_path in EXTENSION_PATHS:
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
                found_risks = [p for p in perms if p in RISKY_PERMISSIONS]
                if found_risks:
                    risky_extensions.append({"type": "EXTENSION_RISK", "name": manifest.get('name', 'Unknown'), "id": ext_id, "risks": list(set(found_risks))})
        except: continue
    return risky_extensions

def check_multimedia_access():
    """Checks for unauthorized camera/mic access."""
    MULTIMEDIA_WHITELIST = [
        'zoom.us', 'Slack', 'Teams', 'Google Chrome', 'Brave Browser', 
        'Arc', 'Discord', 'FaceTime', 'Photo Booth', 'QuickTime Player',
        'obs', 'screencapture', 'avconferenced', 'ControlCenter', 'Skype',
        'Antigravity', 'PowerChime', 'Google', 'say', 'AudiovisualRelay'
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
                if not is_safe and not proc_name.startswith('com.apple.'):
                    threats.append({"type": "MULTIMEDIA_ACCESS", "process": proc_name, "pid": pid})
    except: pass
    return threats

def check_screen_sharing():
    """Detects active screen sharing/recording."""
    SCREEN_SHARING_AGENTS = ['ScreenSharingAgent', 'ScreensharingAgent', 'cp-screen-recorder', 'zoom.us', 'TeamViewer', 'Slack Helper', 'Discord Helper']
    import psutil
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in SCREEN_SHARING_AGENTS: return True
    except: pass
    return False
