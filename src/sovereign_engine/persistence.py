import os
import re
from . import patterns

def check_persistence(last_files=None):
    """
    Checks for new or modified persistence items (LaunchAgents/Daemons).
    Returns: (current_files_dict, detected_threats)
    """
    current_files = {}
    threats = []
    
    for directory in patterns.PERSISTENCE_PATHS:
        if not os.path.exists(directory):
            continue
        try:
            for filename in os.listdir(directory):
                path = os.path.join(directory, filename)
                if os.path.isfile(path):
                    current_files[path] = os.path.getmtime(path)
                    
                    if last_files is not None and path not in last_files:
                        threats.append({
                            "type": "PERSISTENCE_NEW",
                            "severity": "CRITICAL",
                            "title": "⚡️ NEW PERSISTENCE ITEM",
                            "summary": f"New LaunchAgent found: {filename}",
                            "path": path
                        })
                    elif last_files is not None and path in last_files and current_files[path] > last_files[path]:
                        threats.append({
                            "type": "PERSISTENCE_MOD",
                            "severity": "HIGH",
                            "title": "⚡️ PERSISTENCE MODIFIED",
                            "summary": f"Existing LaunchAgent modified: {filename}",
                            "path": path
                        })
        except:
            continue
            
    return current_files, threats

def check_vault_access(proc):
    """
    Checks if a given process is accessing sensitive vault paths.
    Only flags processes NOT in the TRUSTED_VAULT_ACCESSORS list.
    """
    try:
        name = proc.name().lower()
        if any(t in name for t in patterns.TRUSTED_VAULT_ACCESSORS):
            return None
            
        open_files = proc.open_files()
        for f in open_files:
            for v_path in patterns.VAULT_PATHS:
                if f.path.startswith(v_path) or v_path in f.path:
                    return {
                        "type": "VAULT_ACCESS",
                        "severity": "HIGH",
                        "title": "🔐 UNAUTHORIZED VAULT ACCESS",
                        "summary": f"Process '{name}' is reading sensitive files: {os.path.basename(f.path)}",
                        "path": f.path
                    }
    except:
        pass
    return None

def resolve_service_worker_origin(base_path, script_id):
    """
    Attempts to resolve the origin (website) for a given Service Worker script ID.
    Looks in Chrome/Brave/Edge internal LevelDB logs.
    """
    db_path = os.path.join(base_path, 'Service Worker', 'Database')
    if not os.path.exists(db_path):
        return None

    try:
        import subprocess
        # Search for the script ID in the LevelDB logs to find the associated origin
        cmd = f"grep -r '{script_id}' '{db_path}' | head -n 5"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode == 0 and res.stdout:
            # Look for patterns like https://domain.com
            origins = re.findall(r'https?://[a-zA-Z0-9\-\.]+\.[a-z]{2,}', res.stdout)
            if origins:
                return origins[0]
    except:
        pass
    return None

def check_browser_persistence(last_state=None):
    """
    Checks for persistence in Browser Service Workers and Hosted Apps.
    Returns: (current_state, threats)
    """
    current_state = {}
    threats = []
    
    browser_base_paths = [
        os.path.expanduser('~/Library/Application Support/Google/Chrome/Default'),
        os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Default'),
        os.path.expanduser('~/Library/Application Support/Arc/User Data/Default'),
        os.path.expanduser('~/Library/Application Support/Microsoft Edge/Default')
    ]
    
    if os.environ.get('SOVEREIGN_TEST_BROWSER_DIR'):
        browser_base_paths.append(os.environ.get('SOVEREIGN_TEST_BROWSER_DIR'))
    
    for base in browser_base_paths:
        if not os.path.exists(base): continue
        browser_name = base.split('/')[-2] # e.g. 'Google', 'BraveSoftware'
        
        for subdir in patterns.BROWSER_PERSISTENCE_DIRS: # Service Worker, Hosted App Data
            target_dir = os.path.join(base, subdir)
            if not os.path.exists(target_dir): continue
            
            # Walk the directory to get a state hash/mtime
            try:
                for root, _, files in os.walk(target_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        mtime = os.path.getmtime(full_path)
                        state_key = f"{browser_name}:{subdir}:{file}"
                        current_state[state_key] = mtime
                        
                        if last_state:
                            if state_key not in last_state:
                                # Whitelist check for common storage noise (ldb, log, etc)
                                is_safe_ext = any(re.search(p, file) for p in patterns.BROWSER_STORAGE_SAFE_PATTERNS)
                                if is_safe_ext:
                                    continue

                                # Smart Whitelist: Resolve the origin
                                origin = None
                                if subdir == 'Service Worker' and '_' in file:
                                    script_id = file.split('_')[0]
                                    origin = resolve_service_worker_origin(base, script_id)
                                
                                if origin:
                                    is_trusted = any(t in origin for t in patterns.TRUSTED_BROWSER_ORIGINS)
                                    if is_trusted:
                                        # Trusted origin -> Auto-whitelist
                                        continue

                                # New Service Worker/App Data file -> POTENTIAL PERSISTENCE
                                origin_disp = f" ({origin})" if origin else ""
                                threats.append({
                                    "type": "BROWSER_PERSISTENCE",
                                    "severity": "MEDIUM",
                                    "title": "👻 BROWSER GHOST DETECTED",
                                    "summary": f"New {subdir} detected in {browser_name}{origin_disp}: {file}",
                                    "path": full_path
                                })
                            elif mtime > last_state[state_key]:
                                # Modifed -> Update
                                pass # Modifications are too noisy for now, focusing on NEW
            except: continue
            
    return current_state, threats
