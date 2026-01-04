import os
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
