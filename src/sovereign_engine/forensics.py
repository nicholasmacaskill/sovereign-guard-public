import psutil
import time
import logging
import socket
import threading
from . import patterns

def resolve_domain_with_timeout(ip, timeout=1.5):
    """Resolve IP to domain with a strict timeout to prevent blocking"""
    result = {"domain": None}
    
    def target():
        try:
            result["domain"] = socket.gethostbyaddr(ip)[0]
        except:
            pass
            
    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    t.join(timeout)
    return result["domain"]

def get_attacker_ip(pid):
    """Retrieves the remote IP of a suspicious connection."""
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind='inet')
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.remote_address:
                if conn.laddr.port in patterns.DEBUG_PORTS:
                    return conn.remote_address.ip
    except:
        pass
    return None

def audit_clipboard_hijacker():
    """Identifies and neutralizes processes attempting clipboard hijacking."""
    logging.warning("Initiating Clipboard Hijacker Audit...")
    culprits = []
    
    try:
        current_time = time.time()
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'exe']):
            try:
                p_info = proc.info
                name = p_info['name']
                exe = p_info['exe'] or ""
                
                name_low = name.lower()
                is_safe = False
                for safe in patterns.SAFE_LIST_PROCESSES:
                    if name_low == safe or name_low.startswith(f"{safe} ") or name_low.startswith(f"{safe}."):
                        is_safe = True
                        break
                if is_safe: continue
                
                if exe.startswith('/System/') or exe.startswith('/usr/lib/') or exe.startswith('/usr/bin/'):
                    continue

                if (current_time - p_info['create_time']) < 600:
                    if any(k in name_low for k in ['python', 'paste', 'clipboard', 'copy', 'hijack']) or name.startswith('.'):
                        culprits.append(proc)
                    elif '/Users/' in exe and '/Applications/' not in exe:
                        culprits.append(proc)
            except: continue
                
        neutralized_names = []
        for culprit in culprits[:3]:
            try:
                c_pid = culprit.pid
                c_name = culprit.name()
                logging.warning(f"⚡️ NEUTRALIZING HIJACK CULPRIT: {c_name} (PID: {c_pid})")
                culprit.kill()
                neutralized_names.append(f"{c_name} (PID: {c_pid})")
            except: continue
        
        if neutralized_names:
            return f"Neutralized {len(neutralized_names)} suspect(s): " + ", ".join(neutralized_names)
    except Exception as e:
        logging.error(f"Error during hijacker audit: {e}")
        
    return "No clear culprit found. Full malware scan recommended."
