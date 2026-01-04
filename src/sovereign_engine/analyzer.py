import os
import psutil
import logging
import subprocess
import socket
import threading
from . import patterns

def check_process(proc, mode=None, safe_mode=False):
    """
    Check if a process is suspicious or malicious
    """
    # Trigger dynamic reload
    patterns.load_dynamic_whitelist()

    if safe_mode:
        mode = 'warn'
    
    if mode is None:
        try:
            from learning_engine import get_protection_mode
            mode = get_protection_mode()
        except:
            mode = os.getenv('PROTECTION_MODE', 'protect')
    
    try:
        cmdline = proc.cmdline()
        pid = proc.pid
        name = proc.name()
        exe_path = proc.exe() or ""
        
        try:
            from learning_engine import log_process
            log_process(name, exe_path, cmdline)
        except:
             pass

        if mode == 'learn':
            return None
        
        name_lower = name.lower()
        monitored_keywords = [
            'chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi', 'chromium',
            'telegram', 'whatsapp', 'signal', 'slack', 'discord', 'messages', 'zoom'
        ]
        is_monitored_app = any(t in name_lower for t in monitored_keywords)
        
        spoof_detected = False
        if is_monitored_app and exe_path:
            if not any(exe_path.startswith(safe) for safe in patterns.SAFE_BROWSER_PATHS):
                spoof_detected = True

        lineage_suspicious = False
        try:
            parent = proc.parent()
            parent_name = parent.name() if parent else "Unknown"
            parent_pid = parent.pid if parent else "N/A"
            origin_info = f"Launched by: '{parent_name}' (PID: {parent_pid})"
            
            if is_monitored_app and parent_name:
                parent_lower = parent_name.lower()
                if not any(p in parent_lower for p in patterns.TRUSTED_BROWSER_PARENTS):
                    if not any(b in parent_lower for b in ['chrome', 'brave', 'edge', 'arc', 'opera']):
                        lineage_suspicious = True
        except:
            origin_info = "Launched by: Unknown"
            lineage_suspicious = is_monitored_app
        
        critical_detected = []
        suspicious_detected = []
        
        if spoof_detected:
            critical_detected.append("UNSAFE EXECUTABLE PATH (SPOOFING RISK)")
            
        if lineage_suspicious:
            critical_detected.append(f"SUSPICIOUS LINEAGE ({parent_name} -> {name})")
            
        for arg in cmdline:
            for flag in patterns.CRITICAL_FLAGS:
                if arg.startswith(flag):
                    critical_detected.append(flag)
            for flag in patterns.SUSPICIOUS_FLAGS:
                if arg.startswith(flag):
                    suspicious_detected.append(flag)
            
            if arg.startswith(patterns.DEBUG_PORT_FLAG):
                if lineage_suspicious:
                    critical_detected.append(f"{patterns.DEBUG_PORT_FLAG} (UNTRUSTED PARENT)")
        
        detected_flags = critical_detected + suspicious_detected
        
        if detected_flags:
            risk_level = "CRITICAL" if critical_detected or spoof_detected else "SUSPICIOUS"
            risk_title = f"⚡️ SOVEREIGN GUARD: {risk_level} THREAT DETECTED"
            summary_msg = f"SECURITY ALERT: Process '{name}' (PID: {pid}) detected with flags: {', '.join(detected_flags)}"
            
            threat_data = {
                "detected": True,
                "title": risk_title,
                "summary": summary_msg,
                "pid": pid,
                "process": name,
                "spoof": spoof_detected,
                "critical": bool(critical_detected),
                "suspicious": bool(suspicious_detected),
                "origin": origin_info,
                "flags": detected_flags,
                "mode": mode
            }
            
            if mode == 'warn':
                logging.warning(f"[WARN MODE] {summary_msg}")
                return None
            
            return threat_data
            
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return None

def check_network_activity(proc, mode=None):
    """
    Monitors a process for suspicious network connections.
    """
    if mode is None:
        try:
            from learning_engine import get_protection_mode
            mode = get_protection_mode()
        except:
            mode = os.getenv('PROTECTION_MODE', 'protect')

    try:
        pid = proc.pid
        name = proc.name()
        connections = proc.connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Whitelist local and private networks
                if any(remote_ip.startswith(prefix) for prefix in patterns.TRUSTED_NETWORKS):
                    continue
                
                # Check for reverse shell ports
                is_rev_shell = remote_port in patterns.REVERSE_SHELL_PORTS and name.lower() in patterns.SHELL_PROCESSES
                
                if is_rev_shell:
                    return {
                        "detected": True,
                        "critical": True,
                        "title": "🚨 REVERSE SHELL DETECTED",
                        "summary": f"Process '{name}' (PID: {pid}) has an established connection to {remote_ip}:{remote_port} (Potential Reverse Shell)",
                        "remote_ip": remote_ip
                    }
                
                # Check for suspicious browser telemetry or exfiltration
                is_browser = any(b in name.lower() for b in ['chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi', 'chromium'])
                if is_browser and mode != 'learn':
                    # This is where we would do domain reputation checks
                    pass
                    
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return None

def run_malware_scan(scan_paths):
    scan_results = []
    if not scan_paths: return []
    try:
        clamscan_check = subprocess.run(['which', 'clamscan'], capture_output=True, text=True, timeout=2)
        if clamscan_check.returncode != 0:
            scan_results.append("⚠️  ClamAV not installed. Run: brew install clamav")
            return scan_results
    except:
        scan_results.append("⚠️  Unable to check for ClamAV")
        return scan_results
    
    for path in scan_paths:
        if not os.path.exists(path): continue
        try:
            result = subprocess.run(['clamscan', '-r', '--bell', '-i', path], capture_output=True, text=True, timeout=300)
            if 'Infected files: 0' in result.stdout:
                scan_results.append(f"  ✓ {path}: Clean")
            else:
                for line in result.stdout.split('\n'):
                    if 'Infected files:' in line:
                        scan_results.append(f"  🚨 {path}: {line.strip()}")
        except subprocess.TimeoutExpired:
            scan_results.append(f"  ⏱️  {path}: Scan timeout")
        except Exception as e:
            scan_results.append(f"  ❌ {path}: Scan failed")
    return scan_results
