import os
import psutil
import logging
import subprocess
import socket
import threading
from . import patterns
import path_utils

def check_process(proc, mode=None, safe_mode=False, reload_whitelist=True):
    """
    Check if a process is suspicious or malicious
    """
    # Trigger dynamic reload
    if reload_whitelist:
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
        try:
            cmdline = proc.cmdline()
            pid = proc.pid
            name = proc.name()
            exe_path = proc.exe() or ""
            logging.debug(f"[ANALYZER] Checking process: {name} (PID: {pid}) - Path: {exe_path}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return None
        
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
        
        # DISABLED: Spoofing detection was too aggressive and killed legitimate browsers
        spoof_detected = False
        # if is_monitored_app and exe_path:
        #     if not any(exe_path.startswith(safe) for safe in patterns.SAFE_BROWSER_PATHS):
        #         spoof_detected = True

        # Lineage Protection: Detect processes launched by untrusted parents
        lineage_suspicious = False
        try:
            parent = proc.parent()
            parent_name = parent.name() if parent else "Unknown"
            origin_info = f"Launched by: '{parent_name}'"
            
            if is_monitored_app:
                # Proprietary heuristic: Validate the parent relationship
                # Specific trust-chain logic is redacted in the public version
                if parent_name == "Unknown":
                    lineage_suspicious = True
                else:
                    parent_lower = parent_name.lower()
                    # Placeholder for behavioral trust logic
                    is_trusted = any(p.lower() in parent_lower for p in patterns.TRUSTED_BROWSER_PARENTS)
                    if not is_trusted:
                        lineage_suspicious = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            origin_info = "Launched by: [REDACTED]"
            lineage_suspicious = is_monitored_app 
        except Exception:
            origin_info = "Launched by: Internal"
            lineage_suspicious = False 
        
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
                # Proprietary Decision Logic:
                # Redacted: Specific heuristics for filtering legitimate dev activity 
                # from remote debugging exploits.
                is_dev_mode = os.path.exists(path_utils.get_config_file("developer_mode.lock"))
                
                # Internal whitelisting logic redacted
                if is_dev_mode or os.environ.get('SOVEREIGN_TEST_MODE') == '1':
                    continue 
                
                critical_detected.append(f"{patterns.DEBUG_PORT_FLAG} (EXPOSED INTERFACE)")

        
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
            
    except Exception as e:
        logging.error(f"Error in check_process: {e}")
    return None

def check_mitm_vulnerabilities():
    """
    Checks for potential Man-in-the-Middle (MITM) attack vectors.
    1. ARP Spoofing (duplicate MACs for different IPs)
    2. Proxy configuration (checking for unauthorized proxies)
    """
    threats = []
    
    # ARP Scan (Simplified for macOS)
    try:
        output = subprocess.check_output(['arp', '-an'], text=True, stderr=subprocess.DEVNULL)
        mac_map = {}
        for line in output.splitlines():
            # example: ? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
            parts = line.split()
            if len(parts) >= 4 and 'at' in parts:
                ip = parts[1].strip('()')
                mac = parts[parts.index('at') + 1]
                if mac not in ['(incomplete)', 'at']:
                    if mac in mac_map and mac_map[mac] != ip:
                        threats.append({
                            "type": "ARP_SPOOFING",
                            "summary": f"Duplicate MAC detected: {mac} shared by {ip} and {mac_map[mac]}"
                        })
                    mac_map[mac] = ip
    except: pass

    # Proxy Check (macOS)
    try:
        proxy_info = subprocess.check_output(['networksetup', '-getwebproxy', 'Wi-Fi'], text=True, stderr=subprocess.DEVNULL)
        if "Enabled: Yes" in proxy_info:
            threats.append({
                "type": "ACTIVE_PROXY",
                "summary": "HTTP Web Proxy is ENABLED on Wi-Fi"
            })
    except: pass

    return threats

def check_network_activity(proc, mode):
    """
    Monitors a process for suspicious network connections.
    """

    try:
        pid = proc.pid
        name = proc.name()
        logging.debug(f"[ANALYZER] Checking process: {name} (PID: {pid})")
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
                # Browser process prefixes
                browser_prefixes = ['google chrome', 'brave browser', 'microsoft edge', 'arc', 'opera', 'vivaldi', 'chromium', 'safari']
                is_browser = any(name.lower().startswith(p) for p in browser_prefixes) or name.lower() in ['chrome', 'brave', 'edge']
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
