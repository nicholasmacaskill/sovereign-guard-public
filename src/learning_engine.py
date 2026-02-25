"""
Learning Engine for Sovereign Guard
Analyzes observed processes during LEARN mode and builds personalized whitelist
"""

import os
import json
from datetime import datetime, timedelta
from collections import Counter
import path_utils

LEARNING_LOG = path_utils.get_config_file('.learning_log.json')
LEARNING_SUMMARY = path_utils.get_config_file('.learning_summary.json')
NETWORK_LOG = path_utils.get_config_file('.network_learning_log.json')
BOOTSTRAP_MARKER = path_utils.get_config_file('.bootstrap_done')

# Global state to prevent redundant migration checks
_migration_checked = False
NETWORK_CACHE = {}

def log_process(name, exe_path, cmdline):
    """Log a process observation during LEARN mode using NDJSON for performance"""
    global _migration_checked
    try:
        # Check if we need to migrate from old JSON format (skip if already checked this session)
        if not _migration_checked and os.path.exists(LEARNING_LOG) and os.path.getsize(LEARNING_LOG) > 0:
            try:
                with open(LEARNING_LOG, 'r') as f:
                    first_char = f.read(1)
                
                if first_char == '{':
                    # Load old data to preserve start_date if possible
                    backup_path = LEARNING_LOG + '.old'
                    if os.path.exists(LEARNING_LOG):
                        os.rename(LEARNING_LOG, backup_path)
            except Exception as e:
                print(f"Migration check error (non-fatal): {e}")
            
            _migration_checked = True

        # Add observation
        obs = {
            "timestamp": datetime.now().isoformat(),
            "name": name,
            "exe_path": exe_path,
            "cmdline": cmdline
        }
        
        # Append as a single line (NDJSON)
        with open(LEARNING_LOG, 'a') as f:
            f.write(json.dumps(obs) + '\n')
            
    except Exception as e:
        print(f"Error logging process: {e}")

def rotate_logs():
    """Keep logs under a certain size (approx 10,000 entries)"""
    for log_path in [LEARNING_LOG, NETWORK_LOG]:
        if not os.path.exists(log_path):
            continue
            
        try:
            size_mb = os.path.getsize(log_path) / (1024 * 1024)
            if size_mb > 5:
                with open(log_path, 'r') as f:
                    lines = f.readlines()
                
                if len(lines) > 10000:
                    # Keep last 5000 entries
                    new_lines = lines[-5000:]
                    with open(log_path, 'w') as f:
                        f.writelines(new_lines)
                    print(f"✅ Log rotated: {os.path.basename(log_path)} ({size_mb:.1f}MB -> <1MB)")
        except Exception as e:
            print(f"❌ Error rotating {log_path}: {e}")

def log_network_connection(proc_name, remote_ip, remote_port, domain=None):
    """Log a network connection observation during LEARN mode using NDJSON for performance"""
    global NETWORK_CACHE
    
    # 1. Deduplication Cache Check
    cache_key = f"{proc_name}:{remote_ip}:{remote_port}:{domain}"
    now = datetime.now()
    if cache_key in NETWORK_CACHE:
        last_seen = NETWORK_CACHE[cache_key]
        if (now - last_seen).total_seconds() < 60:
            return  # Don't log if seen in the last 60 seconds
    
    NETWORK_CACHE[cache_key] = now
    
    try:
        # Migration: If the file is in the old JSON format, move it to backup and start fresh
        if os.path.exists(NETWORK_LOG) and os.path.getsize(NETWORK_LOG) > 0:
            with open(NETWORK_LOG, 'r') as f:
                first_char = f.read(1)
            if first_char == '{':
                backup_path = NETWORK_LOG + '.old'
                os.rename(NETWORK_LOG, backup_path)
        
        # New observation
        obs = {
            "timestamp": now.isoformat(),
            "process": proc_name,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "domain": domain
        }
        
        # Append as a single line (NDJSON)
        with open(NETWORK_LOG, 'a') as f:
            f.write(json.dumps(obs) + '\n')
            
    except Exception as e:
        print(f"Error logging network connection: {e}")

def analyze_learnings():
    """
    Analyze learning log (NDJSON) and generate whitelist recommendations
    Returns: dict with top processes and auto-whitelist suggestions
    """
    if not os.path.exists(LEARNING_LOG):
        return {
            "status": "no_data",
            "days_elapsed": 0,
            "total_observations": 0,
            "top_processes": [],
            "auto_whitelist": []
        }
    
    try:
        process_counter = Counter()
        total_observations = 0
        first_timestamp = None
        
        with open(LEARNING_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obs = json.loads(line)
                    if not isinstance(obs, dict):
                        continue
                    total_observations += 1
                    process_counter[obs.get("name", "unknown")] += 1
                    if not first_timestamp:
                        first_timestamp = obs.get("timestamp")
                except json.JSONDecodeError:
                    continue
        
        if first_timestamp:
            start_date = datetime.fromisoformat(first_timestamp)
        else:
            start_date = datetime.now()
            
        days_elapsed = (datetime.now() - start_date).days
        
        # Get top processes
        top_processes = [
            {"name": name, "count": count}
            for name, count in process_counter.most_common(20)
        ]
        
        # Auto-whitelist: processes run > 10 times
        auto_whitelist = [
            name for name, count in process_counter.items()
            if count > 10
        ]
        
        summary = {
            "status": "learning",
            "days_elapsed": days_elapsed,
            "total_observations": total_observations,
            "unique_processes": len(process_counter),
            "top_processes": top_processes,
            "auto_whitelist": auto_whitelist
        }
        
        # Save summary
        with open(LEARNING_SUMMARY, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary
        
    except Exception as e:
        print(f"Error analyzing learnings: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

def analyze_network_learnings():
    """
    Analyze network connection log (NDJSON format) and generate recommendations
    """
    if not os.path.exists(NETWORK_LOG):
        return {
            "status": "no_data",
            "total_connections": 0,
            "top_domains": [],
            "auto_trust_domains": []
        }
    
    try:
        domain_counter = Counter()
        total_count = 0
        
        with open(NETWORK_LOG, 'r') as f:
            for line in f:
                try:
                    conn = json.loads(line)
                    total_count += 1
                    if conn.get("domain"):
                        domain_counter[conn["domain"]] += 1
                except json.JSONDecodeError:
                    continue  # Skip corrupted lines
        
        # Get top domains
        top_domains = [
            {"domain": domain, "count": count}
            for domain, count in domain_counter.most_common(20)
        ]
        
        # Auto-trust: domains contacted > 5 times
        auto_trust_domains = [
            domain for domain, count in domain_counter.items()
            if count > 5
        ]
        
        return {
            "status": "learning",
            "total_connections": total_count,
            "unique_domains": len(domain_counter),
            "top_domains": top_domains,
            "auto_trust_domains": auto_trust_domains
        }
    except Exception as e:
        print(f"Error analyzing network learnings: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

_protection_mode_cache = None
_last_protection_mode_check = 0
PROTECTION_MODE_CACHE_TTL = 30 # seconds

def get_protection_mode():
    """
    Determine current protection mode based on elapsed time (NDJSON format)
    Returns: 'learn' | 'warn' | 'protect'
    """
    global _protection_mode_cache, _last_protection_mode_check
    import time
    
    if _protection_mode_cache and (time.time() - _last_protection_mode_check < PROTECTION_MODE_CACHE_TTL):
        return _protection_mode_cache
        
    # 1. Check .env file directly first (Manual Override)
    res = 'learn'
    env_path = path_utils.get_config_file('.env.sovereign')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    if line.startswith('PROTECTION_MODE='):
                        val = line.split('=', 1)[1].strip().lower()
                        if val in ['warn', 'protect', 'learn']:
                            res = val
                            break
        except: pass
    
    if res != 'learn':
        _protection_mode_cache = res
        _last_protection_mode_check = time.time()
        return res
        
    # 2. Fallback to process environment
    env_mode = os.getenv('PROTECTION_MODE', 'learn')
    if env_mode in ['warn', 'protect']:
        _protection_mode_cache = env_mode
        _last_protection_mode_check = time.time()
        return env_mode
    
    # Auto-transition based on time or bootstrap
    if not os.path.exists(LEARNING_LOG):
        return 'learn'
    
    try:
        # Check for bootstrap acceleration
        accelerated = os.path.exists(BOOTSTRAP_MARKER)
        
        # Get the first line to find start_date
        with open(LEARNING_LOG, 'r') as f:
            first_line = f.readline()
            if not first_line:
                return 'learn'
            
            first_obs = json.loads(first_line)
            start_date_str = first_obs.get("timestamp")
            
        if not start_date_str:
            return 'learn'

        start_date = datetime.fromisoformat(start_date_str)
        days_elapsed = (datetime.now() - start_date).days
        
        # If bootstrapped, skip the 7-day learn phase and go straight to WARN
        if accelerated:
            if days_elapsed < 3: # Keep in WARN for at least 3 days even with bootstrap
                return 'warn'
            else:
                return 'protect'

        if days_elapsed < 7:
            return 'learn'
        elif days_elapsed < 14:
            return 'warn'
        else:
            return 'protect'
            
    except:
        return 'learn'

def apply_learned_whitelist():
    """
    Apply auto-whitelist to persistent JSON storage.
    Called when transitioning from LEARN to WARN mode.
    """
    summary = analyze_learnings()
    
    if not summary.get('auto_whitelist'):
        return {"success": False, "message": "No processes to whitelist"}
    
    try:
        whitelist_path = path_utils.get_config_file("whitelist.json")
        new_processes = summary['auto_whitelist']
        
        # Load existing if any
        current_whitelist = []
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f:
                try:
                    current_whitelist = json.load(f)
                except: pass
                
        # Merge unique
        updated_whitelist = list(set(current_whitelist + new_processes))
        
        with open(whitelist_path, 'w') as f:
            json.dump(updated_whitelist, f, indent=2)
            
        return {
            "success": True,
            "message": f"Added {len(new_processes)} learned processes to whitelist",
            "processes": new_processes
        }
            
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def calculate_trust_score():
    """
    Calculate a Trust Score (0-100) based on system security posture.
    Higher score = better security.
    """
    score = 100
    factors = {}
    
    # Scoring constants (Generalized in public version)
    WEIGHT_LEVEL_1 = 30
    WEIGHT_LEVEL_2 = 20
    WEIGHT_LEVEL_3 = 10
    MAX_THREAT_PENALTY = 40

    # 1. Learning Phase Completion
    try:
        summary = analyze_learnings()
        days_elapsed = summary.get('days_elapsed', 0)
        
        if days_elapsed < 3:
            deduction = WEIGHT_LEVEL_1
            factors['learning_phase'] = {'status': 'incomplete', 'deduction': deduction, 'days': days_elapsed}
            score -= deduction
        else:
            factors['learning_phase'] = {'status': 'complete', 'deduction': 0, 'days': days_elapsed}
    except:
        factors['learning_phase'] = {'status': 'unknown', 'deduction': WEIGHT_LEVEL_1}
        score -= WEIGHT_LEVEL_1
    
    # 2. Recent Threats
    try:
        event_log = path_utils.get_config_file('guard_monitor.log')
        threat_count = 0
        if os.path.exists(event_log):
            cutoff = datetime.now() - timedelta(days=7)
            with open(event_log, 'r') as f:
                for line in f:
                    if 'THREAT' in line or 'SUSPICIOUS' in line:
                        threat_count += 1
        
        deduction = min(threat_count * 5, MAX_THREAT_PENALTY)
        factors['recent_threats'] = {'count': threat_count, 'deduction': deduction}
        score -= deduction
    except:
        factors['recent_threats'] = {'count': 0, 'deduction': 0}
    
    # 3. OS Hardening
    try:
        lockdown_override = os.getenv('LOCKDOWN_MODE_ENABLED', '').lower()
        if lockdown_override == 'true':
            factors['os_hardening'] = {'status': 'enabled', 'deduction': 0}
        else:
            import sys
            sys.path.append(os.path.join(path_utils.get_project_root(), "tools"))
            import audit_system
            lockdown_enabled = audit_system.check_mac_lockdown_mode()
            if not lockdown_enabled:
                factors['os_hardening'] = {'status': 'disabled', 'deduction': WEIGHT_LEVEL_2}
                score -= WEIGHT_LEVEL_2
            else:
                factors['os_hardening'] = {'status': 'enabled', 'deduction': 0}
    except Exception as e:
        factors['os_hardening'] = {'status': 'unknown', 'deduction': 0, 'error': str(e)}
    
    # 4. 2FA Configuration
    try:
        env_file = path_utils.get_config_file('.env.sovereign')
        rubicon_enforced = False
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    if line.startswith('RUBICON_ENFORCED='):
                        val = line.split('=', 1)[1].strip().lower()
                        rubicon_enforced = (val == 'true')
                        break
        
        if not rubicon_enforced:
            factors['2fa'] = {'status': 'disabled', 'deduction': WEIGHT_LEVEL_3}
            score -= WEIGHT_LEVEL_3
        else:
            factors['2fa'] = {'status': 'enabled', 'deduction': 0}
    except:
        factors['2fa'] = {'status': 'unknown', 'deduction': WEIGHT_LEVEL_3}
        score -= WEIGHT_LEVEL_3
    
    # Determine grade
    if score >= 90:
        grade = 'Excellent'
        color = 'green'
    elif score >= 70:
        grade = 'Good'
        color = 'yellow'
    elif score >= 50:
        grade = 'Fair'
        color = 'orange'
    else:
        grade = 'At Risk'
        color = 'red'
    
    return {
        'score': max(0, score),
        'grade': grade,
        'color': color,
        'factors': factors
    }

