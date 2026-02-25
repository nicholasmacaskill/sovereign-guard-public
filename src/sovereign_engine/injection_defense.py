"""
Injection Defense Module
-------------------------
Advanced protection against process injection and hijacking attacks.
Implements memory scanning, binary integrity verification, module validation,
and behavioral analysis to detect threats that operate inside legitimate processes.
"""

import os
import re
import subprocess
import hashlib
import psutil
import logging
from datetime import datetime, timedelta
from . import patterns

# State tracking for behavioral analysis
_keychain_access_log = {}  # {pid: [(timestamp, operation), ...]}
_binary_hash_cache = {}    # {path: (hash, timestamp)}
_last_launch_services_state = None

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Failed to hash {file_path}: {e}")
        return None


def verify_binary_integrity():
    """
    Verifies that critical browser binaries haven't been tampered with.
    Returns: list of threats detected
    """
    threats = []
    
    for binary_path in patterns.BROWSER_BINARY_HASHES.keys():
        if not os.path.exists(binary_path):
            continue
            
        try:
            # Calculate current hash
            current_hash = calculate_file_hash(binary_path)
            if not current_hash:
                continue
            
            # Check cache first
            cached = _binary_hash_cache.get(binary_path)
            if cached:
                cached_hash, cached_time = cached
                # Trust cache for 5 minutes
                if datetime.now() - cached_time < timedelta(minutes=5):
                    if cached_hash != current_hash:
                        threats.append({
                            "type": "BINARY_TAMPERING",
                            "severity": "CRITICAL",
                            "title": "🚨 BINARY INTEGRITY VIOLATION",
                            "summary": f"Browser binary has been modified: {os.path.basename(binary_path)}",
                            "path": binary_path,
                            "expected_hash": cached_hash[:16] + "...",
                            "actual_hash": current_hash[:16] + "..."
                        })
                    continue
            
            # First time seeing this binary - establish baseline
            expected_hash = patterns.BROWSER_BINARY_HASHES.get(binary_path)
            
            if expected_hash is None:
                # Auto-populate baseline on first run
                patterns.BROWSER_BINARY_HASHES[binary_path] = current_hash
                _binary_hash_cache[binary_path] = (current_hash, datetime.now())
                logging.info(f"Baseline hash established for {binary_path}: {current_hash[:16]}...")
            elif expected_hash != current_hash:
                threats.append({
                    "type": "BINARY_TAMPERING",
                    "severity": "CRITICAL",
                    "title": "🚨 BINARY INTEGRITY VIOLATION",
                    "summary": f"Browser binary has been modified: {os.path.basename(binary_path)}",
                    "path": binary_path,
                    "expected_hash": expected_hash[:16] + "...",
                    "actual_hash": current_hash[:16] + "..."
                })
            else:
                # Update cache
                _binary_hash_cache[binary_path] = (current_hash, datetime.now())
                
        except Exception as e:
            logging.error(f"Binary integrity check failed for {binary_path}: {e}")
            
    return threats


def scan_process_memory(proc):
    """
    Scans a process's memory for signs of code injection.
    Uses vmmap on macOS to inspect memory regions.
    Returns: threat dict or None
    """
    try:
        pid = proc.pid
        name = proc.name()
        
        # Only scan browser processes (exclude Safari helpers - they have legit exec regions)
        # Browser process prefixes (avoid substring matches like 'edge' in 'spotlightknowledged')
        browser_prefixes = ['google chrome', 'brave browser', 'microsoft edge', 'arc', 'chromium', 'safari']
        is_browser = any(name.lower().startswith(p) for p in browser_prefixes) or name.lower() in ['chrome', 'brave', 'edge']
        
        if not is_browser:
            if any(b in name.lower() for b in ['chrome', 'brave', 'edge', 'arc']):
                 logging.debug(f"DEBUG_SCAN: Process '{name}' (PID: {pid}) blocked by tight prefix filter (would have matched old substring filter)")
            return None
        
        logging.info(f"DEBUG_SCAN: Scanning process '{name}' (PID: {pid}) - passed prefix filter")
        
        # Whitelist for processes that legitimately have unusual memory patterns
        safe_processes = [
            'Safari', 'SearchHelper', 'SafariBookmarksSyncAgent',
            'SafariNotificationAgent', 'SafariLaunchAgent', 'com.apple.Safari'
        ]
        if any(safe in name for safe in safe_processes):
            return None
        
        # Use vmmap to get memory regions (macOS)
        try:
            result = subprocess.run(
                ['vmmap', '-w', str(pid)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return None
                
            # Look for suspicious patterns in memory map
            suspicious_regions = []
            
            for line in result.stdout.splitlines():
                # Format: TYPE START-END [ SIZE] PERMISSIONS PATH
                if 'r-x' not in line and 'rwx' not in line:
                    continue
                    
                # 1. Is this already trusted?
                is_trusted = any(trusted in line for trusted in patterns.TRUSTED_LIBRARY_PATHS)
                if is_trusted:
                    continue
                    
                # 2. Heuristic: Filter legitimate dynamic code regions (JIT/Wasm/etc)
                # Proprietary logic for high-fidelity JIT detection is redacted
                is_dynamic_code = any(token in line for token in ['JS JIT', 'wasm', 'V8', 'MALLOC', 'heap', 'Stack', 'Mapped file'])
                
                # 3. Decision Logic:
                # Detect unusual executable memory regions that don't match standard profiles
                if 'rwx' in line and not is_dynamic_code:
                    suspicious_regions.append(line.strip())
                elif ('Stack' in line or 'heap' in line.lower()) and ('r-p' not in line):
                    if not is_dynamic_code:
                         suspicious_regions.append(line.strip())
            
            if suspicious_regions:
                return {
                    "type": "MEMORY_INJECTION",
                    "severity": "CRITICAL",
                    "title": "🚨 PROCESS INJECTION DETECTED",
                    "summary": f"Process '{name}' (PID: {pid}) has {len(suspicious_regions)} suspicious executable memory regions",
                    "details": suspicious_regions[:3],
                    "pid": pid,
                    "process": name
                }
                
        except subprocess.TimeoutExpired:
            logging.warning(f"vmmap timeout for PID {pid}")
        except FileNotFoundError:
            # vmmap not available, skip silently
            pass
        except Exception as e:
            logging.debug(f"Memory scan error for {name}: {e}")
            
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
        
    return None


def verify_process_modules(proc):
    """
    Verifies all libraries/modules loaded by a process are trusted.
    Detects injection of unsigned or suspicious libraries.
    Returns: threat dict or None
    """
    try:
        pid = proc.pid
        name = proc.name()
        
        # Only check browser processes
        # Browser process prefixes
        browser_prefixes = ['google chrome', 'brave browser', 'microsoft edge', 'arc', 'chromium', 'safari']
        is_browser = any(name.lower().startswith(p) for p in browser_prefixes) or name.lower() in ['chrome', 'brave', 'edge']
        
        if not is_browser:
            return None
        
        # Get loaded libraries
        try:
            # Use lsof to see opened libraries/frameworks
            result = subprocess.run(
                ['lsof', '-p', str(pid)],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode != 0:
                return None
            
            suspicious_libs = []
            
            for line in result.stdout.splitlines():
                # Look for loaded dylibs/frameworks
                if '.dylib' in line or '.framework' in line or '.bundle' in line:
                    # Check if from trusted path
                    is_trusted = any(trusted in line for trusted in patterns.TRUSTED_LIBRARY_PATHS)
                    
                    if not is_trusted:
                        # Extract the library path
                        parts = line.split()
                        if len(parts) >= 9:
                            lib_path = ' '.join(parts[8:])
                            
                            # Additional whitelist checks
                            # Libraries in /tmp, /var/tmp, Downloads are highly suspicious
                            suspicious_paths = ['/tmp/', '/var/tmp/', '/Users/', 'Downloads']
                            if any(susp in lib_path for susp in suspicious_paths):
                                # Only flag if it's actually executable code
                                if '.dylib' in lib_path or '.framework' in lib_path:
                                    suspicious_libs.append(lib_path)
            
            if suspicious_libs:
                return {
                    "type": "MODULE_INJECTION",
                    "severity": "HIGH",
                    "title": "⚠️ SUSPICIOUS MODULE LOADED",
                    "summary": f"Process '{name}' (PID: {pid}) loaded untrusted libraries",
                    "libraries": suspicious_libs[:3],  # Limit output
                    "pid": pid,
                    "process": name
                }
                
        except subprocess.TimeoutExpired:
            logging.warning(f"lsof timeout for PID {pid}")
        except Exception as e:
            logging.debug(f"Module verification error for {name}: {e}")
            
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
        
    return None


def check_launch_services():
    """
    Monitors macOS Launch Services for browser handler hijacking.
    Detects if default browser associations have been tampered with.
    Returns: list of threats
    """
    global _last_launch_services_state
    threats = []
    
    try:
        # Get current default browser for HTTP/HTTPS
        protocols = ['http', 'https']
        current_state = {}
        
        for protocol in protocols:
            try:
                result = subprocess.run(
                    ['defaults', 'read', 'com.apple.LaunchServices/com.apple.launchservices.secure', 'LSHandlers'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.returncode == 0:
                    # Parse the output to find protocol handlers
                    # This is a plist format, simplified parsing
                    for line in result.stdout.splitlines():
                        if protocol in line.lower():
                            current_state[protocol] = line.strip()
                            
            except Exception as e:
                logging.debug(f"Launch Services check error for {protocol}: {e}")
        
        # Check for changes
        if _last_launch_services_state is not None:
            for protocol, handler in current_state.items():
                prev_handler = _last_launch_services_state.get(protocol)
                if prev_handler and prev_handler != handler:
                    threats.append({
                        "type": "LAUNCH_SERVICES_HIJACK",
                        "severity": "HIGH",
                        "title": "🚨 BROWSER HANDLER MODIFIED",
                        "summary": f"Default {protocol.upper()} handler has been changed",
                        "previous": prev_handler[:100],
                        "current": handler[:100]
                    })
        
        # Update state
        _last_launch_services_state = current_state.copy()
        
    except Exception as e:
        logging.error(f"Launch Services check failed: {e}")
        
    return threats


def monitor_keychain_access(procs=None):
    """
    Monitors processes accessing the keychain for unusual patterns.
    Detects excessive or unusual credential access.
    Returns: list of threats
    """
    global _keychain_access_log
    threats = []
    
    try:
        # Watch keychain files AND browser cookie stores
        keychain_paths = [
            'login.keychain',
            'Login.keychain-db',
            'Cookies.binarycookies',
            'Google/Chrome/Default/Cookies',
            'BraveSoftware/Brave-Browser/Default/Cookies',
            'Microsoft Edge/Default/Cookies',
            'Arc/User Data/Default/Cookies',
        ]
        
        current_time = datetime.now()
        
        # Use provided procs or iterate
        process_list = procs if procs is not None else psutil.process_iter(['pid', 'name'])
        
        for proc in process_list:
            try:
                # Handle both Process objects and procs with 'info'
                if isinstance(proc, dict): # if someone passed procs=[p.info for p in procs]
                    pinfo = proc
                    pid = pinfo['pid']
                    name = pinfo['name']
                    # We still need the real Process object to call open_files()
                    p_obj = psutil.Process(pid)
                else:
                    pid = proc.pid
                    name = proc.name()
                    p_obj = proc
                
                # Check open files (this is slow, but we only do it every 30s)
                open_files = p_obj.open_files()
                keychain_access = False
                
                for f in open_files:
                    if any(kc in f.path for kc in keychain_paths):
                        keychain_access = True
                        break
                
                if keychain_access:
                    # Log this access
                    if pid not in _keychain_access_log:
                        _keychain_access_log[pid] = []

                    _keychain_access_log[pid].append((current_time, name))

                    # Analyze patterns - check last minute
                    minute_ago = current_time - timedelta(minutes=1)
                    recent_accesses = [
                        access for access in _keychain_access_log[pid]
                        if access[0] > minute_ago
                    ]

                    # Determine which file was accessed
                    accessed_cookie_file = next(
                        (f.path for f in open_files if any(kc in f.path for kc in keychain_paths)
                         and 'Cookies' in f.path),
                        None
                    )

                    # Tightened whitelist: browsers may only read their OWN cookie file
                    browser_prefixes = ['google chrome', 'brave browser', 'microsoft edge', 'arc', 'chromium', 'safari']
                    is_browser = any(name.lower().startswith(p) for p in browser_prefixes) or name.lower() in ['chrome', 'brave', 'edge']
                    if accessed_cookie_file and is_browser:
                        # Cross-browser cookie access check
                        browser_cookie_owners = {
                            'chrome': 'Google/Chrome',
                            'brave': 'BraveSoftware',
                            'edge': 'Microsoft Edge',
                            'arc': 'Arc',
                            'safari': 'Safari',
                        }
                        owner_path = next(
                            (v for k, v in browser_cookie_owners.items() if k in name.lower()),
                            None
                        )
                        # If the browser is reading a cookie file it doesn't own, flag it
                        if owner_path and owner_path not in accessed_cookie_file:
                            threats.append({
                                "type": "CROSS_BROWSER_COOKIE_ACCESS",
                                "severity": "HIGH",
                                "title": "🔐 CROSS-BROWSER COOKIE THEFT",
                                "summary": f"Process '{name}' (PID: {pid}) is reading another browser's cookie store: {accessed_cookie_file}",
                                "pid": pid,
                                "process": name,
                                "cookie_file": accessed_cookie_file
                            })

                    # Low and Slow Detection: Flag any unauthorized access immediately
                    is_trusted_accessor = is_browser or any(t.lower() in name.lower() for t in patterns.TRUSTED_VAULT_ACCESSORS)
                    
                    if not is_trusted_accessor:
                        threats.append({
                            "type": "UNAUTHORIZED_CREDENTIAL_ACCESS",
                            "severity": "CRITICAL",
                            "title": "🔐 UNAUTHORIZED CREDENTIAL ACCESS",
                            "summary": f"Process '{name}' (PID: {pid}) is accessing a sensitive credential file: {accessed_cookie_file or 'Keychain'}",
                            "pid": pid,
                            "process": name,
                            "target": accessed_cookie_file or "Keychain"
                        })
                            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Cleanup old entries (older than 5 minutes)
        five_min_ago = current_time - timedelta(minutes=5)
        for pid in list(_keychain_access_log.keys()):
            _keychain_access_log[pid] = [
                access for access in _keychain_access_log[pid]
                if access[0] > five_min_ago
            ]
            if not _keychain_access_log[pid]:
                del _keychain_access_log[pid]
                
    except Exception as e:
        logging.error(f"Keychain monitoring failed: {e}")
        
    return threats


def reset_baselines():
    """Reset all baselines (useful for testing or after system updates)."""
    global _binary_hash_cache, _last_launch_services_state, _keychain_access_log
    _binary_hash_cache.clear()
    _last_launch_services_state = None
    _keychain_access_log.clear()
    
    # Reset hash baselines
    for key in patterns.BROWSER_BINARY_HASHES.keys():
        patterns.BROWSER_BINARY_HASHES[key] = None
    
    logging.info("Injection defense baselines reset")
