"""
Sovereign Guard Core Facade
---------------------------
This module provides a backward-compatible interface to the modularized 
sovereign_engine package. All logic has been split into specialized sub-modules 
within the 'sovereign_engine' directory.
"""

from sovereign_engine import (
    # Constants & Patterns
    SAFE_LIST_PROCESSES, DEFAULT_SAFE_LIST, SAFE_BROWSER_PATHS, 
    TRUSTED_NETWORKS, TRUSTED_DOMAINS, REVERSE_SHELL_PORTS, 
    SHELL_PROCESSES, TARGET_PROCESS_NAMES, CRITICAL_FLAGS, 
    SUSPICIOUS_FLAGS, PERSISTENCE_PATHS, VAULT_PATHS, 
    TRUSTED_VAULT_ACCESSORS, DEBUG_PORT_FLAG, DEBUG_PORTS, 
    TRUSTED_BROWSER_PARENTS, THREAT_PATTERNS, STRICT_MODE_THREATS,
    ENABLE_MEMORY_SCANNING, ENABLE_BINARY_VERIFICATION,
    ENABLE_LAUNCH_SERVICES_MONITOR, ENABLE_KEYCHAIN_MONITORING,
    MEMORY_SCAN_INTERVAL, INTEGRITY_CHECK_INTERVAL,
    LAUNCH_SERVICES_CHECK_INTERVAL, KEYCHAIN_MONITOR_INTERVAL,
    
    # Core Functions
    load_dynamic_whitelist, check_process, check_network_activity,
    run_malware_scan, check_persistence, check_browser_persistence, check_vault_access,
    
    # Forensic Functions
    get_attacker_ip, audit_clipboard_hijacker, resolve_domain_with_timeout,
    
    # Trigger Logic
    check_triggers_loop, start_trigger_thread, check_triggers,
    
    # Scanner Functions
    scan_supply_chain, scan_extensions, check_multimedia_access, check_screen_sharing,
    scan_browser_history, check_active_tabs,
    
    # Identity Functions
    verify_totp, verify_identity, verify_hardware_key, generate_backup_codes,
    
    # Injection Defense
    verify_binary_integrity, scan_process_memory, verify_process_modules,
    check_launch_services, monitor_keychain_access,
    
    # Active Defense
    monitor_sensitive_files
)

# Re-expose for explicit compatibility if needed
__all__ = [
    'SAFE_LIST_PROCESSES', 'DEFAULT_SAFE_LIST', 'SAFE_BROWSER_PATHS',
    'TRUSTED_NETWORKS', 'TRUSTED_DOMAINS', 'REVERSE_SHELL_PORTS',
    'SHELL_PROCESSES', 'TARGET_PROCESS_NAMES', 'CRITICAL_FLAGS',
    'SUSPICIOUS_FLAGS', 'PERSISTENCE_PATHS', 'VAULT_PATHS',
    'TRUSTED_VAULT_ACCESSORS', 'DEBUG_PORT_FLAG', 'DEBUG_PORTS',
    'TRUSTED_BROWSER_PARENTS', 'THREAT_PATTERNS', 'STRICT_MODE_THREATS',
    'load_dynamic_whitelist', 'check_process', 'check_network_activity',
    'run_malware_scan', 'check_persistence', 'check_browser_persistence', 'check_vault_access',
    'get_attacker_ip', 'audit_clipboard_hijacker', 'resolve_domain_with_timeout',
    'check_triggers_loop', 'start_trigger_thread', 'check_triggers',
    'scan_supply_chain', 'scan_extensions', 'check_multimedia_access', 'check_screen_sharing',
    'scan_browser_history', 'check_active_tabs',
    'verify_totp', 'verify_identity', 'verify_hardware_key', 'generate_backup_codes',
    'monitor_sensitive_files'
]

