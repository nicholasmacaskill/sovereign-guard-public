import re
import os
import json
import logging
import path_utils

# "Offline AI" Knowledge Base (Heuristic Safe List - FALLBACK DEFAULTS)
DEFAULT_SAFE_LIST = [
    'Antigravity', 'Code Helper', 'Google Chrome Helper', 'secd', 'trustedpeershelper',
    'callservicesd', 'AudioComponentRegistrar', 'PowerChime', 'loginwindow', 'distnoted',
    'cfprefsd', 'UserEventAgent', 'sharingd', 'commcenter', 'notification_center'
]

# Mutable Global Safe List
SAFE_LIST_PROCESSES = list(DEFAULT_SAFE_LIST)

# Dynamic Whitelist Loading (Persistent)
_last_whitelist_mtime = 0

def load_dynamic_whitelist():
    """Reloads the whitelist from JSON if the file has changed"""
    global SAFE_LIST_PROCESSES, _last_whitelist_mtime
    try:
        whitelist_path = path_utils.get_config_file("whitelist.json")
        if not os.path.exists(whitelist_path):
            return

        mtime = os.path.getmtime(whitelist_path)
        if mtime <= _last_whitelist_mtime:
            return # No changes
            
        _last_whitelist_mtime = mtime
        
        with open(whitelist_path, 'r') as f:
            dynamic_whitelist = json.load(f)
            if isinstance(dynamic_whitelist, list):
                current_set = set(DEFAULT_SAFE_LIST)
                current_set.update(dynamic_whitelist)
                SAFE_LIST_PROCESSES = list(current_set)
                logging.info(f"Dynamic whitelist reloaded. Total entries: {len(SAFE_LIST_PROCESSES)}")
    except Exception as e:
        logging.error(f"Failed to load dynamic whitelist: {e}")

# Initial Load
load_dynamic_whitelist()

# Expanded Safe Paths (macOS Defaults)
SAFE_BROWSER_PATHS = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Google Chrome.app/Contents/Frameworks',  # Chrome Helper processes
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
    '/Applications/Brave Browser.app/Contents/Frameworks',  # Brave Helper processes
    '/Applications/Arc.app/Contents/MacOS/Arc',
    '/Applications/Arc.app/Contents/Frameworks',  # Arc Helper processes
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Microsoft Edge.app/Contents/Frameworks',  # Edge Helper processes
    '/Applications/Safari.app/Contents/MacOS/Safari',
    '/System/Applications/Safari.app/Contents/MacOS/Safari',
    '/Applications/Opera.app/Contents/MacOS/Opera',
    '/Applications/Opera.app/Contents/Frameworks',  # Opera Helper processes
    '/Applications/Vivaldi.app/Contents/MacOS/Vivaldi',
    '/Applications/Vivaldi.app/Contents/Frameworks'  # Vivaldi Helper processes
]

TRUSTED_NETWORKS = ['REDACTED_INTERNAL_SUBNETS']
TRUSTED_DOMAINS = ['google.com', 'github.com', 'apple.com', 'localhost']

REVERSE_SHELL_PORTS = [4444, 1337, 8888, 9001]
SHELL_PROCESSES = ['bash', 'sh', 'zsh', 'python', 'perl', 'ruby', 'nc', 'ncat']

TARGET_PROCESS_NAMES = [
    'chrome', 'brave', 'edge', 'arc', 'opera', 'vivaldi', 'chromium',
    'telegram', 'whatsapp', 'signal', 'slack', 'discord', 'messages', 'zoom'
]

# Common Dev/Security Flags
CRITICAL_FLAGS = []  # Removed false positives - legitimate dev flags moved to monitoring only
SUSPICIOUS_FLAGS = ['--disable-web-security', '--no-sandbox', '--headless', '--disable-gpu-sandbox', '--remote-debugging-port']

PERSISTENCE_PATHS = [
    os.path.expanduser('~/Library/LaunchAgents'),
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons'
]

VAULT_PATHS = [
    os.path.expanduser('~/.ssh'),
    os.path.expanduser('~/.aws'),
    os.path.expanduser('~/Library/Keychains')
]

TRUSTED_VAULT_ACCESSORS = ['ssh', 'git', 'ssh-agent', 'security', 'Code Helper', 'secd', 'trustedpeershelper', 'loginwindow']

DEBUG_PORT_FLAG = '--remote-debugging-port'
DEBUG_PORTS = [9222, 9229]

TRUSTED_BROWSER_PARENTS = ['launchd', 'Antigravity', 'Code', 'Finder']

BTC_PATTERN = r'REDACTED_CRYPTO_PATTERN'
ETH_PATTERN = r'REDACTED_CRYPTO_PATTERN'
CRYPTO_RE = re.compile(r'REDACTED_CRYPTO_REGEX')

CMD_INJECTION_PATTERN = r'REDACTED_CMD_INJECTION_PATTERN'
MALICIOUS_JS_PATTERN = r'REDACTED_MALICIOUS_JS_PATTERN'
SENSITIVE_KEY_PATTERN = r'REDACTED_SENSITIVE_KEY_PATTERN'
URL_SPOOF_PATTERN = r'REDACTED_URL_SPOOF_PATTERN'
PASTEJACKING_PATTERN = r'REDACTED_PASTEJACKING_PATTERN'
KNOWN_INFOSTEALERS = [
    r'REDACTED_THREAT_INTEL_DOMAIN_1', 
    r'REDACTED_THREAT_INTEL_DOMAIN_2'
]

TRUSTED_BROWSER_ORIGINS = [
    'google.com', 'github.com', 'slack.com', 'microsoft.com', 
    'apple.com', 'amazon.com', 'netflix.com', 'facebook.com',
    'REDACTED_PARTNER_DOMAIN'
]

MALICIOUS_LINKS = [
    r'REDACTED_MALICIOUS_LINK_PATTERN_1',
    r'REDACTED_MALICIOUS_LINK_PATTERN_2',
    r'REDACTED_MALICIOUS_FILE_EXTENSIONS'
]
BROWSER_PERSISTENCE_DIRS = [
    'Service Worker', 'Hosted App Data', 'Local Storage', 'Extensions'
]

BROWSER_EXTENSION_PATHS = [
    os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Extensions'),
    os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions'),
    os.path.expanduser('~/Library/Application Support/Arc/User Data/Default/Extensions'),
    os.path.expanduser('~/Library/Application Support/Microsoft Edge/Default/Extensions')
]

RISKY_EXTENSION_PERMISSIONS = [
    '<all_urls>', 'http://*/*', 'https://*/*', 'tabs', 'debugger', 'webRequest', 'webRequestBlocking', 'storage', 'proxy'
]

SUSPICIOUS_EXTENSION_KEYWORDS = [
    'free vpn', 'unlimited vpn', 'video downloader', 'mega search', 'coupon finder',
    'easy social', 'adblocker+', 'dark mode for all', 'custom cursor', 'tab manager+'
]

BROWSER_STORAGE_SAFE_PATTERNS = [
    r'\.ldb$', r'\.log$', r'\.tmp$', r'^MANIFEST-', r'^CURRENT$', r'^LOCK$', r'^LOG$', r'^LOG\.old$',
    r'^[a-f0-9]{16}_\d+$'  # Chrome ScriptCache files
]

CLIPBOARD_WHITELIST = [r'^https?://', r'^[a-f0-9]{8}-[a-f0-9]{4}-']

THREAT_PATTERNS = {
    "CMD_INJECTION": re.compile(CMD_INJECTION_PATTERN, re.IGNORECASE),
    "MALICIOUS_JS": re.compile(MALICIOUS_JS_PATTERN, re.IGNORECASE),
    "SENSITIVE_EXPOSURE": re.compile(SENSITIVE_KEY_PATTERN),
    "URL_SPOOF": re.compile(URL_SPOOF_PATTERN, re.IGNORECASE),
    "CRYPTO_SWAP": CRYPTO_RE,
    "PASTEJACKING": re.compile(PASTEJACKING_PATTERN, re.IGNORECASE)
}

STRICT_MODE_THREATS = ["CMD_INJECTION", "MALICIOUS_JS", "CRYPTO_SWAP", "PASTEJACKING"]

# ============================================================================
# INJECTION DEFENSE PATTERNS
# ============================================================================

# Binary Integrity - SHA256 hashes (auto-populated on first run)
BROWSER_BINARY_HASHES = {
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome': None,
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser': None,
    '/Applications/Arc.app/Contents/MacOS/Arc': None,
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge': None,
    '/Applications/Safari.app/Contents/MacOS/Safari': None,
    '/System/Applications/Safari.app/Contents/MacOS/Safari': None,
}

# Trusted library paths for module verification (macOS)
TRUSTED_LIBRARY_PATHS = [
    '/System/Library/',
    '/usr/lib/',
    '/Applications/Google Chrome.app/',
    '/Applications/Brave Browser.app/',
    '/Applications/Arc.app/',
    '/Applications/Microsoft Edge.app/',
    '/Applications/Safari.app/',
    '/Library/Apple/',
]

# Suspicious memory patterns indicating injection
INJECTION_MEMORY_PATTERNS = [
    rb'REDACTED_MEMORY_PATTERN_1',
    rb'REDACTED_MEMORY_PATTERN_2',
    rb'REDACTED_MEMORY_PATTERN_3',
    rb'REDACTED_MEMORY_PATTERN_4',
    rb'REDACTED_MEMORY_PATTERN_5',
]

# Keychain access thresholds
MAX_KEYCHAIN_READS_PER_MINUTE = 50  # Normal browser: ~10-20 accesses per minute

# Injection defense configuration (can be overridden via env vars)
MEMORY_SCAN_INTERVAL = int(os.getenv('MEMORY_SCAN_INTERVAL', '60'))           # seconds
INTEGRITY_CHECK_INTERVAL = int(os.getenv('INTEGRITY_CHECK_INTERVAL', '300'))   # seconds
LAUNCH_SERVICES_CHECK_INTERVAL = int(os.getenv('LAUNCH_SERVICES_CHECK_INTERVAL', '120'))  # seconds
KEYCHAIN_MONITOR_INTERVAL = int(os.getenv('KEYCHAIN_MONITOR_INTERVAL', '30'))  # seconds

# Feature flags
ENABLE_MEMORY_SCANNING = os.getenv('ENABLE_MEMORY_SCANNING', 'true').lower() == 'true'
ENABLE_BINARY_VERIFICATION = os.getenv('ENABLE_BINARY_VERIFICATION', 'true').lower() == 'true'
ENABLE_LAUNCH_SERVICES_MONITOR = os.getenv('ENABLE_LAUNCH_SERVICES_MONITOR', 'true').lower() == 'true'
ENABLE_KEYCHAIN_MONITORING = os.getenv('ENABLE_KEYCHAIN_MONITORING', 'true').lower() == 'true'

