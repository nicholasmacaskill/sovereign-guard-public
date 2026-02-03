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

TRUSTED_NETWORKS = ['127.0.0.1', '::1', '192.168.', '10.', '172.16.']
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

BTC_PATTERN = r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b'
ETH_PATTERN = r'\b0x[a-fA-F0-9]{40}\b'
CRYPTO_RE = re.compile(f"({BTC_PATTERN})|({ETH_PATTERN})")

CMD_INJECTION_PATTERN = r'(?:curl|wget)\s+https?://[^\s]+\s*\|\s*(?:bash|sh|zsh|python)'
MALICIOUS_JS_PATTERN = r'eval\(atob\([\'"][^\'"]+[\'"]\)\)|String\.fromCharCode\(\d+(?:,\s*\d+){5,}\)'
SENSITIVE_KEY_PATTERN = r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----|AKIA[A-Z0-9]{16}|(?:^|[^a-fA-F0-9])[a-f0-9]{64}(?:[^a-fA-F0-9]|$)'
URL_SPOOF_PATTERN = r'https?://[^@\s]+:[^@\s]+@|https?://[^\s]+\.(?:zip|exe|dmg|pkg|scr)(?:\s|$)'
PASTEJACKING_PATTERN = r'(?:\x1b\[[0-9;]*[a-zA-Z]|curl\s+[^\|]+\|\s*sh|powershell\s+-enc|cmd\.exe\s+/c|base64\s+-d|echo\s+[^\n]+\|\s*base64|IEX\s*\(|DownloadString|FromBase64String|mshta\s+|regsvr32\s+|rundll32\s+url\.dll|javascript:)'
KNOWN_INFOSTEALERS = [
    r'ojrq\.net', r'trkn\.us', r'pixel\.facebook\.com', r'google-analytics\.com' # Common trackers often abused/spoofed, plus specific malware domains
]

TRUSTED_BROWSER_ORIGINS = [
    'google.com', 'github.com', 'slack.com', 'microsoft.com', 
    'apple.com', 'amazon.com', 'netflix.com', 'facebook.com',
    'incorpdirect.ca'
]

MALICIOUS_LINKS = [
    r'https?://(?:www\.)?malicious-site\.com',
    r'https?://(?:www\.)?phish-login\.net',
    r'https?://(?:www\.)?account-verify-secure\.xyz',
    r'https?://[^/]+\.scr$',  # Direct downloads of screensavers
    r'https?://[^/]+\.dmg$',  # Direct downloads (warn on these specifically)
    r'https?://[^/]+\.pkg$',
    r'https?://[^/]+\.zip$'
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
    rb'(?:eval|exec)\s*\(',           # Eval in unexpected memory
    rb'CreateRemoteThread',            # Windows injection API
    rb'NtCreateThreadEx',              # Low-level Windows injection
    rb'ptrace',                        # Unix process tracing (can be used for injection)
    rb'dlopen.*\.dylib',              # Dynamic library loading
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

