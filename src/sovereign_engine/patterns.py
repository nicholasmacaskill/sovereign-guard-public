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
PASTEJACKING_PATTERN = r'(?:\x1b\[[0-9;]*[a-zA-Z]|curl\s+[^\|]+\|\s*sh|powershell\s+-enc|cmd\.exe\s+/c|base64\s+-d|echo\s+[^\n]+\|\s*base64)'
KNOWN_INFOSTEALERS = [
    r'REDACTED_MALICIOUS_DOMAIN_1', r'REDACTED_MALICIOUS_DOMAIN_2', r'pixel\.facebook\.com', r'google-analytics\.com' # Common trackers often abused/spoofed, plus specific malware domains
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
    'Service Worker', 'Hosted App Data', 'Local Storage'
]

BROWSER_STORAGE_SAFE_PATTERNS = [
    r'\.ldb$', r'\.log$', r'\.tmp$', r'^MANIFEST-', r'^CURRENT$', r'^LOCK$', r'^LOG$', r'^LOG\.old$'
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
