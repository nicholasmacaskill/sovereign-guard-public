import re
import os
import json
import logging
import path_utils

# "Offline AI" Knowledge Base (Heuristic Safe List - FALLBACK DEFAULTS)
DEFAULT_SAFE_LIST = [
    # 1. Developer Tools
    'code', 'vscode', 'pycharm', 'idea', 'node', 'npm', 'git', 'docker', 'python', 'python3',
    'terminal', 'iterm2', 'warp', 'zsh', 'bash', 'sh', 'make', 'gcc', 'clang',
    'surreal', 'postgres', 'redis-server', 'mongod',
    
    # 2. Apple System Architecture (The "Sovereign Layer")
    'launchd', 'kernel_task', 'distnoted', 'cfprefsd', 'xpcproxy', 'tccd',
    'mdworker', 'mds', 'mds_stores', 'spotlight', 'spotlightknowledged',
    'usernotificationsd', 'loginwindow', 'windowserver', 'dock', 'tail',
    'Cursor', 'Proton Mail', 'ProtonVPN', 'Proton Bridge',
    'translationd', 'com.apple.translationd',
    
    # 3. Apple Background Services (Daemons)
    'searchpartyuseragent', 'com.apple.safari.searchhelper', 'safari',
    'cloudpaird', 'rapportd', 'identityservicesd', 'sharingd',
    'homed', 'remindd', 'calendard', 'siriknowledged', 'coreaudiod', 'biometrickitd',
    'locationd', 'geod', 'timed', 'blued', 'airportd', 'wifid',
    'apsd', 'askpermissiond', 'runningboardd', 'contextstored', 'biome',
    'trialarchivingservice', 'knowledge-agent', 'knowledgeconstructiond',
    
    # 4. Third Party Utilities (Common)
    'alfred', 'raycast', 'rectangle', 'oom', 'git-crypt', 'brave',
    '1password', 'dashlane', 'lastpass', 'bitwarden',
    'dropbox', 'google drive', 'backup and sync', 'antigravity', 'antigravity helper',
    
    # 5. Background Helpers & Services (Common False Positives)
    'helper', 'launcher', 'agent', 'service', 'daemon', 'manager',
    'language_server', 'lsp', 'rust-analyzer', 'gopls', 'pyright',
    'google chrome helper', 'brave browser helper', 'microsoft edge helper',
    
    # 6. DevOps & Remote Access
    'ssh', 'sshd', 'sftp', 'rsync', 'scp',
    'docker-compose', 'kubectl', 'helm', 'terraform', 'ansible', 'vagrant'
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

# Expanded Safe Paths
SAFE_BROWSER_PATHS = [
    '/Applications/', '/System/Applications/', '/System/Library/',
    '/usr/bin/', '/usr/local/bin/', '/usr/libexec/',
    '/Library/Apple/', '/Library/Application Support/', '/private/var/'
]

TRUSTED_NETWORKS = ['127.0.0.1', '192.168.', '10.', '172.16.']
TRUSTED_DOMAINS = [
    'github.com', 'githubusercontent.com', 'pypi.org', 'pythonhosted.org',
    'npmjs.com', 'npmjs.org', 'apple.com', 'icloud.com', 'apple-cloudkit.com',
    'googleapis.com', 'gstatic.com', 'cloudflare.com', 'cloudflare-dns.com',
    'docker.io', 'docker.com', 'dockerhub.com', 'amazonaws.com', 'aws.amazon.com',
    'azure.com', 'microsoft.com', 'windows.net', 'digitalocean.com', 'linode.com', 'vultr.com'
]

REVERSE_SHELL_PORTS = [4444, 1337, 31337, 8080, 9001, 5555, 6666, 7777]
SHELL_PROCESSES = ['bash', 'zsh', 'sh', 'python', 'python3', 'ruby', 'perl', 'node', 'nc', 'netcat']

TARGET_PROCESS_NAMES = [
    'chrome.exe', 'Google Chrome', 'Google Chrome Helper',
    'Brave Browser', 'brave.exe', 'Microsoft Edge', 'msedge.exe',
    'Arc', 'Arc Helper', 'Opera', 'opera.exe', 'Vivaldi', 'vivaldi.exe',
    'Chromium', 'chromium'
]

CRITICAL_FLAGS = ['--load-extension', '--remote-debugging-port', '--remote-allow-origins']
SUSPICIOUS_FLAGS = ['--disable-web-security', '--no-sandbox', '--headless']

PERSISTENCE_PATHS = [
    os.path.expanduser('~/Library/LaunchAgents'),
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons'
]

VAULT_PATHS = [
    os.path.expanduser('~/.ssh'),
    os.path.expanduser('~/.aws'),
    os.path.expanduser('~/.kube'),
    '.env'
]

TRUSTED_VAULT_ACCESSORS = [
    'ssh', 'ssh-add', 'ssh-keygen', 'git', 'git-remote-http',
    'code', 'pycharm', 'cursor', 'docker', 'kubectl', 'terraform',
    'python', 'node', 'npm', 'yarn'
]

DEBUG_PORT_FLAG = '--remote-debugging-port'
DEBUG_PORTS = [9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229, 1337]

TRUSTED_BROWSER_PARENTS = [
    'launchd', 'finder', 'dock', 'iterm2', 'terminal', 'code', 'vscode', 'raycast', 'alfred'
]

BTC_PATTERN = r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b'
ETH_PATTERN = r'\b0x[a-fA-F0-9]{40}\b'
CRYPTO_RE = re.compile(f"({BTC_PATTERN})|({ETH_PATTERN})")

CMD_INJECTION_PATTERN = r'(?:curl|wget)\s+https?://[^\s]+\s*\|\s*(?:bash|sh|zsh|python)'
MALICIOUS_JS_PATTERN = r'eval\(atob\([\'"][^\'"]+[\'"]\)\)|String\.fromCharCode\(\d+(?:,\s*\d+){5,}\)'
SENSITIVE_KEY_PATTERN = r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----|AKIA[A-Z0-9]{16}|(?:^|[^a-fA-F0-9])[a-f0-9]{64}(?:[^a-fA-F0-9]|$)'
URL_SPOOF_PATTERN = r'https?://[^@\s]+:[^@\s]+@|https?://[^\s]+\.(?:zip|exe|dmg|pkg|scr)(?:\s|$)'

CLIPBOARD_WHITELIST = [
    r'https?://[^\s]+',
    r'^[a-zA-Z0-9\-\.]+\.(?:com|org|net|app|io|sh|dev|me)$'
]

THREAT_PATTERNS = {
    "CRYPTO_SWAP": CRYPTO_RE,
    "CMD_INJECTION": re.compile(CMD_INJECTION_PATTERN, re.IGNORECASE),
    "MALICIOUS_SCRIPT": re.compile(MALICIOUS_JS_PATTERN, re.IGNORECASE),
    "URL_SPOOF": re.compile(URL_SPOOF_PATTERN, re.IGNORECASE)
}

STRICT_MODE_THREATS = ["CMD_INJECTION", "MALICIOUS_SCRIPT", "URL_SPOOF"]
