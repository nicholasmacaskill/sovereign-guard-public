import os
import path_utils

RUBICON_SALT = b'sovereign_guard_rubicon'

def get_totp_secret():
    """Retrieves the TOTP secret from .env.sovereign"""
    try:
        env_file = path_utils.get_config_file(".env.sovereign")
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    if line.startswith('SOVEREIGN_2FA_SECRET='):
                        return line.split('=', 1)[1].strip()
    except:
        pass
    return None

def verify_totp(token, secret=None, window=1):
    """Verifies a TOTP token using RFC 6238 (HMAC-SHA1)."""
    import hmac
    import hashlib
    import time
    import struct
    import base64
    
    if not secret:
        secret = get_totp_secret()
    if not secret:
        return False
        
    try:
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)
            
        key = base64.b32decode(secret, casefold=True)
        current_time = int(time.time())
        time_step = 30
        
        for i in range(-window, window + 1):
            counter = int((current_time / time_step) + i)
            msg = struct.pack(">Q", counter)
            digest = hmac.new(key, msg, hashlib.sha1).digest()
            offset = digest[-1] & 0x0f
            code_int = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff
            code_str = str(code_int)[-6:].zfill(6)
            
            if code_str == str(token):
                return True
    except:
        pass
    return False

def verify_backup_code(backup_code):
    """Verifies a 6-digit backup code against the hashed list."""
    import hashlib
    try:
        env_file = path_utils.get_config_file(".env.sovereign")
        stored_hashes = []
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    if line.startswith('RUBICON_BACKUP_HASHES='):
                        stored_hashes = line.split('=', 1)[1].strip().split(',')
                        break
        
        if not stored_hashes:
            return False
            
        input_hash = hashlib.pbkdf2_hmac('sha256', backup_code.encode(), RUBICON_SALT, 100000).hex()
        return input_hash in stored_hashes
    except:
        pass
    return False

def verify_hardware_key(required_id=None):
    """Verifies presence of a physical hardware key or soft key file."""
    try:
        volumes = ['/Volumes/' + v for v in os.listdir('/Volumes')]
        for vol in volumes:
            key_path = os.path.join(vol, '.sovereign_key')
            if os.path.exists(key_path):
                return True
    except:
        pass
    return False

def verify_identity(input_code=None):
    """Master Authentication Function."""
    if verify_hardware_key():
        return True
    if not input_code:
        return False
    if verify_totp(input_code):
        return True
    if verify_backup_code(input_code):
        return True
    return False

def generate_backup_codes(count=5):
    """Generates new backup codes and their hashes."""
    import secrets
    import hashlib
    codes = []
    hashes = []
    for _ in range(count):
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        codes.append(code)
        code_hash = hashlib.pbkdf2_hmac('sha256', code.encode(), RUBICON_SALT, 100000).hex()
        hashes.append(code_hash)
    return codes, hashes
