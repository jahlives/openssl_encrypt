#!/usr/bin/env python3

# Test if the issue is specifically with the v3 KDF configuration not being applied
from mobile_crypto_core import MobileCryptoCore
import base64
import json

# Load v3 fernet test file  
with open('../../openssl_encrypt/unittests/testfiles/v3/test1_fernet.txt', 'rb') as f:
    v3_data = f.read()

parts = v3_data.split(b':', 1)
metadata = json.loads(base64.urlsafe_b64decode(parts[0]).decode())

print('V3 metadata pbkdf2_iterations:', metadata.get('pbkdf2_iterations'))
print('V3 metadata argon2:', metadata.get('hash_config', {}).get('argon2'))

# Test if we get different results with manually configured KDF vs automatic extraction
mobile = MobileCryptoCore()
salt = base64.b64decode(metadata['salt'].encode())

# Test 1: Use what v3 processing currently produces
v3_hash_config = metadata.get('hash_config', {})
hash_config = {}
for algo in ['sha512', 'sha256', 'sha3_256', 'sha3_512', 'blake2b', 'shake256', 'whirlpool']:
    if algo in v3_hash_config:
        hash_config[algo] = v3_hash_config[algo]
    else:
        hash_config[algo] = 0

hash_config = mobile.clean_hash_config(hash_config)

kdf_config = mobile.default_kdf_config.copy()
for kdf in kdf_config:
    kdf_config[kdf]['enabled'] = False

# Enable Argon2 from v3
if 'argon2' in v3_hash_config and isinstance(v3_hash_config['argon2'], dict):
    argon2_params = v3_hash_config['argon2']
    if argon2_params.get('enabled', False):
        kdf_config['argon2']['enabled'] = True
        for param, value in argon2_params.items():
            if param != 'enabled' and param in kdf_config['argon2']:
                kdf_config['argon2'][param] = value

print('Mobile KDF config argon2 enabled:', kdf_config['argon2']['enabled'])
print('Mobile KDF config argon2:', kdf_config['argon2'])

# Test key derivation
key1 = mobile._derive_key('1234', salt, hash_config, kdf_config)
print(f'Mobile key: {key1[:20]}...')

# Test decryption with this key
try:
    from cryptography.fernet import Fernet
    encrypted_data = base64.urlsafe_b64decode(parts[1])
    
    f = Fernet(key1)
    decrypted = f.decrypt(encrypted_data)
    print(f'✅ Decryption successful: {decrypted}')
except Exception as e:
    print(f'❌ Decryption failed: {e}')
    print(f'Key length: {len(key1)}, Key type: {type(key1)}')