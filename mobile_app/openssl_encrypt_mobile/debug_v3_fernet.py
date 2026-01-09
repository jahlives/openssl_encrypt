#!/usr/bin/env python3

# Debug v3 Fernet key derivation
from mobile_crypto_core import MobileCryptoCore
import base64
import json

# Test v3 key derivation manually
with open('../../openssl_encrypt/unittests/testfiles/v3/test1_fernet.txt', 'rb') as f:
    data = f.read()

parts = data.split(b':', 1)
metadata = json.loads(base64.urlsafe_b64decode(parts[0]).decode())

mobile = MobileCryptoCore()
salt = base64.b64decode(metadata['salt'].encode())

# Simulate v3 KDF config extraction
v3_hash_config = metadata.get('hash_config', {})
hash_config = {}

for algo in ['sha512', 'sha256', 'sha3_256', 'sha3_512', 'blake2b', 'shake256', 'whirlpool']:
    hash_config[algo] = v3_hash_config.get(algo, 0)

hash_config = mobile.clean_hash_config(hash_config)
print('Final hash config:', hash_config)

kdf_config = mobile.default_kdf_config.copy()
for kdf in kdf_config:
    kdf_config[kdf]['enabled'] = False

# Enable Argon2 from v3
if 'argon2' in v3_hash_config and isinstance(v3_hash_config['argon2'], dict):
    argon2_params = v3_hash_config['argon2']
    if argon2_params.get('enabled', False):
        kdf_config['argon2']['enabled'] = True
        for param, value in argon2_params.items():
            if param != 'enabled':
                kdf_config['argon2'][param] = value

# Check PBKDF2
pbkdf2_iterations = metadata.get('pbkdf2_iterations', 0)
if pbkdf2_iterations > 0:
    kdf_config['pbkdf2']['enabled'] = True
    kdf_config['pbkdf2']['rounds'] = pbkdf2_iterations

print('Enabled KDFs:', [k for k, v in kdf_config.items() if v.get('enabled', False)])
print('Argon2 config:', kdf_config['argon2'])
print('PBKDF2 config:', kdf_config['pbkdf2'])

# Test key derivation
try:
    key = mobile._derive_key('1234', salt, hash_config, kdf_config)
    print(f'Key derived successfully: {len(key)} bytes')
    print(f'Key (hex): {key.hex()[:50]}...')
    
    # Test Fernet with this key
    from cryptography.fernet import Fernet
    encrypted_data = base64.b64decode(parts[1])
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data)
    print(f'Fernet decryption success: {decrypted}')
    
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()