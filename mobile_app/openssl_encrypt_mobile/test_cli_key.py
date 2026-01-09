#!/usr/bin/env python3

# Test key derivation comparison  
import base64
import json
from mobile_crypto_core import MobileCryptoCore

# Load CLI test file
with open('../../openssl_encrypt/unittests/testfiles/v5/test1_xchacha20-poly1305.txt', 'rb') as f:
    cli_data = f.read()

parts = cli_data.split(b':', 1)
metadata = json.loads(base64.urlsafe_b64decode(parts[0]).decode())

# Extract CLI configuration
derivation_config = metadata['derivation_config']
salt = base64.urlsafe_b64decode(derivation_config['salt'])

print(f'CLI Salt: {salt.hex()}')

# Test key derivation using the same logic as decrypt_data
mobile = MobileCryptoCore()
cli_hash_config = derivation_config.get('hash_config', {})
hash_config = {}
for algo, config in cli_hash_config.items():
    if isinstance(config, dict) and 'rounds' in config:
        hash_config[algo] = config['rounds']
    else:
        hash_config[algo] = config if isinstance(config, int) else 0

for algo in mobile.default_hash_config:
    if algo not in hash_config:
        hash_config[algo] = 0

cli_kdf_config = derivation_config.get('kdf_config', {})
kdf_config = mobile.default_kdf_config.copy()

for kdf in kdf_config:
    kdf_config[kdf]['enabled'] = False

for kdf_name, kdf_params in cli_kdf_config.items():
    if kdf_name in kdf_config:
        if 'enabled' in kdf_params:
            enabled = kdf_params['enabled']
        else:
            enabled = True
        
        kdf_config[kdf_name]['enabled'] = enabled
        
        for param, value in kdf_params.items():
            if param != 'enabled':
                kdf_config[kdf_name][param] = value

print(f'Hash config: {hash_config}')
print(f'Argon2 enabled: {kdf_config["argon2"]["enabled"]}')
print(f'PBKDF2 rounds: {kdf_config["pbkdf2"]["rounds"]}')

# Derive key with algorithm
key = mobile._derive_key_with_algorithm('1234', salt, hash_config, kdf_config, 'xchacha20-poly1305')
print(f'Mobile Key Length: {len(key)}')
print(f'Mobile Key: {key.hex()}')

# Try decryption with this key
encrypted_data_b64 = parts[1].decode()
encrypted_data = base64.urlsafe_b64decode(encrypted_data_b64)

print(f'Encrypted data length: {len(encrypted_data)}')

# Test XChaCha20Poly1305 decryption manually
from mobile_crypto_core import XChaCha20Poly1305

if len(encrypted_data) >= 40:  # 24 (nonce) + 16 (min ciphertext + tag)
    nonce = encrypted_data[:24]  # 24-byte nonce
    ciphertext_and_tag = encrypted_data[24:]  # ciphertext + tag
    
    print(f'Nonce: {nonce.hex()}')
    print(f'Ciphertext+tag length: {len(ciphertext_and_tag)}')
    
    try:
        cipher = XChaCha20Poly1305(key)
        decrypted_data = cipher.decrypt(nonce, ciphertext_and_tag, None)
        print(f'✅ Decryption success: {decrypted_data}')
    except Exception as e:
        print(f'❌ Decryption failed: {e}')
else:
    print('❌ Encrypted data too short')