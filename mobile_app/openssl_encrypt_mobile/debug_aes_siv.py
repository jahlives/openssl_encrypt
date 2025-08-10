#!/usr/bin/env python3

# Debug AES-SIV CLI compatibility step by step
import base64
import json
from mobile_crypto_core import MobileCryptoCore

# Test CLI test file
with open('../../openssl_encrypt/unittests/testfiles/v5/test1_aes-siv.txt', 'rb') as f:
    cli_data = f.read()

parts = cli_data.split(b':', 1)
metadata = json.loads(base64.urlsafe_b64decode(parts[0]).decode())
encrypted_data_b64 = parts[1].decode()

print(f"Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
print(f"Format version: {metadata.get('format_version')}")

# Parse metadata like decrypt_data does
mobile = MobileCryptoCore()

# CLI format with derivation_config
derivation_config = metadata['derivation_config']
salt = base64.urlsafe_b64decode(derivation_config['salt'])

print(f"Salt: {salt.hex()}")

# Process hash config
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

print(f"Hash config: {hash_config}")

# Process KDF config
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

print(f"KDF config enabled: {[k for k, v in kdf_config.items() if v.get('enabled', False)]}")

# Derive key with algorithm
algorithm = metadata.get('encryption', {}).get('algorithm', 'fernet')
print(f"Using algorithm-specific derivation for: {algorithm}")

key = mobile._derive_key_with_algorithm('1234', salt, hash_config, kdf_config, algorithm)
print(f"Key length: {len(key)}")
print(f"Key: {key.hex()[:50]}...")

# Test decryption manually
encrypted_data = base64.urlsafe_b64decode(encrypted_data_b64)
print(f"Encrypted data length: {len(encrypted_data)}")

if len(encrypted_data) >= 32:  # 16 (nonce) + 16 (min ciphertext + tag)
    stored_nonce = encrypted_data[:16]
    siv_data = encrypted_data[16:]
    
    print(f"Stored nonce: {stored_nonce.hex()}")
    print(f"SIV data length: {len(siv_data)}")
    
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV
        
        siv = AESSIV(key)
        decrypted_data = siv.decrypt(siv_data, None)
        print(f"✅ Manual decrypt success: {decrypted_data}")
        
    except Exception as e:
        print(f"❌ Manual decrypt failed: {e}")
        print(f"   Key length: {len(key)}")
        print(f"   SIV data: {siv_data.hex()}")
        
        # Try with 64 bytes
        if len(key) >= 64:
            try:
                siv64 = AESSIV(key[:64])
                decrypted_data = siv64.decrypt(siv_data, None)
                print(f"✅ 64-byte key decrypt success: {decrypted_data}")
            except Exception as e2:
                print(f"❌ 64-byte key decrypt failed: {e2}")

else:
    print("❌ Encrypted data too short")