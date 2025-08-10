#!/usr/bin/env python3

# Test the XChaCha20-Poly1305 fix  
import base64
import json
from mobile_crypto_core import MobileCryptoCore

print("=== Testing XChaCha20-Poly1305 CLI Compatibility Fix ===")

# Load CLI test file
with open('../../openssl_encrypt/unittests/testfiles/v5/test1_xchacha20-poly1305.txt', 'rb') as f:
    cli_data = f.read()

# Parse CLI file (format: base64_metadata:encrypted_data)  
parts = cli_data.split(b':', 1)
metadata_b64 = parts[0]
encrypted_data_b64 = parts[1]

metadata = json.loads(base64.urlsafe_b64decode(metadata_b64).decode())

print(f"CLI algorithm: {metadata.get('encryption', {}).get('algorithm')}")

# Test decryption with mobile
mobile = MobileCryptoCore()
result = mobile.decrypt_data(encrypted_data_b64.decode(), metadata, '1234')

if result['success']:
    decrypted_text = result['decrypted_data'].decode()
    success = decrypted_text == 'Hello World'
    print(f"✅ Mobile decrypt CLI: {success}")
    print(f"   Expected: 'Hello World'")
    print(f"   Got: '{decrypted_text}'")
else:
    print(f"❌ Mobile decrypt CLI failed: {result['error']}")

# Test mobile roundtrip  
print("\n--- Mobile XChaCha20-Poly1305 roundtrip test ---")
test_data = b'Hello World'
encrypt_result = mobile.encrypt_data(test_data, '1234', 'xchacha20-poly1305')

if encrypt_result['success']:
    mobile_metadata = encrypt_result['metadata']
    mobile_encrypted = encrypt_result['encrypted_data']
    
    print(f"Mobile encryption successful")
    
    decrypt_result = mobile.decrypt_data(mobile_encrypted, mobile_metadata, '1234')
    if decrypt_result['success']:
        success = decrypt_result['decrypted_data'] == test_data
        print(f"✅ Mobile roundtrip: {success}")
    else:
        print(f"❌ Mobile roundtrip failed: {decrypt_result['error']}")
else:
    print(f"❌ Mobile encrypt failed: {encrypt_result['error']}")

print("\n=== Test Complete ===")