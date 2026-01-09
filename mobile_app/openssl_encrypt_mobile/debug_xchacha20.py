#!/usr/bin/env python3
"""
Debug XChaCha20-Poly1305 CLI decryption issue
"""

import json
import base64
import binascii
from mobile_crypto_core import MobileCryptoCore

def analyze_cli_xchacha20_format():
    """Analyze the CLI XChaCha20 file format in detail"""
    print("🔍 DEBUGGING XChaCha20-Poly1305 CLI FORMAT")
    print("=" * 60)
    
    # Read CLI XChaCha20 test file
    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_xchacha20-poly1305.txt"
    password = "1234"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    print(f"📄 Raw file content:")
    print(f"   Length: {len(content)} characters")
    print(f"   Content: {content[:100]}...")
    print()
    
    # Parse CLI format
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata_json = metadata_bytes.decode()
    metadata = json.loads(metadata_json)
    
    print(f"🔧 Metadata analysis:")
    print(f"   Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
    print(f"   Format version: {metadata.get('format_version')}")
    print(f"   Salt: {metadata.get('derivation_config', {}).get('salt')}")
    print(f"   Original hash: {metadata.get('hashes', {}).get('original_hash', '')[:20]}...")
    print()
    
    print(f"📊 Encrypted data analysis:")
    print(f"   Base64 length: {len(encrypted_data_b64)} characters")
    
    # Decode the encrypted data
    try:
        encrypted_data = base64.b64decode(encrypted_data_b64)
        print(f"   Binary length: {len(encrypted_data)} bytes")
        print(f"   Binary data (hex): {binascii.hexlify(encrypted_data).decode()}")
        print()
        
        # For XChaCha20-Poly1305, expect: 24-byte nonce + ciphertext + 16-byte tag
        if len(encrypted_data) >= 40:  # Minimum: 24 + 1 + 16 = 41 bytes
            nonce = encrypted_data[:24]
            ciphertext_with_tag = encrypted_data[24:]
            
            if len(ciphertext_with_tag) >= 16:
                tag = ciphertext_with_tag[-16:]
                ciphertext = ciphertext_with_tag[:-16]
                
                print(f"🔑 Format breakdown:")
                print(f"   Nonce (24 bytes): {binascii.hexlify(nonce).decode()}")
                print(f"   Ciphertext ({len(ciphertext)} bytes): {binascii.hexlify(ciphertext).decode()}")
                print(f"   Auth tag (16 bytes): {binascii.hexlify(tag).decode()}")
                print()
            else:
                print(f"❌ Invalid format: ciphertext+tag too short ({len(ciphertext_with_tag)} bytes)")
        else:
            print(f"❌ Invalid format: total data too short ({len(encrypted_data)} bytes)")
            
    except Exception as e:
        print(f"❌ Failed to decode encrypted data: {e}")
        return None, None, None
    
    return metadata, encrypted_data_b64, password

def test_key_derivation_debug():
    """Test key derivation with debugging"""
    metadata, encrypted_data_b64, password = analyze_cli_xchacha20_format()
    if not metadata:
        return
    
    print(f"🔐 KEY DERIVATION DEBUG")
    print("=" * 40)
    
    crypto = MobileCryptoCore()
    
    # Derive the key
    try:
        # Use the same key derivation logic as XChaCha20 in mobile crypto
        derivation_config = metadata.get('derivation_config', {})
        salt = base64.b64decode(derivation_config.get('salt', ''))
        hash_config = derivation_config.get('hash_config', {})
        kdf_config = derivation_config.get('kdf_config', {})
        
        # Clean hash_config (same as in mobile crypto)
        clean_hash_config = {}
        for algo, config in hash_config.items():
            if isinstance(config, dict) and "rounds" in config:
                clean_hash_config[algo] = config["rounds"]
            else:
                clean_hash_config[algo] = config if isinstance(config, int) else 0
        
        # Use same logic as XChaCha20 decryption
        raw_key = crypto.multi_hash_password(password.encode(), salt, clean_hash_config)
        derived_key = crypto.multi_kdf_derive(raw_key, salt, kdf_config)[:32]  # 32 bytes for XChaCha20
        print(f"✅ Key derivation successful")
        print(f"   Key length: {len(derived_key)} bytes")
        print(f"   Key (hex): {binascii.hexlify(derived_key).decode()}")
        print()
        
        # Now try decryption with debugging
        print(f"🔓 DECRYPTION DEBUG")
        print("=" * 30)
        
        encrypted_data = base64.b64decode(encrypted_data_b64)
        
        # Extract components
        nonce = encrypted_data[:24]
        ciphertext_with_tag = encrypted_data[24:]
        
        print(f"   Nonce: {binascii.hexlify(nonce).decode()}")
        print(f"   Ciphertext+Tag length: {len(ciphertext_with_tag)}")
        print(f"   Full ciphertext+tag: {binascii.hexlify(ciphertext_with_tag).decode()}")
        
        # Try XChaCha20-Poly1305 decryption using PyNaCl
        try:
            from nacl.secret import SecretBox
            from nacl.utils import random
            
            # Create SecretBox with derived key
            box = SecretBox(derived_key)
            
            # For PyNaCl, we need nonce + ciphertext format
            nacl_format = nonce + ciphertext_with_tag
            print(f"   NaCl format length: {len(nacl_format)}")
            print(f"   NaCl format: {binascii.hexlify(nacl_format).decode()}")
            
            # Attempt decryption
            decrypted = box.decrypt(nacl_format)
            print(f"✅ PyNaCl decryption successful!")
            print(f"   Decrypted: '{decrypted.decode()}'")
            
        except Exception as e:
            print(f"❌ PyNaCl decryption failed: {e}")
            print(f"   Error type: {type(e).__name__}")
            
    except Exception as e:
        print(f"❌ Key derivation failed: {e}")

def compare_mobile_vs_cli_encryption():
    """Compare mobile encryption format vs CLI format"""
    print(f"\n🔄 COMPARING MOBILE VS CLI ENCRYPTION")
    print("=" * 50)
    
    crypto = MobileCryptoCore()
    test_data = "Hello World"
    password = "1234"
    
    # Test mobile encryption
    result = crypto.encrypt_data(test_data.encode(), password, "xchacha20-poly1305")
    
    if result.get('success'):
        mobile_encrypted = result['encrypted_data']
        mobile_metadata = result['metadata']
        
        print(f"📱 Mobile encryption:")
        print(f"   Success: True")
        print(f"   Encrypted data length: {len(mobile_encrypted)} chars")
        
        mobile_binary = base64.b64decode(mobile_encrypted)
        print(f"   Binary length: {len(mobile_binary)} bytes")
        print(f"   Binary (hex): {binascii.hexlify(mobile_binary).decode()}")
        
        # Test mobile round-trip
        decrypt_result = crypto.decrypt_data(mobile_encrypted, mobile_metadata, password)
        if decrypt_result.get('success'):
            decrypted = decrypt_result['decrypted_data'].decode()
            print(f"   Round-trip result: '{decrypted}'")
            print(f"   Round-trip success: {decrypted == test_data}")
        else:
            print(f"   Round-trip failed: {decrypt_result.get('error')}")
    else:
        print(f"❌ Mobile encryption failed: {result.get('error')}")

def main():
    """Run all debugging functions"""
    try:
        analyze_cli_xchacha20_format()
        test_key_derivation_debug()
        compare_mobile_vs_cli_encryption()
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()