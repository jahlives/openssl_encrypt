#!/usr/bin/env python3
"""
Test PyNaCl XChaCha20-Poly1305 with simple round-trip to verify it works
"""

import nacl.secret
import nacl.utils
import binascii

def test_pynacl_basic():
    """Test PyNaCl XChaCha20-Poly1305 with basic round-trip"""
    print("🧪 TESTING PYNACL XCHACHA20-POLY1305 BASIC FUNCTIONALITY")
    print("=" * 60)
    
    # Generate a random 32-byte key
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    print(f"🔑 Generated key: {binascii.hexlify(key).decode()}")
    print(f"   Key length: {len(key)} bytes")
    
    # Create message
    message = b"Hello World"
    print(f"📄 Message: {message}")
    
    # Create SecretBox
    box = nacl.secret.SecretBox(key)
    
    # Encrypt
    encrypted = box.encrypt(message)
    print(f"🔒 Encrypted length: {len(encrypted)} bytes")
    print(f"   Encrypted (hex): {binascii.hexlify(encrypted).decode()}")
    
    # Decrypt
    decrypted = box.decrypt(encrypted)
    print(f"🔓 Decrypted: {decrypted}")
    print(f"   Match: {decrypted == message}")
    
    return decrypted == message

def test_pynacl_with_custom_nonce():
    """Test PyNaCl with custom nonce (like CLI might use)"""
    print("\n🧪 TESTING PYNACL WITH CUSTOM NONCE")
    print("=" * 50)
    
    # Use a fixed key for testing
    key = bytes.fromhex("8b0545616bfd9dde24a958421186de7553cca66ad0c4bc8d94cfbd48520bb2f2")
    print(f"🔑 Key: {binascii.hexlify(key).decode()}")
    
    # Use specific nonce from CLI data
    nonce = bytes.fromhex("d8e9c617fc95b2212079754e4d2e4901682cc178c59a3994")
    print(f"🎲 Nonce: {binascii.hexlify(nonce).decode()}")
    print(f"   Nonce length: {len(nonce)} bytes")
    
    message = b"Hello World"
    print(f"📄 Message: {message}")
    
    box = nacl.secret.SecretBox(key)
    
    # Encrypt with specific nonce
    encrypted = box.encrypt(message, nonce)
    print(f"🔒 Encrypted length: {len(encrypted)} bytes")
    print(f"   Encrypted (hex): {binascii.hexlify(encrypted).decode()}")
    
    # Decrypt
    try:
        decrypted = box.decrypt(encrypted)
        print(f"🔓 Decrypted: {decrypted}")
        print(f"   Match: {decrypted == message}")
        return True
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return False

def test_pynacl_with_cli_data():
    """Test PyNaCl with exact CLI data"""
    print("\n🧪 TESTING PYNACL WITH CLI DATA")
    print("=" * 40)
    
    # Use the derived key from our debug
    key = bytes.fromhex("8b0545616bfd9dde24a958421186de7553cca66ad0c4bc8d94cfbd48520bb2f2")
    print(f"🔑 Key: {binascii.hexlify(key).decode()}")
    
    # Use exact CLI encrypted data
    cli_data = bytes.fromhex("d8e9c617fc95b2212079754e4d2e4901682cc178c59a3994b9f04526d6271767d779804bd16bbb9d1a64815d3fc4899d6055b622")
    print(f"📦 CLI data length: {len(cli_data)} bytes")
    print(f"   CLI data (hex): {binascii.hexlify(cli_data).decode()}")
    
    box = nacl.secret.SecretBox(key)
    
    try:
        decrypted = box.decrypt(cli_data)
        print(f"🔓 Decrypted: {decrypted}")
        print(f"✅ SUCCESS: CLI data decrypted successfully!")
        return True
    except Exception as e:
        print(f"❌ CLI decryption failed: {e}")
        print(f"   Error type: {type(e).__name__}")
        
        # Try breaking down the data to debug
        print("\n🔍 DEBUGGING CLI DATA FORMAT:")
        nonce = cli_data[:24]
        ciphertext_with_tag = cli_data[24:]
        print(f"   Nonce (24 bytes): {binascii.hexlify(nonce).decode()}")
        print(f"   Ciphertext+Tag ({len(ciphertext_with_tag)} bytes): {binascii.hexlify(ciphertext_with_tag).decode()}")
        
        # Try constructing the format that PyNaCl expects
        # PyNaCl expects: nonce + ciphertext + tag
        # CLI provides: nonce + ciphertext + tag
        # So they should be the same format
        
        return False

if __name__ == "__main__":
    success_count = 0
    total_tests = 3
    
    if test_pynacl_basic():
        success_count += 1
    
    if test_pynacl_with_custom_nonce():
        success_count += 1
    
    if test_pynacl_with_cli_data():
        success_count += 1
    
    print(f"\n📊 TEST RESULTS:")
    print(f"✅ Passed: {success_count}/{total_tests}")
    print(f"❌ Failed: {total_tests - success_count}/{total_tests}")
    
    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED")
    else:
        print("💥 SOME TESTS FAILED")