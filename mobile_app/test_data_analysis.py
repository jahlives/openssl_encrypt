#!/usr/bin/env python3
"""
Analyze CLI encrypted data format
"""

import base64

def analyze_cli_data():
    """Analyze the CLI encrypted data"""
    print("🔍 CLI Data Analysis")
    print("=" * 40)
    
    # Get the encrypted data
    encrypted_data_b64 = "Z0FBQUFBQm9KZHRWcmNyQkpDeUE5dTdScy1rYU9oV01kR3Q0VS12aHQ3dVVkTDdzUEpDSUZYc2tlcWJ5ajNfQk1obXpDS1BYWV85UzVhMWx1cFhxSWlpQkdrbjk3ZlRsekE9PQ=="
    
    print(f"📋 Base64 Analysis:")
    print(f"   Length: {len(encrypted_data_b64)}")
    print(f"   Last 4 chars: {encrypted_data_b64[-4:]}")
    print(f"   Valid padding: {'✅' if encrypted_data_b64.endswith('=') or len(encrypted_data_b64) % 4 == 0 else '❌'}")
    
    # Decode the base64
    try:
        decoded = base64.b64decode(encrypted_data_b64)
        print(f"✅ Base64 decoding successful")
        print(f"   Decoded length: {len(decoded)}")
        print(f"   First 16 bytes: {decoded[:16].hex()}")
        print(f"   Last 16 bytes: {decoded[-16:].hex()}")
        
        # Check if this looks like Fernet data
        print(f"\n📋 Fernet Format Analysis:")
        if len(decoded) >= 73:  # Minimum Fernet token size
            version = decoded[0]
            timestamp = decoded[1:9]
            iv = decoded[9:25]
            ciphertext = decoded[25:-32]
            hmac = decoded[-32:]
            
            print(f"   Version byte: 0x{version:02x} ({'✅ Valid (0x80)' if version == 0x80 else '❌ Invalid'})")
            print(f"   Timestamp: {timestamp.hex()}")
            print(f"   IV length: {len(iv)}")
            print(f"   Ciphertext length: {len(ciphertext)}")
            print(f"   HMAC length: {len(hmac)}")
            
            if version == 0x80:
                print("   ✅ This looks like valid Fernet format!")
            else:
                print("   ❌ This doesn't look like Fernet format")
        else:
            print(f"   ❌ Too short for Fernet (need ≥73 bytes, got {len(decoded)})")
            
            # Maybe it's double-encoded?
            print(f"\n🔄 Checking for double encoding...")
            try:
                double_decoded = base64.b64decode(decoded)
                print(f"   Double decode successful: {len(double_decoded)} bytes")
                print(f"   First 16 bytes: {double_decoded[:16].hex()}")
                
                if len(double_decoded) >= 73 and double_decoded[0] == 0x80:
                    print("   ✅ Double-encoded Fernet data found!")
                    return double_decoded
            except:
                print("   ❌ Not double-encoded")
        
        return decoded
            
    except Exception as e:
        print(f"❌ Base64 decoding failed: {e}")
        return None

def test_cli_decrypt():
    """Test decrypting the CLI data with mobile"""
    print(f"\n🧪 CLI Decryption Test")
    print("=" * 40)
    
    from mobile_crypto_core import MobileCryptoCore
    
    # CLI file parameters
    password = "1234"
    
    core = MobileCryptoCore()
    
    try:
        result = core.decrypt_file("cli_test_file.txt", password, "test_output.txt")
        
        if result["success"]:
            print(f"🎉 SUCCESS: Mobile decrypted CLI file!")
            
            with open("test_output.txt", 'r') as f:
                content = f.read()
            print(f"   Content: {content}")
            
            return True
        else:
            error = result.get("error", "Unknown")
            print(f"❌ Mobile decrypt failed: {error}")
            
            # If it's a Fernet error, that means our key derivation is wrong
            if "Fernet" in error:
                print(f"   → Key derivation mismatch (Fernet can't decrypt)")
            elif "base64" in error:
                print(f"   → Data format issue") 
            else:
                print(f"   → Unknown issue")
                
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    print("🎯 CLI Data Analysis Suite")
    print("=" * 50)
    
    cli_data = analyze_cli_data()
    success = test_cli_decrypt()
    
    if success:
        print(f"\n🎉 SUCCESS: CLI data analysis complete!")
    else:
        print(f"\n🔍 ANALYSIS: CLI data format understanding needed")