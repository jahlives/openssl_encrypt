#!/usr/bin/env python3

# Comprehensive algorithm compatibility test
import base64
import json
import os
from mobile_crypto_core import MobileCryptoCore

print("=== Comprehensive Algorithm Compatibility Test ===")

# Test algorithms that should work
test_algorithms = [
    "fernet", 
    "aes-gcm", 
    "aes-gcm-siv", 
    "aes-ocb3", 
    "aes-siv", 
    "chacha20-poly1305", 
    "xchacha20-poly1305"
]

# Find CLI test files
test_dir = "../../openssl_encrypt/unittests/testfiles/v5/"
test_files = [f for f in os.listdir(test_dir) if f.startswith("test1_") and f.endswith(".txt")]

# Filter to get plain algorithm test files (not hybrid PQC)
plain_algorithm_files = {}
for algo in test_algorithms:
    matching_files = [f for f in test_files if f == f"test1_{algo}.txt"]
    if matching_files:
        plain_algorithm_files[algo] = matching_files[0]

print(f"Found test files for: {list(plain_algorithm_files.keys())}")

mobile = MobileCryptoCore()
results = {}

# Test CLI decryption for each algorithm
print("\n--- CLI Decryption Tests ---")
for algo, filename in plain_algorithm_files.items():
    print(f"Testing {algo}...")
    
    try:
        with open(os.path.join(test_dir, filename), 'rb') as f:
            cli_data = f.read()
        
        parts = cli_data.split(b':', 1)
        if len(parts) != 2:
            results[algo] = {"cli_decrypt": False, "error": "Invalid file format"}
            continue
            
        metadata = json.loads(base64.urlsafe_b64decode(parts[0]).decode())
        encrypted_data_b64 = parts[1].decode()
        
        result = mobile.decrypt_data(encrypted_data_b64, metadata, '1234')
        
        if result['success']:
            decrypted_text = result['decrypted_data'].decode()
            # Handle potential newline differences
            success = decrypted_text.strip() == 'Hello World'
            results[algo] = {"cli_decrypt": success, "decrypted": decrypted_text.strip()}
            status = "✅" if success else "❌"
            print(f"  {status} CLI decrypt: {success}")
        else:
            results[algo] = {"cli_decrypt": False, "error": result['error']}
            print(f"  ❌ CLI decrypt failed: {result['error']}")
            
    except Exception as e:
        results[algo] = {"cli_decrypt": False, "error": str(e)}
        print(f"  ❌ Exception: {e}")

# Test mobile roundtrip for each algorithm  
print("\n--- Mobile Roundtrip Tests ---")
test_data = b'Hello World'

for algo in test_algorithms:
    print(f"Testing {algo} roundtrip...")
    
    try:
        # Encrypt
        encrypt_result = mobile.encrypt_data(test_data, '1234', algo)
        
        if encrypt_result['success']:
            # Decrypt
            decrypt_result = mobile.decrypt_data(
                encrypt_result['encrypted_data'], 
                encrypt_result['metadata'], 
                '1234'
            )
            
            if decrypt_result['success']:
                success = decrypt_result['decrypted_data'] == test_data
                results[algo] = results.get(algo, {})
                results[algo]["mobile_roundtrip"] = success
                status = "✅" if success else "❌"
                print(f"  {status} Mobile roundtrip: {success}")
            else:
                results[algo] = results.get(algo, {})
                results[algo]["mobile_roundtrip"] = False
                results[algo]["roundtrip_error"] = decrypt_result['error']
                print(f"  ❌ Roundtrip decrypt failed: {decrypt_result['error']}")
        else:
            results[algo] = results.get(algo, {})
            results[algo]["mobile_roundtrip"] = False
            results[algo]["roundtrip_error"] = encrypt_result['error']
            print(f"  ❌ Roundtrip encrypt failed: {encrypt_result['error']}")
            
    except Exception as e:
        results[algo] = results.get(algo, {})
        results[algo]["mobile_roundtrip"] = False
        results[algo]["roundtrip_error"] = str(e)
        print(f"  ❌ Exception: {e}")

# Summary
print("\n=== COMPREHENSIVE TEST RESULTS ===")
print("Algorithm               CLI→Mobile    Mobile→Mobile    Status")
print("-" * 65)

fully_working = 0
total_tested = 0

for algo in test_algorithms:
    if algo in results:
        total_tested += 1
        cli_ok = results[algo].get("cli_decrypt", False)
        mobile_ok = results[algo].get("mobile_roundtrip", False)
        
        cli_status = "✅" if cli_ok else "❌"
        mobile_status = "✅" if mobile_ok else "❌"
        
        if cli_ok and mobile_ok:
            overall_status = "PERFECT"
            fully_working += 1
        elif mobile_ok:
            overall_status = "MOBILE ONLY"
        elif cli_ok:
            overall_status = "CLI ONLY"
        else:
            overall_status = "BROKEN"
        
        print(f"{algo:<23} {cli_status:<12} {mobile_status:<13} {overall_status}")
    else:
        print(f"{algo:<23} {'No test':<12} {'No test':<13} UNTESTED")

print("-" * 65)
print(f"SUMMARY: {fully_working}/{total_tested} algorithms fully working ({fully_working/total_tested*100:.1f}%)")

if fully_working == total_tested:
    print("🎉 ALL ALGORITHMS WORKING PERFECTLY! 🎉")
else:
    print(f"📝 {total_tested - fully_working} algorithms still need fixes")

print("\n=== Test Complete ===")