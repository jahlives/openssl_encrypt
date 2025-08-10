#!/usr/bin/env python3
"""
Analyze Post-Quantum Cryptography test files to understand the hybrid structure
"""

import json
import base64
import binascii

def analyze_pqc_test_file(filename, algorithm_name):
    """Analyze a PQC test file structure"""
    print(f"🔍 ANALYZING {algorithm_name.upper()} TEST FILE")
    print("=" * 60)
    
    test_file = f"/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/{filename}"
    
    with open(test_file, 'r') as f:
        content = f.read().strip()
    
    # Parse CLI format
    metadata_b64, encrypted_data_b64 = content.split(':', 1)
    metadata_bytes = base64.b64decode(metadata_b64)
    metadata_json = metadata_bytes.decode()
    metadata = json.loads(metadata_json)
    
    print(f"📄 Basic Information:")
    print(f"   Metadata size: {len(metadata_b64)} chars")
    print(f"   Encrypted data size: {len(encrypted_data_b64)} chars")
    print(f"   Algorithm: {metadata.get('encryption', {}).get('algorithm')}")
    print(f"   Encryption data: {metadata.get('encryption', {}).get('encryption_data', 'N/A')}")
    print()
    
    print(f"🔑 Post-Quantum Key Information:")
    encryption = metadata.get('encryption', {})
    
    if 'pqc_public_key' in encryption:
        pqc_public_key_b64 = encryption['pqc_public_key']
        pqc_public_key = base64.b64decode(pqc_public_key_b64)
        print(f"   PQC Public Key size: {len(pqc_public_key)} bytes")
        print(f"   PQC Public Key (first 32 bytes): {binascii.hexlify(pqc_public_key[:32]).decode()}")
        
    if 'pqc_private_key' in encryption:
        pqc_private_key_b64 = encryption['pqc_private_key']
        pqc_private_key_enc = base64.b64decode(pqc_private_key_b64)
        print(f"   PQC Private Key (encrypted) size: {len(pqc_private_key_enc)} bytes")
        
    if 'pqc_key_salt' in encryption:
        pqc_key_salt = base64.b64decode(encryption['pqc_key_salt'])
        print(f"   PQC Key Salt: {binascii.hexlify(pqc_key_salt).decode()}")
        
    if 'pqc_key_encrypted' in encryption:
        print(f"   PQC Key Encrypted: {encryption['pqc_key_encrypted']}")
        
    print()
    
    print(f"📦 Encrypted Data Analysis:")
    encrypted_data = base64.b64decode(encrypted_data_b64)
    print(f"   Binary size: {len(encrypted_data)} bytes")
    print(f"   First 32 bytes (hex): {binascii.hexlify(encrypted_data[:32]).decode()}")
    print(f"   Last 32 bytes (hex): {binascii.hexlify(encrypted_data[-32:]).decode()}")
    
    # Check if it's test format or real format
    if encrypted_data.startswith(b"TESTDATA"):
        print(f"   ⚠️  TEST FORMAT DETECTED - This is simulation data")
        marker = encrypted_data[:8]
        length_bytes = encrypted_data[8:12]
        data_length = int.from_bytes(length_bytes, byteorder='big')
        actual_data = encrypted_data[12:12+data_length]
        print(f"   Test marker: {marker}")
        print(f"   Data length: {data_length}")
        print(f"   Test data: {actual_data}")
    else:
        print(f"   ✅ REAL ENCRYPTED DATA")
        
    print()
    
    return metadata

def compare_pqc_algorithms():
    """Compare different PQC algorithms"""
    print(f"🔄 COMPARING DIFFERENT PQC ALGORITHMS")
    print("=" * 60)
    
    test_files = [
        ("test1_ml-kem-1024-hybrid-aes-gcm.txt", "ML-KEM-1024"),
        ("test1_mayo-3-hybrid-aes-gcm-siv.txt", "MAYO-3"),
        ("test1_kyber768-aes-gcm-siv.txt", "Kyber768"),
    ]
    
    for filename, algo_name in test_files:
        try:
            analyze_pqc_test_file(filename, algo_name)
            print()
        except FileNotFoundError:
            print(f"❌ File not found: {filename}")
        except Exception as e:
            print(f"❌ Error analyzing {filename}: {e}")

def understand_hybrid_structure():
    """Understand the hybrid encryption structure based on CLI code analysis"""
    print(f"📋 HYBRID ENCRYPTION STRUCTURE (from CLI code analysis)")
    print("=" * 60)
    
    print("🔗 Hybrid Encryption Flow:")
    print("1. Generate/use PQC keypair (public + private key)")
    print("2. Generate random symmetric key (32 bytes for AES-256-GCM)")
    print("3. Encrypt data with symmetric algorithm (AES-GCM, ChaCha20-Poly1305, etc.)")
    print("4. Encrypt symmetric key using PQC public key (KEM encapsulation)")
    print("5. Store both encrypted data and encapsulated key")
    print()
    
    print("📁 Metadata Structure:")
    print("- pqc_public_key: Base64-encoded PQC public key")
    print("- pqc_private_key: Base64-encoded encrypted PQC private key (optional)")
    print("- pqc_key_salt: Salt used for private key encryption")
    print("- pqc_key_encrypted: Boolean indicating if private key is encrypted")
    print("- encryption_data: Symmetric algorithm used (aes-gcm, chacha20-poly1305, etc.)")
    print()
    
    print("💾 Encrypted Data Format:")
    print("- Contains the result of PQC hybrid encryption")
    print("- Format likely: encapsulated_key + symmetric_encrypted_data")
    print("- Encapsulated key: Result of PQC KEM encapsulation")
    print("- Symmetric encrypted data: Result of AES-GCM/ChaCha20 encryption")
    print()

def main():
    """Run all PQC analysis functions"""
    understand_hybrid_structure()
    print()
    compare_pqc_algorithms()

if __name__ == "__main__":
    main()