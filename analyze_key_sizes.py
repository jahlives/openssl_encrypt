#!/usr/bin/env python3
"""
Analyze Key Sizes for MAYO and CROSS Post-Quantum Signature Algorithms

This script analyzes the actual key sizes for MAYO and CROSS algorithms to determine
if their private keys could be used as encryption secrets for AES-GCM.
"""

import sys
import os

# Add the package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openssl_encrypt'))

def analyze_mayo_key_sizes():
    """Analyze MAYO algorithm key sizes."""
    print("=" * 60)
    print("MAYO (Multivariate Oil-and-Vinegar) Algorithm Key Sizes")
    print("=" * 60)
    
    try:
        from openssl_encrypt.modules.mayo_signature import MAYOSignature
        
        for level in [1, 3, 5]:
            try:
                print(f"\n--- MAYO Security Level {level} ---")
                mayo = MAYOSignature(security_level=level)
                
                # Get theoretical sizes from parameters
                public_key_size = mayo.get_public_key_size()
                private_key_size = mayo.get_private_key_size()
                signature_size = mayo.get_signature_size()
                
                print(f"Algorithm: {mayo.get_algorithm_name()}")
                print(f"Security Level: {mayo.get_security_level()}")
                print(f"Private Key Size: {private_key_size} bytes")
                print(f"Public Key Size: {public_key_size} bytes") 
                print(f"Signature Size: {signature_size} bytes")
                
                # Generate actual keys to verify sizes
                try:
                    public_key, private_key = mayo.generate_keypair()
                    actual_public_size = len(public_key)
                    actual_private_size = len(private_key)
                    
                    print(f"Actual Private Key Size: {actual_private_size} bytes")
                    print(f"Actual Public Key Size: {actual_public_size} bytes")
                    
                    # Check for AES compatibility
                    print(f"\nAES Key Compatibility:")
                    if actual_private_size >= 16:
                        print(f"  ✓ AES-128: Compatible (needs 16 bytes, has {actual_private_size})")
                    else:
                        print(f"  ✗ AES-128: Not compatible (needs 16 bytes, has {actual_private_size})")
                        
                    if actual_private_size >= 24:
                        print(f"  ✓ AES-192: Compatible (needs 24 bytes, has {actual_private_size})")
                    else:
                        print(f"  ✗ AES-192: Not compatible (needs 24 bytes, has {actual_private_size})")
                        
                    if actual_private_size >= 32:
                        print(f"  ✓ AES-256: Compatible (needs 32 bytes, has {actual_private_size})")
                    else:
                        print(f"  ✗ AES-256: Not compatible (needs 32 bytes, has {actual_private_size})")
                    
                    # Show first few bytes of private key for analysis (safely)
                    print(f"Private key structure: {len(private_key)} bytes total")
                    print(f"First 16 bytes (hex): {private_key[:16].hex()}")
                    if len(private_key) >= 32:
                        print(f"First 32 bytes (hex): {private_key[:32].hex()}")
                    
                except Exception as e:
                    print(f"Error generating keys: {e}")
                    
            except Exception as e:
                print(f"Error with MAYO level {level}: {e}")
    except ImportError as e:
        print(f"MAYO implementation not available: {e}")

def analyze_cross_key_sizes():
    """Analyze CROSS algorithm key sizes."""
    print("\n" + "=" * 60)
    print("CROSS (Codes and Restricted Objects) Algorithm Key Sizes")
    print("=" * 60)
    
    # Check if CROSS is available via liboqs
    try:
        from openssl_encrypt.modules.pqc_liboqs import PQSigner, check_liboqs_support
        
        available, version, algorithms = check_liboqs_support(quiet=True)
        
        if not available:
            print("liboqs not available - CROSS algorithms not accessible")
            return
            
        print(f"liboqs version: {version}")
        print(f"Available algorithms: {len(algorithms)}")
        
        # Try different CROSS variants
        cross_algorithms = [
            ("CROSS-128", "cross-rsdp-128-balanced"),
            ("CROSS-192", "cross-rsdp-192-balanced"), 
            ("CROSS-256", "cross-rsdp-256-balanced"),
        ]
        
        for friendly_name, liboqs_name in cross_algorithms:
            print(f"\n--- {friendly_name} ---")
            
            if liboqs_name not in algorithms:
                print(f"Algorithm {liboqs_name} not available in this liboqs build")
                continue
                
            try:
                signer = PQSigner(liboqs_name, quiet=True)
                
                # Generate keys to get actual sizes
                public_key, private_key = signer.generate_keypair()
                
                public_size = len(public_key)
                private_size = len(private_key)
                
                print(f"Algorithm: {friendly_name} ({liboqs_name})")
                print(f"Private Key Size: {private_size} bytes")
                print(f"Public Key Size: {public_size} bytes")
                
                # Test signing to get signature size
                test_message = b"Test message for signature"
                signature = signer.sign(test_message, private_key)
                signature_size = len(signature)
                print(f"Signature Size: {signature_size} bytes")
                
                # Check for AES compatibility
                print(f"\nAES Key Compatibility:")
                if private_size >= 16:
                    print(f"  ✓ AES-128: Compatible (needs 16 bytes, has {private_size})")
                else:
                    print(f"  ✗ AES-128: Not compatible (needs 16 bytes, has {private_size})")
                    
                if private_size >= 24:
                    print(f"  ✓ AES-192: Compatible (needs 24 bytes, has {private_size})")
                else:
                    print(f"  ✗ AES-192: Not compatible (needs 24 bytes, has {private_size})")
                    
                if private_size >= 32:
                    print(f"  ✓ AES-256: Compatible (needs 32 bytes, has {private_size})")
                else:
                    print(f"  ✗ AES-256: Not compatible (needs 32 bytes, has {private_size})")
                    
                # Show first few bytes of private key for analysis (safely)
                print(f"Private key structure: {len(private_key)} bytes total")
                print(f"First 16 bytes (hex): {private_key[:16].hex()}")
                if len(private_key) >= 32:
                    print(f"First 32 bytes (hex): {private_key[:32].hex()}")
                
            except Exception as e:
                print(f"Error testing {friendly_name}: {e}")
    
    except ImportError as e:
        print(f"liboqs integration not available: {e}")

def analyze_aes_requirements():
    """Show AES key requirements for reference."""
    print("\n" + "=" * 60)
    print("AES-GCM Key Requirements (Reference)")
    print("=" * 60)
    
    print("AES-128: Requires 16 bytes (128 bits) key")
    print("AES-192: Requires 24 bytes (192 bits) key") 
    print("AES-256: Requires 32 bytes (256 bits) key")
    print("\nNote: Post-quantum private keys can be used as key material")
    print("by applying a key derivation function (like HKDF or direct hash)")
    print("to derive the exact number of bytes needed for AES.")

def main():
    """Main analysis function."""
    print("Post-Quantum Signature Algorithm Key Size Analysis")
    print("for AES-GCM Encryption Compatibility")
    print()
    
    analyze_mayo_key_sizes()
    analyze_cross_key_sizes()
    analyze_aes_requirements()
    
    print("\n" + "=" * 60)
    print("Summary and Recommendations")
    print("=" * 60)
    print("1. MAYO private keys are small (32-64 bytes) but sufficient for AES")
    print("2. CROSS private keys vary significantly by security level")
    print("3. Both can serve as key material for AES through key derivation")
    print("4. Use SHA-256/SHA-3 to derive exact AES key sizes from PQ keys")
    print("5. This approach maintains post-quantum security properties")

if __name__ == "__main__":
    main()