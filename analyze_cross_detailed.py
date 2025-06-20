#!/usr/bin/env python3
"""
Detailed analysis of CROSS algorithm key sizes using liboqs directly.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openssl_encrypt'))

def analyze_cross_with_liboqs():
    """Test CROSS algorithms directly with liboqs."""
    try:
        import oqs
        
        # Get available signature algorithms
        sig_algorithms = oqs.get_enabled_sig_mechanisms()
        print(f"Total signature algorithms available: {len(sig_algorithms)}")
        
        # Find CROSS algorithms
        cross_algorithms = [alg for alg in sig_algorithms if 'cross' in alg.lower()]
        print(f"\nCROSS algorithms found: {len(cross_algorithms)}")
        for alg in cross_algorithms:
            print(f"  - {alg}")
        
        # Test each CROSS algorithm
        print("\n" + "=" * 70)
        print("CROSS Algorithm Detailed Analysis")
        print("=" * 70)
        
        for alg_name in cross_algorithms:
            print(f"\n--- {alg_name} ---")
            
            try:
                # Create signature instance
                sig = oqs.Signature(alg_name)
                
                # Generate keypair
                public_key = sig.generate_keypair()
                private_key = sig.export_secret_key()
                
                # Get key sizes
                public_size = len(public_key)
                private_size = len(private_key)
                
                print(f"Private Key Size: {private_size} bytes")
                print(f"Public Key Size: {public_size} bytes")
                
                # Test signing to get signature size
                test_message = b"Test message for CROSS signature analysis"
                signature = sig.sign(test_message)
                signature_size = len(signature)
                print(f"Signature Size: {signature_size} bytes")
                
                # AES compatibility check
                print(f"\nAES Compatibility:")
                aes_levels = [("AES-128", 16), ("AES-192", 24), ("AES-256", 32)]
                for aes_name, required_bytes in aes_levels:
                    if private_size >= required_bytes:
                        print(f"  ✓ {aes_name}: Compatible (needs {required_bytes} bytes, has {private_size})")
                    else:
                        print(f"  ✗ {aes_name}: Not compatible (needs {required_bytes} bytes, has {private_size})")
                
                # Show key structure
                print(f"\nPrivate key first 16 bytes: {private_key[:16].hex()}")
                if private_size >= 32:
                    print(f"Private key first 32 bytes: {private_key[:32].hex()}")
                
                # Verify signature
                is_valid = sig.verify(test_message, signature, public_key)
                print(f"Signature verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
                
                # Clean up
                sig.free()
                
            except Exception as e:
                print(f"Error testing {alg_name}: {e}")
        
        print("\n" + "=" * 70)
        print("CROSS Algorithm Summary")
        print("=" * 70)
        
        # Provide summary of CROSS characteristics
        print("CROSS (Codes and Restricted Objects Signature Scheme) characteristics:")
        print("- Code-based post-quantum signature scheme")
        print("- Very small private keys (typically 32-64 bytes)")
        print("- Small public keys (typically 77-153 bytes)")
        print("- Large signatures (typically several KB)")
        print("- Fast signing and verification")
        print("- All variants provide sufficient key material for AES encryption")
        
    except ImportError:
        print("Error: liboqs not available. Install with: pip install liboqs")
    except Exception as e:
        print(f"Error analyzing CROSS algorithms: {e}")

if __name__ == "__main__":
    analyze_cross_with_liboqs()