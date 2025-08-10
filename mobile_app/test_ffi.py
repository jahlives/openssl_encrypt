#!/usr/bin/env python3
"""
Test script for the mobile crypto FFI library
"""

import ctypes
import os

def test_ffi_library():
    """Test the FFI library functions"""
    
    # Load the shared library
    lib_path = './libcrypto_ffi.so'
    if not os.path.exists(lib_path):
        print("❌ FFI library not found:", lib_path)
        return False
    
    try:
        lib = ctypes.CDLL(lib_path)
        print("✅ FFI library loaded successfully")
    except Exception as e:
        print("❌ Failed to load FFI library:", e)
        return False
    
    # Define function signatures
    try:
        # int init_crypto_ffi()
        lib.init_crypto_ffi.restype = ctypes.c_int
        
        # char* mobile_crypto_encrypt_text(const char*, const char*)
        lib.mobile_crypto_encrypt_text.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.mobile_crypto_encrypt_text.restype = ctypes.c_char_p
        
        # char* mobile_crypto_decrypt_text(const char*, const char*)
        lib.mobile_crypto_decrypt_text.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.mobile_crypto_decrypt_text.restype = ctypes.c_char_p
        
        # char* mobile_crypto_get_algorithms()
        lib.mobile_crypto_get_algorithms.restype = ctypes.c_char_p
        
        # void free_crypto_string(char*)
        lib.free_crypto_string.argtypes = [ctypes.c_char_p]
        lib.free_crypto_string.restype = None
        
        print("✅ Function signatures defined")
        
    except Exception as e:
        print("❌ Failed to define function signatures:", e)
        return False
    
    # Initialize the crypto module
    try:
        result = lib.init_crypto_ffi()
        if result == 0:
            print("❌ Failed to initialize crypto module")
            return False
        print("✅ Crypto module initialized successfully")
    except Exception as e:
        print("❌ Failed to initialize crypto module:", e)
        return False
    
    # Test get algorithms
    try:
        algorithms_ptr = lib.mobile_crypto_get_algorithms()
        if algorithms_ptr:
            algorithms = algorithms_ptr.decode('utf-8')
            print(f"✅ Supported algorithms: {algorithms}")
            lib.free_crypto_string(algorithms_ptr)
        else:
            print("❌ Failed to get algorithms")
            return False
    except Exception as e:
        print("❌ Failed to get algorithms:", e)
        return False
    
    # Test encryption/decryption
    try:
        test_text = "Hello from OpenSSL Encrypt Mobile FFI!"
        test_password = "test123"
        
        # Encrypt
        encrypted_ptr = lib.mobile_crypto_encrypt_text(
            test_text.encode('utf-8'),
            test_password.encode('utf-8')
        )
        
        if encrypted_ptr:
            encrypted_data = encrypted_ptr.decode('utf-8')
            print(f"✅ Text encrypted: {encrypted_data[:100]}...")
            lib.free_crypto_string(encrypted_ptr)
            
            # Decrypt
            decrypted_ptr = lib.mobile_crypto_decrypt_text(
                encrypted_data.encode('utf-8'),
                test_password.encode('utf-8')
            )
            
            if decrypted_ptr:
                decrypted_text = decrypted_ptr.decode('utf-8')
                print(f"✅ Text decrypted: {decrypted_text}")
                lib.free_crypto_string(decrypted_ptr)
                
                # Verify
                if decrypted_text == test_text:
                    print("✅ Encryption/Decryption test PASSED")
                    return True
                else:
                    print("❌ Encryption/Decryption test FAILED: text mismatch")
                    return False
            else:
                print("❌ Decryption failed")
                return False
        else:
            print("❌ Encryption failed")
            return False
            
    except Exception as e:
        print("❌ Encryption/Decryption test failed:", e)
        return False

if __name__ == "__main__":
    print("Testing OpenSSL Encrypt Mobile FFI Library")
    print("=" * 50)
    
    success = test_ffi_library()
    
    print("=" * 50)
    if success:
        print("🎉 All tests PASSED! FFI library is working correctly.")
    else:
        print("💥 Some tests FAILED. Check the output above.")