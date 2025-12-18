#!/usr/bin/env python3
"""
Trace what CLI actually does when decrypting
"""

import sys

sys.path.insert(0, "../openssl_encrypt")

# Monkey patch to trace function calls
original_multi_hash_password = None
original_functions = {}


def trace_function_calls():
    """Patch CLI functions to trace their calls"""
    try:
        from openssl_encrypt.modules import crypt_core

        # Store original functions
        if hasattr(crypt_core, "multi_hash_password"):
            original_functions["multi_hash_password"] = crypt_core.multi_hash_password

            def traced_multi_hash_password(*args, **kwargs):
                print(f"🔍 CLI multi_hash_password called:")
                print(f"   args: {[type(a).__name__ for a in args]}")
                print(f"   kwargs: {list(kwargs.keys())}")
                result = original_functions["multi_hash_password"](*args, **kwargs)
                print(
                    f"   result type: {type(result).__name__}, length: {len(result) if hasattr(result, '__len__') else 'N/A'}"
                )
                if hasattr(result, "hex"):
                    print(f"   result hex: {result.hex()[:32]}...")
                return result

            crypt_core.multi_hash_password = traced_multi_hash_password

        # Also trace Fernet key creation if possible
        try:
            from cryptography.fernet import Fernet

            original_fernet_init = Fernet.__init__

            def traced_fernet_init(self, key):
                print(f"🔍 Fernet.__init__ called:")
                print(f"   key type: {type(key).__name__}")
                print(f"   key length: {len(key) if hasattr(key, '__len__') else 'N/A'}")
                if hasattr(key, "decode"):
                    print(f"   key (first 32): {key[:32]}...")
                return original_fernet_init(self, key)

            Fernet.__init__ = traced_fernet_init
        except:
            pass

        print("✅ Function tracing enabled")

    except Exception as e:
        print(f"❌ Failed to enable tracing: {e}")


def test_cli_decrypt_with_tracing():
    """Test CLI decrypt with function tracing"""
    print("🔍 Testing CLI Decrypt with Tracing")
    print("=" * 50)

    # Enable tracing first
    trace_function_calls()

    test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
    password = b"1234"

    try:
        from openssl_encrypt.modules.crypt_core import decrypt_file

        print(f"🔑 Decrypting: {test_file}")
        print(f"🔑 Password: {password}")

        result = decrypt_file(test_file, "/tmp/traced_output.txt", password, quiet=True)

        print(f"🎯 CLI Result: {result}")

        if result:
            with open("/tmp/traced_output.txt", "r") as f:
                content = f.read()
            print(f"📄 Decrypted content: '{content}'")

        return result

    except Exception as e:
        print(f"❌ CLI decrypt failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("🎯 CLI Function Tracing")
    print("=" * 50)

    success = test_cli_decrypt_with_tracing()

    if success:
        print(f"\n✅ Traced CLI decrypt successfully")
    else:
        print(f"\n❌ CLI decrypt trace failed")
