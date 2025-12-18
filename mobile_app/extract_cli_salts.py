#!/usr/bin/env python3
"""
Extract the actual PBKDF2 salts used by CLI
"""

import base64
import json
import sys

sys.path.insert(0, "../openssl_encrypt")


def extract_pbkdf2_salts():
    """Patch CLI to capture actual PBKDF2 salts"""
    print("🔍 Extracting CLI PBKDF2 Salts")
    print("=" * 50)

    try:
        from cryptography.fernet import Fernet

        from openssl_encrypt.modules import crypt_core

        # Storage for captured salts
        pbkdf2_data = {"salts": [], "inputs": [], "results": []}

        # Patch PBKDF2 to capture salts
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            original_pbkdf2_derive = PBKDF2HMAC.derive

            def capture_pbkdf2_derive(self, key_material):
                # Store the salt and input
                pbkdf2_data["salts"].append(self._salt.hex())
                pbkdf2_data["inputs"].append(key_material.hex())

                result = original_pbkdf2_derive(self, key_material)
                pbkdf2_data["results"].append(result.hex())

                call_num = len(pbkdf2_data["salts"])
                if call_num <= 5 or call_num % 1000 == 0:
                    print(f"   PBKDF2 call {call_num}:")
                    print(f"      Salt: {self._salt.hex()}")
                    print(f"      Input: {key_material.hex()[:32]}...")
                    print(f"      Result: {result.hex()[:32]}...")

                return result

            PBKDF2HMAC.derive = capture_pbkdf2_derive
            print("✅ PBKDF2 salt capture enabled")

        except Exception as e:
            print(f"❌ PBKDF2 patching failed: {e}")
            return None

        # Run CLI decrypt
        from openssl_encrypt.modules.crypt_core import decrypt_file

        test_file = "/home/work/private/git/openssl_encrypt/openssl_encrypt/unittests/testfiles/v5/test1_fernet.txt"
        result = decrypt_file(test_file, "/tmp/salt_extract.txt", b"1234", quiet=True)

        print(f"\n📋 CLI decrypt result: {result}")

        if len(pbkdf2_data["salts"]) > 0:
            print(f"\n📊 Captured {len(pbkdf2_data['salts'])} PBKDF2 calls")

            # Analyze salt patterns
            base_salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")
            print(f"   Original salt: {base_salt.hex()}")

            # Check first few salts to understand pattern
            print(f"\n🔍 Salt Pattern Analysis:")
            for i in range(min(5, len(pbkdf2_data["salts"]))):
                salt_hex = pbkdf2_data["salts"][i]
                salt_bytes = bytes.fromhex(salt_hex)

                print(f"   Call {i+1} salt: {salt_hex}")
                print(f"      Length: {len(salt_bytes)} bytes")

                # Check if it matches common patterns
                import hashlib

                # Pattern 1: SHA256 of original salt + round number
                pattern1 = hashlib.sha256(base_salt + str(i).encode()).digest()
                if salt_bytes == pattern1:
                    print(f"      ✅ Matches: SHA256(base_salt + '{i}')")
                elif salt_bytes == pattern1[:32]:
                    print(f"      ✅ Matches: SHA256(base_salt + '{i}')[:32]")

                # Pattern 2: SHA256 of original salt + "pbkdf2" + round
                pattern2 = hashlib.sha256(base_salt + b"pbkdf2" + str(i).encode()).digest()
                if salt_bytes == pattern2:
                    print(f"      ✅ Matches: SHA256(base_salt + 'pbkdf2' + '{i}')")

                # Pattern 3: Different round indexing
                pattern3 = hashlib.sha256(base_salt + str(i + 1).encode()).digest()
                if salt_bytes == pattern3:
                    print(f"      ✅ Matches: SHA256(base_salt + '{i+1}')")

            return pbkdf2_data
        else:
            print(f"❌ No PBKDF2 calls captured")
            return None

    except Exception as e:
        print(f"❌ Salt extraction failed: {e}")
        import traceback

        traceback.print_exc()
        return None


def analyze_salt_generation(pbkdf2_data):
    """Analyze how CLI generates PBKDF2 salts"""
    if not pbkdf2_data or len(pbkdf2_data["salts"]) == 0:
        return None

    print(f"\n🧪 Salt Generation Analysis")
    print("=" * 40)

    base_salt = base64.b64decode("yTZN13xtVpwLzYCPl7TPWQ==")

    # Test different patterns
    patterns = []

    for i in range(min(10, len(pbkdf2_data["salts"]))):
        actual_salt = bytes.fromhex(pbkdf2_data["salts"][i])

        # Test various patterns
        import hashlib

        test_patterns = [
            (
                "base_salt",
                base_salt if len(base_salt) == 32 else base_salt + b"\x00" * (32 - len(base_salt)),
            ),
            ("sha256_base_salt", hashlib.sha256(base_salt).digest()),
            ("sha256_base_salt_i", hashlib.sha256(base_salt + str(i).encode()).digest()),
            ("sha256_base_salt_i1", hashlib.sha256(base_salt + str(i + 1).encode()).digest()),
        ]

        for pattern_name, pattern_salt in test_patterns:
            if actual_salt == pattern_salt:
                patterns.append((i, pattern_name))
                print(f"   Round {i}: matches {pattern_name}")
                break
            elif actual_salt == pattern_salt[: len(actual_salt)]:
                patterns.append((i, f"{pattern_name}[:{len(actual_salt)}]"))
                print(f"   Round {i}: matches {pattern_name}[:{len(actual_salt)}]")
                break
        else:
            print(f"   Round {i}: no pattern match")

    # Find the most common pattern
    if patterns:
        pattern_counts = {}
        for _, pattern in patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        most_common = max(pattern_counts, key=pattern_counts.get)
        print(f"\n✅ Most common pattern: {most_common}")
        return most_common

    return None


if __name__ == "__main__":
    # Extract salts
    salt_data = extract_pbkdf2_salts()

    # Analyze patterns
    if salt_data:
        pattern = analyze_salt_generation(salt_data)
        if pattern:
            print(f"\n🎯 Discovered salt pattern: {pattern}")
        else:
            print(f"\n❌ Could not determine salt pattern")
    else:
        print(f"\n❌ Salt extraction failed")
