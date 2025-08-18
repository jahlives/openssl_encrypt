import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    print('🔧 Initializing crypto system for tests...');
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
    print('✅ Crypto system initialized');
  });

  test('Manipulated CLI Data Test (Fixed Metadata Format)', () async {
    print('\n=== TESTING: Manipulated CLI Data with Mobile-Compatible Metadata ===');

    // This is CLI-generated data with manipulated metadata to match mobile format
    // Key changes made:
    // 1. Added "enabled": true to pbkdf2
    // 2. Removed extra hash algorithms (sha384, sha224, sha3_384, sha3_224, shake128)
    // 3. Fixed scrypt n value to 16384
    // 4. Fixed balloon parameters to match mobile format
    // 5. Fixed hkdf info string
    const manipulatedData = 'eyJmb3JtYXRfdmVyc2lvbiI6NSwiZGVyaXZhdGlvbl9jb25maWciOnsic2FsdCI6InV1L2ZyREpObEVKS1VFdFc0Uys1Rnc9PSIsImhhc2hfY29uZmlnIjp7InNoYTUxMiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhMjU2Ijp7InJvdW5kcyI6MTAwMDB9LCJzaGEzXzI1NiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhM181MTIiOnsicm91bmRzIjoxMDAwMH0sImJsYWtlMmIiOnsicm91bmRzIjoxMDAwMH0sImJsYWtlMyI6eyJyb3VuZHMiOjB9LCJzaGFrZTI1NiI6eyJyb3VuZHMiOjB9LCJ3aGlybHBvb2wiOnsicm91bmRzIjoxMDAwMH19LCJrZGZfY29uZmlnIjp7InBia2RmMiI6eyJlbmFibGVkIjp0cnVlLCJyb3VuZHMiOjEwMDAwMH0sInNjcnlwdCI6eyJlbmFibGVkIjpmYWxzZSwibiI6MTYzODQsInIiOjgsInAiOjEsInJvdW5kcyI6MX0sImFyZ29uMiI6eyJlbmFibGVkIjpmYWxzZSwidGltZV9jb3N0IjozLCJtZW1vcnlfY29zdCI6NjU1MzYsInBhcmFsbGVsaXNtIjoxLCJoYXNoX2xlbiI6MzIsInR5cGUiOjIsInJvdW5kcyI6MX0sImJhbGxvb24iOnsiZW5hYmxlZCI6ZmFsc2UsInRpbWVfY29zdCI6MSwic3BhY2VfY29zdCI6OCwicGFyYWxsZWxpc20iOjQsInJvdW5kcyI6MX0sImhrZGYiOnsiZW5hYmxlZCI6ZmFsc2UsInJvdW5kcyI6MSwiYWxnb3JpdGhtIjoic2hhMjU2IiwiaW5mbyI6Ik9wZW5TU0xfRW5jcnlwdF9Nb2JpbGUifX19LCJoYXNoZXMiOnsib3JpZ2luYWxfaGFzaCI6ImE1OTFhNmQ0MGJmNDIwNDA0YTAxMTczM2NmYjdiMTkwZDYyYzY1YmYwYmNkYTMyYjU3YjI3N2Q5YWQ5ZjE0NmUiLCJlbmNyeXB0ZWRfaGFzaCI6Ijc4ZTUyZTYyMDYzZDg4ZTg2MDgwYjBkMWEwMWZkOTI2Y2U4MmZhYzBkNzMxOWVjZDRhMzIxZWY0YWYyNTBmMzgifSwiZW5jcnlwdGlvbiI6eyJhbGdvcml0aG0iOiJmZXJuZXQiLCJlbmNyeXB0aW9uX2RhdGEiOiJhZXMtZ2NtIn19:Z0FBQUFBQm9uaEhyY3BQSHZ3ODBjZGpyNGh4cjJhVmJYRFlVaHVhY0p3NE1abnlVSkZCTGlVNXJieHNiZFlNUHZxWnkxWWNDeTdZNTBJZXQ2Ylk4NVZWd05fYUZpRWtCWlE9PQ==';

    const password = '1234';
    const expected = 'Hello World';

    print('Config: CLI-generated Fernet token + Mobile-compatible metadata');
    print('Password: $password');
    print('Expected: $expected');
    print('🧪 EXPERIMENT: Testing if metadata format was the issue');

    try {
      final result = await cryptoFFI.decryptText(manipulatedData, password);

      print('Result: "$result"');

      if (result == expected) {
        print('🎯 BREAKTHROUGH: Metadata format WAS the issue!');
        print('✅ Mobile can decrypt CLI data when metadata format is fixed!');
      } else {
        print('❌ Still failing: Expected "$expected", got "$result"');
        print('🔍 Metadata format was not the only issue - need deeper investigation');
      }

      expect(result, equals(expected));
    } catch (e) {
      print('❌ ERROR: $e');
      print('🔍 Metadata format fix did not resolve the decryption issue');
      rethrow;
    }
  });
}
