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

  test('Moderate Hash Rounds Test (SHA3-512: 100 rounds)', () async {
    print('\n=== TESTING: Moderate Hash Rounds ===');

    // CLI data with SHA3-512(100) + PBKDF2(10k) only
    const cliData = 'eyJmb3JtYXRfdmVyc2lvbiI6IDUsICJkZXJpdmF0aW9uX2NvbmZpZyI6IHsic2FsdCI6ICJKSy9wbjUrcFJEeDJ1L1RMY055OFd3PT0iLCAiaGFzaF9jb25maWciOiB7InNoYTUxMiI6IHsicm91bmRzIjogMH0sICJzaGEzODQiOiB7InJvdW5kcyI6IDB9LCAic2hhMjU2IjogeyJyb3VuZHMiOiAwfSwgInNoYTIyNCI6IHsicm91bmRzIjogMH0sICJzaGEzXzUxMiI6IHsicm91bmRzIjogMTAwfSwgInNoYTNfMzg0IjogeyJyb3VuZHMiOiAwfSwgInNoYTNfMjU2IjogeyJyb3VuZHMiOiAwfSwgInNoYTNfMjI0IjogeyJyb3VuZHMiOiAwfSwgImJsYWtlMmIiOiB7InJvdW5kcyI6IDB9LCAiYmxha2UzIjogeyJyb3VuZHMiOiAwfSwgInNoYWtlMjU2IjogeyJyb3VuZHMiOiAwfSwgInNoYWtlMTI4IjogeyJyb3VuZHMiOiAwfSwgIndoaXJscG9vbCI6IHsicm91bmRzIjogMH19LCAia2RmX2NvbmZpZyI6IHsicGJrZGYyIjogeyJyb3VuZHMiOiAxMDAwMH0sICJzY3J5cHQiOiB7ImVuYWJsZWQiOiBmYWxzZSwgIm4iOiAxMjgsICJyIjogOCwgInAiOiAxLCAicm91bmRzIjogMH0sICJhcmdvbjIiOiB7ImVuYWJsZWQiOiBmYWxzZSwgInRpbWVfY29zdCI6IDMsICJtZW1vcnlfY29zdCI6IDY1NTM2LCAicGFyYWxsZWxpc20iOiA0LCAiaGFzaF9sZW4iOiAzMiwgInR5cGUiOiAyLCAicm91bmRzIjogMH0sICJiYWxsb29uIjogeyJlbmFibGVkIjogZmFsc2UsICJ0aW1lX2Nvc3QiOiAzLCAic3BhY2VfY29zdCI6IDY1NTM2LCAicGFyYWxsZWxpc20iOiA0LCAicm91bmRzIjogMH0sICJoa2RmIjogeyJlbmFibGVkIjogZmFsc2UsICJyb3VuZHMiOiAxLCAiYWxnb3JpdGhtIjogInNoYTI1NiIsICJpbmZvIjogIm9wZW5zc2xfZW5jcnlwdF9oa2RmIn19fSwgImhhc2hlcyI6IHsib3JpZ2luYWxfaGFzaCI6ICJhNTkxYTZkNDBiZjQyMDQwNGEwMTE3MzNjZmI3YjE5MGQ2MmM2NWJmMGJjZGEzMmI1N2IyNzdkOWFkOWYxNDZlIiwgImVuY3J5cHRlZF9oYXNoIjogImJkMjNiNDIzMDQwNGJkYjVhYmE0YzVlMTM0MjNjYTVlNTgwZjljNzgxMzEzYTc5ZjUxODI3ZDA2ZmFhYWM4MTAifSwgImVuY3J5cHRpb24iOiB7ImFsZ29yaXRobSI6ICJmZXJuZXQiLCAiZW5jcnlwdGlvbl9kYXRhIjogImFlcy1nY20ifX0=:Z0FBQUFBQm9uZy12cUhHS3J0TFRieEotNGg4bnNIa2F0RVladWxQb0xYQ0tkdEFCd2IwMklYbjZjWUVxRWRXT0ZZcDVmeTFSN0NrLXZHMlB5Qmp2bElkQXh5ODJhVHBla1E9PQ==';

    const password = '1234';
    const expected = 'Hello World';

    print('Config: SHA3-512(100 rounds) + PBKDF2(10k)');
    print('Password: $password');
    print('Expected: $expected');

    try {
      final result = await cryptoFFI.decryptText(cliData, password);

      print('Result: "$result"');

      if (result == expected) {
        print('✅ SUCCESS: Moderate hashes work!');
      } else {
        print('❌ FAILED: Expected "$expected", got "$result"');
      }

      expect(result, equals(expected));
    } catch (e) {
      print('❌ ERROR: $e');
      rethrow;
    }
  });
}
