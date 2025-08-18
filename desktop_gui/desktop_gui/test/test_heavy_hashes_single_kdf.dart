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

  test('Heavy Hashes + Single PBKDF2 Test', () async {
    print('\n=== TESTING: All Hashes + Single PBKDF2 ===');

    // CLI data with SHA3-512(10k), SHA-512(1k), SHA-256(1k), BLAKE2b(1k), Whirlpool(1k) + PBKDF2(10k) only
    const cliData = 'eyJmb3JtYXRfdmVyc2lvbiI6IDUsICJkZXJpdmF0aW9uX2NvbmZpZyI6IHsic2FsdCI6ICI3T2I2SkpvMFgwNlBDYnMzdzdtMGpBPT0iLCAiaGFzaF9jb25maWciOiB7InNoYTUxMiI6IHsicm91bmRzIjogMTAwMH0sICJzaGEzODQiOiB7InJvdW5kcyI6IDB9LCAic2hhMjU2IjogeyJyb3VuZHMiOiAxMDAwfSwgInNoYTIyNCI6IHsicm91bmRzIjogMH0sICJzaGEzXzUxMiI6IHsicm91bmRzIjogMTAwMDB9LCAic2hhM18zODQiOiB7InJvdW5kcyI6IDB9LCAic2hhM18yNTYiOiB7InJvdW5kcyI6IDB9LCAic2hhM18yMjQiOiB7InJvdW5kcyI6IDB9LCAiYmxha2UyYiI6IHsicm91bmRzIjogMTAwMH0sICJibGFrZTMiOiB7InJvdW5kcyI6IDB9LCAic2hha2UyNTYiOiB7InJvdW5kcyI6IDB9LCAic2hha2UxMjgiOiB7InJvdW5kcyI6IDB9LCAid2hpcmxwb29sIjogeyJyb3VuZHMiOiAxMDAwfX0sICJrZGZfY29uZmlnIjogeyJwYmtkZjIiOiB7InJvdW5kcyI6IDEwMDAwfSwgInNjcnlwdCI6IHsiZW5hYmxlZCI6IGZhbHNlLCAibiI6IDEyOCwgInIiOiA4LCAicCI6IDEsICJyb3VuZHMiOiAwfSwgImFyZ29uMiI6IHsiZW5hYmxlZCI6IGZhbHNlLCAidGltZV9jb3N0IjogMywgIm1lbW9yeV9jb3N0IjogNjU1MzYsICJwYXJhbGxlbGlzbSI6IDQsICJoYXNoX2xlbiI6IDMyLCAidHlwZSI6IDIsICJyb3VuZHMiOiAwfSwgImJhbGxvb24iOiB7ImVuYWJsZWQiOiBmYWxzZSwgInRpbWVfY29zdCI6IDMsICJzcGFjZV9jb3N0IjogNjU1MzYsICJwYXJhbGxlbGlzbSI6IDQsICJyb3VuZHMiOiAwfSwgImhrZGYiOiB7ImVuYWJsZWQiOiBmYWxzZSwgInJvdW5kcyI6IDEsICJhbGdvcml0aG0iOiAic2hhMjU2IiwgImluZm8iOiAib3BlbnNzbF9lbmNyeXB0X2hrZGYifX19LCAiaGFzaGVzIjogeyJvcmlnaW5hbF9oYXNoIjogImE1OTFhNmQ0MGJmNDIwNDA0YTAxMTczM2NmYjdiMTkwZDYyYzY1YmYwYmNkYTMyYjU3YjI3N2Q5YWQ5ZjE0NmUiLCAiZW5jcnlwdGVkX2hhc2giOiAiYTY3NmY3MWRmYmM3YWQyZTk1YzdhZmE4MjE0ZjIxZmZkM2I1MjM1ZDNjZTAwZWZmMTUxMmI3ZTJmMzI5YmNhZiJ9LCAiZW5jcnlwdGlvbiI6IHsiYWxnb3JpdGhtIjogImZlcm5ldCIsICJlbmNyeXB0aW9uX2RhdGEiOiAiYWVzLWdjbSJ9fQ==:Z0FBQUFBQm9uZzU0M1JwNkNpOW5uVHpmbHMySnYxejB2S2xvcFRlb3dSOWdCd3pZWlk5Y2JvWnZzVDlnR1RpU1VXRGliNXJnMmliZDhzcGtBR1UzSUx4MXl3VDlId0V5WWc9PQ==';

    const password = '1234';
    const expected = 'Hello World';

    print('Config: SHA3-512(10k) + SHA-512(1k) + SHA-256(1k) + BLAKE2b(1k) + Whirlpool(1k) + PBKDF2(10k)');
    print('Password: $password');
    print('Expected: $expected');

    try {
      final result = await cryptoFFI.decryptText(cliData, password);

      print('Result: "$result"');

      if (result == expected) {
        print('✅ SUCCESS: Heavy hashes + single PBKDF2 works!');
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
