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

  test('Mobile-Generated Heavy Hash Test (WORKS in CLI)', () async {
    print('\n=== TESTING: Mobile-Generated Heavy Hash Data ===');

    // This is mobile-generated data with heavy hashes that CLI decrypts successfully!
    // SHA-512(10k) + SHA-256(10k) + SHA3-256(10k) + SHA3-512(10k) + BLAKE2b(10k) + Whirlpool(10k) + PBKDF2(100k)
    const mobileData = 'eyJmb3JtYXRfdmVyc2lvbiI6NSwiZGVyaXZhdGlvbl9jb25maWciOnsic2FsdCI6IjArTlVlUVdjeFU1R0RUWUpoM1RFc0E9PSIsImhhc2hfY29uZmlnIjp7InNoYTUxMiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhMjU2Ijp7InJvdW5kcyI6MTAwMDB9LCJzaGEzXzI1NiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhM181MTIiOnsicm91bmRzIjoxMDAwMH0sImJsYWtlMmIiOnsicm91bmRzIjoxMDAwMH0sImJsYWtlMyI6eyJyb3VuZHMiOjB9LCJzaGFrZTI1NiI6eyJyb3VuZHMiOjB9LCJ3aGlybHBvb2wiOnsicm91bmRzIjoxMDAwMH19LCJrZGZfY29uZmlnIjp7InBia2RmMiI6eyJlbmFibGVkIjp0cnVlLCJyb3VuZHMiOjEwMDAwMH0sInNjcnlwdCI6eyJlbmFibGVkIjpmYWxzZSwibiI6MTYzODQsInIiOjgsInAiOjEsInJvdW5kcyI6MX0sImFyZ29uMiI6eyJlbmFibGVkIjpmYWxzZSwidGltZV9jb3N0IjozLCJtZW1vcnlfY29zdCI6NjU1MzYsInBhcmFsbGVsaXNtIjoxLCJoYXNoX2xlbiI6MzIsInR5cGUiOjIsInJvdW5kcyI6MX0sImJhbGxvb24iOnsiZW5hYmxlZCI6ZmFsc2UsInRpbWVfY29zdCI6MSwic3BhY2VfY29zdCI6OCwicGFyYWxsZWxpc20iOjQsInJvdW5kcyI6MX0sImhrZGYiOnsiZW5hYmxlZCI6ZmFsc2UsInJvdW5kcyI6MSwiYWxnb3JpdGhtIjoic2hhMjU2IiwiaW5mbyI6Ik9wZW5TU0xfRW5jcnlwdF9Nb2JpbGUifX19LCJoYXNoZXMiOnsib3JpZ2luYWxfaGFzaCI6ImE1OTFhNmQ0MGJmNDIwNDA0YTAxMTczM2NmYjdiMTkwZDYyYzY1YmYwYmNkYTMyYjU3YjI3N2Q5YWQ5ZjE0NmUiLCJlbmNyeXB0ZWRfaGFzaCI6Ijc5ZWVhYzE2NGM2OTQzYjA2NzM5ODBlYmMxMWUwODFiNmUwYjYzNTg4N2Y3ODYwZDA1MWVkNjkzNzc4ZGNkOGUifSwiZW5jcnlwdGlvbiI6eyJhbGdvcml0aG0iOiJmZXJuZXQiLCJlbmNyeXB0aW9uX2RhdGEiOiJhZXMtZ2NtIn19:Z0FBQUFBQm9uaEN5T2dkNDlveGlYZ3VDRkMwUXEtbjRIWnFRQ2lYSk9CV3AxZFNaeXlJay1McW9nMHlhX3FFYktuRTk5R2o1cWpkYlJ0U2ZPSURfdVB5ck1wNU9oMHRKb2c9PQ==';

    const password = '1234';
    const expected = 'Hello World';

    print('Config: Mobile-generated data with 10k rounds each of SHA-512, SHA-256, SHA3-256, SHA3-512, BLAKE2b, Whirlpool + PBKDF2(100k)');
    print('Password: $password');
    print('Expected: $expected');
    print('✅ CONFIRMED: CLI decrypts this successfully!');

    try {
      final result = await cryptoFFI.decryptText(mobileData, password);

      print('Result: "$result"');

      if (result == expected) {
        print('✅ SUCCESS: Mobile can decrypt its own heavy hash data!');
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
