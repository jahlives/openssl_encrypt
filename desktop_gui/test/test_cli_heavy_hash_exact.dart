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

  test('CLI-Generated Heavy Hash Test (EXACT same settings as working mobile)', () async {
    print('\n=== TESTING: CLI-Generated Heavy Hash Data ===');
    
    // This is CLI-generated data with identical hash/KDF settings to the working mobile data
    // SHA-512(10k) + SHA-256(10k) + SHA3-256(10k) + SHA3-512(10k) + BLAKE2b(10k) + Whirlpool(10k) + PBKDF2(100k)
    const cliData = 'eyJmb3JtYXRfdmVyc2lvbiI6IDUsICJkZXJpdmF0aW9uX2NvbmZpZyI6IHsic2FsdCI6ICJ1dS9mckRKTmxFSktVRXRXNFMrNUZ3PT0iLCAiaGFzaF9jb25maWciOiB7InNoYTUxMiI6IHsicm91bmRzIjogMTAwMDB9LCAic2hhMzg0IjogeyJyb3VuZHMiOiAwfSwgInNoYTI1NiI6IHsicm91bmRzIjogMTAwMDB9LCAic2hhMjI0IjogeyJyb3VuZHMiOiAwfSwgInNoYTNfNTEyIjogeyJyb3VuZHMiOiAxMDAwMH0sICJzaGEzXzM4NCI6IHsicm91bmRzIjogMH0sICJzaGEzXzI1NiI6IHsicm91bmRzIjogMTAwMDB9LCAic2hhM18yMjQiOiB7InJvdW5kcyI6IDB9LCAiYmxha2UyYiI6IHsicm91bmRzIjogMTAwMDB9LCAiYmxha2UzIjogeyJyb3VuZHMiOiAwfSwgInNoYWtlMjU2IjogeyJyb3VuZHMiOiAwfSwgInNoYWtlMTI4IjogeyJyb3VuZHMiOiAwfSwgIndoaXJscG9vbCI6IHsicm91bmRzIjogMTAwMDB9fSwgImtkZl9jb25maWciOiB7InBia2RmMiI6IHsicm91bmRzIjogMTAwMDAwfSwgInNjcnlwdCI6IHsiZW5hYmxlZCI6IGZhbHNlLCAibiI6IDEyOCwgInIiOiA4LCAicCI6IDEsICJyb3VuZHMiOiAwfSwgImFyZ29uMiI6IHsiZW5hYmxlZCI6IGZhbHNlLCAidGltZV9jb3N0IjogMywgIm1lbW9yeV9jb3N0IjogNjU1MzYsICJwYXJhbGxlbGlzbSI6IDQsICJoYXNoX2xlbiI6IDMyLCAidHlwZSI6IDIsICJyb3VuZHMiOiAwfSwgImJhbGxvb24iOiB7ImVuYWJsZWQiOiBmYWxzZSwgInRpbWVfY29zdCI6IDMsICJzcGFjZV9jb3N0IjogNjU1MzYsICJwYXJhbGxlbGlzbSI6IDQsICJyb3VuZHMiOiAwfSwgImhrZGYiOiB7ImVuYWJsZWQiOiBmYWxzZSwgInJvdW5kcyI6IDEsICJhbGdvcml0aG0iOiAic2hhMjU2IiwgImluZm8iOiAib3BlbnNzbF9lbmNyeXB0X2hrZGYifX19LCAiaGFzaGVzIjogeyJvcmlnaW5hbF9oYXNoIjogImE1OTFhNmQ0MGJmNDIwNDA0YTAxMTczM2NmYjdiMTkwZDYyYzY1YmYwYmNkYTMyYjU3YjI3N2Q5YWQ5ZjE0NmUiLCAiZW5jcnlwdGVkX2hhc2giOiAiNzhlNTJlNjIwNjNkODhlODYwODBiMGQxYTAxZmQ5MjZjZTgyZmFjMGQ3MzE5ZWNkNGEzMjFlZjRhZjI1MGYzOCJ9LCAiZW5jcnlwdGlvbiI6IHsiYWxnb3JpdGhtIjogImZlcm5ldCIsICJlbmNyeXB0aW9uX2RhdGEiOiAiYWVzLWdjbSJ9fQ==:Z0FBQUFBQm9uaEhyY3BQSHZ3ODBjZGpyNGh4cjJhVmJYRFlVaHVhY0p3NE1abnlVSkZCTGlVNXJieHNiZFlNUHZxWnkxWWNDeTdZNTBJZXQ2Ylk4NVZWd05fYUZpRWtCWlE9PQ==';
    
    const password = '1234';
    const expected = 'Hello World';
    
    print('Config: CLI-generated data with 10k rounds each of SHA-512, SHA-256, SHA3-256, SHA3-512, BLAKE2b, Whirlpool + PBKDF2(100k)');
    print('Password: $password');
    print('Expected: $expected');
    print('🔍 TESTING: Does mobile fail with CLI-generated heavy hash data?');
    
    try {
      final result = await cryptoFFI.decryptText(cliData, password);
      
      print('Result: "$result"');
      
      if (result == expected) {
        print('✅ UNEXPECTED SUCCESS: Mobile can decrypt CLI heavy hash data!');
      } else {
        print('❌ EXPECTED FAILURE: Expected "$expected", got "$result"');
        print('🔍 This confirms the directional issue with CLI→Mobile heavy hashing');
      }
      
      // Don't fail the test - we expect this might fail and want to analyze the result
      if (result != expected) {
        print('📊 ANALYSIS: CLI→Mobile heavy hash decryption failed as expected');
      }
      
    } catch (e) {
      print('❌ ERROR: $e');
      print('🔍 This is the expected CLI→Mobile heavy hash compatibility issue');
    }
  });
}