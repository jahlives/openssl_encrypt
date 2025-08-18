import 'dart:convert';
import 'dart:typed_data';
import 'lib/native_crypto.dart';

void main() async {
  print('=== Testing Mobile-to-Mobile Fernet ===');

  final testText = 'Hello World from Mobile';
  final password = 'test123';

  print('Test text: "$testText"');
  print('Password: "$password"');

  try {
    // Test encryption with default configuration
    print('\n--- Encryption ---');
    final encrypted = await NativeCrypto.encryptText(
      testText,
      password,
      {
        'algorithm': 'fernet',
        'hash_rounds': {'sha512': 1000, 'sha256': 1000, 'sha3_256': 1000, 'sha3_512': 1000, 'blake2b': 1000, 'whirlpool': 1000},
        'kdf_config': {'pbkdf2': {'enabled': true, 'rounds': 100000}}
      }
    );
    print('✅ Encryption successful');
    print('Encrypted length: ${encrypted.length}');
    print('Encrypted preview: ${encrypted.substring(0, 100)}...');

    // Test decryption
    print('\n--- Decryption ---');
    final decrypted = await NativeCrypto.decryptData(encrypted, password);
    print('✅ Decryption successful');
    print('Decrypted: "$decrypted"');

    // Verify match
    if (decrypted == testText) {
      print('\n✅ MOBILE-TO-MOBILE FERNET: SUCCESS!');
    } else {
      print('\n❌ MOBILE-TO-MOBILE FERNET: FAILED!');
      print('Expected: "$testText"');
      print('Got: "$decrypted"');
    }

  } catch (e, stack) {
    print('❌ Mobile Fernet test failed: $e');
    print('Stack trace: $stack');
  }
}
