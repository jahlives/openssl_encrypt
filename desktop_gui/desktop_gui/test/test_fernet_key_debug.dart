import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
  });

  test('Debug Fernet Key Processing Logic', () async {
    print('\n=== FERNET KEY DEBUG ===');
    
    const password = '1234';
    const plaintext = 'Test';
    
    NativeCrypto.debugEnabled = true;
    
    try {
      print('🔐 Testing simple config (PBKDF2 only)...');
      final simpleHashConfig = {'sha256': {'rounds': 2}};
      final simpleKdfConfig = {'pbkdf2': {'enabled': true, 'rounds': 10}};
      
      final simpleEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', simpleHashConfig, simpleKdfConfig);
      print('Simple config encrypted length: ${simpleEncrypted.length}');
      
      final simpleDecrypted = await cryptoFFI.decryptText(simpleEncrypted, password);
      print('Simple config decrypted: "$simpleDecrypted"');
      expect(simpleDecrypted, equals(plaintext));
      print('✅ Simple config works');
      
      print('');
      print('🔐 Testing multi-KDF config...');
      final multiHashConfig = {'sha256': {'rounds': 1000}};
      final multiKdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 100000},
        'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
      };
      
      final multiEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', multiHashConfig, multiKdfConfig);
      print('Multi-KDF config encrypted length: ${multiEncrypted.length}');
      
      final multiDecrypted = await cryptoFFI.decryptText(multiEncrypted, password);
      print('Multi-KDF config decrypted: "$multiDecrypted"');
      expect(multiDecrypted, equals(plaintext));
      print('✅ Multi-KDF config works internally');
      
      print('');
      print('🎯 Both configurations work internally - issue must be in CLI compatibility');
      print('Look at debug output above for:');
      print('  - KDF processing detection');
      print('  - Key derivation paths');
      print('  - Fernet key formats');
      
    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });
}