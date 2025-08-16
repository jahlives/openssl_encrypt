import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:convert';
import 'dart:io';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
  });

  test('Fernet Quick Compatibility Test: Mobile->CLI with working multi-KDF', () async {
    print('\n=== FERNET QUICK COMPATIBILITY TEST ===');
    
    const password = '1234';
    const plaintext = 'Test';
    
    print('🔍 Testing Fernet multi-KDF compatibility with fast parameters...');
    
    // Quick multi-KDF config (avoiding HKDF due to CLI bug)
    final hashConfig = {'sha256': {'rounds': 2}};
    final kdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 10},
      'argon2': {'enabled': true, 'time_cost': 1, 'memory_cost': 1024, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 1}
    };
    
    NativeCrypto.debugEnabled = true;
    
    try {
      print('📱 Step 1: Mobile encryption with multi-KDF...');
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', hashConfig, kdfConfig);
      print('✅ Mobile encryption completed');
      
      print('📱 Step 2: Mobile self-test...');
      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      expect(mobileDecrypted, equals(plaintext));
      print('✅ Mobile self-compatibility confirmed');
      
      print('🖥️ Step 3: CLI decryption test...');
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/mobile_test.txt');
      await testFile.writeAsString(mobileEncrypted);
      
      try {
        final cliResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password'
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});
        
        print('CLI decrypt exit code: ${cliResult.exitCode}');
        if (cliResult.exitCode == 0) {
          final output = cliResult.stdout.toString();
          final lines = output.split('\n');
          
          String? decryptedContent;
          for (int i = 0; i < lines.length - 1; i++) {
            if (lines[i].contains('Decrypted content:')) {
              decryptedContent = lines[i + 1].trim();
              break;
            }
          }
          
          if (decryptedContent == plaintext) {
            print('🎉 SUCCESS! CLI decryption worked! Mobile->CLI Fernet multi-KDF compatibility confirmed!');
          } else {
            print('❌ CLI decryption content mismatch');
            print('Expected: "$plaintext"');
            print('Got: "$decryptedContent"');
            fail('CLI decryption content mismatch');
          }
        } else {
          print('❌ CLI decryption FAILED');
          print('STDOUT: ${cliResult.stdout}');
          print('STDERR: ${cliResult.stderr}');
          fail('CLI decryption failed');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });
}