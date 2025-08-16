import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:io';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
  });

  test('Fernet Multi-KDF CLI Compatibility Test', () async {
    print('\n=== FERNET MULTI-KDF CLI COMPATIBILITY ===');
    
    const password = '1234';
    const plaintext = 'Test';
    
    // Multi-KDF config that fails with CLI
    final multiHashConfig = {'sha256': {'rounds': 1000}};
    final multiKdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 100000},
      'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
    };
    
    print('🔐 Generating mobile Fernet encryption with multi-KDF...');
    final multiEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', multiHashConfig, multiKdfConfig);
    
    print('📱 Mobile self-test...');
    final mobileDecrypted = await cryptoFFI.decryptText(multiEncrypted, password);
    expect(mobileDecrypted, equals(plaintext));
    print('✅ Mobile→Mobile works');
    
    print('🖥️ CLI compatibility test...');
    final tempDir = Directory.systemTemp.createTempSync();
    final tempFile = File('${tempDir.path}/multi_kdf_fernet.txt');
    await tempFile.writeAsString(multiEncrypted);
    
    try {
      final cliResult = await Process.run('python', [
        '-m', 'openssl_encrypt.crypt',
        'decrypt',
        '-i', tempFile.path,
        '--password', password,
        '--force-password'
      ]);
      
      print('CLI exit code: ${cliResult.exitCode}');
      print('CLI stdout: ${cliResult.stdout}');
      print('CLI stderr: ${cliResult.stderr}');
      
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
          print('✅ CLI decryption SUCCESS!');
        } else {
          print('❌ CLI decryption content mismatch');
          print('Expected: "$plaintext"');
          print('Got: "$decryptedContent"');
        }
      } else {
        print('❌ CLI command failed');
      }
      
    } finally {
      await tempDir.delete(recursive: true);
    }
  });
}