import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:convert';
import 'dart:io';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    print('🔧 Initializing crypto system for Fernet key hex comparison...');
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
    print('✅ Crypto system initialized');
  });

  test('Fernet Key Hex: Extract final derived keys for comparison', () async {
    print('\n=== FERNET KEY HEX EXTRACTION ===');
    print('Goal: Extract final derived keys to compare mobile vs CLI');
    
    const password = '1234';
    const plaintext = 'Test';
    
    // Temporarily enable debug logging to capture key derivation
    NativeCrypto.debugEnabled = true;
    
    try {
      print('\n🔑 SIMPLE CONFIG - Key Extraction:');
      print('-' * 40);
      
      final simpleHashConfig = {'sha256': {'rounds': 2}};
      final simpleKdfConfig = {'pbkdf2': {'enabled': true, 'rounds': 10}};
      
      print('Encrypting with simple config to extract key...');
      final simpleEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', simpleHashConfig, simpleKdfConfig);
      
      print('Decrypting with simple config to extract key...');
      final simpleDecrypted = await cryptoFFI.decryptText(simpleEncrypted, password);
      
      expect(simpleDecrypted, equals(plaintext));
      print('✅ Simple config works perfectly\n');
      
      print('🔑 MULTI-KDF CONFIG - Key Extraction:');
      print('-' * 40);
      
      // Minimal multi-KDF config for easier comparison
      final multiHashConfig = {'sha256': {'rounds': 1000}};
      final multiKdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 100000},
        'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
      };
      
      print('Encrypting with multi-KDF config to extract key...');
      final multiEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', multiHashConfig, multiKdfConfig);
      
      print('Decrypting with multi-KDF config to extract key...');
      final multiDecrypted = await cryptoFFI.decryptText(multiEncrypted, password);
      
      expect(multiDecrypted, equals(plaintext)); 
      print('✅ Multi-KDF config works internally\n');
      
      print('🖥️ CLI TESTING - Multi-KDF Config:');
      print('-' * 40);
      
      // Test CLI compatibility with multi-KDF config
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
            print('✅ CLI decryption WORKS! Multi-KDF compatibility confirmed.');
          } else {
            print('❌ CLI decryption FAILED!');
            print('Expected: "$plaintext"');
            print('Got: "$decryptedContent"');
            print('\nFull CLI output:');
            print(output);
            print('\nCLI stderr:');
            print(cliResult.stderr);
          }
          
        } else {
          print('❌ CLI command failed with exit code: ${cliResult.exitCode}');
          print('STDERR: ${cliResult.stderr}');
          print('STDOUT: ${cliResult.stdout}');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
      print('\n🎯 KEY EXTRACTION SUMMARY:');
      print('Look for these patterns in the debug output above:');
      print('  1. FINAL DERIVED KEY (hex): [key] - The actual key used');
      print('  2. Fernet key (base64url): [key] - The base64 encoded key');
      print('  3. Compare simple vs multi-KDF key derivation paths');
      print('  4. Check if CLI compatibility matches mobile internal processing');
      
    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });
}