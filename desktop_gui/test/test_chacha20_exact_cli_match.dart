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

  test('ChaCha20 Exact CLI Match: Reproduce your failing command', () async {
    print('\n=== CHACHA20 EXACT CLI MATCH TEST ===');
    print('Reproducing your exact failing CLI parameters...');
    
    const password = '1234';
    const plaintext = 'Test';
    
    // Exact configuration from your CLI command that failed:
    // --sha512-rounds 1000 --sha256-rounds 1000 --sha3-256-rounds 1000 
    // --sha3-512-rounds 1000 --blake2b-rounds 1000 --whirlpool-rounds 1000
    // --enable-argon2 --argon2-rounds 2 --enable-balloon --balloon-rounds 2 
    // --enable-scrypt --scrypt-rounds 2 --pbkdf2-iterations [default]
    final hashConfig = {
      'sha512': {'rounds': 1000},
      'sha256': {'rounds': 1000},
      'sha3_256': {'rounds': 1000},
      'sha3_512': {'rounds': 1000},
      'blake2b': {'rounds': 1000},
      'whirlpool': {'rounds': 1000}
    };
    final kdfConfig = {
      'argon2': {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 2},
      'balloon': {'enabled': true, 'time_cost': 3, 'space_cost': 65536, 'parallelism': 4, 'rounds': 2},
      'scrypt': {'enabled': true, 'n': 128, 'r': 8, 'p': 1, 'rounds': 2},
      'pbkdf2': {'enabled': true, 'rounds': 100000} // Default CLI value
    };
    
    print('🔍 Configuration: Full heavy multi-KDF + multi-hash (exact CLI match)');
    
    NativeCrypto.debugEnabled = true;
    
    try {
      print('📱 Step 1: Mobile ChaCha20 encryption with exact CLI config...');
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, kdfConfig);
      print('✅ Mobile encryption completed');
      print('📤 Mobile data length: ${mobileEncrypted.length}');
      
      // Parse mobile metadata to compare with CLI
      final parts = mobileEncrypted.split(':');
      final metadataB64 = parts[0];
      final metadata = jsonDecode(utf8.decode(base64Decode(metadataB64)));
      
      print('\n📋 Mobile ChaCha20 metadata:');
      print('Algorithm: ${metadata['encryption']['algorithm']}');
      print('Format version: ${metadata['format_version']}');
      print('Hash rounds: ${metadata['derivation_config']['hash_config']}');
      print('KDF config: ${metadata['derivation_config']['kdf_config']}');
      
      print('\n📱 Step 2: Mobile self-test...');
      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      expect(mobileDecrypted, equals(plaintext));
      print('✅ Mobile self-compatibility confirmed');
      
      print('\n🖥️ Step 3: CLI decryption test (this is where your failure occurred)...');
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/mobile_chacha20_exact.txt');
      await testFile.writeAsString(mobileEncrypted);
      
      try {
        print('Running CLI decrypt command...');
        final cliResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password',
          '--debug'  // Add debug to see CLI processing
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});
        
        print('CLI decrypt exit code: ${cliResult.exitCode}');
        
        if (cliResult.exitCode == 0) {
          final output = cliResult.stdout.toString();
          print('✅ CLI STDOUT: ${output.substring(0, 200)}...');
          
          final lines = output.split('\n');
          String? decryptedContent;
          for (int i = 0; i < lines.length - 1; i++) {
            if (lines[i].contains('Decrypted content:')) {
              decryptedContent = lines[i + 1].trim();
              break;
            }
          }
          
          if (decryptedContent == plaintext) {
            print('🎉 SUCCESS! CLI decryption worked - no ChaCha20 issue found!');
            print('\n💡 Conclusion: ChaCha20 is fully compatible with ALL KDF combinations.');
            print('Your earlier failure may have been due to:');
            print('  - Different test data or configuration');
            print('  - Temporary CLI environment issue');
            print('  - Different mobile implementation version');
          } else {
            print('❌ CLI decryption content mismatch');
            print('Expected: "$plaintext"');
            print('Got: "$decryptedContent"');
            fail('CLI decryption content mismatch');
          }
        } else {
          print('❌ CLI decryption FAILED (reproducing your issue)');
          final stdout = cliResult.stdout.toString();
          final stderr = cliResult.stderr.toString();
          
          print('STDOUT: ${stdout.substring(0, 500)}...');
          print('STDERR: $stderr');
          
          if (stderr.contains('Security validation check failed') || stdout.contains('Security validation check failed')) {
            print('\n🔍 FOUND THE ISSUE: "Security validation check failed"');
            print('This is the same error pattern as Fernet+HKDF!');
            print('ChaCha20 + Heavy Multi-KDF has a compatibility issue.');
          }
          
          fail('CLI decryption failed - ChaCha20 heavy multi-KDF incompatibility confirmed');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
    } finally {
      NativeCrypto.debugEnabled = false;
    }
  }, timeout: const Timeout(Duration(minutes: 10)));
}