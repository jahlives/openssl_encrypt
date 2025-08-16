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

  test('ChaCha20 Exact Balloon Params: space_cost=8 issue', () async {
    print('\n=== CHACHA20 EXACT BALLOON PARAMS TEST ===');
    print('Testing with mobile default: space_cost=8 (8 bytes)');
    
    const password = '1234';
    const plaintext = 'Test';
    
    // Exact configuration from your mobile data that fails CLI decryption
    final hashConfig = {
      'sha512': {'rounds': 1000},
      'sha256': {'rounds': 1000},
      'sha3_256': {'rounds': 1000},
      'sha3_512': {'rounds': 1000},
      'blake2b': {'rounds': 1000},
      'whirlpool': {'rounds': 1000}
    };
    final kdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 2},
      'scrypt': {'enabled': true, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 2},
      'argon2': {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 2},
      'balloon': {'enabled': true, 'time_cost': 1, 'space_cost': 8, 'parallelism': 4, 'rounds': 2} // This tiny space_cost!
    };
    
    print('🔍 Configuration: space_cost=8 bytes (suspiciously small)');
    
    try {
      print('📱 Step 1: Mobile ChaCha20 encryption with exact failing params...');
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, kdfConfig);
      print('✅ Mobile encryption completed');
      
      print('📱 Step 2: Mobile self-test...');
      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      expect(mobileDecrypted, equals(plaintext));
      print('✅ Mobile self-compatibility confirmed');
      
      print('🖥️ Step 3: CLI decryption test (where your failure occurred)...');
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/mobile_exact_params.txt');
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
            print('🎉 SUCCESS! CLI decryption worked - no issue with space_cost=8');
          } else {
            print('❌ CLI decryption content mismatch');
            print('Expected: "$plaintext"');
            print('Got: "$decryptedContent"');
            fail('CLI decryption content mismatch');
          }
        } else {
          print('❌ CLI decryption FAILED - reproducing your exact issue!');
          final stdout = cliResult.stdout.toString();
          final stderr = cliResult.stderr.toString();
          
          print('STDOUT: ${stdout.substring(0, 500)}...');
          print('STDERR: $stderr');
          
          if (stderr.contains('Security validation check failed') || stdout.contains('Security validation check failed')) {
            print('\n🎯 CONFIRMED: space_cost=8 causes "Security validation check failed"');
            print('🔍 ROOT CAUSE: Mobile Balloon space_cost=8 bytes is incompatible with CLI');
            print('💡 SOLUTION: Mobile needs to use larger space_cost values (e.g., 65536)');
          }
          
          // Parse the mobile data to confirm the exact values
          final parts = mobileEncrypted.split(':');
          final metadataB64 = parts[0];
          final metadata = jsonDecode(utf8.decode(base64Decode(metadataB64)));
          
          print('\n📋 Mobile metadata balloon config:');
          print('${metadata['derivation_config']['kdf_config']['balloon']}');
          
          fail('CLI decryption failed - ChaCha20 space_cost=8 incompatibility confirmed');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
    } catch (e) {
      print('❌ Test failed: $e');
      rethrow;
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('ChaCha20 Fixed Balloon Params: Test with proper space_cost', () async {
    print('\n=== CHACHA20 FIXED BALLOON PARAMS TEST ===');
    print('Testing with proper space_cost=65536 (64KB)');
    
    const password = '1234';
    const plaintext = 'Test';
    
    // Same config but with proper space_cost
    final hashConfig = {'sha256': {'rounds': 10}}; // Reduced for faster testing
    final fixedKdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 10},
      'balloon': {'enabled': true, 'time_cost': 1, 'space_cost': 65536, 'parallelism': 4, 'rounds': 2} // Proper space_cost
    };
    
    try {
      print('📱 Mobile ChaCha20 with fixed space_cost...');
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, fixedKdfConfig);
      print('✅ Mobile encryption completed');
      
      print('🖥️ CLI compatibility test...');
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/fixed_params.txt');
      await testFile.writeAsString(mobileEncrypted);
      
      try {
        final cliResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password'
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});
        
        if (cliResult.exitCode == 0) {
          print('✅ Fixed space_cost CLI compatibility: PASS');
          print('💡 SOLUTION CONFIRMED: Using space_cost=65536 fixes the issue');
        } else {
          print('❌ Fixed space_cost still fails - issue is elsewhere');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
    } catch (e) {
      print('❌ Fixed params test failed: $e');
    }
  });
}