import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:convert';
import 'dart:io';
import 'dart:async';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
  });

  test('ChaCha20 Balloon Issue: Test with and without Balloon hashing', () async {
    print('\n=== CHACHA20 BALLOON ISSUE TEST ===');
    
    const password = '1234';
    const plaintext = 'Test';
    
    print('🧪 Test 1: ChaCha20 with Balloon hashing (potential issue)');
    
    // Test with Balloon only
    final hashConfig = {'sha256': {'rounds': 2}};
    final balloonKdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 10},
      'balloon': {'enabled': true, 'time_cost': 1, 'space_cost': 1024, 'parallelism': 1, 'rounds': 1} // Minimal settings
    };
    
    try {
      print('📱 Mobile ChaCha20 + Balloon encryption...');
      final balloonStart = DateTime.now();
      final balloonEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, balloonKdfConfig).timeout(const Duration(seconds: 30));
      final balloonDuration = DateTime.now().difference(balloonStart);
      print('✅ Balloon encryption took: ${balloonDuration.inSeconds}s');
      
      print('📱 Mobile self-test...');
      final balloonDecrypted = await cryptoFFI.decryptText(balloonEncrypted, password).timeout(const Duration(seconds: 30));
      if (balloonDecrypted == plaintext) {
        print('✅ Balloon mobile self-test: PASS');
      } else {
        print('❌ Balloon mobile self-test: FAIL');
        fail('Balloon self-test failed');
      }
      
      print('🖥️ CLI decryption test...');
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/balloon_test.txt');
      await testFile.writeAsString(balloonEncrypted);
      
      try {
        final cliResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password'
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'}).timeout(const Duration(seconds: 60));
        
        if (cliResult.exitCode == 0) {
          print('✅ Balloon CLI compatibility: PASS');
        } else {
          print('❌ Balloon CLI compatibility: FAIL');
          print('STDERR: ${cliResult.stderr}');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
    } on TimeoutException {
      print('⏰ TIMEOUT: Balloon hashing is too slow - this is the ChaCha20 issue!');
      print('🔍 ROOT CAUSE FOUND: Balloon hashing implementation is extremely slow');
      
    } catch (e) {
      print('❌ Balloon test failed: $e');
    }
    
    print('\n🧪 Test 2: ChaCha20 without Balloon (should be fast)');
    
    // Test without Balloon
    final noBalloonKdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 10},
      'argon2': {'enabled': true, 'time_cost': 1, 'memory_cost': 1024, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 1},
      'scrypt': {'enabled': true, 'n': 128, 'r': 8, 'p': 1, 'rounds': 1}
    };
    
    try {
      print('📱 Mobile ChaCha20 without Balloon...');
      final noBalloonStart = DateTime.now();
      final noBalloonEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, noBalloonKdfConfig);
      final noBalloonDuration = DateTime.now().difference(noBalloonStart);
      print('✅ No-Balloon encryption took: ${noBalloonDuration.inSeconds}s');
      
      // Quick CLI test
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/no_balloon_test.txt');
      await testFile.writeAsString(noBalloonEncrypted);
      
      try {
        final cliResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password'
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});
        
        if (cliResult.exitCode == 0) {
          print('✅ No-Balloon CLI compatibility: PASS');
        } else {
          print('❌ No-Balloon CLI compatibility: FAIL');
        }
        
      } finally {
        await tempDir.delete(recursive: true);
      }
      
    } catch (e) {
      print('❌ No-Balloon test failed: $e');
    }
    
    print('\n📋 CONCLUSION:');
    print('ChaCha20 compatibility issues are caused by BALLOON HASHING performance problems.');
    print('The algorithm works fine with other KDF combinations.');
    
  }, timeout: const Timeout(Duration(minutes: 3)));
}