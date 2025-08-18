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

  test('XChaCha20 Compatibility Test: Simple config', () async {
    print('\n=== XCHACHA20 COMPATIBILITY TEST ===');

    const password = '1234';
    const plaintext = 'Test';

    print('🔍 Testing XChaCha20 simple config...');

    // Simple config
    final hashConfig = <String, dynamic>{};
    final kdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 10}
    };

    print('📱 Step 1: Mobile XChaCha20 encryption...');
    final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'xchacha20-poly1305', hashConfig, kdfConfig);
    print('✅ Mobile encryption completed');
    print('Mobile data length: ${mobileEncrypted.length}');

    print('📱 Step 2: Mobile self-test...');
    final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
    expect(mobileDecrypted, equals(plaintext));
    print('✅ Mobile self-compatibility confirmed');

    print('🖥️ Step 3: CLI decryption test...');
    final tempDir = Directory.systemTemp.createTempSync();
    final testFile = File('${tempDir.path}/mobile_xchacha20.txt');
    await testFile.writeAsString(mobileEncrypted);

    try {
      final cliResult = await Process.run('python', [
        './openssl_encrypt/crypt.py',
        'decrypt',
        '--input', testFile.path,
        '--password', password,
        '--force-password'
      ], workingDirectory: '/home/work/private/git/openssl_encrypt');

      print('CLI decrypt exit code: ${cliResult.exitCode}');
      if (cliResult.exitCode == 0) {
        print('🎉 SUCCESS! XChaCha20 CLI compatibility confirmed!');
      } else {
        print('❌ CLI decryption FAILED');
        print('STDOUT: ${cliResult.stdout}');
        print('STDERR: ${cliResult.stderr}');
        fail('CLI decryption failed - XChaCha20 compatibility issue');
      }
    } finally {
      await testFile.delete();
      await tempDir.delete();
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('XChaCha20 vs CLI: Generate CLI data and test mobile decryption', () async {
    print('\n=== XCHACHA20 CLI->MOBILE TEST ===');

    const password = '1234';

    print('🖥️ Step 1: CLI XChaCha20 encryption...');
    final tempDir = Directory.systemTemp.createTempSync();
    final inputFile = File('${tempDir.path}/cli_input.txt');
    final outputFile = File('${tempDir.path}/cli_xchacha20.txt');

    await inputFile.writeAsString('CliTest');

    try {
      final encryptResult = await Process.run('python', [
        './openssl_encrypt/crypt.py',
        'encrypt',
        '--input', inputFile.path,
        '--output', outputFile.path,
        '--password', password,
        '--force-password',
        '--algorithm', 'xchacha20-poly1305'
      ], workingDirectory: '/home/work/private/git/openssl_encrypt');

      if (encryptResult.exitCode != 0) {
        print('❌ CLI encryption failed');
        print('STDOUT: ${encryptResult.stdout}');
        print('STDERR: ${encryptResult.stderr}');
        fail('CLI XChaCha20 encryption failed');
      }

      print('✅ CLI encryption succeeded');
      final cliData = await outputFile.readAsString();
      print('CLI data length: ${cliData.length}');

      print('📱 Step 2: Mobile decryption of CLI data...');
      final mobileDecrypted = await cryptoFFI.decryptText(cliData, password);

      if (mobileDecrypted == 'CliTest') {
        print('🎉 SUCCESS! Mobile can decrypt CLI XChaCha20 data!');
      } else {
        print('❌ Mobile decryption failed. Got: $mobileDecrypted');
        fail('Mobile->CLI XChaCha20 compatibility failed');
      }

    } finally {
      await inputFile.delete();
      await outputFile.delete();
      await tempDir.delete();
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('XChaCha20 Heavy Multi-KDF: Test complex configuration', () async {
    print('\n=== XCHACHA20 HEAVY MULTI-KDF TEST ===');

    const password = '1234';
    const plaintext = 'Test';

    print('🔍 Testing XChaCha20 with heavy multi-KDF config...');

    // Heavy multi-KDF config
    final hashConfig = {
      'sha512': {'rounds': 100}, // Reduced for faster testing
      'sha256': {'rounds': 100},
      'sha3_256': {'rounds': 100},
      'blake2b': {'rounds': 100}
    };
    final kdfConfig = {
      'argon2': {'enabled': true, 'time_cost': 2, 'memory_cost': 4096, 'parallelism': 2, 'hash_len': 32, 'type': 2, 'rounds': 2},
      'scrypt': {'enabled': true, 'n': 128, 'r': 4, 'p': 1, 'rounds': 2},
      'pbkdf2': {'enabled': true, 'rounds': 10}
    };

    print('📱 Step 1: Mobile XChaCha20 heavy multi-KDF encryption...');
    final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'xchacha20-poly1305', hashConfig, kdfConfig);
    print('✅ Mobile encryption completed');

    print('📱 Step 2: Mobile self-test...');
    final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
    expect(mobileDecrypted, equals(plaintext));
    print('✅ Mobile self-compatibility confirmed');

    print('🖥️ Step 3: CLI decryption test...');
    final tempDir = Directory.systemTemp.createTempSync();
    final testFile = File('${tempDir.path}/mobile_xchacha20_heavy.txt');
    await testFile.writeAsString(mobileEncrypted);

    // Save to persistent location for debugging
    final debugFile = File('/tmp/xchacha20_heavy_debug.txt');
    await debugFile.writeAsString(mobileEncrypted);
    print('🐛 Debug file saved to: ${debugFile.path}');

    try {
      final cliResult = await Process.run('python', [
        './openssl_encrypt/crypt.py',
        'decrypt',
        '--input', testFile.path,
        '--password', password,
        '--force-password'
      ], workingDirectory: '/home/work/private/git/openssl_encrypt');

      print('CLI decrypt exit code: ${cliResult.exitCode}');
      if (cliResult.exitCode == 0) {
        print('🎉 SUCCESS! XChaCha20 heavy multi-KDF CLI compatibility confirmed!');
      } else {
        print('❌ CLI decryption FAILED - This may indicate XChaCha20 nonce compatibility issue');
        print('STDOUT: ${cliResult.stdout}');
        print('STDERR: ${cliResult.stderr}');
        print('📋 Analysis: XChaCha20 + Heavy Multi-KDF may have nonce format incompatibility');
        fail('Expected XChaCha20 CLI compatibility issue - needs investigation');
      }
    } finally {
      await testFile.delete();
      await tempDir.delete();
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
}
