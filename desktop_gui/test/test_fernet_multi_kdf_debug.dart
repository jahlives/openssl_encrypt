import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:io';
import 'dart:convert';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    print('🔧 Initializing crypto system for Fernet multi-KDF debug tests...');
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
    print('✅ Crypto system initialized');
  });

  test('Fernet Multi-KDF Debug Test: Step-by-step analysis', () async {
    print('\n=== FERNET MULTI-KDF COMPATIBILITY DEBUG ===');
    print('Testing: Fernet with complex multi-KDF configuration');

    const password = '1234';
    const plaintext = 'Hello World';

    // Use mobile-encrypted Fernet data from /tmp/test_mobile.txt
    // This was encrypted with ALL hashes + ALL KDFs but using XChaCha20-Poly1305
    // Let's first create a Fernet version with same configuration

    print('📱 Step 1: Generate mobile Fernet encryption with multi-KDF...');

    try {
      // Configure complex hash + KDF settings matching /tmp/test_mobile.txt
      final hashConfig = {
        'sha512': {'rounds': 1000},
        'sha256': {'rounds': 1000},
        'sha3_256': {'rounds': 1000},
        'sha3_512': {'rounds': 1000},
        'blake2b': {'rounds': 1000},
        'whirlpool': {'rounds': 1000}
      };

      final kdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 100000},
        'scrypt': {'enabled': true, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
        'argon2': {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 1},
        'balloon': {'enabled': true, 'time_cost': 1, 'space_cost': 8, 'parallelism': 4, 'rounds': 1},
        'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
      };

      print('🔐 Configuration Summary:');
      print('  📋 Hashes: 6 active (1000 rounds each)');
      print('  🔑 KDFs: 5 active (PBKDF2: 100k, others: 1 round each)');
      print('  🎯 Algorithm: Fernet');
      print('  🔒 Password: $password');
      print('  📝 Plaintext: "$plaintext"');
      print('');

      // Step 1: Mobile encryption
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', hashConfig, kdfConfig);
      print('✅ Mobile Fernet encryption completed');
      print('📤 Mobile encrypted data: ${mobileEncrypted.substring(0, 100)}...');
      print('📏 Mobile encrypted length: ${mobileEncrypted.length}');
      print('');

      // Step 2: Mobile decryption (self-test)
      print('📱 Step 2: Mobile self-decryption test...');
      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      print('📤 Mobile decrypted: "$mobileDecrypted"');

      if (mobileDecrypted == plaintext) {
        print('✅ Mobile→Mobile Fernet works perfectly!');
      } else {
        print('❌ Mobile→Mobile Fernet FAILED!');
        fail('Mobile self-decryption failed');
      }
      print('');

      // Step 3: CLI decryption test
      print('🖥️ Step 3: CLI decryption of mobile Fernet data...');

      // Write mobile data to temp file for CLI test
      final tempDir = Directory.systemTemp.createTempSync();
      final tempFile = File('${tempDir.path}/mobile_fernet_encrypted.txt');
      await tempFile.writeAsString(mobileEncrypted);

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

          // Find the "Decrypted content:" line and get the next line
          String? decryptedContent;
          for (int i = 0; i < lines.length - 1; i++) {
            if (lines[i].contains('Decrypted content:')) {
              decryptedContent = lines[i + 1].trim();
              break;
            }
          }

          print('🖥️ CLI decryption result: "$decryptedContent"');

          if (decryptedContent == plaintext) {
            print('✅ Mobile→CLI Fernet works perfectly!');
            print('🎉 FERNET MULTI-KDF COMPATIBILITY CONFIRMED!');
          } else {
            print('❌ Mobile→CLI Fernet FAILED!');
            print('Expected: "$plaintext"');
            print('Got: "$decryptedContent"');
            print('');
            print('🔍 DETAILED CLI OUTPUT:');
            print(output);
            print('');
            print('🔍 DETAILED CLI ERROR:');
            print(cliResult.stderr.toString());

            fail('CLI decryption of mobile Fernet data failed');
          }
        } else {
          print('❌ CLI command failed with exit code: ${cliResult.exitCode}');
          print('STDOUT: ${cliResult.stdout}');
          print('STDERR: ${cliResult.stderr}');
          fail('CLI decryption command failed');
        }

      } finally {
        // Cleanup
        await tempDir.delete(recursive: true);
      }

      // Step 4: Reverse test - CLI→Mobile Fernet
      print('');
      print('🔄 Step 4: Reverse test - CLI→Mobile Fernet...');

      // Generate CLI Fernet encryption with same multi-KDF config
      final cliTempDir = Directory.systemTemp.createTempSync();
      final cliInputFile = File('${cliTempDir.path}/plaintext.txt');
      final cliOutputFile = File('${cliTempDir.path}/encrypted.txt');

      await cliInputFile.writeAsString(plaintext);

      try {
        final cliEncryptResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'encrypt',
          '-i', cliInputFile.path,
          '-o', cliOutputFile.path,
          '--password', password,
          '--force-password',
          '--algorithm', 'fernet',
          // Hash configuration
          '--sha512-rounds', '1000',
          '--sha256-rounds', '1000',
          '--sha3-256-rounds', '1000',
          '--sha3-512-rounds', '1000',
          '--blake2b-rounds', '1000',
          '--whirlpool-rounds', '1000',
          // KDF configuration
          '--pbkdf2-iterations', '100000',
          '--enable-scrypt', '--scrypt-rounds', '1',
          '--enable-argon2', '--argon2-rounds', '1',
          '--enable-balloon', '--balloon-rounds', '1',
          '--enable-hkdf', '--hkdf-rounds', '1'
        ]);

        if (cliEncryptResult.exitCode == 0) {
          final cliEncryptedData = await cliOutputFile.readAsString();
          print('✅ CLI Fernet encryption completed');
          print('📤 CLI encrypted data: ${cliEncryptedData.substring(0, 100)}...');

          // Test mobile decryption of CLI data
          final mobileDecryptedCli = await cryptoFFI.decryptText(cliEncryptedData.trim(), password);
          print('📱 Mobile decryption of CLI data: "$mobileDecryptedCli"');

          if (mobileDecryptedCli == plaintext) {
            print('✅ CLI→Mobile Fernet works perfectly!');
            print('🎉 BIDIRECTIONAL FERNET COMPATIBILITY CONFIRMED!');
          } else {
            print('❌ CLI→Mobile Fernet FAILED!');
            print('Expected: "$plaintext"');
            print('Got: "$mobileDecryptedCli"');
            fail('Mobile decryption of CLI Fernet data failed');
          }

        } else {
          print('❌ CLI encryption failed with exit code: ${cliEncryptResult.exitCode}');
          print('STDOUT: ${cliEncryptResult.stdout}');
          print('STDERR: ${cliEncryptResult.stderr}');
          fail('CLI Fernet encryption failed');
        }

      } finally {
        await cliTempDir.delete(recursive: true);
      }

    } catch (e, stackTrace) {
      print('❌ FERNET MULTI-KDF TEST ERROR: $e');
      print('Stack trace: $stackTrace');
      rethrow;
    }
  });

  test('Fernet Key Derivation Debug: Compare mobile vs CLI key generation', () async {
    print('\n=== FERNET KEY DERIVATION COMPARISON ===');
    print('Debugging: Mobile vs CLI key derivation for Fernet');

    const password = '1234';

    // Test with simplified configuration first
    final simpleHashConfig = {
      'sha256': {'rounds': 2}  // Minimal config
    };

    final simpleKdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 10}  // Minimal config
    };

    print('🔍 Testing with MINIMAL configuration:');
    print('  Hash: SHA-256 (2 rounds)');
    print('  KDF: PBKDF2 (10 rounds)');
    print('  Algorithm: Fernet');
    print('');

    try {
      // Enable debug logging temporarily
      NativeCrypto.debugEnabled = true;

      final mobileEncrypted = await cryptoFFI.encryptText('Test', password, 'fernet', simpleHashConfig, simpleKdfConfig);
      print('✅ Mobile Fernet encryption with minimal config completed');

      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      print('📱 Mobile decrypted: "$mobileDecrypted"');

      expect(mobileDecrypted, equals('Test'),
        reason: 'Mobile Fernet with minimal config should work');

      // Test CLI compatibility with same minimal config
      final tempDir = Directory.systemTemp.createTempSync();
      final tempFile = File('${tempDir.path}/minimal_fernet.txt');
      await tempFile.writeAsString(mobileEncrypted);

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
          print('🖥️ CLI output: $output');

          // Extract decrypted content
          final lines = output.split('\n');
          String? decryptedContent;
          for (int i = 0; i < lines.length - 1; i++) {
            if (lines[i].contains('Decrypted content:')) {
              decryptedContent = lines[i + 1].trim();
              break;
            }
          }

          if (decryptedContent == 'Test') {
            print('✅ CLI decryption of minimal Fernet works!');
          } else {
            print('❌ CLI decryption failed: got "$decryptedContent"');
            fail('CLI decryption of minimal config failed');
          }
        } else {
          print('❌ CLI failed: ${cliResult.stderr}');
          fail('CLI command failed');
        }
      } finally {
        await tempDir.delete(recursive: true);
        NativeCrypto.debugEnabled = false;  // Reset debug state
      }

    } catch (e, stackTrace) {
      NativeCrypto.debugEnabled = false;  // Reset debug state
      print('❌ MINIMAL FERNET TEST ERROR: $e');
      rethrow;
    }
  });
}
