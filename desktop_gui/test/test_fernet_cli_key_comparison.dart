import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
  });

  test('Fernet CLI Key Comparison: Generate CLI data and compare keys', () async {
    print('\n=== FERNET CLI KEY COMPARISON ===');

    const password = '1234';
    const plaintext = 'Test';

    // Use a fixed salt for consistent comparison
    final fixedSalt = base64Decode('dGVzdHNhbHQxMjM0NTY3OA=='); // "testsalt12345678"
    final saltB64 = base64Encode(fixedSalt);
    print('🧂 Using fixed salt: $saltB64');

    print('\n📋 STEP 1: Generate CLI Fernet data with multi-KDF');
    print('-' * 50);

    // Generate CLI encryption first
    final cliTempDir = Directory.systemTemp.createTempSync();
    final cliInputFile = File('${cliTempDir.path}/plaintext.txt');
    final cliOutputFile = File('${cliTempDir.path}/encrypted.txt');

    await cliInputFile.writeAsString(plaintext);

    try {
      final cliEncryptResult = await Process.run('python', [
        '-m', 'openssl_encrypt.crypt',
        'encrypt',
        '--input', cliInputFile.path,
        '--output', cliOutputFile.path,
        '--password', password,
        '--force-password',
        '--algorithm', 'fernet',
        // Multi-KDF config (avoiding HKDF due to CLI bug)
        '--sha256-rounds', '1000',
        '--pbkdf2-iterations', '100000',
        '--enable-argon2', '--argon2-rounds', '2'
      ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});

      if (cliEncryptResult.exitCode != 0) {
        print('❌ CLI encryption failed');
        print('STDOUT: ${cliEncryptResult.stdout}');
        print('STDERR: ${cliEncryptResult.stderr}');
        fail('CLI encryption failed');
      }

      final cliEncryptedData = await cliOutputFile.readAsString();
      print('✅ CLI encryption succeeded');
      print('📤 CLI encrypted length: ${cliEncryptedData.trim().length}');

      // Parse CLI metadata to understand the exact format
      final cliParts = cliEncryptedData.trim().split(':');
      final cliMetadataB64 = cliParts[0];
      final cliDataB64 = cliParts[1];

      final cliMetadata = jsonDecode(utf8.decode(base64Decode(cliMetadataB64)));
      print('📋 CLI metadata format_version: ${cliMetadata['format_version']}');
      print('📋 CLI metadata salt: ${cliMetadata['derivation_config']['salt']}');
      print('📋 CLI encryption algorithm: ${cliMetadata['encryption']['algorithm']}');

      print('\n📋 STEP 2: Generate mobile Fernet data with same configuration');
      print('-' * 50);

      // Create mobile encryption with exactly same configuration (avoiding HKDF due to CLI bug)
      final mobileHashConfig = {'sha256': {'rounds': 1000}};
      final mobileKdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 100000},
        'argon2': {'enabled': true, 'time_cost': 2, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 2}
      };

      NativeCrypto.debugEnabled = true;

      try {
        final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', mobileHashConfig, mobileKdfConfig);
        print('✅ Mobile encryption succeeded');
        print('📤 Mobile encrypted length: ${mobileEncrypted.length}');

        // Test mobile self-compatibility
        final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
        expect(mobileDecrypted, equals(plaintext));
        print('✅ Mobile self-compatibility confirmed');

        // Parse mobile metadata
        final mobileParts = mobileEncrypted.split(':');
        final mobileMetadataB64 = mobileParts[0];
        final mobileDataB64 = mobileParts[1];

        final mobileMetadata = jsonDecode(utf8.decode(base64Decode(mobileMetadataB64)));
        print('📋 Mobile metadata format_version: ${mobileMetadata['format_version']}');
        print('📋 Mobile metadata salt: ${mobileMetadata['derivation_config']['salt']}');
        print('📋 Mobile encryption algorithm: ${mobileMetadata['encryption']['algorithm']}');

        print('\n📋 STEP 3: Test CLI decryption of mobile data');
        print('-' * 50);

        // Test CLI decryption of mobile data
        final testFile = File('${cliTempDir.path}/mobile_test.txt');
        await testFile.writeAsString(mobileEncrypted);

        final cliDecryptResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password'
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});

        print('CLI decrypt exit code: ${cliDecryptResult.exitCode}');
        if (cliDecryptResult.exitCode == 0) {
          final output = cliDecryptResult.stdout.toString();
          final lines = output.split('\n');

          String? decryptedContent;
          for (int i = 0; i < lines.length - 1; i++) {
            if (lines[i].contains('Decrypted content:')) {
              decryptedContent = lines[i + 1].trim();
              break;
            }
          }

          if (decryptedContent == plaintext) {
            print('✅ CLI decryption SUCCESS! Issue is resolved!');
          } else {
            print('❌ CLI decryption content mismatch');
            print('Expected: "$plaintext"');
            print('Got: "$decryptedContent"');
            print('\nFull CLI output:');
            print(output);
          }
        } else {
          print('❌ CLI decryption FAILED');
          print('STDOUT: ${cliDecryptResult.stdout}');
          print('STDERR: ${cliDecryptResult.stderr}');

          // Let's analyze what's different
          print('\n📋 STEP 4: Deep comparison of CLI vs Mobile format');
          print('-' * 50);

          print('CLI encrypted data (first 100 chars): ${cliEncryptedData.trim().substring(0, 100)}...');
          print('Mobile encrypted data (first 100 chars): ${mobileEncrypted.substring(0, 100)}...');

          // Compare metadata structures
          print('\nMetadata comparison:');
          print('CLI KDF config: ${cliMetadata['derivation_config']['kdf_config']}');
          print('Mobile KDF config: ${mobileMetadata['derivation_config']['kdf_config']}');
        }

      } finally {
        NativeCrypto.debugEnabled = false;
      }

    } finally {
      await cliTempDir.delete(recursive: true);
    }
  });

  test('Fernet Token Analysis: Compare mobile vs CLI token structure', () async {
    print('\n=== FERNET TOKEN STRUCTURE ANALYSIS ===');

    const password = '1234';
    const plaintext = 'Token';

    // Simple config that works - for baseline comparison
    final simpleHashConfig = {'sha256': {'rounds': 2}};
    final simpleKdfConfig = {'pbkdf2': {'enabled': true, 'rounds': 10}};

    print('🔍 Analyzing simple config token structure...');
    NativeCrypto.debugEnabled = true;

    try {
      final simpleEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', simpleHashConfig, simpleKdfConfig);
      print('Simple encrypted: ${simpleEncrypted.substring(0, 100)}...');

      // Parse the Fernet token from simple config
      final simpleParts = simpleEncrypted.split(':');
      final simpleDataB64 = simpleParts[1];
      final simpleTokenBytes = base64Decode(simpleDataB64);
      final simpleTokenString = utf8.decode(simpleTokenBytes);

      print('Simple token string: ${simpleTokenString.substring(0, 50)}...');
      print('Simple token length: ${simpleTokenString.length}');
      print('Simple token starts with Fernet signature: ${simpleTokenString.startsWith('gAAAAA')}');

      // Verify simple config works with CLI
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/simple_test.txt');
      await testFile.writeAsString(simpleEncrypted);

      try {
        final cliResult = await Process.run('python', [
          '-m', 'openssl_encrypt.crypt',
          'decrypt',
          '--input', testFile.path,
          '--password', password,
          '--force-password'
        ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});

        if (cliResult.exitCode == 0) {
          print('✅ Simple config CLI compatibility confirmed');
        } else {
          print('❌ Simple config CLI compatibility failed');
          print('STDERR: ${cliResult.stderr}');
        }

      } finally {
        await tempDir.delete(recursive: true);
      }

    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });
}
