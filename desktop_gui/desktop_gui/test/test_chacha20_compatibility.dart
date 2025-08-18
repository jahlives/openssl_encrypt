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

  test('ChaCha20 Compatibility Test: Simple config', () async {
    print('\n=== CHACHA20 COMPATIBILITY TEST ===');

    const password = '1234';
    const plaintext = 'Test';

    print('🔍 Testing ChaCha20 simple config...');

    // Simple config first
    final hashConfig = {'sha256': {'rounds': 2}};
    final kdfConfig = {'pbkdf2': {'enabled': true, 'rounds': 10}};

    NativeCrypto.debugEnabled = true;

    try {
      print('📱 Step 1: Mobile ChaCha20 encryption...');
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, kdfConfig);
      print('✅ Mobile encryption completed');
      print('Mobile data length: ${mobileEncrypted.length}');

      print('📱 Step 2: Mobile self-test...');
      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      expect(mobileDecrypted, equals(plaintext));
      print('✅ Mobile self-compatibility confirmed');

      print('🖥️ Step 3: CLI decryption test...');
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/mobile_chacha20.txt');
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
            print('🎉 SUCCESS! ChaCha20 CLI compatibility confirmed!');
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

          // Parse mobile data to see the structure
          final parts = mobileEncrypted.split(':');
          final metadataB64 = parts[0];
          final metadata = jsonDecode(utf8.decode(base64Decode(metadataB64)));

          print('\n📋 Mobile ChaCha20 metadata analysis:');
          print('Format version: ${metadata['format_version']}');
          print('Algorithm: ${metadata['encryption']['algorithm']}');
          print('Encryption data: ${metadata['encryption']['encryption_data']}');
          print('Salt: ${metadata['derivation_config']['salt']}');

          fail('CLI decryption failed');
        }

      } finally {
        await tempDir.delete(recursive: true);
      }

    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });

  test('ChaCha20 vs CLI: Generate CLI data and test mobile decryption', () async {
    print('\n=== CHACHA20 CLI->MOBILE TEST ===');

    const password = '1234';
    const plaintext = 'CliTest';

    print('🖥️ Step 1: CLI ChaCha20 encryption...');
    final tempDir = Directory.systemTemp.createTempSync();
    final inputFile = File('${tempDir.path}/input.txt');
    final outputFile = File('${tempDir.path}/cli_chacha20.txt');

    await inputFile.writeAsString(plaintext);

    try {
      final cliEncryptResult = await Process.run('python', [
        '-m', 'openssl_encrypt.crypt',
        'encrypt',
        '--input', inputFile.path,
        '--output', outputFile.path,
        '--password', password,
        '--force-password',
        '--algorithm', 'chacha20-poly1305',
        '--sha256-rounds', '2',
        '--pbkdf2-iterations', '10'
      ], environment: {'PYTHONPATH': '/home/work/private/git/openssl_encrypt'});

      if (cliEncryptResult.exitCode != 0) {
        print('❌ CLI encryption failed');
        print('STDOUT: ${cliEncryptResult.stdout}');
        print('STDERR: ${cliEncryptResult.stderr}');
        fail('CLI encryption failed');
      }

      final cliEncryptedData = await outputFile.readAsString();
      print('✅ CLI encryption succeeded');
      print('CLI data length: ${cliEncryptedData.trim().length}');

      print('📱 Step 2: Mobile decryption of CLI data...');
      NativeCrypto.debugEnabled = true;

      try {
        final mobileDecrypted = await cryptoFFI.decryptText(cliEncryptedData.trim(), password);
        if (mobileDecrypted == plaintext) {
          print('🎉 SUCCESS! Mobile can decrypt CLI ChaCha20 data!');
        } else {
          print('❌ Mobile decryption content mismatch');
          print('Expected: "$plaintext"');
          print('Got: "$mobileDecrypted"');
          fail('Mobile decryption failed');
        }
      } catch (e) {
        print('❌ Mobile decryption failed with error: $e');

        // Parse CLI data to see the structure
        final parts = cliEncryptedData.trim().split(':');
        final metadataB64 = parts[0];
        final metadata = jsonDecode(utf8.decode(base64Decode(metadataB64)));

        print('\n📋 CLI ChaCha20 metadata analysis:');
        print('Format version: ${metadata['format_version']}');
        print('Algorithm: ${metadata['encryption']['algorithm']}');
        print('Encryption data: ${metadata['encryption']['encryption_data']}');
        print('Salt: ${metadata['derivation_config']['salt']}');

        rethrow;
      } finally {
        NativeCrypto.debugEnabled = false;
      }

    } finally {
      await tempDir.delete(recursive: true);
    }
  });
}
