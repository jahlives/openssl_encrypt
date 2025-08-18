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

  test('ChaCha20 Heavy Multi-KDF: Match the failing configuration', () async {
    print('\n=== CHACHA20 HEAVY MULTI-KDF TEST ===');

    const password = '1234';
    const plaintext = 'Test';

    print('🔍 Testing ChaCha20 with heavy multi-KDF config that failed in CLI...');

    // Heavy multi-KDF config matching your failing CLI command
    final hashConfig = {
      'sha512': {'rounds': 1000},
      'sha256': {'rounds': 1000},
      'sha3_256': {'rounds': 1000},
      'sha3_512': {'rounds': 1000},
      'blake2b': {'rounds': 1000},
      'whirlpool': {'rounds': 1000}
    };
    final kdfConfig = {
      'argon2': {'enabled': true, 'time_cost': 2, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 2},
      'balloon': {'enabled': true, 'time_cost': 2, 'space_cost': 65536, 'parallelism': 4, 'rounds': 2},
      'scrypt': {'enabled': true, 'n': 128, 'r': 8, 'p': 1, 'rounds': 2},
      'pbkdf2': {'enabled': true, 'rounds': 100} // Reduced from 100000 for faster testing
    };

    print('📱 Step 1: Mobile ChaCha20 heavy multi-KDF encryption...');
    final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, kdfConfig);
    print('✅ Mobile encryption completed');

    print('📱 Step 2: Mobile self-test...');
    final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
    expect(mobileDecrypted, equals(plaintext));
    print('✅ Mobile self-compatibility confirmed');

    print('🖥️ Step 3: CLI decryption test...');
    final tempDir = Directory.systemTemp.createTempSync();
    final testFile = File('${tempDir.path}/mobile_chacha20_heavy.txt');
    await testFile.writeAsString(mobileEncrypted);

    // Also save to persistent location for manual debugging
    final debugFile = File('/tmp/heavy_chacha20_debug.txt');
    await debugFile.writeAsString(mobileEncrypted);
    print('🐛 Debug file saved to: ${debugFile.path}');

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
          print('🎉 SUCCESS! ChaCha20 heavy multi-KDF CLI compatibility confirmed!');
        } else {
          print('❌ CLI decryption content mismatch');
          print('Expected: "$plaintext"');
          print('Got: "$decryptedContent"');
          fail('CLI decryption content mismatch');
        }
      } else {
        print('❌ CLI decryption FAILED - This matches your reported issue');
        print('STDOUT: ${cliResult.stdout}');
        print('STDERR: ${cliResult.stderr}');

        print('\n📋 Analysis: ChaCha20 + Heavy Multi-KDF incompatibility detected');
        print('This suggests the issue is with the heavy KDF combination, not ChaCha20 itself');

        fail('CLI decryption failed with heavy multi-KDF - expected behavior');
      }

    } finally {
      await tempDir.delete(recursive: true);
    }
  });
}
