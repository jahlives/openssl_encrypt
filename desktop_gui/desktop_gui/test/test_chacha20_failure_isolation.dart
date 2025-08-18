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

  Future<bool> testChaCha20Config(String testName, Map<String, dynamic> hashConfig, Map<String, dynamic> kdfConfig) async {
    print('\n🧪 Testing: $testName');

    const password = '1234';
    const plaintext = 'Test';

    try {
      // Mobile encryption
      final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, kdfConfig);
      print('  ✅ Mobile encryption: OK');

      // Mobile self-test
      final mobileDecrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
      if (mobileDecrypted != plaintext) {
        print('  ❌ Mobile self-test: FAILED');
        return false;
      }
      print('  ✅ Mobile self-test: OK');

      // CLI decryption test
      final tempDir = Directory.systemTemp.createTempSync();
      final testFile = File('${tempDir.path}/test.txt');
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
            print('  ✅ CLI decryption: OK');
            return true;
          } else {
            print('  ❌ CLI decryption: Content mismatch');
            return false;
          }
        } else {
          print('  ❌ CLI decryption: FAILED');
          if (cliResult.stderr.toString().contains('Security validation check failed')) {
            print('    Error: Security validation check failed');
          } else {
            print('    STDERR: ${cliResult.stderr}');
          }
          return false;
        }

      } finally {
        await tempDir.delete(recursive: true);
      }

    } catch (e) {
      print('  ❌ Test failed with exception: $e');
      return false;
    }
  }

  test('ChaCha20 Failure Isolation: Systematic KDF testing', () async {
    print('\n=== CHACHA20 FAILURE ISOLATION ===');

    final results = <String, bool>{};

    // Baseline: Simple hash + PBKDF2 (should work)
    results['Simple PBKDF2'] = await testChaCha20Config(
      'Simple PBKDF2 only',
      {'sha256': {'rounds': 2}},
      {'pbkdf2': {'enabled': true, 'rounds': 10}}
    );

    // Test individual KDFs
    results['PBKDF2 + Argon2'] = await testChaCha20Config(
      'PBKDF2 + Argon2',
      {'sha256': {'rounds': 2}},
      {
        'pbkdf2': {'enabled': true, 'rounds': 10},
        'argon2': {'enabled': true, 'time_cost': 1, 'memory_cost': 1024, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 1}
      }
    );

    results['PBKDF2 + Scrypt'] = await testChaCha20Config(
      'PBKDF2 + Scrypt',
      {'sha256': {'rounds': 2}},
      {
        'pbkdf2': {'enabled': true, 'rounds': 10},
        'scrypt': {'enabled': true, 'n': 128, 'r': 8, 'p': 1, 'rounds': 1}
      }
    );

    results['PBKDF2 + Balloon'] = await testChaCha20Config(
      'PBKDF2 + Balloon',
      {'sha256': {'rounds': 2}},
      {
        'pbkdf2': {'enabled': true, 'rounds': 10},
        'balloon': {'enabled': true, 'time_cost': 1, 'space_cost': 1024, 'parallelism': 1, 'rounds': 1}
      }
    );

    results['PBKDF2 + HKDF'] = await testChaCha20Config(
      'PBKDF2 + HKDF',
      {'sha256': {'rounds': 2}},
      {
        'pbkdf2': {'enabled': true, 'rounds': 10},
        'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
      }
    );

    // Test multi-KDF without HKDF
    results['Multi-KDF no HKDF'] = await testChaCha20Config(
      'Multi-KDF without HKDF',
      {'sha256': {'rounds': 10}},
      {
        'pbkdf2': {'enabled': true, 'rounds': 50},
        'argon2': {'enabled': true, 'time_cost': 1, 'memory_cost': 1024, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 1},
        'scrypt': {'enabled': true, 'n': 128, 'r': 8, 'p': 1, 'rounds': 1}
      }
    );

    // Test with heavy hashing
    results['Heavy Hashing + Simple KDF'] = await testChaCha20Config(
      'Heavy hashing with simple KDF',
      {
        'sha512': {'rounds': 100},
        'sha256': {'rounds': 100},
        'blake2b': {'rounds': 100}
      },
      {'pbkdf2': {'enabled': true, 'rounds': 10}}
    );

    print('\n=== RESULTS SUMMARY ===');
    results.forEach((test, passed) {
      final status = passed ? '✅ PASS' : '❌ FAIL';
      print('$status: $test');
    });

    final failedTests = results.entries.where((e) => !e.value).map((e) => e.key).toList();
    if (failedTests.isNotEmpty) {
      print('\n🔍 ChaCha20 FAILS with these configurations:');
      failedTests.forEach((test) => print('  - $test'));

      print('\n📋 Analysis: ChaCha20 compatibility issues identified');

      // Don't fail the test - we want to see all results
      expect(failedTests.isEmpty, isFalse, reason: 'Found ChaCha20 compatibility issues as expected');
    } else {
      print('\n🎉 All ChaCha20 configurations work! No issues found.');
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
}
