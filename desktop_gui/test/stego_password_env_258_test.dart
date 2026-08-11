import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

/// F21/F22 (gitlab#258, CWE-214): the steganography password must NOT be placed
/// on the child process argv (visible in /proc/<pid>/cmdline). It now travels
/// via the CRYPT_STEGO_PASSWORD environment variable, exactly like the main
/// password's CRYPT_PASSWORD channel.
void main() {
  tearDown(CLIService.resetForTesting);

  List<String> capture() {
    late List<String> seen;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      seen = args;
      return ProcessResult(0, 0, '{}', '');
    };
    return seen = <String>[];
  }

  test('encrypt: stego password is not on argv and is passed via the environment',
      () async {
    final seen = capture();
    await CLIService.encryptWithSteganography(
      inputPath: '/tmp/in.txt',
      coverImagePath: '/tmp/cover.png',
      outputPath: '/tmp/out.png',
      password: 'main-pw',
      stegoPassword: 'secret-stego',
    );
    expect(seen.contains('--stego-password'), isFalse);
    expect(seen.contains('secret-stego'), isFalse);
    expect(CLIService.lastEnvironmentForTesting?['CRYPT_STEGO_PASSWORD'],
        'secret-stego');
    // The main password still travels the same way.
    expect(CLIService.lastEnvironmentForTesting?['CRYPT_PASSWORD'], 'main-pw');
  });

  test('decrypt: stego password is not on argv and is passed via the environment',
      () async {
    final seen = capture();
    await CLIService.decryptFromSteganography(
      stegoImagePath: '/tmp/out.png',
      outputPath: '/tmp/recovered.txt',
      password: 'main-pw',
      stegoPassword: 'secret-stego',
    );
    expect(seen.contains('--stego-password'), isFalse);
    expect(seen.contains('secret-stego'), isFalse);
    expect(CLIService.lastEnvironmentForTesting?['CRYPT_STEGO_PASSWORD'],
        'secret-stego');
  });

  test('no stego password: CRYPT_STEGO_PASSWORD is absent from the environment',
      () async {
    capture();
    await CLIService.encryptWithSteganography(
      inputPath: '/tmp/in.txt',
      coverImagePath: '/tmp/cover.png',
      outputPath: '/tmp/out.png',
      password: 'main-pw',
    );
    expect(
        CLIService.lastEnvironmentForTesting?.containsKey('CRYPT_STEGO_PASSWORD'),
        isFalse);
  });
}
