import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

/// Tests for the 1.5.x contact-import mechanism (gitlab#192).
///
/// 1.5.x's `identity import` reads the document from a FILE (`--file`), not
/// from `--data` (which the GUI used to send and which this line's CLI does
/// not accept) nor from stdin. The pasted document may contain a mis-pasted
/// private key, so it is written to a restrictive temp file and removed after.
void main() {
  tearDown(CLIService.resetForTesting);

  test('importContact writes the document to a temp file and passes --file',
      () async {
    List<String>? seen;
    String? fileContents;
    String? filePath;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      seen = args;
      final i = args.indexOf('--file');
      if (i >= 0 && i + 1 < args.length) {
        filePath = args[i + 1];
        // Read while the call is still in flight (before the finally deletes).
        fileContents = await File(filePath!).readAsString();
      }
      return ProcessResult(0, 0, 'Identity imported successfully!', '');
    };

    await CLIService.importContact('{"name":"bob","fingerprint":"aa:bb"}');

    expect(seen, isNotNull);
    expect(seen, contains('--file'));
    // The document is NOT on argv (that is the whole point — /proc/cmdline).
    expect(seen, isNot(contains('{"name":"bob","fingerprint":"aa:bb"}')));
    // The temp file carried the document...
    expect(fileContents, contains('bob'));
    // ...and was cleaned up afterwards.
    expect(File(filePath!).existsSync(), isFalse);
  });

  test('a nonzero exit throws', () async {
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      return ProcessResult(0, 1, '', 'ERROR: malformed identity document');
    };
    expect(CLIService.importContact('not json'), throwsA(isA<Exception>()));
  });

  test('a document that looks like a private key is refused BEFORE any disk '
      'write or CLI call', () async {
    var invoked = false;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      invoked = true;
      return ProcessResult(0, 0, '', '');
    };

    // Contact import takes only PUBLIC documents; a mis-pasted private key
    // must never be written to disk. Both a PEM private key and a JSON with
    // a private-key field are refused up front.
    for (final doc in [
      '-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----',
      '{"name":"bob","encryption_private_key":"deadbeef"}',
    ]) {
      await expectLater(
        CLIService.importContact(doc),
        throwsA(isA<Exception>()),
      );
    }
    expect(invoked, isFalse, reason: 'the CLI must not run for private input');
  });

  test('a legitimate public export whose name/email merely contains the words '
      'is NOT refused', () async {
    // Identity names allow underscores and emails are free text, so a real
    // public document can carry these substrings as VALUES — they must not
    // trip the private-key guard, which keys on the JSON field name / PEM
    // header, never on a value.
    var invoked = false;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      invoked = true;
      return ProcessResult(0, 0, 'Identity imported successfully!', '');
    };

    await CLIService.importContact(
      '{"name":"alice_private_key","email":"my private key backup",'
      '"encryption_public_key":"AAAA","signing_public_key":"BBBB"}',
    );

    expect(invoked, isTrue, reason: 'a public export must be accepted');
  });
}
