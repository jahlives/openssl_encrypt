import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

/// Service-layer tests for the identity flags of gitlab#161 on 1.5.x:
/// `--no-touch` on identity create and `--allow-key-change` on contact import.
///
/// 1.5.x's import reads the document from a file (`--file`, gitlab#192), so
/// the key-change flags travel alongside `--file` rather than `--data-stdin`.
/// The key-change path must surface the CLI's refusal as a typed error
/// carrying the old/new fingerprints — never a bare retry.
void main() {
  tearDown(CLIService.resetForTesting);

  group('createIdentity --no-touch', () {
    test('is omitted by default', () async {
      late List<String> seen;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        return ProcessResult(0, 0, '', '');
      };

      await CLIService.createIdentity(
        name: 'alice',
        passphrase: 'pw',
        hsmType: 'yubikey',
      );

      expect(seen, isNot(contains('--no-touch')));
    });

    test('is emitted only when noTouch is true', () async {
      late List<String> seen;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        return ProcessResult(0, 0, '', '');
      };

      await CLIService.createIdentity(
        name: 'alice',
        passphrase: 'pw',
        hsmType: 'yubikey',
        noTouch: true,
      );

      expect(seen, contains('--no-touch'));
    });
  });

  group('importContact --allow-key-change', () {
    // The exact stderr the 1.5.x CLI prints when refusing a TOFU key change
    // (identity_cli.py cmd_import): byte-identical to 1.4.x.
    const keyChangedStderr =
        '\n⚠️  WARNING: the key for this contact has CHANGED.\n'
        '  Identity:        bob\n'
        '  Stored (pinned): aa:bb:cc:dd\n'
        '  Imported:        11:22:33:44\n'
        'ERROR: refusing to replace a pinned key non-interactively. '
        'Re-run with --allow-key-change once you have verified the new '
        'fingerprint.\n';

    test('does not send --allow-key-change by default', () async {
      late List<String> seen;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        return ProcessResult(0, 0, '', '');
      };

      await CLIService.importContact('{"name":"bob"}');

      expect(seen, isNot(contains('--allow-key-change')));
    });

    test('a refused key change throws IdentityKeyChangedError with both '
        'fingerprints', () async {
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        expect(args, isNot(contains('--allow-key-change')));
        return ProcessResult(0, 1, '', keyChangedStderr);
      };

      final error = await CLIService.importContact('{"name":"bob"}')
          .then<Object?>((_) => null, onError: (e) => e);

      expect(error, isA<IdentityKeyChangedError>());
      final e = error as IdentityKeyChangedError;
      expect(e.name, 'bob');
      expect(e.oldFingerprint, 'aa:bb:cc:dd');
      expect(e.newFingerprint, '11:22:33:44');
    });

    test('a non-fingerprint value is not accepted as a fingerprint '
        '(label-injection guard)', () async {
      const forged = '\n⚠️  WARNING: the key for this contact has CHANGED.\n'
          '  Identity:        evil\n'
          '  Stored (pinned): TRUST ME THIS IS FINE\n'
          '  Imported:        also not a fingerprint\n';
      expect(IdentityKeyChangedError.tryParse(forged), isNull);
    });

    test('identical fingerprints are not treated as a key change', () async {
      const sameFp = '\n⚠️  WARNING: the key for this contact has CHANGED.\n'
          '  Identity:        bob\n'
          '  Stored (pinned): aa:bb:cc:dd\n'
          '  Imported:        aa:bb:cc:dd\n';
      expect(IdentityKeyChangedError.tryParse(sameFp), isNull);
    });

    test('an ordinary failure stays a generic error, not a key-change one',
        () async {
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        return ProcessResult(0, 1, '', 'ERROR: malformed identity document');
      };

      final error = await CLIService.importContact('{"name":"x"}')
          .then<Object?>((_) => null, onError: (e) => e);

      expect(error, isNot(isA<IdentityKeyChangedError>()));
    });

    test('allowKeyChange:true sends --allow-key-change AND --overwrite together',
        () async {
      // The CLI needs both to replace a pinned contact: --allow-key-change
      // passes the TOFU gate but Identity.save still refuses to overwrite the
      // existing directory without --overwrite. The fake enforces that real
      // contract so a missing --overwrite is a red test.
      late List<String> seen;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        final isImport =
            args.length >= 2 && args[0] == 'identity' && args[1] == 'import';
        if (isImport &&
            args.contains('--allow-key-change') &&
            !args.contains('--overwrite')) {
          return ProcessResult(
              0, 1, '', 'ERROR: Identity already exists at /store/bob');
        }
        return ProcessResult(0, 0, '', '');
      };

      await CLIService.importContact('{"name":"bob"}', allowKeyChange: true);

      expect(seen, containsAll(['--allow-key-change', '--overwrite']));
    });
  });
}
