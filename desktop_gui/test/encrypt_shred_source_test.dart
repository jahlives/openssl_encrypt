import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/tabs/encrypt_tab.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

// Tests for "shred the source file after encrypting" ported to 1.5.x
// (gitlab#151 / github#69).
//
// The GUI encrypts file-mode input by reading its TEXT and passing it through
// encryptTextWithProgress, so the encrypt command's own --shred has no input
// file to wipe. The source is therefore shredded as a separate `shred` command
// after a successful encryption — hence the control lives here, gated on its
// own confirmation, and the service escapes glob metacharacters (the CLI's
// shred globs -i, so a literal path with `*` could delete siblings).
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    CLIService.commandRunnerOverride =
        (args, {stdinInput}) async => ProcessResult(0, 1, '', '');
  });

  tearDown(CLIService.resetForTesting);

  Widget wrap(Widget child) => MaterialApp(home: Scaffold(body: child));

  Future<void> openAdvanced(WidgetTester tester) async {
    final header = find.text('Advanced Options');
    await tester.ensureVisible(header);
    await tester.pump();
    await tester.tap(header);
    await tester.pump(const Duration(milliseconds: 400));
  }

  group('shred service', () {
    test('emits `shred -i <path> --shred-passes N`', () async {
      List<String>? seen;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        return ProcessResult(0, 0, '', 'Shredded.');
      };

      await CLIService.shred('/home/me/secret.txt', passes: 7);

      expect(seen, containsAllInOrder(['shred', '-i']));
      expect(seen, containsAll(['--shred-passes', '7']));
      expect(seen, contains('/home/me/secret.txt'));
    });

    test('escapes glob metacharacters so siblings are never deleted', () async {
      // The CLI globs -i, so a literal path like "data*.bin" would expand to
      // and delete every matching sibling. The escaped form matches only the
      // literal file.
      List<String>? seen;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        return ProcessResult(0, 0, '', '');
      };

      await CLIService.shred('/tmp/data*.bin');

      final iIndex = seen!.indexOf('-i');
      final passed = seen![iIndex + 1];
      expect(passed, isNot(contains('data*.bin'))); // raw glob not passed
      expect(passed, '/tmp/data[*].bin'); // glob.escape form
    });

    test('a nonzero exit throws', () async {
      CLIService.commandRunnerOverride =
          (args, {stdinInput}) async => ProcessResult(0, 1, '', 'denied');
      expect(CLIService.shred('/x'), throwsA(isA<Exception>()));
    });
  });

  group('shred control', () {
    testWidgets('is present and off by default', (WidgetTester tester) async {
      await tester.pumpWidget(
          wrap(EncryptTab(fileManager: FileManager(), isProMode: true)));
      await tester.pump();
      await openAdvanced(tester);

      final option =
          find.text('Securely delete the source file after encrypting');
      expect(option, findsOneWidget);

      final tile = tester.widget<SwitchListTile>(
        find.ancestor(of: option, matching: find.byType(SwitchListTile)),
      );
      // Off by default: destroying the only plaintext copy is an explicit
      // choice, never an inherited default.
      expect(tile.value, isFalse);
    });

    testWidgets('warns that the action is irreversible',
        (WidgetTester tester) async {
      await tester.pumpWidget(
          wrap(EncryptTab(fileManager: FileManager(), isProMode: true)));
      await tester.pump();
      await openAdvanced(tester);

      expect(find.textContaining('cannot be recovered'), findsWidgets);
    });
  });
}
