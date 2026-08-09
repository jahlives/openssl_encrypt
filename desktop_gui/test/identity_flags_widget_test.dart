import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/identity_management_screen.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';

/// Widget tests for the gitlab#161 identity flags in the Identity Management
/// screen: the `--no-touch` control on Create, and the two-phase
/// `--allow-key-change` confirmation on Import.
void main() {
  // Serve an empty identity store so the screen builds without a real CLI.
  ProcessResult emptyIdentities(List<String> args) => ProcessResult(
        0,
        0,
        jsonEncode({
          'own': <Map<String, dynamic>>[],
          'contacts': <Map<String, dynamic>>[],
          'skipped': <Map<String, dynamic>>[],
        }),
        '',
      );

  tearDown(CLIService.resetForTesting);

  // The Create/Import dialogs are taller than the default 600px test viewport,
  // so controls near the bottom fall off-screen and taps on them miss.
  Future<void> useTallSurface(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1200, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  }

  Widget wrap() => const MaterialApp(home: IdentityManagementScreen());

  // On 1.5.x importContact does real filesystem IO (writes the document to a
  // temp file) before the CLI override is reached; that real async does not
  // resolve under the widget tester's fake clock, so let it run for real,
  // then rebuild to surface any resulting dialog.
  // The import-triggering tap must run inside runAsync: importContact does
  // real filesystem IO (temp file) before the CLI override, which the widget
  // tester's fake clock would otherwise never advance past.
  Future<void> tapReal(WidgetTester tester, Finder finder) async {
    await tester.runAsync(() async {
      await tester.tap(finder);
      await Future.delayed(const Duration(milliseconds: 400));
    });
    await tester.pumpAndSettle();
  }

  group('Create: --no-touch', () {
    testWidgets('the touch control appears only with an HSM, off by default',
        (WidgetTester tester) async {
      CLIService.commandRunnerOverride =
          (args, {stdinInput}) async => emptyIdentities(args);

      await useTallSurface(tester);
      await tester.pumpWidget(wrap());
      await tester.pumpAndSettle();

      // Open the Create dialog.
      await tester.tap(find.text('Create Identity').first);
      await tester.pumpAndSettle();

      const touchLabel = 'Show a touch reminder when this identity is used';

      // Without an HSM the control is not shown at all.
      expect(find.text(touchLabel), findsNothing);

      // Enable HSM.
      final hsmTile = find.text('Use HSM (Hardware Security Module)');
      await tester.ensureVisible(hsmTile);
      await tester.tap(hsmTile);
      await tester.pumpAndSettle();

      final tileFinder = find.ancestor(
        of: find.text(touchLabel),
        matching: find.byType(SwitchListTile),
      );
      expect(tileFinder, findsOneWidget);
      // Default ON, matching the CLI default (touch reminder shown).
      expect(tester.widget<SwitchListTile>(tileFinder).value, isTrue);

      // The copy must NOT assert a hardware protection the flag does not
      // provide (gitlab#218): no man-in-the-middle / "used silently" framing.
      expect(find.textContaining('silently'), findsNothing);
      expect(find.textContaining('malware'), findsNothing);
    });
  });

  group('Import: --allow-key-change', () {
    const keyChangedStderr =
        '\n⚠️  WARNING: the key for this contact has CHANGED.\n'
        '  Identity:        bob\n'
        '  Stored (pinned): aa:bb:cc:dd\n'
        '  Imported:        11:22:33:44\n'
        'ERROR: refusing to replace a pinned key non-interactively.\n';

    testWidgets('a refused key change shows both fingerprints and a MITM '
        'warning, and does not retry unless confirmed',
        (WidgetTester tester) async {
      var importAttempts = 0;
      var sawAllowFlag = false;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        if (args.length >= 2 && args[0] == 'identity' && args[1] == 'import') {
          importAttempts++;
          if (args.contains('--allow-key-change')) sawAllowFlag = true;
          return ProcessResult(0, 1, '', keyChangedStderr);
        }
        return emptyIdentities(args);
      };

      await useTallSurface(tester);
      await tester.pumpWidget(wrap());
      await tester.pumpAndSettle();

      // Switch to the Contacts tab, then open Import.
      await tester.tap(find.text('Contacts'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Import Contact').first);
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, '{"name":"bob"}');
      await tapReal(tester, find.text('Import'));

      // The confirmation must show what changed, both fingerprints, and the
      // MITM framing — never a bare "failed".
      expect(find.textContaining('aa:bb:cc:dd'), findsOneWidget);
      expect(find.textContaining('11:22:33:44'), findsOneWidget);
      expect(find.textContaining('man-in-the-middle'), findsOneWidget);

      // One attempt so far, and the override flag was not sent on it.
      expect(importAttempts, 1);
      expect(sawAllowFlag, isFalse);

      // Cancelling must NOT replace the pinned key.
      final cancel = find.widgetWithText(TextButton, 'Keep the pinned key');
      expect(cancel, findsOneWidget);
      await tester.tap(cancel);
      await tester.pumpAndSettle();
      expect(sawAllowFlag, isFalse);
      expect(importAttempts, 1);
    });

    testWidgets('confirming the key change retries with --allow-key-change',
        (WidgetTester tester) async {
      var sawReplace = false;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        if (args.length >= 2 && args[0] == 'identity' && args[1] == 'import') {
          if (args.contains('--allow-key-change')) {
            // Enforce the real CLI contract: --allow-key-change alone is
            // refused; only --allow-key-change + --overwrite replaces.
            if (!args.contains('--overwrite')) {
              return ProcessResult(
                  0, 1, '', 'ERROR: Identity already exists at /store/bob');
            }
            sawReplace = true;
            return ProcessResult(0, 0, '', '');
          }
          return ProcessResult(0, 1, '', keyChangedStderr);
        }
        return emptyIdentities(args);
      };

      await useTallSurface(tester);
      await tester.pumpWidget(wrap());
      await tester.pumpAndSettle();

      await tester.tap(find.text('Contacts'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Import Contact').first);
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, '{"name":"bob"}');
      await tapReal(tester, find.text('Import'));

      final accept =
          find.widgetWithText(ElevatedButton, 'Replace the pinned key');
      expect(accept, findsOneWidget);
      await tapReal(tester, accept);

      expect(sawReplace, isTrue);
    });
  });
}
