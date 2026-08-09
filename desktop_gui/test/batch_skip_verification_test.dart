import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/main.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

// Regression tests for the batch tab's "Skip signature verification"
// checkbox (gitlab#214 / github#125).
//
// The checkbox's backing _skipVerification value has always been passed to
// CLIService on batch asymmetric decrypt, but the widget sat behind an
// `if (_showAdvanced)` gate that nothing ever set — invisible but
// transmitted. These tests pin the repaired wiring, mirroring the guards
// the single-file Decrypt tab has always had:
//  - the signature sub-options only render once a decryption identity is
//    chosen (CLIService only sends --verify-from/--no-verify then),
//  - skipping defaults to OFF and shows its red warning banner only while
//    actually armed,
//  - checking "skip" clears and disables the "verify from" dropdown,
//  - changing the decryption identity resets the skip choice.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    CLIService.commandRunnerOverride = _fakeCliWithIdentities;
  });

  tearDown(() {
    CLIService.commandRunnerOverride = null;
  });

  Future<void> useTallSurface(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1400, 3000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  }

  Widget wrap(Widget child) => MaterialApp(home: Scaffold(body: child));

  Widget batchTab() => BatchOperationsTab(
        fileManager: _StubFileManager(),
        onDebugChanged: (_) {},
      );

  Future<void> selectFiles(WidgetTester tester) async {
    final addButton = find.text('Select Files');
    await tester.ensureVisible(addButton.first);
    await tester.pump();
    await tester.tap(addButton.first);
    await tester.pump(const Duration(milliseconds: 300));
  }

  // Drive the tab into asymmetric-decrypt configuration.
  Future<void> enterAsymmetricDecrypt(WidgetTester tester) async {
    await selectFiles(tester);

    final decryptRadio = find.text('Decrypt Files');
    expect(decryptRadio, findsOneWidget,
        reason: 'operation radios must be present once files are selected');
    await tester.ensureVisible(decryptRadio);
    await tester.pump();
    await tester.tap(decryptRadio);
    await tester.pump(const Duration(milliseconds: 300));

    final asymmetric = find.textContaining('Asymmetric');
    expect(asymmetric, findsWidgets,
        reason: 'the encryption-mode selector must offer Asymmetric');
    await tester.ensureVisible(asymmetric.first);
    await tester.pump();
    await tester.tap(asymmetric.first);
    await tester.pump(const Duration(milliseconds: 300));
  }

  Future<void> chooseIdentity(WidgetTester tester, String name) async {
    // Match on the decoration, not the visible text: once an identity is
    // selected the hint text is replaced by the identity name.
    final dropdown = find.byWidgetPredicate((w) =>
        w is DropdownButtonFormField<String> &&
        w.decoration.hintText == 'Select decryption identity');
    expect(dropdown, findsOneWidget);
    await tester.ensureVisible(dropdown);
    await tester.pump();
    await tester.tap(dropdown, warnIfMissed: false);
    await tester.pumpAndSettle();
    await tester.tap(find.text(name).last);
    await tester.pumpAndSettle();
  }

  const skipLabel = 'Skip signature verification (dangerous)';
  const bannerFragment = 'authenticity will NOT be checked';

  testWidgets(
      'signature sub-options are hidden until a decryption identity is chosen',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await enterAsymmetricDecrypt(tester);

    // Identity selector is offered, but no identity chosen yet: the skip
    // checkbox and the signer dropdown must not render — CLIService would
    // not send their flags in this state.
    expect(find.text('Decrypt with identity:'), findsOneWidget);
    expect(find.text(skipLabel), findsNothing);
    expect(find.textContaining('Verify signature from'), findsNothing);
  });

  testWidgets(
      'skip defaults to OFF and the warning banner renders only while armed',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await enterAsymmetricDecrypt(tester);
    await chooseIdentity(tester, 'alice');

    final checkboxFinder = find.ancestor(
      of: find.text(skipLabel),
      matching: find.byType(CheckboxListTile),
    );
    expect(checkboxFinder, findsOneWidget,
        reason: 'the skip checkbox must be reachable once an identity is set');

    // Default state: off, no red banner.
    expect(
        tester.widget<CheckboxListTile>(checkboxFinder).value, isFalse);
    expect(find.textContaining(bannerFragment), findsNothing);

    // Arm it: banner appears.
    await tester.ensureVisible(checkboxFinder);
    await tester.pump();
    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isTrue);
    expect(find.textContaining(bannerFragment), findsOneWidget);
  });

  testWidgets('arming skip clears and disables the verify-from dropdown',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await enterAsymmetricDecrypt(tester);
    await chooseIdentity(tester, 'alice');

    final signerDropdown = find.byWidgetPredicate((w) =>
        w is DropdownButtonFormField<String> &&
        w.decoration.hintText == 'Select sender to verify');
    expect(signerDropdown, findsOneWidget);
    expect(
        tester
            .widget<DropdownButtonFormField<String>>(signerDropdown)
            .onChanged,
        isNotNull,
        reason: 'signer dropdown starts enabled');

    // Choose a signer so the clearing below is observable.
    await tester.ensureVisible(signerDropdown);
    await tester.pump();
    await tester.tap(signerDropdown, warnIfMissed: false);
    await tester.pumpAndSettle();
    await tester.tap(find.text('bob (own)').last);
    await tester.pumpAndSettle();
    expect(
        tester
            .widget<DropdownButtonFormField<String>>(signerDropdown)
            .initialValue,
        'bob');

    final checkboxFinder = find.ancestor(
      of: find.text(skipLabel),
      matching: find.byType(CheckboxListTile),
    );
    await tester.ensureVisible(checkboxFinder);
    await tester.pump();
    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(milliseconds: 300));

    // Verifying a specific signer is meaningless while skipping: the
    // selection must be CLEARED (not just visually frozen) and the
    // dropdown disabled, so the UI cannot claim an authenticity guarantee
    // the CLI will silently drop.
    expect(
        tester
            .widget<DropdownButtonFormField<String>>(signerDropdown)
            .initialValue,
        isNull);
    expect(
        tester
            .widget<DropdownButtonFormField<String>>(signerDropdown)
            .onChanged,
        isNull);
  });

  testWidgets('switching the operation resets the skip choice',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await enterAsymmetricDecrypt(tester);
    await chooseIdentity(tester, 'alice');

    final checkboxFinder = find.ancestor(
      of: find.text(skipLabel),
      matching: find.byType(CheckboxListTile),
    );
    await tester.ensureVisible(checkboxFinder);
    await tester.pump();
    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isTrue);

    // Encrypt and back to decrypt: the armed skip must not survive.
    final encryptRadio = find.text('Encrypt Files');
    await tester.ensureVisible(encryptRadio);
    await tester.pump();
    await tester.tap(encryptRadio);
    await tester.pump(const Duration(milliseconds: 300));

    final decryptRadio = find.text('Decrypt Files');
    await tester.ensureVisible(decryptRadio);
    await tester.pump();
    await tester.tap(decryptRadio);
    await tester.pump(const Duration(milliseconds: 300));
    await chooseIdentity(tester, 'alice');

    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isFalse);
    expect(find.textContaining(bannerFragment), findsNothing);
  });

  testWidgets('switching the encryption mode resets the skip choice',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await enterAsymmetricDecrypt(tester);
    await chooseIdentity(tester, 'alice');

    final checkboxFinder = find.ancestor(
      of: find.text(skipLabel),
      matching: find.byType(CheckboxListTile),
    );
    await tester.ensureVisible(checkboxFinder);
    await tester.pump();
    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isTrue);

    // Symmetric and back to asymmetric: the armed skip must not survive.
    final symmetric = find.textContaining('Symmetric');
    await tester.ensureVisible(symmetric.first);
    await tester.pump();
    await tester.tap(symmetric.first);
    await tester.pump(const Duration(milliseconds: 300));

    final asymmetric = find.textContaining('Asymmetric');
    await tester.ensureVisible(asymmetric.first);
    await tester.pump();
    await tester.tap(asymmetric.first);
    await tester.pump(const Duration(milliseconds: 300));
    await chooseIdentity(tester, 'alice');

    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isFalse);
    expect(find.textContaining(bannerFragment), findsNothing);
  });

  testWidgets('changing the decryption identity resets the skip choice',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await enterAsymmetricDecrypt(tester);
    await chooseIdentity(tester, 'alice');

    final checkboxFinder = find.ancestor(
      of: find.text(skipLabel),
      matching: find.byType(CheckboxListTile),
    );
    await tester.ensureVisible(checkboxFinder);
    await tester.pump();
    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(milliseconds: 300));
    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isTrue);

    // A skip choice must never survive a change of identity.
    await chooseIdentity(tester, 'bob');
    expect(tester.widget<CheckboxListTile>(checkboxFinder).value, isFalse);
    expect(find.textContaining(bannerFragment), findsNothing);
  });
}

/// Fake CLI runner serving two own identities, so the asymmetric-decrypt
/// section renders its identity selector (empty stores hide it entirely).
Future<ProcessResult> _fakeCliWithIdentities(List<String> args,
    {String? stdinInput}) async {
  if (args.length >= 2 && args[0] == 'identity' && args[1] == 'list') {
    return ProcessResult(
        0,
        0,
        jsonEncode({
          'own': [
            {'name': 'alice', 'fingerprint': 'aa:bb'},
            {'name': 'bob', 'fingerprint': 'cc:dd'},
          ],
          'contacts': <Map<String, dynamic>>[],
          'skipped': <Map<String, dynamic>>[],
        }),
        '');
  }
  if (args.isNotEmpty && args.first == 'list-available-algorithms') {
    return ProcessResult(
        0,
        0,
        jsonEncode({
          'ciphers': <String, dynamic>{},
          'hashes': <String, dynamic>{},
          'kdfs': <String, dynamic>{},
          'kems': <String, dynamic>{},
          'signatures': <String, dynamic>{},
          'libraries': <String, dynamic>{},
        }),
        '');
  }
  return ProcessResult(
      0, 1, '', 'no canned response for: ${args.join(' ')}');
}

/// Returns a fixed selection instead of opening a native file dialog.
class _StubFileManager extends FileManager {
  @override
  Future<List<FileInfo>> pickMultipleFiles({List<String>? allowedExtensions}) async {
    return [
      FileInfo(
        name: 'a.txt',
        path: '/tmp/a.txt',
        size: 10,
        extension: '.txt',
        lastModified: DateTime.fromMillisecondsSinceEpoch(0),
      ),
    ];
  }
}
