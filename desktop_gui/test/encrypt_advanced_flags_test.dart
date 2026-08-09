import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/tabs/encrypt_tab.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

// Widget tests for the Encrypt tab's PQC-keyfile / KDF-composition controls
// ported to 1.5.x (gitlab#153 / gitlab#198), plan items P17 and P19.
//
// EncryptTab.initState() shells out to the CLI for hash algorithms, so the
// fake seam is installed; no real CLI runs and nothing is encrypted.
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

  testWidgets('PQC keyfile and KDF composition controls are present, keyring is'
      ' deliberately absent', (WidgetTester tester) async {
    await tester
        .pumpWidget(wrap(EncryptTab(fileManager: FileManager(), isProMode: true)));
    await tester.pump();
    await openAdvanced(tester);

    expect(find.text('Load PQC key file'), findsOneWidget);
    expect(find.text('Key derivation'), findsOneWidget);
    expect(find.text('Use legacy sequential key derivation'), findsOneWidget);

    // Keyring is deliberately not offered: the CLI's --keyring-store reads the
    // -p value, but the GUI passes the password via CRYPT_PASSWORD, so the
    // store would never run (gitlab#156).
    expect(find.textContaining('keyring'), findsNothing);
  });

  testWidgets('the legacy composition is off by default and warns',
      (WidgetTester tester) async {
    await tester
        .pumpWidget(wrap(EncryptTab(fileManager: FileManager(), isProMode: true)));
    await tester.pump();
    await openAdvanced(tester);

    final tile = tester.widget<SwitchListTile>(
      find.ancestor(
        of: find.text('Use legacy sequential key derivation'),
        matching: find.byType(SwitchListTile),
      ),
    );
    expect(tile.value, isFalse);
    expect(find.textContaining('weakest step'), findsOneWidget);
  });

  testWidgets('no parallel-KDF control is offered on 1.5.x',
      (WidgetTester tester) async {
    // --parallel-kdf is inert on every format this line can produce (v13/v14
    // both delegate to sequential derivation — gitlab#220), so the control is
    // deliberately absent rather than shipped as a no-op that promises
    // parallelism the core does not deliver.
    await tester
        .pumpWidget(wrap(EncryptTab(fileManager: FileManager(), isProMode: true)));
    await tester.pump();
    await openAdvanced(tester);

    expect(find.text('Parallel key derivation'), findsNothing);
    expect(find.text('Worker threads:'), findsNothing);
  });

  group('encryptTextWithProgress composition validation', () {
    test('rejects asking for both compositions at once', () async {
      expect(
        CLIService.encryptTextWithProgress('x', 'pw', 'aes-gcm', null, null,
            independentXor: true, useXorComposition: true),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects a worker count outside 1..64', () async {
      expect(
        CLIService.encryptTextWithProgress('x', 'pw', 'aes-gcm', null, null,
            parallelKdf: true, kdfWorkers: 0),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
