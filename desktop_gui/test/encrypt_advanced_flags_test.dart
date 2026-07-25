import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/tabs/encrypt_tab.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

// Widget tests for the Encrypt tab's keyring / PQC-keyfile / KDF-composition
// controls (gitlab#153 / github#71), plan items P16, P17 and P19.
//
// No CLI runs: every control defaults to off/empty and nothing is encrypted.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
  });

  Widget wrap(Widget child) => MaterialApp(home: Scaffold(body: child));

  Future<void> openAdvanced(WidgetTester tester) async {
    final header = find.text('Advanced Options');
    await tester.ensureVisible(header);
    await tester.pump();
    await tester.tap(header);
    await tester.pump(const Duration(milliseconds: 400));
  }

  testWidgets('keyring, PQC keyfile and KDF composition controls are present',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(
      EncryptTab(fileManager: FileManager(), isProMode: true),
    ));
    await tester.pump();
    await openAdvanced(tester);

    expect(find.text('Load PQC key file'), findsOneWidget);
    expect(find.text('Key derivation'), findsOneWidget);
    expect(find.text('Use legacy sequential key derivation'), findsOneWidget);

    // The keyring control is deliberately absent: on this path the CLI reads
    // args.password (the -p value) and the GUI passes CRYPT_PASSWORD, so the
    // store never runs. Offering it would invite a user to discard the only
    // copy of a password that was never saved (gitlab#156).
    expect(find.textContaining('keyring'), findsNothing);
  });

  testWidgets('the legacy composition is off by default and warns',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(
      EncryptTab(fileManager: FileManager(), isProMode: true),
    ));
    await tester.pump();
    await openAdvanced(tester);

    final legacy = find.text('Use legacy sequential key derivation');
    final tile = tester.widget<SwitchListTile>(
      find.ancestor(of: legacy, matching: find.byType(SwitchListTile)),
    );
    // It pins an older format with weaker key derivation, so it must never be
    // the default and must say what it costs.
    expect(tile.value, isFalse);
    expect(find.textContaining('weakest step'), findsOneWidget);
  });

  testWidgets('parallel derivation is available by default and blocked on legacy',
      (WidgetTester tester) async {
    // The CLI does NOT reject parallel derivation without an explicit
    // composition flag, and the current default composition is already the
    // independent one — so the valid combination must not be blocked.
    await tester.pumpWidget(wrap(
      EncryptTab(fileManager: FileManager(), isProMode: true),
    ));
    await tester.pump();
    await openAdvanced(tester);

    final parallel = find.text('Parallel key derivation');
    var tile = tester.widget<SwitchListTile>(
      find.ancestor(of: parallel, matching: find.byType(SwitchListTile)),
    );
    expect(tile.onChanged, isNotNull);

    // Invoke the switch's own callback rather than simulating a tap: the point
    // under test is the dependency rule, not hit-testing a tile below the fold.
    final legacyTile = tester.widget<SwitchListTile>(
      find.ancestor(
        of: find.text('Use legacy sequential key derivation'),
        matching: find.byType(SwitchListTile),
      ),
    );
    legacyTile.onChanged!(true);
    await tester.pump();

    tile = tester.widget<SwitchListTile>(
      find.ancestor(of: parallel, matching: find.byType(SwitchListTile)),
    );
    expect(tile.onChanged, isNull);
  });

  test('CLIService refuses combinations the CLI mishandles', () async {
    // Both compositions at once: rejected by the CLI itself.
    expect(
      () => CLIService.encryptTextWithProgress(
        'x', 'pw', 'fernet', null, null,
        independentXor: true,
        useXorComposition: true,
      ),
      throwsArgumentError,
    );
    // A template already picks the composition, and the CLI lets the flag win —
    // silently downgrading the template the user asked for.
    expect(
      () => CLIService.encryptTextWithProgress(
        'x', 'pw', 'fernet', null, null,
        template: 'standard',
        useXorComposition: true,
      ),
      throwsArgumentError,
    );
    // Worker count is used verbatim by the CLI with no clamp.
    expect(
      () => CLIService.encryptTextWithProgress(
        'x', 'pw', 'fernet', null, null,
        parallelKdf: true,
        kdfWorkers: 0,
      ),
      throwsArgumentError,
    );
  });
}
