import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/tabs/encrypt_tab.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

// Widget tests for "shred the source file after encrypting" (gitlab#151 /
// github#69).
//
// The GUI encrypts file-mode input by reading its text and passing it through
// the temp-file path, so the CLI's own --shred would wipe the temp file rather
// than the user's source. The source is therefore shredded as a separate step
// after a successful encryption, which is why the control lives here and is
// gated on its own confirmation.
//
// No CLI runs: the option is off by default and nothing is encrypted.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
  });

  Widget wrap(Widget child) => MaterialApp(home: Scaffold(body: child));

  // The file options live under a collapsed "Advanced Options" ExpansionTile.
  Future<void> openAdvanced(WidgetTester tester) async {
    final header = find.text('Advanced Options');
    await tester.ensureVisible(header);
    await tester.pump();
    await tester.tap(header);
    await tester.pump(const Duration(milliseconds: 400));
  }

  testWidgets('the shred-source option is present and off by default',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(
      EncryptTab(fileManager: FileManager(), isProMode: true),
    ));
    await tester.pump();
    await openAdvanced(tester);

    final option = find.text('Securely delete the source file after encrypting');
    expect(option, findsOneWidget);

    // Off by default: destroying the user's only plaintext copy must be an
    // explicit choice, never an inherited default.
    final tile = tester.widget<SwitchListTile>(
      find.ancestor(of: option, matching: find.byType(SwitchListTile)),
    );
    expect(tile.value, isFalse);
  });

  testWidgets('the option warns that the action is irreversible',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(
      EncryptTab(fileManager: FileManager(), isProMode: true),
    ));
    await tester.pump();
    await openAdvanced(tester);

    expect(
      find.textContaining('cannot be recovered'),
      findsWidgets,
    );
  });
}
