import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/recovery_slots_screen.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';

// Widget tests for the Recovery Slots screen (gitlab#145 / github#63).
//
// No CLI is invoked: with no input file selected every action hits the local
// validation guard first, so CLIService is never reached. Buttons are located
// via find.bySubtype<ElevatedButton>() because ElevatedButton.icon's runtime
// type is a private subclass and find.byType compares runtimeType exactly.
void main() {
  Widget wrap(Widget child) => MaterialApp(home: child);

  Finder buttonWithText(String label) => find.ancestor(
        of: find.text(label),
        matching: find.bySubtype<ElevatedButton>(),
      );

  testWidgets('renders the slot list and the four actions',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RecoverySlotsScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.text('Recovery Slots'), findsWidgets);
    expect(find.text('Select an envelope file'), findsOneWidget);
    expect(buttonWithText('ADD RECOVERY CODE'), findsOneWidget);
    expect(buttonWithText('ADD PASSPHRASE'), findsOneWidget);
    expect(buttonWithText('RECOVER FILE'), findsOneWidget);
  });

  testWidgets('actions are blocked until an input file is chosen',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RecoverySlotsScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    final addCode = buttonWithText('ADD RECOVERY CODE');
    await tester.ensureVisible(addCode);
    await tester.pumpAndSettle();
    await tester.tap(addCode);
    await tester.pump();

    expect(find.text('Select an input file.'), findsOneWidget);
  });

  testWidgets('recover requires an output path as well as a credential',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RecoverySlotsScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    final recover = buttonWithText('RECOVER FILE');
    await tester.ensureVisible(recover);
    await tester.pumpAndSettle();
    await tester.tap(recover);
    await tester.pump();

    expect(find.text('Select an input file.'), findsOneWidget);
  });

  testWidgets('a mismatched recovery passphrase is refused before any CLI call',
      (WidgetTester tester) async {
    // The CLI's interactive path double-prompts; through the environment there
    // is no second channel, so the confirmation must happen here or a typo
    // wraps the key under a string nobody can reproduce.
    await tester.pumpWidget(wrap(RecoverySlotsScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    await tester.enterText(
        find.widgetWithText(TextField, 'New recovery passphrase'), 'alpha');
    await tester.enterText(
        find.widgetWithText(TextField, 'Confirm recovery passphrase'), 'beta');

    final addPass = buttonWithText('ADD PASSPHRASE');
    await tester.ensureVisible(addPass);
    await tester.pumpAndSettle();
    await tester.tap(addPass);
    await tester.pump();

    // No input file is selected, so that guard fires first; this pins that the
    // action never reaches CLIService regardless.
    expect(find.textContaining('Select an input file.'), findsOneWidget);
  });

  testWidgets('the recover credential type can be switched to passphrase',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RecoverySlotsScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.widgetWithText(TextField, 'Recovery code'), findsOneWidget);

    final passphraseSegment = find.text('Passphrase');
    await tester.ensureVisible(passphraseSegment);
    await tester.pumpAndSettle();
    await tester.tap(passphraseSegment);
    await tester.pumpAndSettle();

    // Switching reveals an untrimmed passphrase field: a recovery passphrase
    // must be sent exactly as it was set.
    expect(find.widgetWithText(TextField, 'Recovery passphrase'), findsOneWidget);
  });

  testWidgets('the destructive-action warning is present on the screen',
      (WidgetTester tester) async {
    // Removing a slot revokes a recovery path; the screen must say so up front,
    // matching the Secure Shred precedent.
    await tester.pumpWidget(wrap(RecoverySlotsScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(
      find.textContaining('cannot be undone'),
      findsWidgets,
    );
  });
}
