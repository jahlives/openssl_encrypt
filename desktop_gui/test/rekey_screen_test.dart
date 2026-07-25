import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/rekey_screen.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';

// Widget tests for the Rekey screen (gitlab#142 / github#60).
// No CLI is invoked: with no input file selected, pressing REKEY hits the
// local validation guard and never calls CLIService.rekey.
void main() {
  Widget wrap(Widget child) => MaterialApp(home: child);

  // The button is built with ElevatedButton.icon, whose runtime type is the
  // private _ElevatedButtonWithIcon subclass. find.byType (and therefore
  // find.widgetWithText) compares runtimeType exactly and would never match
  // it, so match on the subtype instead.
  final rekeyButton = find.ancestor(
    of: find.text('REKEY'),
    matching: find.bySubtype<ElevatedButton>(),
  );

  testWidgets('renders rekey fields', (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RekeyScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.text('Rekey'), findsWidgets); // title + button label
    expect(find.text('Current password'), findsOneWidget);
    expect(find.text('New password'), findsOneWidget);
    expect(find.text('Confirm new password'), findsOneWidget);
    expect(rekeyButton, findsOneWidget);
  });

  testWidgets('validation blocks rekey with no input file',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RekeyScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    // The button sits below the fold of the 800x600 test viewport; without
    // scrolling it into view the tap lands on nothing.
    await tester.ensureVisible(rekeyButton);
    await tester.pumpAndSettle();

    await tester.tap(rekeyButton);
    await tester.pump();

    expect(find.text('Select an input file.'), findsOneWidget);
  });
}
