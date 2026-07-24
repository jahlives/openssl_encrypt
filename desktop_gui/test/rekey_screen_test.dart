import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/rekey_screen.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';

// Widget tests for the Rekey screen (gitlab#142 / github#60).
// No CLI is invoked: with no input file selected, pressing REKEY hits the
// local validation guard and never calls CLIService.rekey.
void main() {
  Widget wrap(Widget child) => MaterialApp(home: child);

  testWidgets('renders rekey fields', (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RekeyScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.text('Rekey'), findsWidgets); // title + button label
    expect(find.text('Current password'), findsOneWidget);
    expect(find.text('New password'), findsOneWidget);
    expect(find.text('Confirm new password'), findsOneWidget);
    expect(find.widgetWithText(ElevatedButton, 'REKEY'), findsOneWidget);
  });

  testWidgets('validation blocks rekey with no input file',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(RekeyScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(ElevatedButton, 'REKEY'));
    await tester.pump();

    expect(find.text('Select an input file.'), findsOneWidget);
  });
}
