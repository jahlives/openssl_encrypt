import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/shred_screen.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';

// Widget tests for the Secure Shred screen (gitlab#140 / github#58).
// No CLI is invoked on load; shredding only runs after the confirmation dialog.
void main() {
  Widget wrap(Widget child) => MaterialApp(home: child);

  testWidgets('renders shred controls; SHRED disabled with no files selected',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(ShredScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.text('Secure Shred'), findsOneWidget);
    expect(find.text('Add files'), findsOneWidget);
    expect(find.text('Overwrite passes:'), findsOneWidget);

    // The button is built with ElevatedButton.icon, whose runtime type is the
    // private _ElevatedButtonWithIcon subclass. find.byType (and therefore
    // find.widgetWithText) compares runtimeType exactly and would never match
    // it, so match on the subtype instead.
    final shredFinder = find.ancestor(
      of: find.text('SHRED'),
      matching: find.bySubtype<ElevatedButton>(),
    );
    expect(shredFinder, findsOneWidget);

    // The SHRED button exists but is disabled until at least one path is added.
    final shredButton = tester.widget<ElevatedButton>(shredFinder);
    expect(shredButton.onPressed, isNull);
  });
}
