import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/password_generator_screen.dart';

// Widget tests for the Password Generator screen (gitlab#139 / github#57).
// Generation is only triggered on button press (never in initState), so these
// tests never shell out to the CLI.
void main() {
  Widget wrap(Widget child) => MaterialApp(home: child);

  testWidgets('renders mode toggle, character options, and generate button',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(const PasswordGeneratorScreen()));
    await tester.pumpAndSettle();

    expect(find.text('Password Generator'), findsOneWidget);
    expect(find.text('GENERATE'), findsOneWidget);

    // Mode toggle segments.
    expect(find.text('Character'), findsOneWidget);
    expect(find.text('Diceware'), findsOneWidget);

    // Character mode is the default: length + charset controls visible.
    expect(find.text('Length: 32'), findsOneWidget);
    expect(find.text('Lowercase (a-z)'), findsOneWidget);
    expect(find.text('Special characters'), findsOneWidget);
  });

  testWidgets('switching to Diceware shows passphrase options',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(const PasswordGeneratorScreen()));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Diceware'));
    await tester.pumpAndSettle();

    expect(find.text('Word count: 10'), findsOneWidget);
    expect(find.text('Word separator (optional)'), findsOneWidget);
    // Character-only control is gone.
    expect(find.text('Lowercase (a-z)'), findsNothing);
  });
}
