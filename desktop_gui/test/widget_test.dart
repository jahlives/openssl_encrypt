import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/main.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

void main() {
  setUp(() async {
    // Initialize SharedPreferences mock for tests
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
  });

  // The default UI mode is 'simple' (SettingsService.getUiMode falls back to
  // 'simple'), so the navigation rail carries exactly three destinations:
  // Encrypt, Decrypt and Settings.
  testWidgets('Desktop GUI smoke test', (WidgetTester tester) async {
    await tester.pumpWidget(const OpenSSLEncryptApp());

    expect(find.byType(MaterialApp), findsOneWidget);
    expect(find.byType(NavigationRail), findsOneWidget);

    expect(find.widgetWithText(NavigationRail, 'Encrypt'), findsOneWidget);
    expect(find.widgetWithText(NavigationRail, 'Decrypt'), findsOneWidget);
    expect(find.widgetWithText(NavigationRail, 'Settings'), findsOneWidget);

    // Pro-only destinations must stay hidden in simple mode.
    expect(
      find.widgetWithText(NavigationRail, 'Batch Operations'),
      findsNothing,
    );
    expect(find.widgetWithText(NavigationRail, 'Rekey'), findsNothing);
  });

  testWidgets('Encrypt tab UI elements present', (WidgetTester tester) async {
    await tester.pumpWidget(const OpenSSLEncryptApp());

    // Encrypt tab is selected by default: input text field and password field.
    expect(find.byType(TextField), findsWidgets);
  });

  testWidgets('Navigation switches to the settings tab',
      (WidgetTester tester) async {
    await tester.pumpWidget(const OpenSSLEncryptApp());

    await tester.tap(
      find.descendant(
        of: find.byType(NavigationRail),
        matching: find.byIcon(Icons.settings_outlined),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Settings & Preferences'), findsOneWidget);
  });

  // Regression test for gitlab#143 / github#61: _MainScreenState.dispose()
  // called setState() through _hideDebugWindow(), which asserts because the
  // element is already defunct by then.
  testWidgets('main screen tears down without throwing',
      (WidgetTester tester) async {
    await tester.pumpWidget(const OpenSSLEncryptApp());

    // Replacing the tree disposes _MainScreenState.
    await tester.pumpWidget(const SizedBox.shrink());

    expect(tester.takeException(), isNull);
  });
}
