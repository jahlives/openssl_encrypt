import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/main.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

import 'support/fake_cli.dart';

/// Regression tests for gitlab#213: the draggable debug window lost its only
/// entry point when TextCryptoTab was removed, leaving _toggleDebugWindow
/// uncalled and the overlay unreachable. It is now wired to a Help-menu item.
void main() {
  const windowTitle = 'Live Debug Logs (Draggable Window)';

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    CLIService.commandRunnerOverride = fakeCliRunner;
  });

  tearDown(CLIService.resetForTesting);

  // The window spawns at (100,100) sized 600x500; on the default 800x600
  // test surface it would obstruct the Help dropdown, which a desktop-sized
  // window does not.
  Future<void> pumpApp(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1600, 1200);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(const OpenSSLEncryptApp());
  }

  Future<void> toggleViaHelpMenu(WidgetTester tester) async {
    await tester.tap(find.widgetWithText(SubmenuButton, 'Help'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Debug Window'));
    await tester.pumpAndSettle();
  }

  testWidgets('Help menu opens and closes the debug window',
      (WidgetTester tester) async {
    await pumpApp(tester);

    expect(find.text(windowTitle), findsNothing);

    await toggleViaHelpMenu(tester);
    expect(find.text(windowTitle), findsOneWidget);

    await toggleViaHelpMenu(tester);
    expect(find.text(windowTitle), findsNothing);
  });

  testWidgets('debug window close button hides the overlay',
      (WidgetTester tester) async {
    await pumpApp(tester);

    await toggleViaHelpMenu(tester);
    expect(find.text(windowTitle), findsOneWidget);

    await tester.tap(find.byTooltip('Close window'));
    await tester.pumpAndSettle();
    expect(find.text(windowTitle), findsNothing);
  });

  testWidgets('main screen tears down safely while the window is shown',
      (WidgetTester tester) async {
    await pumpApp(tester);

    await toggleViaHelpMenu(tester);
    expect(find.text(windowTitle), findsOneWidget);

    // Replacing the tree disposes _MainScreenState with the overlay active.
    await tester.pumpWidget(const SizedBox.shrink());

    expect(tester.takeException(), isNull);
  });
}
