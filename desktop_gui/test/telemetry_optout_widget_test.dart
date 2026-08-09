import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/settings_screen.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

/// Widget tests for the telemetry opt-out action in Settings (gitlab#165 P34).
///
/// Opt-out is irreversible (deletes pending events + the API key), so the GUI
/// must show its own confirmation naming what is destroyed before invoking
/// `telemetry opt-out --force`, and must not run anything on cancel.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
  });

  tearDown(CLIService.resetForTesting);

  Future<void> useTallSurface(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1400, 3200);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  }

  Widget wrap() => const MaterialApp(home: SettingsScreen());

  const optOutLabel = 'Disable telemetry and delete data';

  testWidgets('the opt-out action confirms, names what is destroyed, and only '
      'then invokes the CLI', (WidgetTester tester) async {
    var invocations = 0;
    List<String>? seen;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      invocations++;
      seen = args;
      return ProcessResult(0, 0, 'Telemetry disabled.', '');
    };

    await useTallSurface(tester);
    await tester.pumpWidget(wrap());
    await tester.pumpAndSettle();

    final button = find.text(optOutLabel);
    expect(button, findsOneWidget);
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pumpAndSettle();

    // Confirmation names the destroyed data; nothing has run yet.
    expect(find.textContaining('API key'), findsOneWidget);
    expect(find.textContaining('pending'), findsOneWidget);
    expect(invocations, 0);

    // Cancel: still nothing runs.
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();
    expect(invocations, 0);

    // Reopen and confirm: the CLI is invoked with --force.
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(ElevatedButton, 'Disable telemetry'));
    await tester.pumpAndSettle();

    expect(invocations, 1);
    expect(seen, ['telemetry', 'opt-out', '--force']);
  });
}
