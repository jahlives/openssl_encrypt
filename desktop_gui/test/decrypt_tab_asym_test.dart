import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/tabs/decrypt_tab.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';

import 'support/fake_cli.dart';

// Regression tests for GitLab #137 / GitHub #55:
// the Decrypt tab's asymmetric-decryption fields (_decryptionIdentity /
// _verifyFrom / _skipVerification, mapped to --with-key / --verify-from /
// --no-verify) used to be declared and passed to CLIService but were never
// settable from any widget. These tests assert the controls now exist.
//
// DecryptTab.initState() calls CLIService.listIdentities() in Pro mode, so
// the fake CLI seam must be installed (gitlab#211) — a real subprocess inside
// the test binding leaves a pending timer that fails at teardown. The fake
// serves empty identity lists; the assertions depend only on static labels.
void main() {
  setUp(() {
    CLIService.commandRunnerOverride = fakeCliRunner;
  });

  tearDown(CLIService.resetForTesting);

  Widget wrap(Widget child) =>
      MaterialApp(home: Scaffold(body: child));

  testWidgets(
      'Pro mode: Advanced Options exposes a decryption-identity selector',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      wrap(DecryptTab(fileManager: FileManager(), isProMode: true)),
    );
    await tester.pumpAndSettle();

    // The Advanced Options section exists in Pro mode.
    expect(find.text('Advanced Options'), findsOneWidget);

    // Expand it.
    await tester.tap(find.text('Advanced Options'));
    await tester.pumpAndSettle();

    // The new decryption-identity control (--with-key) is present.
    expect(find.text('Decryption identity'), findsOneWidget);

    // Signature sub-options (--verify-from / --no-verify) are gated behind
    // selecting an identity, so they are hidden until one is chosen. With no
    // identity selected they must not be visible.
    expect(find.text('Skip signature verification'), findsNothing);
    expect(find.text('Verify signature from'), findsNothing);
  });

  testWidgets(
      'Simple mode: asymmetric decryption controls are hidden',
      (WidgetTester tester) async {
    await tester.pumpWidget(
      wrap(DecryptTab(fileManager: FileManager(), isProMode: false)),
    );
    await tester.pumpAndSettle();

    // No Advanced Options / identity selector in Simple mode.
    expect(find.text('Advanced Options'), findsNothing);
    expect(find.text('Decryption identity'), findsNothing);
  });
}
