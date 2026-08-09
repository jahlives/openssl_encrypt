import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/widgets/password_strength_meter.dart';

/// Tests for the password-strength meter ported to 1.5.x (gitlab#141).
///
/// The meter shells out to `check-password --json --password-policy none`,
/// feeding the typed password on stdin. On 1.5.x check-password reads
/// CRYPT_PASSWORD BEFORE stdin, so the service must scrub it from the child
/// env or the meter would score a stale env value — that scrub is not directly
/// observable through the command-runner seam, so it is verified by review.
void main() {
  tearDown(CLIService.resetForTesting);

  group('checkPassword service', () {
    test('sends check-password --json --password-policy none on stdin and '
        'parses the report', () async {
      List<String>? seen;
      String? seenStdin;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        seen = args;
        seenStdin = stdinInput;
        return ProcessResult(
          0,
          0,
          jsonEncode({
            'length': 8,
            'bits': 42.5,
            'raw_bits': 52.6,
            'category': 'weak',
            'warnings': ['too short'],
            'valid': true,
            'failures': <String>[],
          }),
          '',
        );
      };

      final result = await CLIService.checkPassword('hunter2!');

      expect(seen, containsAllInOrder(['check-password', '--json']));
      expect(seen, containsAll(['--password-policy', 'none']));
      expect(seenStdin, 'hunter2!');
      expect(result, isNotNull);
      expect(result!.bits, 42.5);
      expect(result.category, 'weak');
      expect(result.warnings, contains('too short'));
    });

    test('an empty password returns null without invoking the CLI', () async {
      var invoked = false;
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        invoked = true;
        return ProcessResult(0, 0, '', '');
      };

      expect(await CLIService.checkPassword(''), isNull);
      expect(invoked, isFalse);
    });
  });

  group('PasswordStrengthMeter widget', () {
    testWidgets('shows a checking indicator, then the reported category',
        (WidgetTester tester) async {
      CLIService.commandRunnerOverride = (args, {stdinInput}) async {
        return ProcessResult(
          0,
          0,
          jsonEncode({
            'length': 12,
            'bits': 80.0,
            'raw_bits': 90.0,
            'category': 'strong',
            'warnings': <String>[],
            'valid': true,
            'failures': <String>[],
          }),
          '',
        );
      };

      final controller = TextEditingController();
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(body: PasswordStrengthMeter(controller: controller)),
      ));

      // Typing triggers a debounced check.
      controller.text = 'a-strong-one';
      await tester.pump(); // rebuild on controller change
      await tester.pump(const Duration(seconds: 1)); // past the debounce

      // Let the (real) CLI future resolve.
      await tester.runAsync(() => Future.delayed(const Duration(milliseconds: 100)));
      await tester.pumpAndSettle();

      expect(find.textContaining('strong', findRichText: true), findsWidgets);
    });
  });
}
