import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/widgets/password_strength_meter.dart';

// Widget tests for the password-strength meter (gitlab#141 / github#59).
// The meter only shells out to the CLI after a debounce; these tests assert
// the empty state and the immediate "checking" state, then dispose the widget
// before the debounce fires so no CLI process is ever spawned.
void main() {
  testWidgets('renders nothing for an empty password',
      (WidgetTester tester) async {
    final controller = TextEditingController();
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: PasswordStrengthMeter(controller: controller)),
    ));

    expect(find.byType(LinearProgressIndicator), findsNothing);
    expect(find.textContaining('Strength:'), findsNothing);

    controller.dispose();
  });

  testWidgets('shows a checking indicator immediately after typing',
      (WidgetTester tester) async {
    final controller = TextEditingController();
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: PasswordStrengthMeter(
          controller: controller,
          debounce: const Duration(milliseconds: 500),
        ),
      ),
    ));

    controller.text = 'some-password';
    // Pump less than the debounce window: the checking indicator is shown but
    // the CLI call has not been scheduled to fire yet.
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.byType(LinearProgressIndicator), findsOneWidget);

    // Replace the widget to dispose it and cancel the pending debounce timer,
    // so the test never actually invokes the CLI.
    await tester.pumpWidget(const SizedBox());
    controller.dispose();
  });
}
