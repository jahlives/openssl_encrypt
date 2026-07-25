import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/verify_signature_screen.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';

// Widget tests for the Verify Signature screen (gitlab#158 / github#76),
// plan item P26.
//
// Verification needs no credential, so nothing here reaches the CLI: with no
// input file selected every action hits the local guard first.
void main() {
  Widget wrap(Widget child) => MaterialApp(home: child);

  Finder buttonWithText(String label) => find.ancestor(
        of: find.text(label),
        matching: find.bySubtype<ElevatedButton>(),
      );

  testWidgets('renders the inputs and the verify action',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(VerifySignatureScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.text('Verify Signature'), findsWidgets);
    expect(find.text('Select the signed file'), findsOneWidget);
    expect(buttonWithText('VERIFY'), findsOneWidget);
  });

  testWidgets('verification is blocked until a file is chosen',
      (WidgetTester tester) async {
    await tester.pumpWidget(wrap(VerifySignatureScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    final verify = buttonWithText('VERIFY');
    await tester.ensureVisible(verify);
    await tester.pumpAndSettle();
    await tester.tap(verify);
    await tester.pump();

    expect(find.text('Select the signed file.'), findsOneWidget);
  });

  testWidgets('the screen explains what pinning a signer changes',
      (WidgetTester tester) async {
    // "Signed by someone in your store" is a much weaker statement than
    // "signed by the identity you named", and the UI has to say so.
    await tester.pumpWidget(wrap(VerifySignatureScreen(fileManager: FileManager())));
    await tester.pumpAndSettle();

    expect(find.textContaining('resolved from the signature'), findsWidgets);
  });

  group('SignatureVerification', () {
    test('a bad signature is not mistaken for a verification error', () {
      // The CLI exits 1 both for "signature is invalid" and for "could not
      // check" (missing signature file, unknown signer). Only the first has a
      // JSON document; conflating them would let a genuine BAD signature be
      // reported as a mere error the user shrugs off.
      final bad = SignatureVerification.fromJson({
        'valid': false,
        'file_match': false,
        'signature_valid': true,
        'signer': 'alice',
        'signer_fingerprint': 'AB12',
        'signed_at': '2026-07-25T00:00:00Z',
        'components': [
          {'component': 'ed25519', 'valid': true}
        ],
        'reason': 'file digest does not match the signature',
      });

      expect(bad.valid, isFalse);
      expect(bad.fileMatch, isFalse);
      expect(bad.reason, contains('digest'));
      expect(bad.signer, 'alice');
    });

    test('a good signature reports every component', () {
      final good = SignatureVerification.fromJson({
        'valid': true,
        'file_match': true,
        'signature_valid': true,
        'signer': 'bob',
        'signer_fingerprint': 'CD34',
        'signed_at': '2026-07-25T00:00:00Z',
        'components': [
          {'component': 'ed25519', 'valid': true},
          {'component': 'ml-dsa-65', 'valid': true},
        ],
        'reason': '',
      });

      expect(good.valid, isTrue);
      expect(good.components.length, 2);
      expect(good.components.every((c) => c.valid), isTrue);
    });

    test('a truncated document does not read as a good signature', () {
      // {"valid": true} alone would otherwise render a full green verdict with
      // no signer, no fingerprint and no components at all — the strongest
      // reassurance built from the weakest possible document.
      final truncated = SignatureVerification.fromJson({'valid': true});
      expect(truncated.valid, isFalse);
      expect(truncated.components, isEmpty);
    });

    test('valid cannot be true while a component failed', () {
      // Re-derived rather than trusted: a document asserting overall validity
      // while carrying a failing component must not be believed.
      final lying = SignatureVerification.fromJson({
        'valid': true,
        'file_match': true,
        'signature_valid': true,
        'signer': 'mallory',
        'signer_fingerprint': 'EF56',
        'signed_at': '2026-07-25T00:00:00Z',
        'components': [
          {'component': 'ed25519', 'valid': true},
          {'component': 'ml-dsa-65', 'valid': false},
        ],
        'reason': '',
      });
      expect(lying.valid, isFalse);
    });

    test('a wrong-typed field is rejected rather than crashing the caller', () {
      // A TypeError is an Error, not an Exception, so it would escape an
      // `on Exception` guard in any future caller.
      expect(
        () => SignatureVerification.fromJson({'valid': true, 'signer': 42}),
        throwsA(anything),
      );
    });

    test('a partially valid component set is still not a good signature', () {
      // If any component fails the overall verdict must be false, so a
      // post-quantum component failing cannot be hidden by a classical one
      // passing.
      final mixed = SignatureVerification.fromJson({
        'valid': false,
        'file_match': true,
        'signature_valid': false,
        'signer': 'bob',
        'signer_fingerprint': 'CD34',
        'signed_at': '2026-07-25T00:00:00Z',
        'components': [
          {'component': 'ed25519', 'valid': true},
          {'component': 'ml-dsa-65', 'valid': false},
        ],
        'reason': 'ml-dsa-65 component failed',
      });

      expect(mixed.valid, isFalse);
      expect(mixed.components.where((c) => !c.valid).length, 1);
    });
  });
}
