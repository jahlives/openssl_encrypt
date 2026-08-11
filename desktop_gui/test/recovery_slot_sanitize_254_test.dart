import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

/// F19 (gitlab#254, CWE-116): recovery-slot id/type come from a file's
/// unauthenticated `list-recovery --json` output and were rendered raw in the
/// removal dialog. Flutter treats U+2028/U+2029 as line breaks and honours bidi
/// overrides, so crafted slot metadata could forge a line under the irreversible
/// removal warning. RecoverySlot.fromJson now sanitizes every displayed field;
/// the raw id is kept only for the `--slot-id` argument.
void main() {
  group('RecoverySlot.fromJson display sanitization', () {
    test('id U+2029 is escaped for display but rawId is preserved', () {
      final rawId = 'slot1\u2029FAKE: trusted';
      final slot = RecoverySlot.fromJson({'id': rawId, 'type': 'recovery_code'});

      // Display id escapes U+2029 (Flutter renders it as a mandatory line break).
      expect(slot.id.contains('\u2029'), isFalse);
      expect(slot.id.contains(r'\u2029'), isTrue);
      // Raw id is preserved verbatim for the CLI --slot-id argument.
      expect(slot.rawId, rawId);
    });

    test('unknown type (bidi override) is sanitized in typeLabel', () {
      final slot = RecoverySlot.fromJson({'id': 'x', 'type': 'evil\u202etype'});
      expect(slot.typeLabel.contains('\u202e'), isFalse);
      expect(slot.typeLabel.contains(r'\u202e'), isTrue);
    });

    test('known type labels still resolve after sanitization', () {
      expect(RecoverySlot.fromJson({'id': 'a', 'type': 'recovery_code'}).typeLabel,
          'Recovery code');
      expect(RecoverySlot.fromJson({'id': 'a', 'type': 'passphrase'}).typeLabel, 'Passphrase');
      expect(RecoverySlot.fromJson({'id': 'a', 'type': 'pqc'}).typeLabel, 'PQC escrow');
    });

    test('keyId zero-width is escaped for display', () {
      final slot =
          RecoverySlot.fromJson({'id': 'a', 'type': 'pqc', 'key_id': 'k\u200bid'});
      expect(slot.keyId, isNotNull);
      expect(slot.keyId!.contains('\u200b'), isFalse);
      expect(slot.keyId!.contains(r'\u200b'), isTrue);
    });

    test('control character (NUL) in id is escaped for display', () {
      final slot = RecoverySlot.fromJson({'id': 'a\u0000bc', 'type': 't'});
      expect(slot.id.contains('\u0000'), isFalse);
      expect(slot.id, r'a\u0000bc');
    });
  });
}
