// Tests for InputValidator.sanitizeForDisplay coverage (gitlab#183).
//
// The CLI's `identity list --json` channel is deliberately unsanitized
// (machine-readable), so the renderer owns display safety: CLIService
// .listIdentities sanitizes email/created_at at the decode boundary.
// Flutter honours Unicode bidi overrides in text rendering and treats
// U+2028/U+2029 as mandatory line breaks (UAX #14), so the class must
// cover more than the C0+DEL a terminal cares about.
//
// Every control character below is written as an escape on purpose: a raw
// one would be invisible in review, which is the very failure mode these
// tests exist to prevent.

import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_desktop/input_validation.dart';

void main() {
  group('sanitizeForDisplay', () {
    test('C0 controls are escaped, not blanked', () {
      expect(InputValidator.sanitizeForDisplay('a\u0000b'), r'a\u0000b');
      expect(InputValidator.sanitizeForDisplay('a\u001Bb'), r'a\u001bb');
      expect(InputValidator.sanitizeForDisplay('a\nb'), r'a\u000ab');
    });

    test('DEL and C1 are escaped', () {
      expect(InputValidator.sanitizeForDisplay('a\u007Fb'), r'a\u007fb');
      expect(InputValidator.sanitizeForDisplay('a\u009Bb'), r'a\u009bb');
    });

    test('bidi, format, line-separator and zero-width are escaped', () {
      const controls = [
        '\u202E',
        '\u202A',
        '\u2066',
        '\u200F',
        '\u200E',
        '\u061C',
        '\u2028',
        '\u2029',
        '\u200B',
        '\uFEFF',
      ];
      for (final ch in controls) {
        final out = InputValidator.sanitizeForDisplay('a${ch}b');
        expect(out.contains(ch), isFalse,
            reason: 'U+${ch.codeUnitAt(0).toRadixString(16)} must not pass');
        expect(out.startsWith(r'a\u'), isTrue, reason: out);
      }
    });

    test('backslash is escaped so the escapes cannot be forged', () {
      // A stored value containing the literal six characters \\u202e must
      // not render identically to a real U+202E that was escaped.
      expect(InputValidator.sanitizeForDisplay(r'a\u202e'), r'a\u005cu202e');
      expect(InputValidator.sanitizeForDisplay(r'a\u202e'),
          isNot(InputValidator.sanitizeForDisplay('a\u202E')));
    });

    test('a crafted bidi email cannot render reversed', () {
      const crafted = 'moc.elpmaxe@ecila\u202E';
      expect(
        InputValidator.sanitizeForDisplay(crafted).contains('\u202E'),
        isFalse,
      );
    });

    test('emoji joiners and script-critical ZWNJ/ZWJ are preserved', () {
      // U+200C/U+200D are load-bearing in Persian and Indic scripts and
      // in emoji sequences; escaping them would corrupt legitimate text.
      const joined = 'a\u200Cb\u200Dc';
      expect(InputValidator.sanitizeForDisplay(joined), joined);
    });

    test('plain text and non-ASCII pass through unchanged', () {
      expect(
        InputValidator.sanitizeForDisplay('alice@example.com'),
        'alice@example.com',
      );
      expect(InputValidator.sanitizeForDisplay('h\u00e9llo w\u00f6rld'),
          'h\u00e9llo w\u00f6rld');
      expect(InputValidator.sanitizeForDisplay('\u540d\u524d'), '\u540d\u524d');
    });
  });
}
