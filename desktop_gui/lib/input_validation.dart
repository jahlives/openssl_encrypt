import 'dart:convert';

/// Input validation utilities for GUI security
class InputValidator {
  // Security: Maximum lengths to prevent buffer overflow attacks
  static const int maxPasswordLength = 1024;
  static const int maxTextLength = 1048576; // 1MB
  static const int maxFilenameLength = 255;
  static const int maxPathLength = 4096;

  /// Validate password input
  static String? validatePassword(String? value) {
    if (value == null) return 'Password cannot be null';

    // Security: Check for maximum length to prevent buffer overflow
    if (value.length > maxPasswordLength) {
      return 'Password exceeds maximum length of $maxPasswordLength characters';
    }

    // Security: Check for null bytes which could cause issues in CLI integration
    if (value.contains('\u0000')) {
      return 'Password contains invalid null characters';
    }

    // Security: Check for control characters that could cause command injection
    for (int i = 0; i < value.length; i++) {
      final charCode = value.codeUnitAt(i);
      // Allow printable ASCII, extended ASCII, and common Unicode ranges
      if (charCode < 32 && charCode != 9 && charCode != 10 && charCode != 13) {
        return 'Password contains invalid control characters';
      }
    }

    return null; // Valid
  }

  /// Validate text content input
  static String? validateTextContent(String? value) {
    if (value == null) return null; // Allow empty text

    // Security: Check for maximum length to prevent DoS
    if (value.length > maxTextLength) {
      return 'Text exceeds maximum length of ${maxTextLength ~/ 1024}KB';
    }

    // Security: Check for null bytes
    if (value.contains('\u0000')) {
      return 'Text contains invalid null characters';
    }

    return null; // Valid
  }

  /// Validate filename input
  static String? validateFilename(String? value) {
    if (value == null || value.isEmpty) return 'Filename cannot be empty';

    // Security: Check for maximum length
    if (value.length > maxFilenameLength) {
      return 'Filename exceeds maximum length of $maxFilenameLength characters';
    }

    // Security: Check for path traversal attempts
    if (value.contains('..') || value.contains('/') || value.contains('\\')) {
      return 'Filename contains invalid path characters';
    }

    // Security: Check for control characters and null bytes
    if (value.contains('\u0000')) {
      return 'Filename contains invalid null characters';
    }

    for (int i = 0; i < value.length; i++) {
      final charCode = value.codeUnitAt(i);
      if (charCode < 32) {
        return 'Filename contains invalid control characters';
      }
    }

    // Security: Check for reserved names (Windows)
    final reservedNames = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3',
                          'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                          'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6',
                          'LPT7', 'LPT8', 'LPT9'];
    if (reservedNames.contains(value.toUpperCase())) {
      return 'Filename is a reserved system name';
    }

    return null; // Valid
  }

  /// Validate integer input with range
  static String? validateInteger(String? value, {int? min, int? max}) {
    if (value == null || value.isEmpty) return 'Value cannot be empty';

    // Security: Check for maximum length to prevent DoS
    if (value.length > 20) {
      return 'Number is too long';
    }

    final intValue = int.tryParse(value);
    if (intValue == null) {
      return 'Must be a valid integer';
    }

    if (min != null && intValue < min) {
      return 'Value must be at least $min';
    }

    if (max != null && intValue > max) {
      return 'Value must be at most $max';
    }

    return null; // Valid
  }

  /// Sanitize string for safe display (remove/escape dangerous characters)
  static String sanitizeForDisplay(String input) {
    // NUL is escaped like every other control character, not stripped:
    // deleting it would contradict the escape rule below and hide it.
    String sanitized = input;

    // Escape, do not blank out: the CLI states the rule (crypt_utils
    // sanitize_for_display) -- keeping the evidence visible lets the user
    // tell a spoofing attempt from an unrenderable glyph, and U+FFFD is
    // itself a legal input character an attacker could pre-seed to make the
    // two indistinguishable.
    //
    // Backslash is escaped too, for the same reason the CLI escapes it: a
    // stored value containing the literal six characters \u202e must not
    // render identically to a real U+202E that was escaped, or the evidence
    // trail is forgeable.
    //
    // Covers C0, DEL, C1, the Unicode bidi/format controls, U+2028/U+2029
    // and the zero-width set (gitlab#183). Flutter honours bidi overrides in
    // text rendering, and unlike a terminal it treats U+2028/U+2029 as
    // mandatory line breaks (UAX #14), so attacker text could otherwise
    // start its own line inside trust UI. ZWNJ/ZWJ (U+200C/U+200D) are
    // deliberately NOT escaped: they are load-bearing in Persian and Indic
    // scripts and in emoji sequences. The CLI's JSON channel is
    // deliberately unsanitized (machine-readable) -- the renderer owns
    // display safety.
    sanitized = sanitized.replaceAllMapped(
      RegExp(r'[\x00-\x1F\x5C\x7F-\x9F\u061C\u200B\u200E\u200F\u202A-\u202E\u2028\u2029\u2060-\u2064\u2066-\u2069\uFEFF]'),
      (m) =>
          '\\u${m[0]!.codeUnitAt(0).toRadixString(16).padLeft(4, '0')}',
    );

    return sanitized;
  }

  /// Validate JSON input for configuration imports
  static String? validateJsonInput(String? value) {
    if (value == null || value.isEmpty) return 'JSON cannot be empty';

    // Security: Check for maximum length to prevent DoS
    if (value.length > 1048576) { // 1MB limit
      return 'JSON exceeds maximum size of 1MB';
    }

    try {
      // Security: Parse JSON to validate structure
      final parsed = json.decode(value);

      // Security: Only allow Map<String, dynamic> structure
      if (parsed is! Map<String, dynamic>) {
        return 'JSON must be an object, not an array or primitive';
      }

      // Security: Limit nesting depth to prevent stack overflow
      if (_getJsonDepth(parsed) > 10) {
        return 'JSON nesting too deep (maximum 10 levels)';
      }

      return null; // Valid
    } catch (e) {
      return 'Invalid JSON format: ${e.toString()}';
    }
  }

  /// Get JSON object nesting depth
  static int _getJsonDepth(dynamic obj, [int depth = 0]) {
    if (depth > 10) return depth; // Prevent infinite recursion

    if (obj is Map) {
      int maxDepth = depth;
      for (final value in obj.values) {
        final childDepth = _getJsonDepth(value, depth + 1);
        if (childDepth > maxDepth) maxDepth = childDepth;
      }
      return maxDepth;
    } else if (obj is List) {
      int maxDepth = depth;
      for (final item in obj) {
        final childDepth = _getJsonDepth(item, depth + 1);
        if (childDepth > maxDepth) maxDepth = childDepth;
      }
      return maxDepth;
    }

    return depth;
  }
}
