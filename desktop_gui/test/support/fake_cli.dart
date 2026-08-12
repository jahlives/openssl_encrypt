import 'dart:convert';
import 'dart:io';

/// Canned `list-available-algorithms` payload matching the CLI's JSON wire
/// format (parsed by [AvailabilityInfo.fromJson]).
const Map<String, dynamic> fakeAvailabilityJson = {
  'ciphers': {
    'fernet': {
      'display_name': 'Fernet',
      'available': true,
      'security_level': 'STANDARD',
    },
    'aes-gcm': {
      'display_name': 'AES-GCM',
      'available': true,
      'security_level': 'STANDARD',
    },
    'chacha20-poly1305': {
      'display_name': 'ChaCha20-Poly1305',
      'available': true,
      'security_level': 'STANDARD',
    },
  },
  'hashes': {
    'sha256': {
      'display_name': 'SHA-256',
      'available': true,
      'security_level': 'STANDARD',
    },
    'sha512': {
      'display_name': 'SHA-512',
      'available': true,
      'security_level': 'STANDARD',
    },
    'sha3-256': {
      'display_name': 'SHA3-256',
      'available': true,
      'security_level': 'STANDARD',
    },
    'sha3-512': {
      'display_name': 'SHA3-512',
      'available': true,
      'security_level': 'STANDARD',
    },
    'shake256': {
      'display_name': 'SHAKE-256',
      'available': true,
      'security_level': 'STANDARD',
    },
    'blake2b': {
      'display_name': 'BLAKE2b',
      'available': true,
      'security_level': 'STANDARD',
    },
    'blake3': {
      'display_name': 'BLAKE3',
      'available': true,
      'security_level': 'STANDARD',
    },
  },
  'kdfs': {
    'argon2': {
      'display_name': 'Argon2',
      'available': true,
      'security_level': 'STANDARD',
    },
  },
  'kems': {},
  'signatures': {},
  'libraries': {},
};

/// Canned `identity list --include-contacts --json` payload
/// (parsed by [CLIService.listIdentities]).
const Map<String, dynamic> fakeIdentityListJson = {
  'own': <Map<String, dynamic>>[],
  'contacts': <Map<String, dynamic>>[],
  'skipped': <Map<String, dynamic>>[],
};

/// Fake CLI command runner for widget tests: answers the commands the GUI
/// issues while building its widget tree with canned data, so no real
/// subprocess (and therefore no pending timer) is ever created inside the
/// test binding (gitlab#211).
///
/// Unknown commands fail with a nonzero exit code so widgets exercise their
/// error paths instead of hanging on real process output.
Future<ProcessResult> fakeCliRunner(List<String> args,
    {String? stdinInput}) async {
  if (args.isNotEmpty && args.first == 'list-available-algorithms') {
    return ProcessResult(0, 0, jsonEncode(fakeAvailabilityJson), '');
  }
  if (args.length >= 2 && args[0] == 'identity' && args[1] == 'list') {
    return ProcessResult(0, 0, jsonEncode(fakeIdentityListJson), '');
  }
  return ProcessResult(
      0, 1, '', 'fakeCliRunner: no canned response for: ${args.join(' ')}');
}
