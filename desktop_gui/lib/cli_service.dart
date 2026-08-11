import 'dart:convert';

import 'input_validation.dart';
import 'dart:io';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as path;

/// Result of a `generate-password --json` invocation.
class GeneratedPassword {
  final String password;
  final double entropyBits;
  final String mode; // "character" | "diceware"
  final String? strength; // character mode only
  final int? length; // character mode only
  final int? wordCount; // diceware mode only

  GeneratedPassword({
    required this.password,
    required this.entropyBits,
    required this.mode,
    this.strength,
    this.length,
    this.wordCount,
  });

  factory GeneratedPassword.fromJson(Map<String, dynamic> json) {
    return GeneratedPassword(
      password: json['password'] as String,
      entropyBits: (json['entropy_bits'] as num).toDouble(),
      mode: json['mode'] as String,
      strength: json['strength'] as String?,
      length: (json['length'] as num?)?.toInt(),
      wordCount: (json['word_count'] as num?)?.toInt(),
    );
  }
}

/// Result of a `check-password --json` strength report.
class PasswordStrength {
  final int length;
  final double bits; // pattern-aware estimate
  final double rawBits; // raw search-space estimate
  final String category; // e.g. "very weak" .. "strong"
  final List<String> warnings;

  PasswordStrength({
    required this.length,
    required this.bits,
    required this.rawBits,
    required this.category,
    required this.warnings,
  });

  factory PasswordStrength.fromJson(Map<String, dynamic> json) {
    return PasswordStrength(
      length: (json['length'] as num?)?.toInt() ?? 0,
      bits: (json['bits'] as num?)?.toDouble() ?? 0,
      rawBits: (json['raw_bits'] as num?)?.toDouble() ?? 0,
      category: (json['category'] as String?) ?? 'unknown',
      warnings: (json['warnings'] as List<dynamic>?)
              ?.map((w) => w.toString())
              .toList() ??
          const [],
    );
  }
}

/// Service layer for integrating with OpenSSL Encrypt CLI
/// Replaces all pure Dart crypto implementations
class CLIService {
  static const String _cliPath = '/app/bin/openssl-encrypt'; // Flatpak CLI path
  static String? _flatpakBranch; // Detected Flatpak branch

  static bool debugEnabled = false;
  static String? _cliVersion;
  static String? _gitCommit;
  static String? _pythonVersion;
  static String? _systemInfo;
  static final Map<String, String> _dependencies = {};
  static bool _isFlaspakVersion = false;
  static final List<String> _debugLogs = [];
  static String? _debugLogFile;
  static VoidCallback? _onDebugLogAdded;

  // Cache for algorithm availability info (fetched once at startup)
  static AvailabilityInfo? _availabilityCache;
  static Future<AvailabilityInfo?>? _availabilityFuture;

  /// When set, every CLI invocation is answered by this function instead of
  /// spawning a subprocess. Production code must never set it: it exists so
  /// widget tests can supply canned CLI output — a real subprocess spawned
  /// inside the test binding leaves a pending timer that fails the test at
  /// teardown (gitlab#211).
  @visibleForTesting
  static Future<ProcessResult> Function(List<String> args,
      {String? stdinInput})? commandRunnerOverride;

  /// Clears the runner override and the availability cache so state cannot
  /// leak from one test into the next.
  @visibleForTesting
  static void resetForTesting() {
    commandRunnerOverride = null;
    _availabilityCache = null;
    _availabilityFuture = null;
  }

  /// Initialize CLI service and verify CLI is available
  static Future<bool> initialize() async {
    try {
      // Check if CLI is available in Flatpak environment
      if (await File(_cliPath).exists()) {
        _outputDebugLog('CLI found at: $_cliPath');
        _isFlaspakVersion = true;
        await _detectFlatpakBranch();
        await _detectVersion();
        print('=== CLI Backend Initialized ===');
        print(getVersionInfo());
        print('===============================');

        // Fetch algorithm availability info at startup (non-blocking)
        getAvailabilityInfo();

        return true;
      }

      // For development, try running CLI via parent directory
      try {
        final result = await Process.run('python', ['-m', 'openssl_encrypt.cli', '--help'],
          workingDirectory: '/home/work/private/git/openssl_encrypt');
        if (result.exitCode == 0) {
          _outputDebugLog('CLI found via development path');
          _isFlaspakVersion = false;
          await _detectVersion();
          print('=== CLI Backend Initialized ===');
          print(getVersionInfo());
          print('===============================');

          // Fetch algorithm availability info at startup (non-blocking)
          getAvailabilityInfo();

          return true;
        }
      } catch (e) {
        _outputDebugLog('Development CLI test failed: $e');
      }

      _outputDebugLog('CLI not found');
      return false;
    } catch (e) {
      _outputDebugLog('CLI initialization error: $e');
      return false;
    }
  }

  /// Get algorithm availability info (cached at startup)
  ///
  /// Concurrent callers share a single in-flight fetch instead of polling
  /// with timers, which would trip the test binding's pending-timer check
  /// (gitlab#211).
  static Future<AvailabilityInfo?> getAvailabilityInfo() {
    if (_availabilityCache != null) return Future.value(_availabilityCache);
    return _availabilityFuture ??= _fetchAvailabilityInfo();
  }

  static Future<AvailabilityInfo?> _fetchAvailabilityInfo() async {
    try {
      final result = await _runCLICommand(['list-available-algorithms']);
      if (result.exitCode == 0) {
        final json = jsonDecode(result.stdout.toString()) as Map<String, dynamic>;
        _availabilityCache = AvailabilityInfo.fromJson(json);
      }
    } catch (e) {
      _outputDebugLog('Error fetching availability info: $e');
    } finally {
      if (_availabilityCache == null) {
        // Failed fetch: drop the shared future so a later call can retry.
        _availabilityFuture = null;
      }
    }
    return _availabilityCache;
  }

  /// Check if a specific algorithm is available
  static Future<bool> isAlgorithmAvailable(
      String algorithm, String category) async {
    final info = await getAvailabilityInfo();
    if (info == null) return true; // Assume available if can't check

    switch (category) {
      case 'cipher':
        return info.ciphers[algorithm]?.available ?? true;
      case 'hash':
        return info.hashes[algorithm]?.available ?? true;
      case 'kdf':
        return info.kdfs[algorithm]?.available ?? true;
      case 'kem':
        return info.kems[algorithm]?.available ?? true;
      case 'signature':
        return info.signatures[algorithm]?.available ?? true;
      default:
        return true;
    }
  }

  /// Get list of supported algorithms organized by category
  static Future<Map<String, List<String>>> getSupportedAlgorithms() async {
    try {
      final availabilityInfo = await getAvailabilityInfo();
      if (availabilityInfo == null) {
        // Fallback to basic algorithms if availability info not available
        return {
          'Classical Symmetric': [
            'fernet',
            'aes-gcm', 'aes-gcm-siv', 'aes-siv',
            'chacha20-poly1305', 'xchacha20-poly1305',
          ],
        };
      }

      final result = <String, List<String>>{};

      // Build Classical Symmetric category with all classical ciphers
      // Ordered by family: Fernet first, then AES, ChaCha, Threefish
      final classicalSymmetric = <String>[];

      // Fernet first
      if (availabilityInfo.ciphers.containsKey('fernet')) {
        classicalSymmetric.add('fernet');
      }

      // AES Family
      final aesCiphers = availabilityInfo.ciphers.entries
          .where((e) => e.key.startsWith('aes-'))
          .map((e) => e.key)
          .toList()..sort();
      classicalSymmetric.addAll(aesCiphers);

      // ChaCha Family
      final chachaCiphers = availabilityInfo.ciphers.entries
          .where((e) => e.key.contains('chacha20') && !e.key.contains('ml-kem'))
          .map((e) => e.key)
          .toList()..sort();
      classicalSymmetric.addAll(chachaCiphers);

      // Threefish (Large Block)
      final threefishCiphers = availabilityInfo.ciphers.entries
          .where((e) => e.key.startsWith('threefish-'))
          .map((e) => e.key)
          .toList()..sort();
      classicalSymmetric.addAll(threefishCiphers);

      if (classicalSymmetric.isNotEmpty) {
        result['Classical Symmetric'] = classicalSymmetric;
      }

      // Post-Quantum Hybrid (ML-KEM) - hardcoded since not in cipher registry
      result['Post-Quantum Hybrid (ML-KEM)'] = [
        'ml-kem-512-hybrid',
        'ml-kem-768-hybrid',
        'ml-kem-1024-hybrid',
      ];

      // Post-Quantum ChaCha20 - hardcoded since not in cipher registry
      result['Post-Quantum ChaCha20'] = [
        'ml-kem-512-chacha20',
        'ml-kem-768-chacha20',
        'ml-kem-1024-chacha20',
      ];

      // Post-Quantum Hybrid (Kyber Legacy) - hardcoded since not in cipher registry
      result['Post-Quantum Hybrid (Kyber Legacy)'] = [
        'kyber512-hybrid',
        'kyber768-hybrid',
        'kyber1024-hybrid',
      ];

      // Post-Quantum HQC - hardcoded since not in cipher registry
      result['Post-Quantum HQC'] = [
        'hqc-128-hybrid',
        'hqc-192-hybrid',
        'hqc-256-hybrid',
      ];

      // Post-Quantum Signatures (MAYO) - hardcoded since not in cipher registry
      result['Post-Quantum Signatures (MAYO)'] = [
        'mayo-1-hybrid',
        'mayo-3-hybrid',
        'mayo-5-hybrid',
      ];

      // Post-Quantum Signatures (CROSS) - hardcoded since not in cipher registry
      result['Post-Quantum Signatures (CROSS)'] = [
        'cross-128-hybrid',
        'cross-192-hybrid',
        'cross-256-hybrid',
      ];

      return result;
    } catch (e) {
      _outputDebugLog('Error getting algorithms: $e');
      // Return basic algorithms if there's an error
      return {
        'Classical Symmetric': ['fernet', 'aes-gcm', 'chacha20-poly1305'],
      };
    }
  }

  /// Get flat list of all algorithms for backward compatibility
  static Future<List<String>> getSupportedAlgorithmsList() async {
    final categorized = await getSupportedAlgorithms();
    final allAlgorithms = <String>[];
    for (final category in categorized.values) {
      allAlgorithms.addAll(category);
    }
    return allAlgorithms;
  }

  /// Get list of supported hash algorithms organized by category
  static Future<Map<String, List<String>>> getHashAlgorithms() async {
    try {
      final availabilityInfo = await getAvailabilityInfo();
      if (availabilityInfo == null) {
        // Fallback to basic hash algorithms if availability info not available
        return {
          'SHA-2 Family': ['sha256', 'sha384', 'sha512'],
          'SHA-3 Family': ['sha3-256', 'sha3-384', 'sha3-512'],
          'SHAKE (XOF)': ['shake128', 'shake256'],
          'BLAKE Family': ['blake2b', 'blake2s', 'blake3'],
        };
      }

      final result = <String, List<String>>{};

      // SHA-2 Family
      final sha2Hashes = availabilityInfo.hashes.entries
          .where((e) => e.key.startsWith('sha') && !e.key.startsWith('sha3-') && !e.key.startsWith('shake'))
          .map((e) => e.key)
          .toList();
      // Add sha224 if not already present (may not be in registry but supported by CLI)
      if (!sha2Hashes.contains('sha224')) {
        sha2Hashes.insert(0, 'sha224');
      }
      sha2Hashes.sort();
      if (sha2Hashes.isNotEmpty) {
        result['SHA-2 Family'] = sha2Hashes;
      }

      // SHA-3 Family
      final sha3Hashes = availabilityInfo.hashes.entries
          .where((e) => e.key.startsWith('sha3-'))
          .map((e) => e.key)
          .toList();
      // Add sha3-224 if not already present (may not be in registry but supported by CLI)
      if (!sha3Hashes.contains('sha3-224')) {
        sha3Hashes.insert(0, 'sha3-224');
      }
      sha3Hashes.sort();
      if (sha3Hashes.isNotEmpty) {
        result['SHA-3 Family'] = sha3Hashes;
      }

      // SHAKE (XOF)
      final shakeHashes = availabilityInfo.hashes.entries
          .where((e) => e.key.startsWith('shake'))
          .map((e) => e.key)
          .toList()..sort();
      if (shakeHashes.isNotEmpty) {
        result['SHAKE (XOF)'] = shakeHashes;
      }

      // BLAKE Family
      final blakeHashes = availabilityInfo.hashes.entries
          .where((e) => e.key.startsWith('blake'))
          .map((e) => e.key)
          .toList()..sort();
      if (blakeHashes.isNotEmpty) {
        result['BLAKE Family'] = blakeHashes;
      }

      // NOTE: WHIRLPOOL is intentionally excluded. It is decrypt-only on
      // 1.4 and removed entirely in 1.5, and no subparser declares
      // --whirlpool-rounds, so offering it produced argv that exited 2
      // (gitlab#189).

      return result;
    } catch (e) {
      _outputDebugLog('Error getting hash algorithms: $e');
      // Return basic hash algorithms if there's an error
      return {
        'SHA-2 Family': ['sha256', 'sha512'],
        'BLAKE Family': ['blake2b'],
      };
    }
  }

  /// Get flat list of all hash algorithms for backward compatibility
  static Future<List<String>> getHashAlgorithmsList() async {
    final categorized = await getHashAlgorithms();
    final allHashAlgorithms = <String>[];
    for (final category in categorized.values) {
      allHashAlgorithms.addAll(category);
    }
    return allHashAlgorithms;
  }

  /// Encrypt text using CLI with progress callbacks
  static Future<String> encryptTextWithProgress(
    String text,
    String password,
    String algorithm,
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
    {String? encryptData,
     String? hsmPlugin,
     int? hsmSlot,
     bool enableIntegrity = false,
     List<String>? forIdentities,      // Asymmetric: recipients
     String? signWith,                  // Asymmetric: signing identity
     bool useKeyserver = false,         // Asymmetric: keyserver lookup
     String? identityStore,             // Asymmetric: identity store path
     String? cascadePreset,             // Cascade: 'standard', 'paranoia', or null for custom
     List<String>? cascadeAlgorithms,   // Cascade: custom algorithm chain
     String cascadeHash = 'sha256',     // Cascade: HKDF hash function
     bool noDiversityCheck = false,     // Cascade: --no-diversity-check
     bool strictDiversity = false,      // Cascade: --strict-diversity
     bool forcePassword = false,        // Force acceptance of weak passwords
     bool enablePepper = false,         // Remote pepper: enable pepper plugin
     String? pepperName,                // Remote pepper: named pepper to use
     bool showProgress = false,         // CLI --progress flag
     String? template,                  // Security template: 'standard', 'quick', 'paranoid'
     String? pqcKeyfile,                // Path to LOAD an existing PQC key file
     bool independentXor = false,       // KDF composition: independent XOR
     bool useXorComposition = false,    // KDF composition: sequential XOR (v13-pinned)
     bool parallelKdf = false,          // Parallel key derivation (independent composition)
     int? kdfWorkers,                   // Worker count for parallel key derivation
     Function(String)? onProgress,
     Function(String)? onStatus}
  ) async {
    // The CLI does not validate this pair (verified: no check anywhere in
    // crypt_cli.py), and the current default composition already IS independent
    // XOR, so parallel derivation is valid without an explicit flag. What is
    // genuinely invalid is asking for both compositions at once, which
    // crypt_cli.py:8421-8427 rejects.
    if (independentXor && useXorComposition) {
      throw ArgumentError(
        'Choose either independent XOR or sequential XOR composition, not both.',
      );
    }
    // Sequential composition pins the legacy v13 format. A security template
    // forces independent XOR, and crypt_cli.py:7093 lets the composition flag
    // win — silently downgrading the template the user asked for.
    if (template != null && (useXorComposition || independentXor)) {
      throw ArgumentError(
        'A security template already selects the key-derivation composition; '
        'do not override it.',
      );
    }
    if (kdfWorkers != null && (kdfWorkers < 1 || kdfWorkers > 64)) {
      // Since gitlab#220/#224 the CLI itself clamps the pool (CPU count,
      // component count and a concurrent-memory ceiling); this guard is
      // defense-in-depth against sending a nonsensical flag value.
      throw ArgumentError('Key-derivation workers must be between 1 and 64.');
    }
    Directory? tempDir;
    try {
      // Create temporary directory with restrictive permissions
      tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_');

      // Security: Set restrictive permissions on temp directory first (prevents race condition)
      if (!Platform.isWindows) {
        try {
          await Process.run('chmod', ['700', tempDir.path]);
        } catch (e) {
          _outputDebugLog('Warning: Could not set restrictive permissions on temp directory: $e');
        }
      }

      final inputFile = File('${tempDir.path}/input.txt');
      final outputFile = File('${tempDir.path}/output.txt');

      // Create files atomically with secure permissions (Unix-like systems)
      if (!Platform.isWindows) {
        try {
          // Use install command to atomically create files with 0o600 permissions
          await Process.run('install', ['-m', '600', '/dev/null', inputFile.path]);
          await Process.run('install', ['-m', '600', '/dev/null', outputFile.path]);
        } catch (e) {
          _outputDebugLog('Warning: install command not available, falling back to write+chmod: $e');
          // Fallback: create empty files, chmod will be applied after write
          await inputFile.create();
          await outputFile.create();
          await Process.run('chmod', ['600', inputFile.path]);
          await Process.run('chmod', ['600', outputFile.path]);
        }
      } else {
        // Windows: create files normally (Windows has different permission model)
        await inputFile.create();
        await outputFile.create();
      }

      // Write data to the already-protected input file
      await inputFile.writeAsString(text);

      // Build CLI command - password passed via environment variable for security
      final args = [
        'encrypt',
        '-i', inputFile.path,
        '-o', outputFile.path,
      ];

      // When a template is specified, use --standard/--quick/--paranoid flag
      // and skip individual algorithm/hash/kdf arguments
      if (template != null) {
        args.add('--$template');
      } else {
        args.addAll(['--algorithm', algorithm]);
      }

      // Add HSM configuration if provided
      if (hsmPlugin != null && hsmPlugin != 'none') {
        args.addAll(['--hsm', hsmPlugin]);
        if (hsmSlot != null) {
          args.addAll(['--hsm-slot', hsmSlot.toString()]);
        }
      }

      // Add hash configuration if provided (skip when using template)
      if (hashConfig != null && template == null) {
        for (final entry in hashConfig.entries) {
          final hashName = entry.key;
          final config = entry.value;
          if (config['enabled'] == true && config['rounds'] != null && config['rounds'] > 0) {
            switch (hashName) {
              case 'sha256':
                args.addAll(['--sha256-rounds', config['rounds'].toString()]);
                break;
              case 'sha512':
                args.addAll(['--sha512-rounds', config['rounds'].toString()]);
                break;
              case 'blake2b':
                args.addAll(['--blake2b-rounds', config['rounds'].toString()]);
                break;
              case 'blake3':
                args.addAll(['--blake3-rounds', config['rounds'].toString()]);
                break;
              case 'shake256':
                args.addAll(['--shake256-rounds', config['rounds'].toString()]);
                break;
              case 'shake128':
                args.addAll(['--shake128-rounds', config['rounds'].toString()]);
                break;
              case 'sha224':
                args.addAll(['--sha224-rounds', config['rounds'].toString()]);
                break;
              case 'sha384':
                args.addAll(['--sha384-rounds', config['rounds'].toString()]);
                break;
              case 'sha3-224':
                args.addAll(['--sha3-224-rounds', config['rounds'].toString()]);
                break;
              case 'sha3-256':
                args.addAll(['--sha3-256-rounds', config['rounds'].toString()]);
                break;
              case 'sha3-384':
                args.addAll(['--sha3-384-rounds', config['rounds'].toString()]);
                break;
              case 'sha3-512':
                args.addAll(['--sha3-512-rounds', config['rounds'].toString()]);
                break;
            }
          }
        }
      }

      // Add KDF configuration if provided (skip when using template)
      if (kdfConfig != null && template == null) {
        for (final entry in kdfConfig.entries) {
          final kdfName = entry.key;
          final config = entry.value;
          if (config['enabled'] == true) {
            switch (kdfName) {
              case 'pbkdf2':
                if (config['enabled'] == true && config['iterations'] != null && config['iterations'] > 0) {
                  args.addAll(['--pbkdf2-iterations', config['iterations'].toString()]);
                }
                break;
              case 'scrypt':
                if (config['enabled'] == true) {
                  args.add('--enable-scrypt');
                  if (config['n'] != null) args.addAll(['--scrypt-n', config['n'].toString()]);
                  if (config['r'] != null) args.addAll(['--scrypt-r', config['r'].toString()]);
                  if (config['p'] != null) args.addAll(['--scrypt-p', config['p'].toString()]);
                  if (config['rounds'] != null) args.addAll(['--scrypt-rounds', config['rounds'].toString()]);
                }
                break;
              case 'argon2':
                if (config['enabled'] == true) {
                  args.add('--enable-argon2');
                  if (config['time_cost'] != null) args.addAll(['--argon2-time', config['time_cost'].toString()]);
                  if (config['memory_cost'] != null) args.addAll(['--argon2-memory', config['memory_cost'].toString()]);
                  if (config['parallelism'] != null) args.addAll(['--argon2-parallelism', config['parallelism'].toString()]);
                  if (config['hash_len'] != null) args.addAll(['--argon2-hash-len', config['hash_len'].toString()]);
                  if (config['type'] != null) {
                    final typeMap = {0: 'd', 1: 'i', 2: 'id'};
                    args.addAll(['--argon2-type', typeMap[config['type']] ?? 'id']);
                  }
                  if (config['rounds'] != null) args.addAll(['--argon2-rounds', config['rounds'].toString()]);
                }
                break;
              case 'hkdf':
                if (config['enabled'] == true) {
                  args.add('--enable-hkdf');
                  if (config['rounds'] != null) args.addAll(['--hkdf-rounds', config['rounds'].toString()]);
                  if (config['algorithm'] != null) args.addAll(['--hkdf-algorithm', config['algorithm']]);
                  if (config['info'] != null) args.addAll(['--hkdf-info', config['info']]);
                }
                break;
              case 'balloon':
                if (config['enabled'] == true) {
                  args.add('--enable-balloon');
                  if (config['time_cost'] != null) args.addAll(['--balloon-time-cost', config['time_cost'].toString()]);
                  if (config['space_cost'] != null) args.addAll(['--balloon-space-cost', config['space_cost'].toString()]);
                  if (config['parallelism'] != null) args.addAll(['--balloon-parallelism', config['parallelism'].toString()]);
                  if (config['rounds'] != null) args.addAll(['--balloon-rounds', config['rounds'].toString()]);
                  if (config['hash_len'] != null) args.addAll(['--balloon-hash-len', config['hash_len'].toString()]);
                }
                break;
              case 'randomx':
                if (config['enabled'] == true) {
                  args.add('--enable-randomx');
                  if (config['rounds'] != null) args.addAll(['--randomx-rounds', config['rounds'].toString()]);
                  if (config['mode'] != null) args.addAll(['--randomx-mode', config['mode']]);
                  if (config['height'] != null) args.addAll(['--randomx-height', config['height'].toString()]);
                  if (config['hash_len'] != null) args.addAll(['--randomx-hash-len', config['hash_len'].toString()]);
                }
                break;
            }
          }
        }
      }

      // Add post-quantum specific parameters
      if (_isPostQuantumAlgorithm(algorithm)) {
        args.add('--pqc-store-key');
        args.add('--dual-encrypt-key');
        if (encryptData != null) {
          args.addAll(['--encryption-data', encryptData]);
        }
      }

      // Add integrity plugin if enabled
      if (enableIntegrity) {
        args.add('--integrity');
      }

      // Add pepper plugin parameters if enabled
      if (enablePepper) {
        if (pepperName != null && pepperName.isNotEmpty) {
          args.addAll(['--pepper-name', pepperName]);
        } else {
          args.add('--pepper');
        }
      }

      // Add asymmetric encryption parameters if provided
      if (forIdentities != null && forIdentities.isNotEmpty) {
        for (final recipient in forIdentities) {
          args.addAll(['--for-identity', recipient]);
        }
        if (signWith != null && signWith.isNotEmpty) {
          args.addAll(['--sign-with', signWith]);
        }
        if (identityStore != null && identityStore.isNotEmpty) {
          args.addAll(['--identity-store', identityStore]);
        }
        if (useKeyserver) {
          args.add('--use-keyserver');
        }
      }

      // Add cascade encryption parameters if provided
      if (cascadePreset != null || cascadeAlgorithms != null) {
        if (cascadePreset != null && cascadePreset != 'custom') {
          // Use preset: --cascade=standard or --cascade=paranoia
          args.add('--cascade=$cascadePreset');
        } else if (cascadeAlgorithms != null && cascadeAlgorithms.isNotEmpty) {
          // Custom chain: --cascade --algorithm algo1,algo2,algo3
          args.add('--cascade');
          args.addAll(['--algorithm', cascadeAlgorithms.join(',')]);
        }
        // Add HKDF hash function
        args.addAll(['--cascade-hash', cascadeHash]);
        // Add diversity check options
        if (noDiversityCheck) {
          args.add('--no-diversity-check');
        }
        if (strictDiversity) {
          args.add('--strict-diversity');
        }
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      // Add force password if enabled
      if (forcePassword) {
        args.add('--force-password');
      }
      if (pqcKeyfile != null && pqcKeyfile.isNotEmpty) {
        args.addAll(['--pqc-keyfile', pqcKeyfile]);
      }
      if (independentXor) {
        args.add('--independent-xor');
      }
      if (useXorComposition) {
        args.add('--use-xor-composition');
      }
      if (parallelKdf) {
        args.add('--parallel-kdf');
      }
      if (kdfWorkers != null) {
        args.addAll(['--kdf-workers', '$kdfWorkers']);
      }


      // Add progress flag if enabled
      if (showProgress) {
        args.add('--progress');
      }

      final maskedCommand = _getMaskedCommand(args);
      _outputDebugLog('=== CLI ENCRYPT COMMAND ===');
      _outputDebugLog('Full command: $maskedCommand');
      _outputDebugLog('Raw args (masked): ${_getMaskedCommand(args)}');

      final result = await _runCLICommandWithProgress(
        args,
        environment: {'CRYPT_PASSWORD': password},
        commandForStatus: maskedCommand,
        onStdout: (line) {
          if (debugEnabled) _outputDebugLog('CLI stdout: $line');
        },
        onStderr: (line) {
          if (debugEnabled) _outputDebugLog('CLI stderr: $line');
        },
        onProgress: (line) {
          onProgress?.call(line);
        },
        onStatus: (line) {
          onStatus?.call(line);
        },
      );

      if (result.exitCode != 0) {
        final errorMsg = result.stderr.toString().trim();
        final stdoutMsg = result.stdout.toString().trim();
        _outputDebugLog('CLI encryption failed. Exit code: ${result.exitCode}');
        _outputDebugLog('Stderr: $errorMsg');
        // An error path is exactly when stdout may hold partially written
        // plaintext or a credential; length only.
        _outputDebugLog('Stdout: <suppressed, ${stdoutMsg.length} chars>');
        throw Exception('Encryption failed: ${errorMsg.isNotEmpty ? errorMsg : "exit ${result.exitCode}"}\n\nCommand executed: $maskedCommand');
      }

      // Read encrypted output
      if (!await outputFile.exists()) {
        throw Exception('CLI did not create output file');
      }

      final encryptedContent = await outputFile.readAsString();

      // Cleanup temporary files
      await tempDir.delete(recursive: true);

      return encryptedContent.trim();
    } catch (e) {
      _outputDebugLog('Encryption error: $e');
      onStatus?.call('Encryption failed: $e');
      // Try to cleanup temp files even on error
      if (tempDir != null) {
        try {
          if (await tempDir.exists()) {
            await tempDir.delete(recursive: true);
          }
        } catch (cleanupError) {
          _outputDebugLog('Temp cleanup error: $cleanupError');
        }
      }
      throw Exception('Encryption failed: $e');
    }
  }

  /// Legacy encrypt method for backward compatibility
  static Future<String> encryptText(
    String text,
    String password,
    String algorithm,
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
    {String? encryptData}
  ) async {
    return encryptTextWithProgress(text, password, algorithm, hashConfig, kdfConfig, encryptData: encryptData);
  }


  /// Decrypt text using CLI with progress callbacks
  static Future<String> decryptTextWithProgress(
    String encryptedData,
    String password,
    {String? hsmPlugin,
     int? hsmSlot,
     bool verifyIntegrity = false,
     String? withKey,                // Asymmetric: decryption identity
     String? verifyFrom,             // Asymmetric: sender verification
     bool skipVerification = false,  // Asymmetric: skip signature check
     bool forcePassword = false,     // Force acceptance of weak passwords
     bool showProgress = false,      // CLI --progress flag
     Function(String)? onProgress,
     Function(String)? onStatus,
     Future<bool> Function(String)? onIntegrityPrompt}
  ) async {
    Directory? tempDir;
    try {
      // Create temporary directory with restrictive permissions
      tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_');

      // Security: Set restrictive permissions on temp directory first (prevents race condition)
      if (!Platform.isWindows) {
        try {
          await Process.run('chmod', ['700', tempDir.path]);
        } catch (e) {
          _outputDebugLog('Warning: Could not set restrictive permissions on temp directory: $e');
        }
      }

      final inputFile = File('${tempDir.path}/input.txt');
      final outputFile = File('${tempDir.path}/output.txt');

      // Create files atomically with secure permissions (Unix-like systems)
      if (!Platform.isWindows) {
        try {
          // Use install command to atomically create files with 0o600 permissions
          await Process.run('install', ['-m', '600', '/dev/null', inputFile.path]);
          await Process.run('install', ['-m', '600', '/dev/null', outputFile.path]);
        } catch (e) {
          _outputDebugLog('Warning: install command not available, falling back to write+chmod: $e');
          // Fallback: create empty files, chmod will be applied after write
          await inputFile.create();
          await outputFile.create();
          await Process.run('chmod', ['600', inputFile.path]);
          await Process.run('chmod', ['600', outputFile.path]);
        }
      } else {
        // Windows: create files normally (Windows has different permission model)
        await inputFile.create();
        await outputFile.create();
      }

      // Write data to the already-protected input file
      await inputFile.writeAsString(encryptedData);

      // Check if file requires HSM for decryption
      final hsmRequired = requiresHsm(encryptedData);
      _outputDebugLog('Decrypt: HSM required = $hsmRequired');

      // Build CLI command - password passed via environment variable for security
      final args = [
        'decrypt',
        '-i', inputFile.path,
        '-o', outputFile.path,
      ];

      // Add HSM arguments if specified
      if (hsmPlugin != null && hsmPlugin != 'none') {
        args.addAll(['--hsm', hsmPlugin]);
        if (hsmSlot != null) {
          args.addAll(['--hsm-slot', hsmSlot.toString()]);
        }
      }

      // Add integrity verification if enabled
      if (verifyIntegrity) {
        args.add('--verify-integrity');
      }

      // Add asymmetric decryption parameters if provided
      if (withKey != null && withKey.isNotEmpty) {
        args.addAll(['--with-key', withKey]);
        // Never emit --verify-from together with --no-verify: the CLI
        // silently prefers --no-verify, so the pair would claim an
        // authenticity check that never happens. The tabs prevent the
        // combination in the UI; this keeps every (future) caller honest.
        if (skipVerification) {
          args.add('--no-verify');
        } else if (verifyFrom != null && verifyFrom.isNotEmpty) {
          args.addAll(['--verify-from', verifyFrom]);
        }
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      // Add force password if enabled
      if (forcePassword) {
        args.add('--force-password');
      }

      // Add progress flag if enabled
      if (showProgress) {
        args.add('--progress');
      }

      final maskedCommand = _getMaskedCommand(args);
      _outputDebugLog('=== CLI DECRYPT COMMAND ===');
      _outputDebugLog('Full command: $maskedCommand');
      _outputDebugLog('Raw args (masked): ${_getMaskedCommand(args)}');

      // Use interactive method if integrity verification with callback is enabled
      final ProcessResult result;
      if (verifyIntegrity && onIntegrityPrompt != null) {
        _outputDebugLog('Using interactive CLI for integrity verification');
        result = await _runCLICommandWithInteraction(
          args,
          environment: {'CRYPT_PASSWORD': password},
          commandForStatus: maskedCommand,
          hsmDetectionEnabled: hsmRequired,
          onIntegrityPrompt: onIntegrityPrompt,
          onStdout: (line) {
            if (debugEnabled) _outputDebugLog('CLI stdout: $line');
          },
          onStderr: (line) {
            if (debugEnabled) _outputDebugLog('CLI stderr: $line');
          },
          onProgress: (line) {
            onProgress?.call(line);
          },
          onStatus: (line) {
            onStatus?.call(line);
          },
        );
      } else {
        result = await _runCLICommandWithProgress(
          args,
          environment: {'CRYPT_PASSWORD': password},
          commandForStatus: maskedCommand,
          hsmDetectionEnabled: hsmRequired,
          onStdout: (line) {
            if (debugEnabled) _outputDebugLog('CLI stdout: $line');
          },
          onStderr: (line) {
            if (debugEnabled) _outputDebugLog('CLI stderr: $line');
          },
          onProgress: (line) {
            onProgress?.call(line);
          },
          onStatus: (line) {
            onStatus?.call(line);
          },
        );
      }

      if (result.exitCode != 0) {
        final errorMsg = result.stderr.toString().trim();
        final stdoutMsg = result.stdout.toString().trim();
        _outputDebugLog('CLI decryption failed. Exit code: ${result.exitCode}');
        _outputDebugLog('Stderr: $errorMsg');
        // An error path is exactly when stdout may hold partially written
        // plaintext or a credential; length only.
        _outputDebugLog('Stdout: <suppressed, ${stdoutMsg.length} chars>');
        throw Exception('Decryption failed: ${errorMsg.isNotEmpty ? errorMsg : "exit ${result.exitCode}"}\n\nCommand executed: $maskedCommand');
      }

      // Read decrypted output
      if (!await outputFile.exists()) {
        throw Exception('CLI did not create output file');
      }

      final decryptedContent = await outputFile.readAsString();

      // Cleanup temporary files
      await tempDir.delete(recursive: true);

      return decryptedContent.trim();
    } catch (e) {
      _outputDebugLog('Decryption error: $e');
      onStatus?.call('Decryption failed: $e');
      // Try to cleanup temp files even on error
      if (tempDir != null) {
        try {
          if (await tempDir.exists()) {
            await tempDir.delete(recursive: true);
          }
        } catch (cleanupError) {
          _outputDebugLog('Temp cleanup error: $cleanupError');
        }
      }
      throw Exception('Decryption failed: $e');
    }
  }

  /// Legacy decrypt method for backward compatibility
  static Future<String> decryptText(String encryptedData, String password) async {
    return decryptTextWithProgress(encryptedData, password);
  }

  /// Parse encrypted file metadata to check for HSM configuration
  /// Returns true if the encrypted file requires HSM/YubiKey for decryption
  static bool requiresHsm(String encryptedData) {
    try {
      // Format: base64(metadata):base64(encrypted_data)
      final colonIndex = encryptedData.indexOf(':');
      if (colonIndex == -1) {
        _outputDebugLog('requiresHsm: No colon found in encrypted data');
        return false;
      }

      final metadataB64 = encryptedData.substring(0, colonIndex);
      final metadataBytes = base64Decode(metadataB64);
      final metadataJson = utf8.decode(metadataBytes);
      final metadata = jsonDecode(metadataJson) as Map<String, dynamic>;

      // Check for hsm_plugin in encryption config
      final encryption = metadata['encryption'] as Map<String, dynamic>?;
      final hasHsm = encryption?.containsKey('hsm_plugin') ?? false;

      _outputDebugLog('requiresHsm: HSM plugin present = $hasHsm');
      return hasHsm;
    } catch (e) {
      _outputDebugLog('requiresHsm: Parse error - $e');
      return false; // Assume no HSM on parse failure
    }
  }


  /// Run CLI command with appropriate executable path
  /// Run a CLI command and return its result.
  ///
  /// [logStdout] must be false for commands whose stdout contains secret
  /// material (e.g. `generate-password --json`, whose stdout is the generated
  /// password). When false, the debug log records only the stdout length, so a
  /// secret cannot land in the persistent debug log under --debug.
  ///
  /// Defaults to NOT logging stdout: it carries data (decrypted plaintext,
  /// generated credentials), so logging is opted into per call rather than
  /// opted out of.
  ///
  /// [environment] is merged over the inherited environment for this child
  /// only. Secrets belong here rather than on argv, which is visible in the
  /// world-readable /proc/PID/cmdline; the CLI consumes each variable on read
  /// so it is not inherited further.
  static Future<ProcessResult> _runCLICommand(List<String> args,
      {bool logStdout = false, Map<String, String>? environment}) async {
    final override = commandRunnerOverride;
    if (override != null) return override(args);

    // Strip inherited credential variables before applying ours. If this
    // process itself inherited e.g. OPENSSL_ENCRYPT_RECOVERY_CODE, the CLI
    // would use it to unlock INSTEAD of the password the user typed, silently.
    // Clearing to '' is not equivalent -- the CLI refuses a set-but-empty
    // credential -- so the key must be absent.
    Map<String, String>? childEnv;
    if (environment != null) {
      childEnv = {...Platform.environment};
      for (final name in _credentialEnvNames) {
        childEnv.remove(name);
      }
      childEnv.addAll(environment);
    }

    // When running inside Flatpak, use direct CLI path for better performance and reliability
    if (_isFlaspakVersion && await File(_cliPath).exists()) {
      _outputDebugLog('Using direct Flatpak CLI: $_cliPath ${_getMaskedCommand(args)}');
      final result = await Process.run(_cliPath, args, environment: childEnv);
      _outputDebugLog('Flatpak CLI exit code: ${result.exitCode}');
      return result;
    }

    // Try development CLI when not in Flatpak environment
    try {
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];

      _outputDebugLog('Attempting development CLI: ${_getMaskedCommand(args)}');
      _outputDebugLog('Working directory: /home/work/private/git/openssl_encrypt');

      // Check if input file exists before calling CLI
      for (int i = 0; i < args.length; i++) {
        if (args[i] == '-i' && i + 1 < args.length) {
          final inputFile = File(args[i + 1]);
          final exists = await inputFile.exists();
          final size = exists ? await inputFile.length() : 0;
          _outputDebugLog('Input file ${args[i + 1]}: exists=$exists, size=${size}bytes');
          break;
        }
      }

      // Add environment debugging
      final env = Map<String, String>.from(Platform.environment);
      _outputDebugLog('Environment PATH: ${env['PATH']}');
      _outputDebugLog('Environment LD_LIBRARY_PATH: ${env['LD_LIBRARY_PATH'] ?? 'not set'}');
      _outputDebugLog('Environment PYTHONPATH: ${env['PYTHONPATH'] ?? 'not set'}');

      if (environment != null) {
        for (final name in _credentialEnvNames) {
          env.remove(name);
        }
        env.addAll(environment);
      }
      final result = await Process.run('python', pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: env);

      _outputDebugLog('Development CLI exit code: ${result.exitCode}');
      if (logStdout) {
        _outputDebugLog('Development CLI stdout: ${result.stdout}');
      } else {
        // Secret-bearing stdout (e.g. a generated password): log only length.
        _outputDebugLog(
            'Development CLI stdout: <redacted, ${(result.stdout as String).length} chars>');
      }
      _outputDebugLog('Development CLI stderr: ${result.stderr}');

      return result;
    } catch (e) {
      _outputDebugLog('Development CLI exception: $e');
      throw Exception('No CLI available');
    }
  }

  /// Run CLI command with stdin input (for passphrases, etc.)
  static Future<ProcessResult> _runCLICommandWithStdin(List<String> args, String stdinInput,
      {Map<String, String>? environment}) async {
    final override = commandRunnerOverride;
    if (override != null) return override(args, stdinInput: stdinInput);

    Process process;

    // When running inside Flatpak, use direct CLI path
    if (_isFlaspakVersion && await File(_cliPath).exists()) {
      _outputDebugLog('Using direct Flatpak CLI with stdin: $_cliPath ${_getMaskedCommand(args)}');
      // When an explicit environment is given it is authoritative (used to
      // remove vars like CRYPT_PASSWORD that would override the stdin value).
      process = environment != null
          ? await Process.start(_cliPath, args,
              environment: environment, includeParentEnvironment: false)
          : await Process.start(_cliPath, args);
    } else {
      // Development CLI
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];
      _outputDebugLog('Attempting development CLI with stdin: python ${pythonArgs.join(' ')}');

      // includeParentEnvironment is false in both cases: with it true the
      // parent environment is merged back over `env`, which would undo the
      // credential scrub entirely. _inheritableEnvironment() is a full copy
      // of the parent minus credentials, so nothing else is lost.
      final env = environment ?? _inheritableEnvironment();
      process = await Process.start('python', pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: env,
        includeParentEnvironment: false);
    }

    final result = await pumpStdinAndCollect(process, stdinInput);
    _outputDebugLog('CLI with stdin exit code: ${result.exitCode}');
    return result;
  }

  /// Write [stdinInput] to [process] and collect its output, draining
  /// stdout/stderr CONCURRENTLY with the write (gitlab#175).
  ///
  /// Two properties this ordering guarantees, which a write-then-drain order
  /// does not:
  ///  - No deadlock: a child that emits more than a pipe buffer (~64 KiB)
  ///    before it reads stdin cannot wedge against a larger payload, because
  ///    we are already reading its output while we write.
  ///  - No masking: if the child exits before reading stdin, the
  ///    `write`/`flush`/`close` raises a broken-pipe `SocketException`; we
  ///    swallow it so the child's real exit code and stderr are what the
  ///    caller sees, not the write failure (which hid the true argparse error
  ///    from a stale CLI bundle).
  ///
  /// Public as a test seam: the commandRunnerOverride injection short-circuits
  /// the real process path, so this is the only way to exercise the actual
  /// pipe behaviour.
  static Future<ProcessResult> pumpStdinAndCollect(
    Process process,
    String stdinInput,
  ) async {
    // Start draining before writing stdin.
    final stdoutFuture = process.stdout.transform(utf8.decoder).join();
    final stderrFuture = process.stderr.transform(utf8.decoder).join();

    try {
      process.stdin.write(stdinInput);
      if (!stdinInput.endsWith('\n')) {
        process.stdin.write('\n');
      }
      await process.stdin.flush();
      await process.stdin.close();
    } on IOException {
      // The child closed stdin early (e.g. exited before reading it, or does
      // not accept --data-stdin). Its exit code and stderr below carry the
      // real reason; do not let the write failure mask them. Caught as the
      // IOException supertype, not just SocketException: a broken child pipe
      // surfaces as SocketException on POSIX but can be a different IOException
      // subtype elsewhere, and the guarantee should not be platform-specific.
    }

    final stdout = await stdoutFuture;
    final stderr = await stderrFuture;
    final exitCode = await process.exitCode;

    return ProcessResult(process.pid, exitCode, stdout, stderr);
  }

  /// Run CLI command with real-time progress streaming
  static Future<ProcessResult> _runCLICommandWithProgress(
    List<String> args,
    {Map<String, String>? environment, Function(String)? onStdout, Function(String)? onStderr, Function(String)? onProgress, Function(String)? onStatus, String? commandForStatus, bool hsmDetectionEnabled = false}
  ) async {
    final override = commandRunnerOverride;
    if (override != null) return override(args);

    Process process;

    // Merge environment variables for secure password passing.
    //
    // The credential scrub runs unconditionally, not only when an explicit
    // `environment` map is passed: this is the helper encrypt and decrypt use,
    // so a credential inherited from the GUI's own environment would otherwise
    // reach the child on the path that matters most.
    final processEnv = _inheritableEnvironment();
    processEnv['PYTHONUNBUFFERED'] = '1';  // Force unbuffered Python output for real-time YubiKey prompts
    if (environment != null) {
      processEnv.addAll(environment);
    }

    // Prefer development CLI when available due to Flatpak post-quantum issues
    try {
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];
      process = await Process.start('python', pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: processEnv);
      _outputDebugLog('Using development CLI with progress (python module)');
    } catch (e) {
      _outputDebugLog('Development CLI unavailable: ${_safeProcessError(e)}, trying Flatpak CLI with progress');
      // Fallback to Flatpak CLI
      if (await File(_cliPath).exists()) {
        process = await Process.start(_cliPath, args, environment: processEnv);
        _outputDebugLog('Using Flatpak CLI with progress');
      } else {
        throw Exception('No CLI available');
      }
    }

    // Capture stdout and stderr streams
    final stdoutBuffer = StringBuffer();
    final stderrBuffer = StringBuffer();

    // Listen to stdout stream
    process.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      stdoutBuffer.writeln(line);
      onStdout?.call(line);

      // Parse progress information from CLI output
      if (line.contains('Progress:') || line.contains('%') || line.contains('Processing')) {
        onProgress?.call(line);
      }

      final lowerLine = line.toLowerCase();

      // Only detect HSM/YubiKey prompts if HSM was actually used during encryption
      if (hsmDetectionEnabled) {
        // Detect HSM/YubiKey touch completion (pepper derived = touch was successful)
        if (lowerLine.contains('hardware pepper derived') ||
            lowerLine.contains('pepper derived')) {
          // Show executed command immediately after touch is detected
          if (commandForStatus != null) {
            onStatus?.call('Executed: $commandForStatus');
          } else {
            onStatus?.call('YubiKey touch registered, processing...');
          }
        }
        // Detect HSM/YubiKey touch prompts (waiting for touch)
        else if (lowerLine.contains('touch') ||
            lowerLine.contains('press') ||
            lowerLine.contains('yubikey') ||
            lowerLine.contains('waiting for') ||
            lowerLine.contains('user presence') ||
            lowerLine.contains('confirm on device')) {
          onStatus?.call(line);
        }
      }

      // Pass through any status/info messages
      if (line.contains('INFO:') || line.contains('Status:')) {
        onStatus?.call(line);
      }
    });

    // Listen to stderr stream
    process.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      stderrBuffer.writeln(line);
      onStderr?.call(line);

      // Some CLI tools output progress to stderr
      if (line.contains('Progress:') || line.contains('%') || line.contains('Processing')) {
        onProgress?.call(line);
      }

      final lowerLine = line.toLowerCase();

      // Only detect HSM/YubiKey prompts if HSM was actually used during encryption
      if (hsmDetectionEnabled) {
        // Detect HSM/YubiKey touch completion (pepper derived = touch was successful)
        if (lowerLine.contains('hardware pepper derived') ||
            lowerLine.contains('pepper derived')) {
          // Show executed command immediately after touch is detected
          if (commandForStatus != null) {
            onStatus?.call('Executed: $commandForStatus');
          } else {
            onStatus?.call('YubiKey touch registered, processing...');
          }
        }
        // Detect HSM/YubiKey touch prompts in stderr as well (waiting for touch)
        else if (lowerLine.contains('touch') ||
            lowerLine.contains('press') ||
            lowerLine.contains('yubikey') ||
            lowerLine.contains('waiting for') ||
            lowerLine.contains('user presence') ||
            lowerLine.contains('confirm on device')) {
          onStatus?.call(line);
        }
      }

      // Pass through any status/info messages
      if (line.contains('INFO:') || line.contains('Status:')) {
        onStatus?.call(line);
      }
    });

    // Wait for process completion
    final exitCode = await process.exitCode;

    // Return a ProcessResult-compatible object
    return ProcessResult(
      process.pid,
      exitCode,
      stdoutBuffer.toString(),
      stderrBuffer.toString(),
    );
  }

  /// Run CLI command with real-time progress streaming and interactive stdin support
  /// Used for commands that may require user confirmation (e.g., integrity verification)
  static Future<ProcessResult> _runCLICommandWithInteraction(
    List<String> args,
    {Map<String, String>? environment,
     Function(String)? onStdout,
     Function(String)? onStderr,
     Function(String)? onProgress,
     Function(String)? onStatus,
     String? commandForStatus,
     bool hsmDetectionEnabled = false,
     Future<bool> Function(String)? onIntegrityPrompt}
  ) async {
    Process process;

    // Merge environment variables for secure password passing.
    // Scrubbed unconditionally, like the other spawn helpers: this one serves
    // decrypt when integrity verification is interactive.
    final processEnv = _inheritableEnvironment();
    processEnv['PYTHONUNBUFFERED'] = '1';  // Force unbuffered Python output
    if (environment != null) {
      processEnv.addAll(environment);
    }

    // Prefer development CLI when available
    try {
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];
      process = await Process.start('python', pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: processEnv);
      _outputDebugLog('Using development CLI with interaction (python module)');
    } catch (e) {
      _outputDebugLog('Development CLI unavailable: ${_safeProcessError(e)}, trying Flatpak CLI with interaction');
      // Fallback to Flatpak CLI
      if (await File(_cliPath).exists()) {
        process = await Process.start(_cliPath, args, environment: processEnv);
        _outputDebugLog('Using Flatpak CLI with interaction');
      } else {
        throw Exception('No CLI available');
      }
    }

    // Capture stdout and stderr streams
    final stdoutBuffer = StringBuffer();
    final stderrBuffer = StringBuffer();
    bool integrityPromptDetected = false;

    // Listen to stdout stream with integrity prompt detection
    process.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) async {
      stdoutBuffer.writeln(line);
      onStdout?.call(line);

      // Parse progress information from CLI output
      if (line.contains('Progress:') || line.contains('%') || line.contains('Processing')) {
        onProgress?.call(line);
      }

      final lowerLine = line.toLowerCase();

      // Detect integrity verification failure prompt
      if (!integrityPromptDetected &&
          (line.contains('INTEGRITY VERIFICATION FAILED') ||
           line.contains('Do you want to proceed anyway?'))) {
        integrityPromptDetected = true;
        _outputDebugLog('Integrity prompt detected, showing dialog');

        if (onIntegrityPrompt != null) {
          try {
            final shouldProceed = await onIntegrityPrompt(line);
            _outputDebugLog('User response to integrity prompt: $shouldProceed');

            if (shouldProceed) {
              // Write 'y' to stdin to continue
              process.stdin.writeln('y');
              await process.stdin.flush();
              _outputDebugLog('Sent "y" to CLI stdin');
            } else {
              // User chose to abort, kill the process
              _outputDebugLog('User aborted, killing process');
              process.kill();
            }
          } catch (e) {
            _outputDebugLog('Error handling integrity prompt: $e');
            process.kill();
          }
        } else {
          // No callback provided, kill process (fail-safe)
          _outputDebugLog('No integrity callback, killing process');
          process.kill();
        }
      }

      // Only detect HSM/YubiKey prompts if HSM was actually used during encryption
      if (hsmDetectionEnabled) {
        // Detect HSM/YubiKey touch completion (pepper derived = touch was successful)
        if (lowerLine.contains('hardware pepper derived') ||
            lowerLine.contains('pepper derived')) {
          // Show executed command immediately after touch is detected
          if (commandForStatus != null) {
            onStatus?.call('Executed: $commandForStatus');
          } else {
            onStatus?.call('YubiKey touch registered, processing...');
          }
        }
        // Detect HSM/YubiKey touch prompts (waiting for touch)
        else if (lowerLine.contains('touch') ||
            lowerLine.contains('press') ||
            lowerLine.contains('yubikey') ||
            lowerLine.contains('waiting for') ||
            lowerLine.contains('user presence') ||
            lowerLine.contains('confirm on device')) {
          onStatus?.call(line);
        }
      }

      // Pass through any status/info messages
      if (line.contains('INFO:') || line.contains('Status:')) {
        onStatus?.call(line);
      }
    });

    // Listen to stderr stream
    process.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      stderrBuffer.writeln(line);
      onStderr?.call(line);

      // Some CLI tools output progress to stderr
      if (line.contains('Progress:') || line.contains('%') || line.contains('Processing')) {
        onProgress?.call(line);
      }

      final lowerLine = line.toLowerCase();

      // Only detect HSM/YubiKey prompts if HSM was actually used during encryption
      if (hsmDetectionEnabled) {
        // Detect HSM/YubiKey touch completion (pepper derived = touch was successful)
        if (lowerLine.contains('hardware pepper derived') ||
            lowerLine.contains('pepper derived')) {
          // Show executed command immediately after touch is detected
          if (commandForStatus != null) {
            onStatus?.call('Executed: $commandForStatus');
          } else {
            onStatus?.call('YubiKey touch registered, processing...');
          }
        }
        // Detect HSM/YubiKey touch prompts in stderr as well (waiting for touch)
        else if (lowerLine.contains('touch') ||
            lowerLine.contains('press') ||
            lowerLine.contains('yubikey') ||
            lowerLine.contains('waiting for') ||
            lowerLine.contains('user presence') ||
            lowerLine.contains('confirm on device')) {
          onStatus?.call(line);
        }
      }

      // Pass through any status/info messages
      if (line.contains('INFO:') || line.contains('Status:')) {
        onStatus?.call(line);
      }
    });

    // Wait for process completion
    final exitCode = await process.exitCode;

    // Return a ProcessResult-compatible object
    return ProcessResult(
      process.pid,
      exitCode,
      stdoutBuffer.toString(),
      stderrBuffer.toString(),
    );
  }

  /// Initialize debug log file
  static Future<void> _initializeDebugLogFile() async {
    if (debugEnabled && _debugLogFile == null) {
      try {
        // Use user's Documents directory or fallback to temp
        final documentsDir = Directory(path.join(
          Platform.environment['HOME'] ?? '/tmp',
          'Documents'
        ));

        final logDir = Directory(path.join(documentsDir.path, 'OpenSSL_Encrypt_Logs'));
        if (!await logDir.exists()) {
          await logDir.create(recursive: true);
        }
        // gitlab#215 review F4: the log can contain sensitive operational
        // detail; restrict the directory to the owner.
        if (!Platform.isWindows) {
          try {
            await Process.run('chmod', ['700', logDir.path]);
          } catch (_) {}
        }

        final timestamp = DateTime.now().toIso8601String().replaceAll(':', '-').substring(0, 19);
        _debugLogFile = path.join(logDir.path, 'debug_$timestamp.log');

        // Write initial header
        final headerInfo = [
          '=== OpenSSL Encrypt Desktop Debug Log ===',
          'Started: ${DateTime.now().toIso8601String()}',
          'Backend: ${_isFlaspakVersion ? 'Flatpak' : 'Development'}',
          'CLI Version: ${_cliVersion ?? 'Unknown'}',
          'WARNING: this log may contain sensitive operational detail '
              '(file paths, argv, error text). Secret VALUES are masked, but '
              'treat this file as confidential and delete it when done.',
          '==========================================',
          ''
        ];

        final file = File(_debugLogFile!);
        await file.writeAsString(headerInfo.join('\n'));
        // Owner-only: the log lands in ~/Documents (default 0644 umask).
        if (!Platform.isWindows) {
          try {
            await Process.run('chmod', ['600', _debugLogFile!]);
          } catch (_) {}
        }

        outputDebugLog('Debug log file initialized: $_debugLogFile');
      } catch (e) {
        print('Failed to initialize debug log file: $e');
      }
    }
  }

  /// Debug logging utility - internal use
  static void _outputDebugLog(String message) {
    if (debugEnabled) {
      final timestamp = DateTime.now().toIso8601String().substring(11, 19);
      final logEntry = '[$timestamp] [CLI-SERVICE] $message';
      print(logEntry);
      _debugLogs.add(logEntry);

      // Write to file
      _writeLogToFile(logEntry);

      // Keep only last 100 log entries to prevent memory issues
      if (_debugLogs.length > 100) {
        _debugLogs.removeAt(0);
      }

      // Notify listeners of new debug log entry
      _onDebugLogAdded?.call();
    }
  }

  /// Public debug logging utility for other components
  static void outputDebugLog(String message) {
    if (debugEnabled) {
      final timestamp = DateTime.now().toIso8601String().substring(11, 19);
      final logEntry = '[$timestamp] [DEBUG] $message';
      print(logEntry);
      _debugLogs.add(logEntry);

      // Write to file
      _writeLogToFile(logEntry);

      // Keep only last 100 log entries to prevent memory issues
      if (_debugLogs.length > 100) {
        _debugLogs.removeAt(0);
      }
    }
  }

  /// Write log entry to file
  static void _writeLogToFile(String logEntry) {
    if (_debugLogFile != null) {
      try {
        final file = File(_debugLogFile!);
        file.writeAsStringSync('$logEntry\n', mode: FileMode.append);
      } catch (e) {
        // Silently fail to avoid infinite logging loops
      }
    }
  }

  /// Get debug logs for display in UI
  static List<String> getDebugLogs() {
    return List.from(_debugLogs);
  }

  /// Clear debug logs
  static void clearDebugLogs() {
    _debugLogs.clear();
  }

  /// Get debug log file path
  static String? getDebugLogFile() {
    return _debugLogFile;
  }

  /// Set callback to be notified when new debug logs are added
  static void setDebugLogCallback(VoidCallback? callback) {
    _onDebugLogAdded = callback;
  }

  /// Enable debug logging with file initialization
  static Future<void> enableDebugLogging() async {
    debugEnabled = true;
    await _initializeDebugLogFile();
  }

  /// Disable debug logging
  static void disableDebugLogging() {
    debugEnabled = false;
    _debugLogFile = null;
  }

  /// Detect CLI version information
  static Future<void> _detectVersion() async {
    try {
      final result = await _runCLICommand(['version']);

      if (result.exitCode == 0) {
        final output = result.stdout.toString();

        // Parse version output
        // Expected format: "openssl_encrypt: v1.1.0 (commit: d324c72f169aebdd2134eafb4fe06aa04692ccd3)"
        final versionRegex = RegExp(r'openssl_encrypt:\s*v([0-9.]+(?:-rc\d+)?)\s*\(commit:\s*([a-f0-9]+)\)');
        final pythonRegex = RegExp(r'Python:\s*(.+)');
        final systemRegex = RegExp(r'System:\s*(.+)');

        final versionMatch = versionRegex.firstMatch(output);
        if (versionMatch != null) {
          _cliVersion = versionMatch.group(1);
          _gitCommit = versionMatch.group(2);
        }

        final pythonMatch = pythonRegex.firstMatch(output);
        if (pythonMatch != null) {
          _pythonVersion = pythonMatch.group(1);
        }

        final systemMatch = systemRegex.firstMatch(output);
        if (systemMatch != null) {
          _systemInfo = systemMatch.group(1);
        }

        // Parse dependencies section
        _dependencies.clear();
        final lines = output.split('\n');
        bool inDependencies = false;
        for (final line in lines) {
          if (line.trim() == 'Dependencies:') {
            inDependencies = true;
            continue;
          }
          if (inDependencies && line.trim().isNotEmpty) {
            // Parse dependency lines like "  cryptography: 44.0.3"
            final depMatch = RegExp(r'^\s*([^:]+):\s*(.+)$').firstMatch(line);
            if (depMatch != null) {
              _dependencies[depMatch.group(1)!.trim()] = depMatch.group(2)!.trim();
            } else if (!line.startsWith('  ')) {
              // End of dependencies section
              break;
            }
          }
        }

        _outputDebugLog('CLI Version: $_cliVersion');
        _outputDebugLog('Git Commit: $_gitCommit');
        _outputDebugLog('Python: $_pythonVersion');
        _outputDebugLog('System: $_systemInfo');
        _outputDebugLog('Flatpak: $_isFlaspakVersion');
      }
    } catch (e) {
      _outputDebugLog('Version detection failed: $e');
    }
  }

  /// Detect current Flatpak branch from environment or process info
  static Future<void> _detectFlatpakBranch() async {
    try {
      // Try to detect branch from FLATPAK_DEST environment variable
      String? flatpakDest = Platform.environment['FLATPAK_DEST'];
      if (flatpakDest != null && flatpakDest.contains('app/com.opensslencrypt.OpenSSLEncrypt')) {
        _outputDebugLog('FLATPAK_DEST: $flatpakDest');
      }

      // Try to detect from process command line by checking parent processes
      try {
        final result = await Process.run('flatpak', ['ps', '--columns=application,branch']);
        if (result.exitCode == 0) {
          final output = result.stdout.toString();
          final lines = output.split('\n');

          for (final line in lines) {
            if (line.contains('com.opensslencrypt.OpenSSLEncrypt')) {
              // Parse format: "com.opensslencrypt.OpenSSLEncrypt	branch"
              final parts = line.split('\t');
              if (parts.length >= 2 && parts[0].trim() == 'com.opensslencrypt.OpenSSLEncrypt') {
                _flatpakBranch = parts[1].trim();
                _outputDebugLog('Detected Flatpak branch: $_flatpakBranch');
                return;
              }
            }
          }
        }
      } catch (e) {
        _outputDebugLog('Failed to detect branch from flatpak ps: $e');
      }

      // Fallback: try to detect from process environment
      try {
        final procSelfCmdline = await File('/proc/self/cmdline').readAsString();
        final cmdlineArgs = procSelfCmdline.split('\x00');

        for (final arg in cmdlineArgs) {
          if (arg.contains('com.opensslencrypt.OpenSSLEncrypt//')) {
            final branchMatch = RegExp(r'com\.opensslencrypt\.OpenSSLEncrypt//([^\s/]+)').firstMatch(arg);
            if (branchMatch != null) {
              _flatpakBranch = branchMatch.group(1);
              _outputDebugLog('Detected Flatpak branch from cmdline: $_flatpakBranch');
              return;
            }
          }
        }
      } catch (e) {
        _outputDebugLog('Failed to read /proc/self/cmdline: $e');
      }

      _outputDebugLog('No specific Flatpak branch detected, using default');
    } catch (e) {
      _outputDebugLog('Flatpak branch detection failed: $e');
    }
  }

  /// Get CLI version string
  static String? get cliVersion => _cliVersion;

  /// Get git commit hash
  static String? get gitCommit => _gitCommit;

  /// Get Python version information
  static String? get pythonVersion => _pythonVersion;

  /// Get system information
  static String? get systemInfo => _systemInfo;

  /// Check if running via Flatpak
  static bool get isFlatpakVersion => _isFlaspakVersion;

  /// Get formatted version information
  static String getVersionInfo() {
    if (_cliVersion == null) {
      return 'CLI version not detected';
    }

    String info = 'OpenSSL Encrypt CLI v$_cliVersion';
    if (_gitCommit != null) {
      info += ' (${_gitCommit!.substring(0, 8)})';
    }
    info += '\n';

    if (_pythonVersion != null) {
      info += 'Python: $_pythonVersion\n';
    }

    if (_systemInfo != null) {
      info += 'System: $_systemInfo\n';
    }

    String backendInfo = _isFlaspakVersion
        ? (_flatpakBranch != null
            ? 'Flatpak (com.opensslencrypt.OpenSSLEncrypt//$_flatpakBranch)'
            : 'Flatpak (/app/bin/openssl-encrypt)')
        : 'Development (python -m openssl_encrypt.cli)';
    info += 'Backend: $backendInfo\n';

    // Add dependencies if available
    if (_dependencies.isNotEmpty) {
      info += '\nDependencies:\n';
      _dependencies.forEach((name, version) {
        info += '  $name: $version\n';
      });
    }

    return info.trim();
  }

  /// Compare version strings (returns true if current >= target)
  static bool isVersionAtLeast(String targetVersion) {
    if (_cliVersion == null) return false;

    try {
      return _compareVersions(_cliVersion!, targetVersion) >= 0;
    } catch (e) {
      _outputDebugLog('Version comparison failed: $e');
      return false;
    }
  }

  /// Compare two version strings (returns -1, 0, or 1)
  static int _compareVersions(String version1, String version2) {
    // Remove 'rc' suffixes for comparison
    final v1Clean = version1.replaceAll(RegExp(r'-rc\d+'), '');
    final v2Clean = version2.replaceAll(RegExp(r'-rc\d+'), '');

    final v1Parts = v1Clean.split('.').map(int.parse).toList();
    final v2Parts = v2Clean.split('.').map(int.parse).toList();

    // Pad shorter version with zeros
    while (v1Parts.length < v2Parts.length) {
      v1Parts.add(0);
    }
    while (v2Parts.length < v1Parts.length) {
      v2Parts.add(0);
    }

    for (int i = 0; i < v1Parts.length; i++) {
      if (v1Parts[i] < v2Parts[i]) return -1;
      if (v1Parts[i] > v2Parts[i]) return 1;
    }

    return 0;
  }

  /// Check if legacy algorithms should be hidden (CLI v1.2+)
  static bool shouldHideLegacyAlgorithms() {
    return isVersionAtLeast('1.2.0');
  }

  /// Generate CLI command preview without execution
  static String previewEncryptCommand(
    String inputText,
    String password,
    String algorithm,
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
  ) {
    final args = <String>[
      'encrypt',
      '-i', '[input-file]',
      '-o', '[output-file]',
      '--algorithm', algorithm,
    ];

    // Add hash configuration if provided
    if (hashConfig != null) {
      for (final entry in hashConfig.entries) {
        final hashName = entry.key;
        final config = entry.value;
        if (config['enabled'] == true && config['rounds'] != null && config['rounds'] > 0) {
          switch (hashName) {
            case 'sha256':
              args.addAll(['--sha256-rounds', config['rounds'].toString()]);
              break;
            case 'sha512':
              args.addAll(['--sha512-rounds', config['rounds'].toString()]);
              break;
            case 'blake2b':
              args.addAll(['--blake2b-rounds', config['rounds'].toString()]);
              break;
            case 'blake3':
              args.addAll(['--blake3-rounds', config['rounds'].toString()]);
              break;
            case 'shake256':
              args.addAll(['--shake256-rounds', config['rounds'].toString()]);
              break;
            case 'shake128':
              args.addAll(['--shake128-rounds', config['rounds'].toString()]);
              break;
            case 'sha224':
              args.addAll(['--sha224-rounds', config['rounds'].toString()]);
              break;
            case 'sha384':
              args.addAll(['--sha384-rounds', config['rounds'].toString()]);
              break;
            case 'sha3-224':
              args.addAll(['--sha3-224-rounds', config['rounds'].toString()]);
              break;
            case 'sha3-256':
              args.addAll(['--sha3-256-rounds', config['rounds'].toString()]);
              break;
            case 'sha3-384':
              args.addAll(['--sha3-384-rounds', config['rounds'].toString()]);
              break;
            case 'sha3-512':
              args.addAll(['--sha3-512-rounds', config['rounds'].toString()]);
              break;
          }
        }
      }
    }

    // Add KDF configuration if provided
    if (kdfConfig != null) {
      for (final entry in kdfConfig.entries) {
        final kdfName = entry.key;
        final config = entry.value;
        if (config['enabled'] == true) {
          switch (kdfName) {
            case 'pbkdf2':
              if (config['enabled'] == true && config['iterations'] != null && config['iterations'] > 0) {
                args.addAll(['--pbkdf2-iterations', config['iterations'].toString()]);
              }
              break;
            case 'scrypt':
              if (config['enabled'] == true) {
                args.add('--enable-scrypt');
                if (config['n'] != null) args.addAll(['--scrypt-n', config['n'].toString()]);
                if (config['r'] != null) args.addAll(['--scrypt-r', config['r'].toString()]);
                if (config['p'] != null) args.addAll(['--scrypt-p', config['p'].toString()]);
                if (config['rounds'] != null) args.addAll(['--scrypt-rounds', config['rounds'].toString()]);
              }
              break;
            case 'argon2':
              if (config['enabled'] == true) {
                args.add('--enable-argon2');
                if (config['time_cost'] != null) args.addAll(['--argon2-time', config['time_cost'].toString()]);
                if (config['memory_cost'] != null) args.addAll(['--argon2-memory', config['memory_cost'].toString()]);
                if (config['parallelism'] != null) args.addAll(['--argon2-parallelism', config['parallelism'].toString()]);
                if (config['hash_len'] != null) args.addAll(['--argon2-hash-len', config['hash_len'].toString()]);
                if (config['type'] != null) {
                  final typeMap = {0: 'd', 1: 'i', 2: 'id'};
                  args.addAll(['--argon2-type', typeMap[config['type']] ?? 'id']);
                }
                if (config['rounds'] != null) args.addAll(['--argon2-rounds', config['rounds'].toString()]);
              }
              break;
            case 'hkdf':
              if (config['enabled'] == true) {
                args.add('--enable-hkdf');
                if (config['rounds'] != null) args.addAll(['--hkdf-rounds', config['rounds'].toString()]);
                if (config['algorithm'] != null) args.addAll(['--hkdf-algorithm', config['algorithm']]);
                if (config['info'] != null) args.addAll(['--hkdf-info', config['info']]);
              }
              break;
            case 'balloon':
              if (config['enabled'] == true) {
                args.add('--enable-balloon');
                if (config['time_cost'] != null) args.addAll(['--balloon-time-cost', config['time_cost'].toString()]);
                if (config['space_cost'] != null) args.addAll(['--balloon-space-cost', config['space_cost'].toString()]);
                if (config['parallelism'] != null) args.addAll(['--balloon-parallelism', config['parallelism'].toString()]);
                if (config['rounds'] != null) args.addAll(['--balloon-rounds', config['rounds'].toString()]);
                if (config['hash_len'] != null) args.addAll(['--balloon-hash-len', config['hash_len'].toString()]);
              }
              break;
          }
        }
      }
    }

    if (debugEnabled) {
      args.add('--debug');
    }

    // Add force password for simple passwords
    args.add('--force-password');

    // Show actual command that would be executed with secure environment variable
    String commandPrefix = '';
    if (_isFlaspakVersion) {
      commandPrefix = '/app/bin/openssl-encrypt';
    } else {
      commandPrefix = 'python -m openssl_encrypt.cli';
    }

    return 'CRYPT_PASSWORD="[password]" $commandPrefix ${_getMaskedCommand(args)}';
  }

  /// Generate CLI command preview for decryption without execution
  static String previewDecryptCommand(String password) {
    final args = <String>[
      'decrypt',
      '-i', '[encrypted-file]',
      '-o', '[output-file]',
    ];

    if (debugEnabled) {
      args.add('--debug');
    }

    // Add force password for simple passwords
    args.add('--force-password');

    // Show actual command that would be executed with secure environment variable
    String commandPrefix = '';
    if (_isFlaspakVersion) {
      commandPrefix = '/app/bin/openssl-encrypt';
    } else {
      commandPrefix = 'python -m openssl_encrypt.cli';
    }

    return 'CRYPT_PASSWORD="[password]" $commandPrefix ${_getMaskedCommand(args)}';
  }

  /// Generate copy-pasteable CLI command with masked password
  /// Log-safe rendering of a process error: ProcessException.toString()
  /// embeds the full argv -- including secret-valued flags -- so it must
  /// never reach a log line verbatim (gitlab#215 review F1).
  static String _safeProcessError(Object e) => e is ProcessException
      ? 'ProcessException(${e.executable}): ${e.message} [${e.errorCode}]'
      : e.toString();

  static String _getMaskedCommand(List<String> args) {
    // Determine command prefix
    String commandPrefix = '';
    if (_isFlaspakVersion) {
      commandPrefix = 'flatpak run com.opensslencrypt.OpenSSLEncrypt';
    } else {
      commandPrefix = 'python -m openssl_encrypt.cli';
    }

    // Create masked args by replacing secret values with asterisks.
    // gitlab#215 item 5: --stego-password (and friends) were displayed
    // verbatim; keep this set in sync with the CLI's
    // SECRET_VALUE_CLI_OPTIONS.
    const secretFlags = {
      '-p',
      '--password',
      '--second-password',
      '--keystore-password',
      '--manifest-password',
      '--rekey-password',
      '--recovery-code',
      '--stego-password',
      '--encryption-data',
      '--code',
    };
    // F19 review (gitlab#254): this is a DISPLAY formatter — its output reaches
    // the terminal, the persistent debug-log file, and the in-app log viewer
    // (rendered with a bare Text widget). Untrusted argv values (e.g. a
    // crafted recovery-slot id passed as --slot-id) must be escaped here too, or
    // a raw ESC/newline/bidi sequence forges log lines or a spoofed screen. This
    // never touches the exec path (Process.run gets the raw List<String>).
    final maskedArgs = <String>[];
    for (int i = 0; i < args.length; i++) {
      if (secretFlags.contains(args[i]) && i + 1 < args.length) {
        maskedArgs.add(InputValidator.sanitizeForDisplay(args[i]));
        maskedArgs.add('****');
        i++; // Skip the actual secret value
      } else {
        maskedArgs.add(InputValidator.sanitizeForDisplay(args[i]));
      }
    }

    return '$commandPrefix ${maskedArgs.join(' ')}';
  }

  /// Check if algorithm is post-quantum
  static bool _isPostQuantumAlgorithm(String algorithm) {
    return algorithm.contains('ml-kem') ||
           algorithm.contains('kyber') ||
           algorithm.contains('hqc') ||
           algorithm.contains('mayo') ||
           algorithm.contains('cross');
  }

  /// Encrypt file and hide in steganographic cover image
  static Future<ProcessResult> encryptWithSteganography({
    required String inputPath,
    required String coverImagePath,
    required String outputPath,
    required String password,
    String? stegoPassword,
    String algorithm = 'aes-gcm',
    String stegoMethod = 'lsb',              // Steganography method
    int bitsPerChannel = 1,
    bool randomizePixels = false,
    bool addDecoyData = false,
    int? jpegQuality,                        // JPEG quality (70-100)
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
    String? hsmPlugin,
    int? hsmSlot,
    bool enableIntegrity = false,
    List<String>? forIdentities,      // Asymmetric: recipients
    String? signWith,                  // Asymmetric: signing identity
    bool useKeyserver = false,         // Asymmetric: keyserver lookup
    String? identityStore,             // Asymmetric: identity store path
    String? cascadePreset,             // Cascade: 'standard', 'paranoia', or null
    List<String>? cascadeAlgorithms,   // Cascade: custom algorithm chain
    String cascadeHash = 'sha256',     // Cascade: HKDF hash function
    bool noDiversityCheck = false,     // Cascade: --no-diversity-check
    bool strictDiversity = false,      // Cascade: --strict-diversity
  }) async {
    final args = [
      'encrypt',
      '-i', inputPath,
      '--stego-hide', coverImagePath,
      '-o', outputPath,
      // --algorithm, NOT -a: `-a` is the short form of --armor, a
      // store_true, so `-a aes-gcm` set armor=True and left the algorithm as
      // an unrecognised positional -- encrypt declares none, so the command
      // died with exit 2 and steganographic encryption never worked from the
      // GUI. Had it parsed, the user's cipher choice would silently have
      // become "ASCII armor" (gitlab#190).
      '--algorithm', algorithm,
      '--stego-method', stegoMethod,
      '--stego-bits-per-channel', bitsPerChannel.toString(),
    ];

    // Add steganography password if provided
    if (stegoPassword != null && stegoPassword.isNotEmpty) {
      args.addAll(['--stego-password', stegoPassword]);
    }

    // Add pixel randomization if enabled and stego password is provided
    if (randomizePixels && stegoPassword != null && stegoPassword.isNotEmpty) {
      args.add('--stego-randomize-pixels');
    }

    // Add decoy data if enabled
    if (addDecoyData) {
      args.add('--stego-decoy-data');
    }

    // Add JPEG quality if provided
    if (jpegQuality != null) {
      args.addAll(['--jpeg-quality', jpegQuality.toString()]);
    }

    // Add hash configuration if provided
    if (hashConfig != null) {
      for (final entry in hashConfig.entries) {
        final hashName = entry.key;
        final config = entry.value;
        if (config['enabled'] == true && config['rounds'] != null && config['rounds'] > 0) {
          args.addAll(['--$hashName-rounds', config['rounds'].toString()]);
        }
      }
    }

    // Add KDF configuration if provided
    if (kdfConfig != null) {
      for (final entry in kdfConfig.entries) {
        final kdfName = entry.key;
        final config = entry.value;
        if (config['enabled'] == true) {
          switch (kdfName) {
            case 'pbkdf2':
              if (config['iterations'] != null && config['iterations'] > 0) {
                args.addAll(['--pbkdf2-iterations', config['iterations'].toString()]);
              }
              break;
            case 'scrypt':
              args.add('--enable-scrypt');
              if (config['n'] != null) args.addAll(['--scrypt-n', config['n'].toString()]);
              if (config['r'] != null) args.addAll(['--scrypt-r', config['r'].toString()]);
              if (config['p'] != null) args.addAll(['--scrypt-p', config['p'].toString()]);
              if (config['rounds'] != null) args.addAll(['--scrypt-rounds', config['rounds'].toString()]);
              break;
            case 'argon2':
              args.add('--enable-argon2');
              if (config['time_cost'] != null) args.addAll(['--argon2-time', config['time_cost'].toString()]);
              if (config['memory_cost'] != null) args.addAll(['--argon2-memory', config['memory_cost'].toString()]);
              if (config['parallelism'] != null) args.addAll(['--argon2-parallelism', config['parallelism'].toString()]);
              if (config['hash_len'] != null) args.addAll(['--argon2-hash-len', config['hash_len'].toString()]);
              if (config['type'] != null) {
                final typeMap = {0: 'd', 1: 'i', 2: 'id'};
                args.addAll(['--argon2-type', typeMap[config['type']] ?? 'id']);
              }
              if (config['rounds'] != null) args.addAll(['--argon2-rounds', config['rounds'].toString()]);
              break;
            case 'hkdf':
              args.add('--enable-hkdf');
              if (config['rounds'] != null) args.addAll(['--hkdf-rounds', config['rounds'].toString()]);
              if (config['algorithm'] != null) args.addAll(['--hkdf-algorithm', config['algorithm']]);
              if (config['info'] != null) args.addAll(['--hkdf-info', config['info']]);
              break;
            case 'balloon':
              args.add('--enable-balloon');
              if (config['time_cost'] != null) args.addAll(['--balloon-time-cost', config['time_cost'].toString()]);
              if (config['space_cost'] != null) args.addAll(['--balloon-space-cost', config['space_cost'].toString()]);
              if (config['parallelism'] != null) args.addAll(['--balloon-parallelism', config['parallelism'].toString()]);
              if (config['rounds'] != null) args.addAll(['--balloon-rounds', config['rounds'].toString()]);
              if (config['hash_len'] != null) args.addAll(['--balloon-hash-len', config['hash_len'].toString()]);
              break;
            case 'randomx':
              args.add('--enable-randomx');
              if (config['rounds'] != null) args.addAll(['--randomx-rounds', config['rounds'].toString()]);
              if (config['mode'] != null) args.addAll(['--randomx-mode', config['mode']]);
              if (config['height'] != null) args.addAll(['--randomx-height', config['height'].toString()]);
              if (config['hash_len'] != null) args.addAll(['--randomx-hash-len', config['hash_len'].toString()]);
              break;
          }
        }
      }
    }

    // Add HSM arguments if specified
    if (hsmPlugin != null && hsmPlugin != 'none') {
      args.addAll(['--hsm', hsmPlugin]);
      if (hsmSlot != null) {
        args.addAll(['--hsm-slot', hsmSlot.toString()]);
      }
    }

    // Add integrity plugin if enabled
    if (enableIntegrity) {
      args.add('--integrity');
    }

    // Add asymmetric encryption parameters if provided
    if (forIdentities != null && forIdentities.isNotEmpty) {
      for (final recipient in forIdentities) {
        args.addAll(['--for-identity', recipient]);
      }
      if (signWith != null && signWith.isNotEmpty) {
        args.addAll(['--sign-with', signWith]);
      }
      if (useKeyserver) {
        args.add('--use-keyserver');
      }
      if (identityStore != null && identityStore.isNotEmpty) {
        args.addAll(['--identity-store', identityStore]);
      }
    }

    // Add cascade encryption parameters if provided
    if (cascadePreset != null || cascadeAlgorithms != null) {
      if (cascadePreset != null && cascadePreset != 'custom') {
        args.add('--cascade=$cascadePreset');
      } else if (cascadeAlgorithms != null && cascadeAlgorithms.isNotEmpty) {
        args.add('--cascade');
        args.addAll(['--algorithm', cascadeAlgorithms.join(',')]);
      }
      args.addAll(['--cascade-hash', cascadeHash]);
      if (noDiversityCheck) {
        args.add('--no-diversity-check');
      }
      if (strictDiversity) {
        args.add('--strict-diversity');
      }
    }

    return await _runCLICommandWithProgress(
      args,
      environment: {'CRYPT_PASSWORD': password},
    );
  }

  /// Encrypt text and hide in steganographic cover media
  static Future<String> encryptTextWithSteganography({
    required String text,
    required String coverMediaPath,
    required String outputPath,
    required String password,
    String? stegoPassword,
    String algorithm = 'aes-gcm',
    String stegoMethod = 'lsb',
    int bitsPerChannel = 1,
    bool randomizePixels = false,
    bool addDecoyData = false,
    int? jpegQuality,
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
    String? hsmPlugin,
    int? hsmSlot,
    bool enableIntegrity = false,
    List<String>? forIdentities,
    String? signWith,
    bool useKeyserver = false,
    String? identityStore,
    String? cascadePreset,
    List<String>? cascadeAlgorithms,
    String cascadeHash = 'sha256',
    bool noDiversityCheck = false,
    bool strictDiversity = false,
  }) async {
    // Create temporary file for text
    final tempDir = await Directory.systemTemp.createTemp('stego_text_');
    final tempFile = File('${tempDir.path}/input.txt');
    await tempFile.writeAsString(text);

    try {
      // Encrypt temp file with steganography
      final result = await encryptWithSteganography(
        inputPath: tempFile.path,
        coverImagePath: coverMediaPath,
        outputPath: outputPath,
        password: password,
        stegoPassword: stegoPassword,
        algorithm: algorithm,
        stegoMethod: stegoMethod,
        bitsPerChannel: bitsPerChannel,
        randomizePixels: randomizePixels,
        addDecoyData: addDecoyData,
        jpegQuality: jpegQuality,
        hashConfig: hashConfig,
        kdfConfig: kdfConfig,
        hsmPlugin: hsmPlugin,
        hsmSlot: hsmSlot,
        enableIntegrity: enableIntegrity,
        forIdentities: forIdentities,
        signWith: signWith,
        useKeyserver: useKeyserver,
        identityStore: identityStore,
        cascadePreset: cascadePreset,
        cascadeAlgorithms: cascadeAlgorithms,
        cascadeHash: cascadeHash,
        noDiversityCheck: noDiversityCheck,
        strictDiversity: strictDiversity,
      );

      if (result.exitCode != 0) {
        throw Exception('Steganography encryption failed: ${result.stderr}');
      }

      return outputPath;
    } finally {
      // Clean up temp file and directory
      try {
        if (await tempFile.exists()) await tempFile.delete();
        if (await tempDir.exists()) await tempDir.delete();
      } catch (e) {
        outputDebugLog('Failed to clean up temp file: $e');
      }
    }
  }

  /// Decrypt file from steganographic image
  static Future<ProcessResult> decryptFromSteganography({
    required String stegoImagePath,
    required String outputPath,
    required String password,
    String? stegoPassword,
    int bitsPerChannel = 1,
    String? hsmPlugin,
    int? hsmSlot,
    bool verifyIntegrity = false,
    String? withKey,                // Asymmetric: decryption identity
    String? verifyFrom,             // Asymmetric: sender verification
    bool skipVerification = false,  // Asymmetric: skip signature check
  }) async {
    final args = [
      'decrypt',
      '-i', stegoImagePath,
      '-o', outputPath,
      '--stego-extract',
      '--stego-method', 'lsb',
      '--stego-bits-per-channel', bitsPerChannel.toString(),
    ];

    // Add steganography password if provided
    if (stegoPassword != null && stegoPassword.isNotEmpty) {
      args.addAll(['--stego-password', stegoPassword]);
    }

    // Add HSM arguments if specified
    if (hsmPlugin != null && hsmPlugin != 'none') {
      args.addAll(['--hsm', hsmPlugin]);
      if (hsmSlot != null) {
        args.addAll(['--hsm-slot', hsmSlot.toString()]);
      }
    }

    // Add integrity verification if enabled
    if (verifyIntegrity) {
      args.add('--verify-integrity');
    }

    // Add asymmetric decryption parameters if provided
    if (withKey != null && withKey.isNotEmpty) {
      args.addAll(['--with-key', withKey]);
      // Never emit --verify-from together with --no-verify: the CLI
      // silently prefers --no-verify, so the pair would claim an
      // authenticity check that never happens. The tabs prevent the
      // combination in the UI; this keeps every (future) caller honest.
      if (skipVerification) {
        args.add('--no-verify');
      } else if (verifyFrom != null && verifyFrom.isNotEmpty) {
        args.addAll(['--verify-from', verifyFrom]);
      }
    }

    return await _runCLICommandWithProgress(
      args,
      environment: {'CRYPT_PASSWORD': password},
    );
  }

  /// Register a new FIDO2 credential
  static Future<void> registerFido2Credential(String description, bool isBackup) async {
    final args = [
      'hsm',
      'fido2-register',
      '--description', description,
    ];

    if (isBackup) {
      args.add('--backup');
    }

    final result = await _runCLICommand(args);
    if (result.exitCode != 0) {
      throw Exception('Failed to register FIDO2 credential: ${result.stderr}');
    }
  }

  /// List all registered FIDO2 credentials
  static Future<List<Map<String, dynamic>>> listFido2Credentials() async {
    try {
      // Read credentials from ~/.openssl_encrypt/plugins/fido2/credentials.json
      final homeDir = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
      if (homeDir == null) {
        throw Exception('Could not determine home directory');
      }

      final credentialsFile = File('$homeDir/.openssl_encrypt/plugins/fido2/credentials.json');

      if (!await credentialsFile.exists()) {
        return [];
      }

      final content = await credentialsFile.readAsString();
      final data = jsonDecode(content) as Map<String, dynamic>;
      final credentials = data['credentials'] as List<dynamic>? ?? [];

      return credentials.map((c) => c as Map<String, dynamic>).toList();
    } catch (e) {
      _outputDebugLog('Error reading FIDO2 credentials: $e');
      return [];
    }
  }

  /// Delete a FIDO2 credential
  static Future<void> deleteFido2Credential(String credentialId) async {
    // For now, we'll need to manually edit the credentials file
    // In a future version, the CLI could support a delete command
    try {
      final homeDir = Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
      if (homeDir == null) {
        throw Exception('Could not determine home directory');
      }

      final credentialsFile = File('$homeDir/.openssl_encrypt/plugins/fido2/credentials.json');

      if (!await credentialsFile.exists()) {
        throw Exception('Credentials file not found');
      }

      final content = await credentialsFile.readAsString();
      final data = jsonDecode(content) as Map<String, dynamic>;
      final credentials = data['credentials'] as List<dynamic>? ?? [];

      // Remove the credential with matching ID
      credentials.removeWhere((c) {
        final cred = c as Map<String, dynamic>;
        return cred['credential_id'] == credentialId;
      });

      // Write back to file
      data['credentials'] = credentials;
      await credentialsFile.writeAsString(
        const JsonEncoder.withIndent('  ').convert(data),
      );
    } catch (e) {
      throw Exception('Failed to delete credential: $e');
    }
  }

  // ==================== Password Generation ====================

  /// Generate a password via the CLI `generate-password --json` command.
  ///
  /// Character mode (default) uses [length] and the four charset toggles; if
  /// no charset is selected the CLI defaults to all four. Diceware mode
  /// ([dice] = true) draws [diceCount] words joined by [diceSep], optionally
  /// from a custom [diceList] wordlist. Requires the CLI's `--json` support
  /// (gitlab#138). Throws on non-zero exit.
  static Future<GeneratedPassword> generatePassword({
    int length = 32,
    bool useLowercase = true,
    bool useUppercase = true,
    bool useDigits = true,
    bool useSpecial = true,
    bool dice = false,
    int diceCount = 10,
    String diceSep = '',
    String? diceList,
    bool forceWordlist = false,
  }) async {
    final args = <String>['generate-password'];

    if (dice) {
      args.add('--dice');
      args.addAll(['--dice-count', diceCount.toString()]);
      // Only pass a non-default separator; the empty default is valid but
      // passing "--dice-sep ''" is harmless. Skip when empty for a cleaner argv.
      if (diceSep.isNotEmpty) {
        args.addAll(['--dice-sep', diceSep]);
      }
      if (diceList != null && diceList.isNotEmpty) {
        args.addAll(['--dice-list', diceList]);
      }
      if (forceWordlist) {
        args.add('--force-wordlist');
      }
    } else {
      // Length is a positional argument in character mode.
      args.add(length.toString());
      if (useLowercase) args.add('--use-lowercase');
      if (useUppercase) args.add('--use-uppercase');
      if (useDigits) args.add('--use-digits');
      if (useSpecial) args.add('--use-special');
    }

    args.add('--json');

    // logStdout: false — stdout is the generated password; keep it out of logs.
    final result = await _runCLICommand(args, logStdout: false);
    if (result.exitCode != 0) {
      throw Exception('Password generation failed: ${result.stderr}');
    }

    try {
      // stdout is a single JSON object; the password never touches stderr
      // under --json (see gitlab#138).
      final data = jsonDecode((result.stdout as String).trim()) as Map<String, dynamic>;
      return GeneratedPassword.fromJson(data);
    } catch (_) {
      // Do not interpolate the decode error: its message can echo a snippet of
      // the (secret-bearing) stdout into the UI error card.
      throw Exception('Could not parse generated password output (invalid JSON)');
    }
  }

  // ==================== Password Strength ====================

  /// Report the strength of [password] via `check-password --json`.
  ///
  /// The password is passed on **stdin** (never as a `-p` argument, which would
  /// leak it to the process list), and the policy is set to "none" so this is a
  /// pure strength report that always exits 0. Returns null for an empty
  /// password. The password is not written to any log (the stdin runner logs
  /// only the argv; stdout is the report, not the password).
  static Future<PasswordStrength?> checkPassword(String password) async {
    if (password.isEmpty) return null;
    final args = <String>[
      'check-password',
      '--json',
      '--password-policy',
      'none',
    ];
    // Strip CRYPT_PASSWORD so the CLI scores the typed password (it reads that
    // env var before stdin), making the meter reflect the field, not the env.
    // _inheritableEnvironment() already drops CRYPT_PASSWORD along with every
    // other credential variable.
    final env = _inheritableEnvironment();
    final result = await _runCLICommandWithStdin(args, password, environment: env);
    if (result.exitCode != 0) {
      throw Exception('Strength check failed: ${(result.stderr as String).trim()}');
    }
    final data = jsonDecode((result.stdout as String).trim()) as Map<String, dynamic>;
    return PasswordStrength.fromJson(data);
  }

  // ==================== Rekey ====================

  /// Re-encrypt [inputPath] to [outputPath] with a new password (and optionally
  /// a new [algorithm]) via the CLI `rekey` command.
  ///
  /// The OLD password is passed via `CRYPT_PASSWORD` and the NEW password via
  /// `OPENSSL_ENCRYPT_REKEY_PASSWORD` — both environment variables, which the
  /// CLI reads and then deletes; neither reaches the process list or a temp
  /// file. Throws on non-zero exit (e.g. wrong old password, weak new password
  /// without [forcePassword]).
  static Future<String> rekey({
    required String inputPath,
    required String outputPath,
    required String oldPassword,
    required String newPassword,
    String? algorithm,
    bool forcePassword = false,
  }) async {
    final args = <String>['rekey', '-i', inputPath, '-o', outputPath];
    if (algorithm != null && algorithm.isNotEmpty) {
      args.addAll(['--algorithm', algorithm]);
    }
    if (forcePassword) {
      args.add('--force-password');
    }

    final result = await _runCLICommandWithProgress(
      args,
      environment: {
        'CRYPT_PASSWORD': oldPassword,
        'OPENSSL_ENCRYPT_REKEY_PASSWORD': newPassword,
      },
    );
    if (result.exitCode != 0) {
      final err = (result.stderr as String).trim();
      throw Exception(err.isEmpty ? 'Rekey failed (exit ${result.exitCode})' : err);
    }
    return (result.stdout as String).trim();
  }

  // ==================== Secure Shred ====================

  /// Securely delete a file (or directory with [recursive]) via the CLI
  /// `shred` command. [inputPath] may be a glob pattern. Overwrites with
  /// [passes] passes. Returns the CLI's human-readable output (stderr).
  /// Throws on non-zero exit.
  ///
  /// The caller MUST confirm this irreversible action first, and MUST set
  /// [recursive] when [inputPath] is (or matches) a directory — the CLI would
  /// otherwise fall into an interactive confirmation prompt that has no stdin
  /// under Process.run.
  static Future<String> shred(
    String inputPath, {
    int passes = 3,
    bool recursive = false,
  }) async {
    // The CLI shred handler runs -i through glob expansion (glob.glob), so a
    // real, picker-supplied path whose name contains glob metacharacters (e.g.
    // "data*.bin") would expand to and irreversibly delete siblings that were
    // never in the confirmation dialog. GUI paths are always literal, so escape
    // the metacharacters (mirrors Python's glob.escape) to force literal match.
    final args = <String>[
      'shred',
      '-i',
      _escapeGlob(inputPath),
      '--shred-passes',
      passes.toString(),
    ];
    if (recursive) {
      args.add('--recursive');
    }

    final result = await _runCLICommand(args);
    if (result.exitCode != 0) {
      final err = (result.stderr as String).trim();
      throw Exception(err.isEmpty ? 'Shred failed (exit ${result.exitCode})' : err);
    }
    // shred writes its progress/summary to stderr; stdout is empty.
    return (result.stderr as String).trim();
  }

  /// Escape glob metacharacters (`*`, `?`, `[`) so the CLI treats the argument
  /// as a literal path, mirroring Python's `glob.escape`. Each special char is
  /// wrapped in a single-character class; `]` needs no escaping.
  static String _escapeGlob(String path) {
    return path.replaceAllMapped(RegExp(r'([*?\[])'), (m) => '[${m[1]}]');
  }

  // ==================== Identity Management Methods ====================

  /// List all identities (own + contacts)
  static Future<Map<String, dynamic>> listIdentities() async {
    try {
      final args = ['identity', 'list', '--include-contacts', '--json'];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode != 0) {
        // Throw, do not return empty: an empty list is indistinguishable
        // from an empty store, which is exactly how a CLI flag that never
        // existed went unnoticed for the whole life of this feature
        // (gitlab#183). Every caller has an error path.
        _outputDebugLog('Failed to list identities (exit ${result.exitCode})');
        final detail = result.stderr.trim();
        throw Exception(
          'identity list failed (exit ${result.exitCode})'
          '${detail.isEmpty ? '' : ': ${InputValidator.sanitizeForDisplay(detail)}'}',
        );
      }

      final data = jsonDecode(result.stdout) as Map<String, dynamic>;

      // Sanitize once, here, rather than at each widget: this is where the
      // untrusted values enter the app, and a per-widget approach silently
      // misses the next new screen (gitlab#183).
      //
      // Only the free-text fields. `name` and `fingerprint` are regex-locked
      // by the CLI AND are passed back to it as argument values
      // (--with-key, recipient selection), so substituting characters there
      // would corrupt the argument, not harden the display.
      List<Map<String, dynamic>> clean(String key) =>
          (data[key] as List<dynamic>?)
              ?.map((i) => i as Map<String, dynamic>)
              .map((i) => {
                    ...i,
                    if (i['email'] != null)
                      'email': InputValidator.sanitizeForDisplay(i['email'] as String),
                    if (i['created_at'] != null)
                      'created_at':
                          InputValidator.sanitizeForDisplay(i['created_at'] as String),
                  })
              .toList() ??
          [];

      // Absent entries are not the same as absent identities, so `skipped`
      // is RETURNED, not just logged: a debug-log line is invisible in a
      // default build, and the whole point is that the user learns a
      // recipient is missing rather than silently omitting one.
      final skipped = ((data['skipped'] as List<dynamic>?) ?? [])
          .map((s) => s as Map<String, dynamic>)
          .map((s) => {
                ...s,
                if (s['entry'] != null)
                  'entry': InputValidator.sanitizeForDisplay(s['entry'] as String),
                if (s['reason'] != null)
                  'reason': InputValidator.sanitizeForDisplay(s['reason'] as String),
              })
          .toList();
      if (skipped.isNotEmpty) {
        _outputDebugLog('identity list: ${skipped.length} store entry/entries could not be loaded');
      }

      return {
        'own': clean('own'),
        'contacts': clean('contacts'),
        'skipped': skipped,
      };
    } catch (e) {
      _outputDebugLog('Error listing identities: $e');
      rethrow;
    }
  }

  /// Create a new identity
  static Future<Map<String, dynamic>> createIdentity({
    required String name,
    String? email,
    required String passphrase,
    String kemAlgorithm = 'ML-KEM-768',
    String sigAlgorithm = 'ML-DSA-65',
    String? hsmType,
    int? hsmSlot,
    bool noTouch = false,
  }) async {
    final args = [
      'identity',
      'create',
      '--name', name,
      '--kem-algorithm', kemAlgorithm,
      '--sig-algorithm', sigAlgorithm,
    ];

    if (email != null && email.isNotEmpty) {
      args.addAll(['--email', email]);
    }

    if (hsmType != null && hsmType != 'none') {
      args.addAll(['--hsm', hsmType]);
      if (hsmSlot != null) {
        args.addAll(['--hsm-slot', hsmSlot.toString()]);
      }
      // --no-touch only has meaning with an HSM, and even then it only
      // suppresses the tool's "touch your key" REMINDER (identity_protection
      // .py) — it does NOT change whether the key demands a physical press,
      // which is a hardware slot setting (gitlab#218). Never emitted without
      // an HSM, and never by default.
      if (noTouch) {
        args.add('--no-touch');
      }
    }

    if (debugEnabled) {
      args.add('--debug');
    }

    // Use stdin for passphrase
    final process = await _runCLICommandWithStdin(args, passphrase);

    if (process.exitCode != 0) {
      throw Exception('Failed to create identity: ${process.stderr}');
    }

    // Return basic info
    return {
      'success': true,
      'name': name,
      'email': email,
    };
  }

  /// Export public identity for sharing
  static Future<String> exportIdentity(String name) async {
    try {
      final args = ['identity', 'export', name];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode != 0) {
        throw Exception('Failed to export identity: ${result.stderr}');
      }

      return result.stdout.trim();
    } catch (e) {
      throw Exception('Error exporting identity: $e');
    }
  }

  /// Import a contact's public key
  static Future<void> importContact(
    String publicKeyData, {
    String? alias,
    bool allowKeyChange = false,
  }) async {
    // The document goes over stdin, never argv: /proc/PID/cmdline is
    // world-readable, so an argv channel would publish the contact's
    // metadata to every local process -- and this field is a free-text
    // paste box, so a mis-pasted private key or passphrase would be leaked
    // at execve, before the CLI could reject it (gitlab#164).
    final args = ['identity', 'import', '--data-stdin'];

    if (alias != null && alias.isNotEmpty) {
      args.addAll(['--alias', alias]);
    }

    // --allow-key-change replaces a pinned key. The CLI refuses a
    // stdin-sourced key change non-interactively (identity_cli.py), so the
    // GUI must catch IdentityKeyChangedError, show the fingerprints, and only
    // then re-call with allowKeyChange:true. Never set silently.
    //
    // --overwrite is required IN ADDITION: --allow-key-change only passes the
    // TOFU gate, but Identity.save still refuses to overwrite the existing
    // contact directory without --overwrite (identity.py:616), so the replace
    // fails without it. The CLI's own interactive branch passes both
    // (identity_cli.py). Both stay gated behind allowKeyChange so the
    // unconfirmed first attempt can never overwrite.
    if (allowKeyChange) {
      args.addAll(['--allow-key-change', '--overwrite']);
    }

    final result = await _runCLICommandWithStdin(args, publicKeyData);

    if (result.exitCode != 0) {
      final stderr = result.stderr.toString();
      // Distinguish the TOFU key-change refusal from an ordinary failure:
      // it is the one error whose remedy is a security decision, not a retry.
      final keyChanged = IdentityKeyChangedError.tryParse(stderr);
      if (keyChanged != null) {
        throw keyChanged;
      }
      throw Exception('Failed to import contact: $stderr');
    }
  }

  /// Delete an identity or contact.
  ///
  /// `--kind` decides WHICH entry goes when a name exists as both an own
  /// identity and a contact. Deleting both is destructive in two different
  /// ways -- it destroys the own identity's private keys, making every file
  /// encrypted to it unreadable, and it drops the contact's TOFU pin, so a
  /// later import of that name is accepted as first use with no key-change
  /// warning -- so the caller has to say which one it means.
  ///
  /// This used to send `--contact`, a flag that has never existed on any
  /// branch: argparse exited 2 and GUI contact deletion had never worked
  /// (gitlab#185). `--force` skips the CLI's confirmation prompt, which a
  /// subprocess cannot answer -- the app runs its own dialogue first, and
  /// without it the prompt's `input()` raised EOFError on a non-tty pipe.
  static Future<void> deleteIdentity(String name, {bool isContact = false}) async {
    try {
      final args = [
        'identity',
        'delete',
        name,
        '--kind', isContact ? 'contact' : 'own',
        '--force',
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode != 0) {
        throw Exception('Failed to delete identity: ${result.stderr}');
      }
    } catch (e) {
      throw Exception('Error deleting identity: $e');
    }
  }

  /// Validate cascade cipher chain and return diversity warnings
  static Future<List<Map<String, dynamic>>> validateCascade(
    List<String> algorithms, {
    bool strict = false,
  }) async {
    try {
      // For now, return basic validation
      // In future, could call CLI for detailed validation
      final warnings = <Map<String, dynamic>>[];

      if (algorithms.length < 2) {
        warnings.add({
          'level': 'ERROR',
          'message': 'Cascade mode requires at least 2 ciphers',
          'suggestion': 'Add more algorithms to the chain',
        });
        return warnings;
      }

      // Check for duplicate algorithms
      final uniqueAlgos = algorithms.toSet();
      if (uniqueAlgos.length < algorithms.length) {
        warnings.add({
          'level': 'WARNING',
          'message': 'Duplicate algorithms in cascade chain',
          'suggestion': 'Use different algorithms for better security',
        });
      }

      // Check for same family (basic check)
      final hasMultipleAES = algorithms.where((a) => a.contains('aes')).length > 1;
      final hasMultipleChaCha = algorithms.where((a) => a.contains('chacha')).length > 1;
      final hasMultipleThreefish = algorithms.where((a) => a.contains('threefish')).length > 1;

      if (hasMultipleAES) {
        warnings.add({
          'level': 'WARNING',
          'message': 'Multiple AES variants in chain',
          'suggestion': 'Mix different cipher families (AES + ChaCha + Threefish) for diversity',
        });
      }

      if (hasMultipleChaCha) {
        warnings.add({
          'level': 'WARNING',
          'message': 'Multiple ChaCha variants in chain',
          'suggestion': 'Mix different cipher families for better diversity',
        });
      }

      if (hasMultipleThreefish) {
        warnings.add({
          'level': 'INFO',
          'message': 'Multiple Threefish variants in chain',
          'suggestion': 'Consider mixing with AES or ChaCha for diversity',
        });
      }

      return warnings;
    } catch (e) {
      _outputDebugLog('Error validating cascade: $e');
      return [];
    }
  }

  // ==================== Network Plugin Methods ====================

  /// Check the configured keyserver.
  ///
  /// Reports on the server the CLI is configured with. It used to send
  /// `plugin keyserver test --url <url>`, a command that has never existed
  /// (`plugin` offers only sign/trust-key/list-keys), so the check always
  /// failed at argparse and the GUI reported "unreachable" for a server
  /// that was fine -- gitlab#188. `keyserver status` takes no --url, so the
  /// caller's url is no longer accepted: callers must not imply that an
  /// arbitrary server was probed.
  static Future<bool> checkKeyserverStatus() async {
    try {
      final args = ['keyserver', 'status'];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);
      return result.exitCode == 0;
    } catch (e) {
      _outputDebugLog('Keyserver status check failed: $e');
      return false;
    }
  }

  /// Clear keyserver cache
  static Future<bool> clearKeyserverCache() async {
    try {
      // `plugin keyserver clear-cache` never existed (gitlab#188); the
      // real command is `keyserver cache-clear`. --force skips its
      // confirmation prompt, which no GUI subprocess can answer.
      final args = ['keyserver', 'cache-clear', '--force'];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);
      return result.exitCode == 0;
    } catch (e) {
      _outputDebugLog('Failed to clear keyserver cache: $e');
      return false;
    }
  }

  /// Test pepper server connection with mTLS
  static Future<Map<String, dynamic>> testPepperConnection({
    required String url,
    String? clientCertPath,
    String? clientKeyPath,
    String? caCertPath,
  }) async {
    try {
      final args = [
        'plugin',
        'pepper',
        'test',
        '--url', url,
      ];

      if (clientCertPath != null && clientCertPath.isNotEmpty) {
        args.addAll(['--client-cert', clientCertPath]);
      }
      if (clientKeyPath != null && clientKeyPath.isNotEmpty) {
        args.addAll(['--client-key', clientKeyPath]);
      }
      if (caCertPath != null && caCertPath.isNotEmpty) {
        args.addAll(['--ca-cert', caCertPath]);
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      return {
        'success': result.exitCode == 0,
        'message': result.exitCode == 0 ? result.stdout : result.stderr,
      };
    } catch (e) {
      _outputDebugLog('Pepper connection test failed: $e');
      return {
        'success': false,
        'message': 'Connection test failed: $e',
      };
    }
  }

  /// List stored peppers
  static Future<List<Map<String, dynamic>>> listPeppers() async {
    try {
      final args = [
        'plugin',
        'pepper',
        'list',
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode == 0 && result.stdout.isNotEmpty) {
        final data = jsonDecode(result.stdout);
        if (data is Map && data.containsKey('peppers')) {
          return (data['peppers'] as List<dynamic>)
              .map((p) => p as Map<String, dynamic>)
              .toList();
        }
      }

      return [];
    } catch (e) {
      _outputDebugLog('Failed to list peppers: $e');
      return [];
    }
  }

  /// Setup TOTP 2FA for pepper
  static Future<Map<String, dynamic>> setupPepperTotp() async {
    try {
      final args = [
        'plugin',
        'pepper',
        'setup-totp',
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode == 0 && result.stdout.isNotEmpty) {
        final data = jsonDecode(result.stdout);
        return {
          'success': true,
          'secret': data['secret'],
          'qr_code': data['qr_code'],
        };
      }

      return {
        'success': false,
        'message': result.stderr,
      };
    } catch (e) {
      _outputDebugLog('Failed to setup TOTP: $e');
      return {
        'success': false,
        'message': 'Setup failed: $e',
      };
    }
  }

  /// Verify TOTP code
  static Future<bool> verifyPepperTotp(String code) async {
    try {
      final args = [
        'plugin',
        'pepper',
        'verify-totp',
        '--code', code,
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);
      return result.exitCode == 0;
    } catch (e) {
      _outputDebugLog('TOTP verification failed: $e');
      return false;
    }
  }

  /// Configure dead man's switch
  static Future<bool> configurePepperDeadman({
    required bool enabled,
    int? intervalDays,
    int? gracePeriodDays,
  }) async {
    try {
      final args = [
        'plugin',
        'pepper',
        'configure-deadman',
      ];

      if (enabled) {
        args.add('--enable');
        if (intervalDays != null) {
          args.addAll(['--interval', intervalDays.toString()]);
        }
        if (gracePeriodDays != null) {
          args.addAll(['--grace-period', gracePeriodDays.toString()]);
        }
      } else {
        args.add('--disable');
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);
      return result.exitCode == 0;
    } catch (e) {
      _outputDebugLog('Failed to configure dead man switch: $e');
      return false;
    }
  }

  /// Test integrity server connection with mTLS
  static Future<Map<String, dynamic>> testIntegrityConnection({
    required String url,
    String? clientCertPath,
    String? clientKeyPath,
    String? caCertPath,
  }) async {
    try {
      final args = [
        'plugin',
        'integrity',
        'test',
        '--url', url,
      ];

      if (clientCertPath != null && clientCertPath.isNotEmpty) {
        args.addAll(['--client-cert', clientCertPath]);
      }
      if (clientKeyPath != null && clientKeyPath.isNotEmpty) {
        args.addAll(['--client-key', clientKeyPath]);
      }
      if (caCertPath != null && caCertPath.isNotEmpty) {
        args.addAll(['--ca-cert', caCertPath]);
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      return {
        'success': result.exitCode == 0,
        'message': result.exitCode == 0 ? result.stdout : result.stderr,
      };
    } catch (e) {
      _outputDebugLog('Integrity connection test failed: $e');
      return {
        'success': false,
        'message': 'Connection test failed: $e',
      };
    }
  }

  /// Get integrity verification statistics
  static Future<Map<String, dynamic>> getIntegrityStats() async {
    try {
      final args = [
        'plugin',
        'integrity',
        'stats',
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode == 0 && result.stdout.isNotEmpty) {
        final data = jsonDecode(result.stdout);
        return {
          'success': true,
          'total_verifications': data['total_verifications'] ?? 0,
          'successful_verifications': data['successful_verifications'] ?? 0,
          'failed_verifications': data['failed_verifications'] ?? 0,
          'last_verification': data['last_verification'],
        };
      }

      return {
        'success': false,
        'message': result.stderr,
      };
    } catch (e) {
      _outputDebugLog('Failed to get integrity stats: $e');
      return {
        'success': false,
        'message': 'Failed to get stats: $e',
      };
    }
  }

  /// Verify file integrity
  static Future<bool> verifyFileIntegrity({
    required String fileId,
    required String metadataHash,
  }) async {
    try {
      final args = [
        'plugin',
        'integrity',
        'verify',
        '--file-id', fileId,
        '--metadata-hash', metadataHash,
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);
      return result.exitCode == 0;
    } catch (e) {
      _outputDebugLog('Integrity verification failed: $e');
      return false;
    }
  }

  // ==================== Signature verification (gitlab#158) ============

  /// Verify a detached signature over [inputPath].
  ///
  /// Needs no credential: verification uses public keys, and trust comes from
  /// the local identity store — the CLI refuses an unknown signer rather than
  /// reporting the file as merely unverified.
  ///
  /// [signer] pins the expected identity by name. Without it the signer is
  /// resolved from the signature's fingerprint, which is a materially weaker
  /// statement: "signed by someone in your store" rather than "signed by the
  /// identity you named".
  ///
  /// Throws when verification could not be performed. A signature that is
  /// simply BAD is returned as a result with `valid == false`, never as an
  /// exception — conflating the two would let a genuine bad signature be
  /// reported as an error the user shrugs off.
  static Future<SignatureVerification> verifySignature({
    required String inputPath,
    String? signaturePath,
    String? signer,
    String? identityStore,
  }) async {
    final args = ['verify-signature', '-i', inputPath, '--json'];
    if (signaturePath != null && signaturePath.isNotEmpty) {
      args.addAll(['--signature', signaturePath]);
    }
    if (signer != null && signer.isNotEmpty) {
      args.addAll(['--signer', signer]);
    }
    if (identityStore != null && identityStore.isNotEmpty) {
      args.addAll(['--identity-store', identityStore]);
    }

    // logStdout stays false. The verdict is public, but the document is not
    // just the verdict: signed_at and every component label come verbatim from
    // an attacker-supplied .sig, unbounded in count and length, and are NOT
    // covered by the signature. A summary is everything a bug report needs.
    final result = await _runCLICommand(args);
    final out = (result.stdout as String).trim();

    // The CLI exits 1 for a bad signature AND for "could not check at all"
    // (missing signature file, unknown signer), but only the former emits
    // JSON. Parse first, and treat the absence of a document as an error.
    if (out.isEmpty) {
      throw Exception(_cliError(result, 'Could not verify the signature'));
    }
    try {
      final v = SignatureVerification.fromJson(
          jsonDecode(out) as Map<String, dynamic>);
      _outputDebugLog(
        'verify-signature: valid=${v.valid} file_match=${v.fileMatch} '
        'signature_valid=${v.signatureValid} components=${v.components.length} '
        'failing=${v.components.where((c) => !c.valid).length}',
      );
      return v;
    } catch (_) {
      // Catch, not `on FormatException`: a wrong-typed field raises TypeError,
      // which is an Error rather than an Exception and would escape the
      // documented contract.
      throw Exception(_cliError(result, 'Could not verify the signature'));
    }
  }

  // ==================== Recovery slots (gitlab#145) ====================

  /// List the recovery slots on [inputPath]. Requires no credential.
  static Future<List<RecoverySlot>> listRecoverySlots(String inputPath) async {
    // logStdout stays false: the slot fields are non-secret but come verbatim
    // from an untrusted file header, and nothing bounds how many slots a
    // crafted file declares. Log the count instead of the document.
    final result = await _runCLICommand(['list-recovery', '-i', inputPath, '--json']);
    if (result.exitCode != 0) {
      throw Exception(_cliError(result, 'Could not read recovery slots'));
    }
    final doc = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    return ((doc['slots'] as List<dynamic>?) ?? const [])
        .map((e) => RecoverySlot.fromJson(e as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Add a freshly generated recovery code to [inputPath].
  ///
  /// The code is password-equivalent, so the CLI writes it to a 0600 file of
  /// our choosing rather than to any stream (gitlab#146); this reads it back,
  /// deletes the file, and returns it for one-time display.
  /// Add a freshly generated recovery code to [inputPath].
  ///
  /// [onCode] receives the code as soon as it exists and MUST deliver it to the
  /// user; the temporary file is shredded only after it returns. Delivery is
  /// deliberately a precondition of deletion — the CLI itself refuses to delete
  /// this file on failure, because a failure does not prove the slot is absent,
  /// and deleting it unread would destroy the only credential that opens a slot
  /// that exists. Losing it because a widget went away is the same bug.
  static Future<void> addRecoveryCode({
    required String inputPath,
    required String outputPath,
    required Future<void> Function(String code, bool afterFailure) onCode,
    String? password,
    String? recoveryCode,
  }) async {
    final dir = await _credentialTempDir();
    final codeFile = File('${dir.path}/code');
    String? code;
    Object? failure;

    try {
      final result = await _runCLICommand(
        [
          'add-recovery',
          '-i', inputPath,
          '-o', outputPath,
          '--add-code',
          '--json',
          '--recovery-code-out', codeFile.path,
        ],
        environment: _recoveryEnv(password: password, recoveryCode: recoveryCode),
      );
      if (result.exitCode != 0) {
        failure = RecoveryCodeException(
          _cliError(result, 'Could not add a recovery code'));
      }
    } catch (e) {
      // A throw is not proof the code was not written either.
      failure = e;
    }

    try {
      if (await codeFile.exists()) {
        final read = (await codeFile.readAsString()).trim();
        if (read.isNotEmpty) code = read;
      }

      if (code != null) {
        // Deliver first, shred second. If delivery throws, the file is left in
        // place rather than destroyed.
        await onCode(code, failure != null);
      } else {
        failure ??= Exception(
          'The CLI reported success but wrote no recovery code',
        );
      }
    } finally {
      if (code != null) {
        final warning = await _shredTempDir(dir, codeFile);
        if (warning != null) _lastShredWarning = warning;
      }
    }

    if (failure != null) throw failure;
  }

  /// Set when a temporary credential file could not be removed.
  ///
  /// Surfaced in the UI rather than only logged: the debug log is off by
  /// default, so logging alone would silently leave a credential on disk.
  static String? _lastShredWarning;

  /// Take and clear the pending shred warning, if any.
  static String? takeShredWarning() {
    final w = _lastShredWarning;
    _lastShredWarning = null;
    return w;
  }

  /// A directory for a short-lived credential file.
  ///
  /// Prefers $XDG_RUNTIME_DIR: it is tmpfs-backed, 0700, per-user and cleared
  /// at logout, whereas systemTemp is usually disk-backed /tmp and can survive
  /// a reboot. Falls back to systemTemp when unset (e.g. on Windows).
  static Future<Directory> _credentialTempDir() async {
    final runtimeDir = Platform.environment['XDG_RUNTIME_DIR'];
    if (runtimeDir != null && runtimeDir.isNotEmpty) {
      final base = Directory(runtimeDir);
      if (await base.exists()) {
        return base.createTemp('oe_recovery_');
      }
    }
    return Directory.systemTemp.createTemp('oe_recovery_');
  }

  /// Overwrite the credential file's bytes, then remove the directory.
  ///
  /// An unlink alone leaves a password-equivalent credential in free blocks.
  /// Best effort: a failure is logged (path only) rather than swallowed, so a
  /// credential left on disk is at least visible.
  static Future<String?> _shredTempDir(Directory dir, File codeFile) async {
    try {
      if (await codeFile.exists()) {
        final length = await codeFile.length();
        await codeFile.writeAsBytes(List<int>.filled(length, 0), flush: true);
      }
      await dir.delete(recursive: true);
      return null;
    } catch (e) {
      final warning =
          'WARNING: the temporary recovery-code file at ${codeFile.path} could '
          'not be removed and may still be on disk. Delete it manually.';
      _outputDebugLog(warning);
      return warning;
    }
  }

  /// Add a recovery passphrase slot to [inputPath].
  ///
  /// [forcePassword] accepts a passphrase that fails the CLI's password
  /// policy. A recovery slot is another wrapping of the same file key, so the
  /// file is only as strong as its weakest slot, which is why the CLI gates
  /// this at all (gitlab#149) -- but the flag has to be reachable, or the
  /// error text tells the user to pass something the app cannot pass.
  static Future<void> addRecoveryPassphrase({
    required String inputPath,
    required String outputPath,
    required String newPassphrase,
    String? password,
    String? recoveryCode,
    bool forcePassword = false,
  }) async {
    final result = await _runCLICommand(
      [
        'add-recovery', '-i', inputPath, '-o', outputPath, '--add-passphrase', '--json',
        if (forcePassword) '--force-password',
      ],
      environment: _recoveryEnv(
        password: password,
        recoveryCode: recoveryCode,
        addPassphrase: newPassphrase,
      ),
    );
    if (result.exitCode != 0) {
      throw Exception(_cliError(result, 'Could not add a recovery passphrase'));
    }
  }

  /// Remove the recovery slot [slotId] from [inputPath].
  ///
  /// The caller MUST confirm first: this revokes that recovery path on the
  /// rewritten file and cannot be undone.
  static Future<void> removeRecoverySlot({
    required String inputPath,
    required String outputPath,
    required String slotId,
    String? password,
    String? recoveryCode,
  }) async {
    final result = await _runCLICommand(
      ['remove-recovery', '-i', inputPath, '-o', outputPath, '--slot-id', slotId, '--json'],
      environment: _recoveryEnv(password: password, recoveryCode: recoveryCode),
    );
    if (result.exitCode != 0) {
      throw Exception(_cliError(result, 'Could not remove the recovery slot'));
    }
  }

  /// Decrypt [inputPath] using a recovery credential instead of the password.
  static Future<void> recoverFile({
    required String inputPath,
    required String outputPath,
    String? recoveryCode,
    String? recoveryPassphrase,
  }) async {
    final args = ['recover', '-i', inputPath, '-o', outputPath, '--json'];
    if (recoveryPassphrase != null && recoveryPassphrase.isNotEmpty) {
      // The flag selects the credential type; the env var carries its value.
      args.add('--recovery-passphrase');
    }
    final result = await _runCLICommand(
      args,
      environment: _recoveryEnv(
        recoveryCode: recoveryCode,
        recoveryPassphrase: recoveryPassphrase,
      ),
    );
    if (result.exitCode != 0) {
      throw Exception(_cliError(result, 'Could not recover the file'));
    }
  }

  /// Disable telemetry and delete all collected data
  /// (`telemetry opt-out --force`).
  ///
  /// `--force` skips the CLI's own interactive confirmation — which a
  /// subprocess cannot answer — so the GUI is responsible for having shown
  /// its own first. The action is destructive (deletes pending events and the
  /// API key), so a nonzero exit is surfaced as an error: a caller must never
  /// report the data gone when it is not. It is not a persistent setting —
  /// telemetry can be re-enabled by `OPENSSL_ENCRYPT_TELEMETRY=1` or a config
  /// file — which the GUI confirmation states.
  static Future<void> telemetryOptOut() async {
    final result = await _runCLICommand(['telemetry', 'opt-out', '--force']);
    if (result.exitCode != 0) {
      throw Exception(_cliError(result, 'Telemetry opt-out failed'));
    }
  }

  /// Build the credential environment for a recovery command.
  ///
  /// Every value goes through the environment, never argv: a recovery code on
  /// the command line is visible in the world-readable /proc/PID/cmdline. The
  /// CLI reads each variable once and removes it.
  /// Credential-bearing variables the CLI reads; never inherited into a child.
  ///
  /// Keep in lockstep with `security_logger._SECRET_ENV_VARS` on the CLI side:
  /// a name missing here is inherited from the GUI's own environment straight
  /// into every child process.
  /// The parent environment minus every credential-bearing variable.
  ///
  /// Use this instead of `Platform.environment` in every spawn helper: a
  /// credential inherited from the GUI's own environment would otherwise
  /// reach the CLI child and, for variables the CLI acts on, change what it
  /// does.
  static Map<String, String> _inheritableEnvironment() {
    final env = Map<String, String>.from(Platform.environment);
    for (final name in _credentialEnvNames) {
      env.remove(name);
    }
    return env;
  }

  static const List<String> _credentialEnvNames = [
    'CRYPT_PASSWORD',
    'OPENSSL_ENCRYPT_PASSWORD',
    'OPENSSL_ENCRYPT_RECOVERY_CODE',
    'OPENSSL_ENCRYPT_RECOVERY_PASSPHRASE',
    'OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE',
    'OPENSSL_ENCRYPT_SECOND_PASSWORD',
    'OPENSSL_ENCRYPT_SIGNER_PASSPHRASE',
  ];

  static Map<String, String> _recoveryEnv({
    String? password,
    String? recoveryCode,
    String? recoveryPassphrase,
    String? addPassphrase,
  }) {
    final env = <String, String>{};
    if (password != null && password.isNotEmpty) {
      env['CRYPT_PASSWORD'] = password;
    }
    if (recoveryCode != null && recoveryCode.isNotEmpty) {
      env['OPENSSL_ENCRYPT_RECOVERY_CODE'] = recoveryCode;
    }
    if (recoveryPassphrase != null && recoveryPassphrase.isNotEmpty) {
      env['OPENSSL_ENCRYPT_RECOVERY_PASSPHRASE'] = recoveryPassphrase;
    }
    if (addPassphrase != null && addPassphrase.isNotEmpty) {
      env['OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE'] = addPassphrase;
    }
    return env;
  }

  /// Human-readable message for a failed recovery command.
  ///
  /// Uses stderr only: stdout on these commands is the JSON document, which on
  /// a failure path may be partial, and is never surfaced.
  static String _cliError(ProcessResult result, String fallback) {
    final err = (result.stderr as String).trim();
    return err.isEmpty ? '$fallback (exit ${result.exitCode})' : err;
  }
}

/// An add-recovery failure that may nonetheless have produced a live code.
///
/// The CLI writes the recovery code before modifying the envelope and does not
/// delete it on failure, because a failure does not prove the slot was absent.
/// When [code] is non-null the caller MUST show it to the user rather than
/// discard it: a slot may exist that only this code opens.
class RecoveryCodeException implements Exception {
  final String message;
  final String? code;

  const RecoveryCodeException(this.message, {this.code});

  @override
  String toString() => message;
}

/// A contact import was refused because the imported key differs from the one
/// already pinned for that identity (TOFU key-substitution).
///
/// This is the exact step an attacker needs in a key-substitution / MITM
/// attack, so it is a typed error rather than a generic failure: the GUI must
/// show the user the old and new fingerprints and get an explicit,
/// out-of-band-verified confirmation before retrying with allowKeyChange:true.
/// Never auto-retry.
class IdentityKeyChangedError implements Exception {
  final String name;
  final String oldFingerprint;
  final String newFingerprint;

  const IdentityKeyChangedError({
    required this.name,
    required this.oldFingerprint,
    required this.newFingerprint,
  });

  /// Parse the refusal from the CLI's stderr, or null if this is not a
  /// key-change refusal. Keyed on the CLI's stable labels
  /// (identity_cli.py: "Identity:", "Stored (pinned):", "Imported:").
  ///
  /// The `name` comes from the untrusted imported document. The CLI escapes
  /// control characters before printing (sanitize_for_display, gitlab#172),
  /// so a name cannot inject a real newline to forge a "Stored (pinned):"
  /// line — but the fingerprint fields are additionally constrained to
  /// colon-hex here, so even if that sanitization regressed, a crafted name
  /// could never be mistaken for a fingerprint and mislead the confirmation.
  static IdentityKeyChangedError? tryParse(String stderr) {
    if (!stderr.contains('the key for this contact has CHANGED')) {
      return null;
    }
    String? field(String label, String valuePattern) {
      final match = RegExp('^\\s*$label\\s+($valuePattern)\\s*\$', multiLine: true)
          .firstMatch(stderr);
      return match?.group(1);
    }

    // SSH-style colon-separated hex (pqc_signing.calculate_fingerprint), and
    // the identity-name charset (identity.py:124). Constraining both means a
    // rewrite of the human-readable stderr, a localization, or a regressed
    // upstream sanitizer cannot put arbitrary text into the trust dialog.
    const fingerprint = r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+';
    const identityName = r'[A-Za-z0-9][A-Za-z0-9._-]*';
    final name = field('Identity:', identityName);
    final oldFp = field(r'Stored \(pinned\):', fingerprint);
    final newFp = field('Imported:', fingerprint);
    if (name == null || oldFp == null || newFp == null) {
      return null;
    }
    // Identical fingerprints are not a key change: treat as a parse failure
    // so the dialog never asks the user to "verify" a change that isn't one.
    if (oldFp.toLowerCase() == newFp.toLowerCase()) {
      return null;
    }
    return IdentityKeyChangedError(
      name: name,
      oldFingerprint: oldFp,
      newFingerprint: newFp,
    );
  }

  @override
  String toString() =>
      'The key for "$name" has changed (pinned $oldFingerprint, imported '
      '$newFingerprint).';
}

/// One algorithm's contribution to a signature verification.
class SignatureComponent {
  final String component;
  final bool valid;

  const SignatureComponent({required this.component, required this.valid});

  factory SignatureComponent.fromJson(Map<String, dynamic> json) =>
      SignatureComponent(
        component: (json['component'] ?? '') as String,
        valid: json['valid'] == true,
      );
}

/// The result of verifying a detached signature.
///
/// [valid] is the only field that should drive a pass/fail indicator. The
/// component list exists so a partial failure is visible: a post-quantum
/// component failing while a classical one passes is still a bad signature,
/// and showing only the classical result would hide that.
class SignatureVerification {
  final bool valid;
  final bool fileMatch;
  final bool signatureValid;
  final String signer;
  final String signerFingerprint;
  final String signedAt;
  final List<SignatureComponent> components;
  final String reason;

  const SignatureVerification({
    required this.valid,
    required this.fileMatch,
    required this.signatureValid,
    required this.signer,
    required this.signerFingerprint,
    required this.signedAt,
    required this.components,
    required this.reason,
  });

  factory SignatureVerification.fromJson(Map<String, dynamic> json) {
    final components = ((json['components'] as List<dynamic>?) ?? const [])
        .map((e) => SignatureComponent.fromJson(e as Map<String, dynamic>))
        .toList(growable: false);
    final fileMatch = json['file_match'] == true;
    final signatureValid = json['signature_valid'] == true;
    return SignatureVerification(
        // Re-derived rather than trusted: a truncated but parseable
        // {"valid": true} would otherwise render a full green verdict with no
        // signer, no fingerprint and no components at all.
        valid: json['valid'] == true &&
            fileMatch &&
            signatureValid &&
            components.isNotEmpty &&
            components.every((c) => c.valid),
        fileMatch: fileMatch,
        signatureValid: signatureValid,
        signer: (json['signer'] ?? '') as String,
        signerFingerprint: (json['signer_fingerprint'] ?? '') as String,
        signedAt: (json['signed_at'] ?? '') as String,
        components: components,
        reason: (json['reason'] ?? '') as String,
    );
  }
}

/// One recovery slot on an envelope file.
class RecoverySlot {
  /// Sanitized id, safe to render in the UI.
  final String id;

  /// The raw, unsanitized id EXACTLY as the CLI reported it. Use this ONLY as
  /// the `--slot-id` argument to remove-recovery (the CLI must match the real
  /// id); never render it (F19, gitlab#254).
  final String rawId;
  final String type;
  final String? keyId;

  const RecoverySlot({
    required this.id,
    required this.rawId,
    required this.type,
    this.keyId,
  });

  /// F19 (gitlab#254, CWE-116): id/type/key_id come from the file's
  /// unauthenticated `list-recovery --json` output. Flutter honours bidi
  /// overrides and treats U+2028/U+2029 as line breaks, so a crafted slot could
  /// otherwise forge a line inside the irreversible-removal dialog. Sanitize
  /// every DISPLAYED field at the decode boundary; keep the raw id for --slot-id.
  factory RecoverySlot.fromJson(Map<String, dynamic> json) {
    final rawId = (json['id'] ?? '') as String;
    final keyId = json['key_id'] as String?;
    return RecoverySlot(
      id: InputValidator.sanitizeForDisplay(rawId),
      rawId: rawId,
      type: InputValidator.sanitizeForDisplay((json['type'] ?? '') as String),
      keyId: keyId == null ? null : InputValidator.sanitizeForDisplay(keyId),
    );
  }

  /// Label for the slot type, for display.
  String get typeLabel {
    switch (type) {
      case 'recovery_code':
        return 'Recovery code';
      case 'passphrase':
        return 'Passphrase';
      case 'pqc':
        return 'PQC escrow';
      default:
        return type;
    }
  }
}

/// Algorithm availability information
class AlgorithmAvailability {
  final String name;
  final String displayName;
  final bool available;
  final String? requiredLibrary;
  final String securityLevel;
  final String? description;
  final String? libraryVersion;

  AlgorithmAvailability({
    required this.name,
    required this.displayName,
    required this.available,
    this.requiredLibrary,
    required this.securityLevel,
    this.description,
    this.libraryVersion,
  });

  factory AlgorithmAvailability.fromJson(
    String name,
    Map<String, dynamic> json,
    Map<String, dynamic> libraries,
  ) {
    final requiredLib = json['required_library'] as String?;
    String? libVersion;
    if (requiredLib != null && libraries.containsKey(requiredLib)) {
      final libInfo = libraries[requiredLib] as Map<String, dynamic>;
      if (libInfo['available'] == true) {
        libVersion = libInfo['version'] as String?;
      }
    }

    return AlgorithmAvailability(
      name: name,
      displayName: json['display_name'] as String? ?? name,
      available: json['available'] as bool? ?? false,
      requiredLibrary: requiredLib,
      securityLevel: json['security_level'] as String? ?? 'STANDARD',
      description: json['description'] as String?,
      libraryVersion: libVersion,
    );
  }
}

/// Library information
class LibraryInfo {
  final bool available;
  final String? version;
  final List<String> requiredFor;

  LibraryInfo({
    required this.available,
    this.version,
    required this.requiredFor,
  });

  factory LibraryInfo.fromJson(Map<String, dynamic> json) {
    return LibraryInfo(
      available: json['available'] as bool? ?? false,
      version: json['version'] as String?,
      requiredFor: (json['required_for'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          [],
    );
  }
}

/// Complete availability information from CLI
class AvailabilityInfo {
  final Map<String, AlgorithmAvailability> ciphers;
  final Map<String, AlgorithmAvailability> hashes;
  final Map<String, AlgorithmAvailability> kdfs;
  final Map<String, AlgorithmAvailability> kems;
  final Map<String, AlgorithmAvailability> signatures;
  final Map<String, LibraryInfo> libraries;

  AvailabilityInfo({
    required this.ciphers,
    required this.hashes,
    required this.kdfs,
    required this.kems,
    required this.signatures,
    required this.libraries,
  });

  factory AvailabilityInfo.fromJson(Map<String, dynamic> json) {
    final libraries = <String, LibraryInfo>{};
    final libsJson = json['libraries'] as Map<String, dynamic>? ?? {};
    for (final entry in libsJson.entries) {
      libraries[entry.key] =
          LibraryInfo.fromJson(entry.value as Map<String, dynamic>);
    }

    return AvailabilityInfo(
      ciphers: _parseAlgorithms(
          json['ciphers'] as Map<String, dynamic>?, libsJson),
      hashes:
          _parseAlgorithms(json['hashes'] as Map<String, dynamic>?, libsJson),
      kdfs: _parseAlgorithms(json['kdfs'] as Map<String, dynamic>?, libsJson),
      kems: _parseAlgorithms(json['kems'] as Map<String, dynamic>?, libsJson),
      signatures: _parseAlgorithms(
          json['signatures'] as Map<String, dynamic>?, libsJson),
      libraries: libraries,
    );
  }

  static Map<String, AlgorithmAvailability> _parseAlgorithms(
    Map<String, dynamic>? json,
    Map<String, dynamic> libraries,
  ) {
    if (json == null) return {};
    final result = <String, AlgorithmAvailability>{};
    for (final entry in json.entries) {
      result[entry.key] = AlgorithmAvailability.fromJson(
        entry.key,
        entry.value as Map<String, dynamic>,
        libraries,
      );
    }
    return result;
  }
}

/// Configuration classes for CLI parameters
class CLIConfig {
  final String algorithm;
  final Map<String, Map<String, dynamic>>? hashConfig;
  final Map<String, Map<String, dynamic>>? kdfConfig;

  CLIConfig({
    required this.algorithm,
    this.hashConfig,
    this.kdfConfig,
  });
}
