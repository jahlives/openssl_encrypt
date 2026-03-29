import 'dart:convert';
import 'dart:io';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as path;

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
  static bool _availabilityLoading = false;

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
  static Future<AvailabilityInfo?> getAvailabilityInfo() async {
    if (_availabilityCache != null) return _availabilityCache;
    if (_availabilityLoading) {
      // Wait for loading to complete
      while (_availabilityLoading) {
        await Future.delayed(const Duration(milliseconds: 50));
      }
      return _availabilityCache;
    }

    _availabilityLoading = true;
    try {
      final result = await _runCLICommand(['list-available-algorithms']);
      if (result.exitCode == 0) {
        final json = jsonDecode(result.stdout.toString()) as Map<String, dynamic>;
        _availabilityCache = AvailabilityInfo.fromJson(json);
      }
    } catch (e) {
      _outputDebugLog('Error fetching availability info: $e');
    } finally {
      _availabilityLoading = false;
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

      // NOTE: WHIRLPOOL is intentionally excluded (legacy, not recommended)

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
     Function(String)? onProgress,
     Function(String)? onStatus}
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
              case 'whirlpool':
                args.addAll(['--whirlpool-rounds', config['rounds'].toString()]);
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

      // Add progress flag if enabled
      if (showProgress) {
        args.add('--progress');
      }

      final maskedCommand = _getMaskedCommand(args);
      _outputDebugLog('=== CLI ENCRYPT COMMAND ===');
      _outputDebugLog('Full command: $maskedCommand');
      _outputDebugLog('Raw args: ${args.join(' ')}');

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
        _outputDebugLog('Stdout: $stdoutMsg');
        throw Exception('Encryption failed: ${errorMsg.isNotEmpty ? errorMsg : stdoutMsg}\n\nCommand executed: $maskedCommand');
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
        if (verifyFrom != null && verifyFrom.isNotEmpty) {
          args.addAll(['--verify-from', verifyFrom]);
        }
        if (skipVerification) {
          args.add('--no-verify');
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
      _outputDebugLog('Raw args: ${args.join(' ')}');

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
        _outputDebugLog('Stdout: $stdoutMsg');
        throw Exception('Decryption failed: ${errorMsg.isNotEmpty ? errorMsg : stdoutMsg}\n\nCommand executed: $maskedCommand');
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
  static Future<ProcessResult> _runCLICommand(List<String> args) async {
    // When running inside Flatpak, use direct CLI path for better performance and reliability
    if (_isFlaspakVersion && await File(_cliPath).exists()) {
      _outputDebugLog('Using direct Flatpak CLI: $_cliPath ${args.join(' ')}');
      final result = await Process.run(_cliPath, args);
      _outputDebugLog('Flatpak CLI exit code: ${result.exitCode}');
      return result;
    }

    // Try development CLI when not in Flatpak environment
    try {
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];

      _outputDebugLog('Attempting development CLI: python ${pythonArgs.join(' ')}');
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

      final result = await Process.run('python', pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: env);

      _outputDebugLog('Development CLI exit code: ${result.exitCode}');
      _outputDebugLog('Development CLI stdout: ${result.stdout}');
      _outputDebugLog('Development CLI stderr: ${result.stderr}');

      return result;
    } catch (e) {
      _outputDebugLog('Development CLI exception: $e');
      throw Exception('No CLI available');
    }
  }

  /// Run CLI command with stdin input (for passphrases, etc.)
  static Future<ProcessResult> _runCLICommandWithStdin(List<String> args, String stdinInput) async {
    Process process;

    // When running inside Flatpak, use direct CLI path
    if (_isFlaspakVersion && await File(_cliPath).exists()) {
      _outputDebugLog('Using direct Flatpak CLI with stdin: $_cliPath ${args.join(' ')}');
      process = await Process.start(_cliPath, args);
    } else {
      // Development CLI
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];
      _outputDebugLog('Attempting development CLI with stdin: python ${pythonArgs.join(' ')}');

      final env = Map<String, String>.from(Platform.environment);
      process = await Process.start('python', pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: env);
    }

    // Send stdin input
    process.stdin.write(stdinInput);
    if (!stdinInput.endsWith('\n')) {
      process.stdin.write('\n');
    }
    await process.stdin.flush();
    await process.stdin.close();

    // Collect output
    final stdout = await process.stdout.transform(utf8.decoder).join();
    final stderr = await process.stderr.transform(utf8.decoder).join();
    final exitCode = await process.exitCode;

    _outputDebugLog('CLI with stdin exit code: $exitCode');

    return ProcessResult(process.pid, exitCode, stdout, stderr);
  }

  /// Run CLI command with real-time progress streaming
  static Future<ProcessResult> _runCLICommandWithProgress(
    List<String> args,
    {Map<String, String>? environment, Function(String)? onStdout, Function(String)? onStderr, Function(String)? onProgress, Function(String)? onStatus, String? commandForStatus, bool hsmDetectionEnabled = false}
  ) async {
    Process process;

    // Merge environment variables for secure password passing
    final processEnv = Map<String, String>.from(Platform.environment);
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
      _outputDebugLog('Development CLI unavailable: $e, trying Flatpak CLI with progress');
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

    // Merge environment variables for secure password passing
    final processEnv = Map<String, String>.from(Platform.environment);
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
      _outputDebugLog('Development CLI unavailable: $e, trying Flatpak CLI with interaction');
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

        final timestamp = DateTime.now().toIso8601String().replaceAll(':', '-').substring(0, 19);
        _debugLogFile = path.join(logDir.path, 'debug_$timestamp.log');

        // Write initial header
        final headerInfo = [
          '=== OpenSSL Encrypt Desktop Debug Log ===',
          'Started: ${DateTime.now().toIso8601String()}',
          'Backend: ${_isFlaspakVersion ? 'Flatpak' : 'Development'}',
          'CLI Version: ${_cliVersion ?? 'Unknown'}',
          '==========================================',
          ''
        ];

        final file = File(_debugLogFile!);
        await file.writeAsString(headerInfo.join('\n'));

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
            case 'whirlpool':
              if (config['rounds'] != null && config['rounds'] > 0) {
                args.addAll(['--whirlpool-rounds', config['rounds'].toString()]);
              }
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

    return 'CRYPT_PASSWORD="[password]" $commandPrefix ${args.join(' ')}';
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

    return 'CRYPT_PASSWORD="[password]" $commandPrefix ${args.join(' ')}';
  }

  /// Generate copy-pasteable CLI command with masked password
  static String _getMaskedCommand(List<String> args) {
    // Determine command prefix
    String commandPrefix = '';
    if (_isFlaspakVersion) {
      commandPrefix = 'flatpak run com.opensslencrypt.OpenSSLEncrypt';
    } else {
      commandPrefix = 'python -m openssl_encrypt.cli';
    }

    // Create masked args by replacing password values with asterisks
    final maskedArgs = <String>[];
    for (int i = 0; i < args.length; i++) {
      if (args[i] == '--password' && i + 1 < args.length) {
        maskedArgs.add(args[i]);
        maskedArgs.add('****');
        i++; // Skip the actual password value
      } else {
        maskedArgs.add(args[i]);
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
    // Video steganography options
    double? videoQuantizationStep,           // default 8.0
    double? videoAdaptationFactor,           // default 1.2
    double? videoCompensationFactor,         // default 0.5
    int? videoBitsPerCoefficient,            // 1-4, default 2
    bool videoTemporalSpread = true,         // default enabled
    int? videoQualityPreservation,           // 1-10, default 8
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
      '-a', algorithm,
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

    // Add video steganography options if provided
    if (videoQuantizationStep != null) {
      args.addAll(['--video-quantization-step', videoQuantizationStep.toString()]);
    }
    if (videoAdaptationFactor != null) {
      args.addAll(['--video-adaptation-factor', videoAdaptationFactor.toString()]);
    }
    if (videoCompensationFactor != null) {
      args.addAll(['--video-compensation-factor', videoCompensationFactor.toString()]);
    }
    if (videoBitsPerCoefficient != null) {
      args.addAll(['--video-bits-per-coefficient', videoBitsPerCoefficient.toString()]);
    }
    if (!videoTemporalSpread) {
      // Only add flag if disabled (default is enabled)
      args.add('--no-video-temporal-spread');
    }
    if (videoQualityPreservation != null) {
      args.addAll(['--video-quality-preservation', videoQualityPreservation.toString()]);
    }

    // Add hash configuration if provided
    if (hashConfig != null) {
      for (final entry in hashConfig.entries) {
        final hashName = entry.key;
        final config = entry.value;
        if (config['enabled'] == true && config['rounds'] != null && config['rounds'] > 0) {
          args.addAll(['--${hashName}-rounds', config['rounds'].toString()]);
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
    // Video steganography options
    double? videoQuantizationStep,
    double? videoAdaptationFactor,
    double? videoCompensationFactor,
    int? videoBitsPerCoefficient,
    bool videoTemporalSpread = true,
    int? videoQualityPreservation,
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
        videoQuantizationStep: videoQuantizationStep,
        videoAdaptationFactor: videoAdaptationFactor,
        videoCompensationFactor: videoCompensationFactor,
        videoBitsPerCoefficient: videoBitsPerCoefficient,
        videoTemporalSpread: videoTemporalSpread,
        videoQualityPreservation: videoQualityPreservation,
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
      if (verifyFrom != null && verifyFrom.isNotEmpty) {
        args.addAll(['--verify-from', verifyFrom]);
      }
      if (skipVerification) {
        args.add('--no-verify');
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

  // ==================== Identity Management Methods ====================

  /// List all identities (own + contacts)
  static Future<Map<String, List<Map<String, dynamic>>>> listIdentities() async {
    try {
      final args = ['identity', 'list', '--include-contacts', '--json'];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode != 0) {
        _outputDebugLog('Failed to list identities: ${result.stderr}');
        return {'own': [], 'contacts': []};
      }

      final data = jsonDecode(result.stdout) as Map<String, dynamic>;

      return {
        'own': (data['own'] as List<dynamic>?)?.map((i) => i as Map<String, dynamic>).toList() ?? [],
        'contacts': (data['contacts'] as List<dynamic>?)?.map((i) => i as Map<String, dynamic>).toList() ?? [],
      };
    } catch (e) {
      _outputDebugLog('Error listing identities: $e');
      return {'own': [], 'contacts': []};
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
  static Future<void> importContact(String publicKeyData, {String? alias}) async {
    try {
      final args = ['identity', 'import', '--data', publicKeyData];

      if (alias != null && alias.isNotEmpty) {
        args.addAll(['--alias', alias]);
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);

      if (result.exitCode != 0) {
        throw Exception('Failed to import contact: ${result.stderr}');
      }
    } catch (e) {
      throw Exception('Error importing contact: $e');
    }
  }

  /// Delete an identity or contact
  static Future<void> deleteIdentity(String name, {bool isContact = false}) async {
    try {
      final args = ['identity', 'delete', name];

      if (isContact) {
        args.add('--contact');
      }

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

  /// Test keyserver connection
  static Future<bool> testKeyserverConnection(String url) async {
    try {
      final args = [
        'plugin',
        'keyserver',
        'test',
        '--url', url,
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      final result = await _runCLICommand(args);
      return result.exitCode == 0;
    } catch (e) {
      _outputDebugLog('Keyserver connection test failed: $e');
      return false;
    }
  }

  /// Clear keyserver cache
  static Future<bool> clearKeyserverCache() async {
    try {
      final args = [
        'plugin',
        'keyserver',
        'clear-cache',
      ];

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
