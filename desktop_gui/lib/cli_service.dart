import 'dart:convert';
import 'dart:io';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as path;

/// Service layer for integrating with OpenSSL Encrypt CLI
/// Replaces all pure Dart crypto implementations
class CLIService {
  static const String _cliPath = '/app/bin/openssl-encrypt'; // Flatpak CLI path

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

  /// Initialize CLI service and verify CLI is available
  static Future<bool> initialize() async {
    try {
      // Check if CLI is available in Flatpak environment
      if (await File(_cliPath).exists()) {
        _outputDebugLog('CLI found at: $_cliPath');
        _isFlaspakVersion = true;
        await _detectVersion();
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

  /// Get list of supported algorithms organized by category
  static Future<Map<String, List<String>>> getSupportedAlgorithms() async {
    try {
      // For now, return the known algorithm list from CLI help
      // In the future, this could parse CLI output dynamically
      return {
        'Classical Symmetric': [
          'fernet',
          'aes-gcm',
          'chacha20-poly1305',
          'xchacha20-poly1305',
          'aes-siv',
          'aes-gcm-siv',
          'aes-ocb3',
          'camellia',
        ],
        'Post-Quantum Hybrid (ML-KEM)': [
          'ml-kem-512-hybrid',
          'ml-kem-768-hybrid',
          'ml-kem-1024-hybrid',
        ],
        'Post-Quantum Hybrid (Kyber Legacy)': [
          'kyber512-hybrid',
          'kyber768-hybrid',
          'kyber1024-hybrid',
        ],
        'Post-Quantum ChaCha20': [
          'ml-kem-512-chacha20',
          'ml-kem-768-chacha20',
          'ml-kem-1024-chacha20',
        ],
        'Post-Quantum HQC': [
          'hqc-128-hybrid',
          'hqc-192-hybrid',
          'hqc-256-hybrid',
        ],
        'Post-Quantum Signatures (MAYO)': [
          'mayo-1-hybrid',
          'mayo-3-hybrid',
          'mayo-5-hybrid',
        ],
        'Post-Quantum Signatures (CROSS)': [
          'cross-128-hybrid',
          'cross-192-hybrid',
          'cross-256-hybrid',
        ],
      };
    } catch (e) {
      _outputDebugLog('Error getting algorithms: $e');
      // Return basic algorithms if there's an error
      return {
        'Classical Symmetric': ['fernet', 'aes-gcm', 'chacha20-poly1305', 'xchacha20-poly1305'],
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
      // Return the known hash algorithms from CLI help
      return {
        'SHA-2 Family': [
          'sha224',
          'sha256',
          'sha384',
          'sha512',
        ],
        'SHA-3 Family': [
          'sha3-224',
          'sha3-256',
          'sha3-384',
          'sha3-512',
        ],
        'SHAKE Functions': [
          'shake128',
          'shake256',
        ],
        'Modern Hash Functions': [
          'blake2b',
          'blake3',
        ],
        if (!shouldHideLegacyAlgorithms()) 'Legacy Hash Functions': [
          'whirlpool',
        ],
      };
    } catch (e) {
      _outputDebugLog('Error getting hash algorithms: $e');
      // Return basic hash algorithms if there's an error
      return {
        'SHA-2 Family': ['sha256', 'sha512'],
        'Modern Hash Functions': ['blake2b'],
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
    {String? encryptData, Function(String)? onProgress, Function(String)? onStatus}
  ) async {
    Directory? tempDir;
    try {
      onStatus?.call('Initializing encryption...');

      // Create temporary input file
      tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_');
      final inputFile = File('${tempDir.path}/input.txt');
      final outputFile = File('${tempDir.path}/output.txt');

      await inputFile.writeAsString(text);
      onStatus?.call('Prepared temporary files');

      // Build CLI command
      final args = [
        'encrypt',
        '-i', inputFile.path,
        '-o', outputFile.path,
        '--password', password,
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

      // Add post-quantum specific parameters
      if (_isPostQuantumAlgorithm(algorithm)) {
        args.add('--pqc-store-key');
        args.add('--dual-encrypt-key');
        if (encryptData != null) {
          args.addAll(['--encryption-data', encryptData]);
        }
      }

      if (debugEnabled) {
        args.add('--debug');
      }

      // Add force password for simple passwords
      args.add('--force-password');

      final maskedCommand = _getMaskedCommand(args);
      _outputDebugLog('=== CLI ENCRYPT COMMAND ===');
      _outputDebugLog('Full command: $maskedCommand');
      _outputDebugLog('Raw args: ${args.join(' ')}');
      onStatus?.call('Executing: $maskedCommand');

      final result = await _runCLICommandWithProgress(
        args,
        onStdout: (line) {
          if (debugEnabled) _outputDebugLog('CLI stdout: $line');
        },
        onStderr: (line) {
          if (debugEnabled) _outputDebugLog('CLI stderr: $line');
        },
        onProgress: (line) {
          onProgress?.call(line);
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

      onStatus?.call('Reading encrypted output...');

      // Read encrypted output
      if (!await outputFile.exists()) {
        throw Exception('CLI did not create output file');
      }

      final encryptedContent = await outputFile.readAsString();

      // Cleanup temporary files
      await tempDir.delete(recursive: true);
      onStatus?.call('Encryption completed successfully');

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
    {Function(String)? onProgress, Function(String)? onStatus}
  ) async {
    Directory? tempDir;
    try {
      onStatus?.call('Initializing decryption...');

      // Create temporary input file
      tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_');
      final inputFile = File('${tempDir.path}/input.txt');
      final outputFile = File('${tempDir.path}/output.txt');

      await inputFile.writeAsString(encryptedData);
      onStatus?.call('Prepared temporary files');

      // Build CLI command
      final args = [
        'decrypt',
        '-i', inputFile.path,
        '-o', outputFile.path,
        '--password', password,
      ];

      if (debugEnabled) {
        args.add('--debug');
      }

      // Add force password for simple passwords
      args.add('--force-password');

      final maskedCommand = _getMaskedCommand(args);
      _outputDebugLog('=== CLI DECRYPT COMMAND ===');
      _outputDebugLog('Full command: $maskedCommand');
      _outputDebugLog('Raw args: ${args.join(' ')}');
      onStatus?.call('Executing: $maskedCommand');

      final result = await _runCLICommandWithProgress(
        args,
        onStdout: (line) {
          if (debugEnabled) _outputDebugLog('CLI stdout: $line');
        },
        onStderr: (line) {
          if (debugEnabled) _outputDebugLog('CLI stderr: $line');
        },
        onProgress: (line) {
          onProgress?.call(line);
        },
      );

      if (result.exitCode != 0) {
        final errorMsg = result.stderr.toString().trim();
        final stdoutMsg = result.stdout.toString().trim();
        _outputDebugLog('CLI decryption failed. Exit code: ${result.exitCode}');
        _outputDebugLog('Stderr: $errorMsg');
        _outputDebugLog('Stdout: $stdoutMsg');
        throw Exception('Decryption failed: ${errorMsg.isNotEmpty ? errorMsg : stdoutMsg}\n\nCommand executed: $maskedCommand');
      }

      onStatus?.call('Reading decrypted output...');

      // Read decrypted output
      if (!await outputFile.exists()) {
        throw Exception('CLI did not create output file');
      }

      final decryptedContent = await outputFile.readAsString();

      // Cleanup temporary files
      await tempDir.delete(recursive: true);
      onStatus?.call('Decryption completed successfully');

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


  /// Run CLI command with appropriate executable path
  static Future<ProcessResult> _runCLICommand(List<String> args) async {
    // Prefer development CLI when available due to Flatpak post-quantum issues
    try {
      final pythonCmd = '/usr/bin/python';  // Use the python that has pip install -e .
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];

      _outputDebugLog('Attempting development CLI: $pythonCmd ${pythonArgs.join(' ')}');
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

      final result = await Process.run(pythonCmd, pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt',
        environment: env);

      _outputDebugLog('Development CLI exit code: ${result.exitCode}');
      _outputDebugLog('Development CLI stdout: ${result.stdout}');
      _outputDebugLog('Development CLI stderr: ${result.stderr}');

      return result;
    } catch (e) {
      _outputDebugLog('Development CLI exception: $e');
      _outputDebugLog('Falling back to Flatpak CLI');
    }

    // Fallback to Flatpak CLI when development CLI is unavailable
    if (await File(_cliPath).exists()) {
      _outputDebugLog('Using Flatpak CLI: $_cliPath ${args.join(' ')}');
      final result = await Process.run(_cliPath, args);
      _outputDebugLog('Flatpak CLI exit code: ${result.exitCode}');
      return result;
    }

    throw Exception('No CLI available');
  }

  /// Run CLI command with real-time progress streaming
  static Future<ProcessResult> _runCLICommandWithProgress(
    List<String> args,
    {Function(String)? onStdout, Function(String)? onStderr, Function(String)? onProgress}
  ) async {
    Process process;

    // Prefer development CLI when available due to Flatpak post-quantum issues
    try {
      final pythonCmd = '/usr/bin/python';  // Use the python that has pip install -e .
      final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];
      process = await Process.start(pythonCmd, pythonArgs,
        workingDirectory: '/home/work/private/git/openssl_encrypt');
      _outputDebugLog('Using development CLI with progress (python module)');
    } catch (e) {
      _outputDebugLog('Development CLI unavailable: $e, trying Flatpak CLI with progress');
      // Fallback to Flatpak CLI
      if (await File(_cliPath).exists()) {
        process = await Process.start(_cliPath, args);
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
    });

    // Listen to stderr stream
    process.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      stderrBuffer.writeln(line);
      onStderr?.call(line);

      // Some CLI tools output progress to stderr
      if (line.contains('Progress:') || line.contains('%') || line.contains('Processing')) {
        onProgress?.call(line);
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

    info += 'Backend: ${_isFlaspakVersion ? 'Flatpak (/app/bin/openssl-encrypt)' : 'Development (python -m openssl_encrypt.cli)'}\n';

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
      '--password', '[password]',
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

    // Show actual command that would be executed
    String commandPrefix = '';
    if (_isFlaspakVersion) {
      commandPrefix = '/app/bin/openssl-encrypt';
    } else {
      commandPrefix = 'python -m openssl_encrypt.cli';
    }

    return '$commandPrefix ${args.join(' ')}';
  }

  /// Generate CLI command preview for decryption without execution
  static String previewDecryptCommand(String password) {
    final args = <String>[
      'decrypt',
      '-i', '[encrypted-file]',
      '-o', '[output-file]',
      '--password', '[password]',
    ];

    if (debugEnabled) {
      args.add('--debug');
    }

    // Add force password for simple passwords
    args.add('--force-password');

    // Show actual command that would be executed
    String commandPrefix = '';
    if (_isFlaspakVersion) {
      commandPrefix = '/app/bin/openssl-encrypt';
    } else {
      commandPrefix = 'python -m openssl_encrypt.cli';
    }

    return '$commandPrefix ${args.join(' ')}';
  }

  /// Generate copy-pasteable CLI command with masked password
  static String _getMaskedCommand(List<String> args) {
    // Use same priority logic as actual CLI execution
    String commandPrefix = 'python -m openssl_encrypt.cli';

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
