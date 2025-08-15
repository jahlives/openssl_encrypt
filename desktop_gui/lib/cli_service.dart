import 'dart:convert';
import 'dart:io';
import 'dart:async';

/// Service layer for integrating with OpenSSL Encrypt CLI
/// Replaces all pure Dart crypto implementations
class CLIService {
  static const String _cliPath = '/app/bin/openssl-encrypt'; // Flatpak CLI path
  
  static bool debugEnabled = false;
  
  /// Initialize CLI service and verify CLI is available
  static Future<bool> initialize() async {
    try {
      // Check if CLI is available in Flatpak environment
      if (await File(_cliPath).exists()) {
        _outputDebugLog('CLI found at: $_cliPath');
        return true;
      }
      
      // For development, try running CLI via parent directory
      try {
        final result = await Process.run('python', ['-m', 'openssl_encrypt.cli', '--help'], 
          workingDirectory: '/home/work/private/git/openssl_encrypt');
        if (result.exitCode == 0) {
          _outputDebugLog('CLI found via development path');
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
  
  /// Get list of supported algorithms from CLI
  static Future<List<String>> getSupportedAlgorithms() async {
    try {
      final result = await _runCLICommand(['--list-algorithms']);
      if (result.exitCode != 0) {
        throw Exception('Failed to get algorithms: ${result.stderr}');
      }
      
      // Parse algorithm list from CLI output
      final lines = result.stdout.toString().split('\n');
      final algorithms = <String>[];
      for (final line in lines) {
        final trimmed = line.trim();
        if (trimmed.isNotEmpty && !trimmed.startsWith('Available algorithms:')) {
          algorithms.add(trimmed);
        }
      }
      
      return algorithms.isNotEmpty ? algorithms : ['fernet', 'aes-gcm', 'chacha20-poly1305', 'xchacha20-poly1305'];
    } catch (e) {
      _outputDebugLog('Error getting algorithms: $e');
      // Return default algorithms if CLI call fails
      return ['fernet', 'aes-gcm', 'chacha20-poly1305', 'xchacha20-poly1305'];
    }
  }
  
  /// Get list of supported hash algorithms from CLI
  static Future<List<String>> getHashAlgorithms() async {
    try {
      final result = await _runCLICommand(['--list-hash']);
      if (result.exitCode != 0) {
        throw Exception('Failed to get hash algorithms: ${result.stderr}');
      }
      
      // Parse hash algorithm list from CLI output
      final lines = result.stdout.toString().split('\n');
      final hashAlgorithms = <String>[];
      for (final line in lines) {
        final trimmed = line.trim();
        if (trimmed.isNotEmpty && !trimmed.startsWith('Available hash functions:')) {
          hashAlgorithms.add(trimmed);
        }
      }
      
      return hashAlgorithms.isNotEmpty ? hashAlgorithms : ['sha256', 'sha512', 'blake2b', 'blake3', 'shake256'];
    } catch (e) {
      _outputDebugLog('Error getting hash algorithms: $e');
      // Return default hash algorithms if CLI call fails
      return ['sha256', 'sha512', 'blake2b', 'blake3', 'shake256'];
    }
  }
  
  /// Encrypt text using CLI
  static Future<String> encryptText(
    String text, 
    String password, 
    String algorithm, 
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
  ) async {
    try {
      // Create temporary input file
      final tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_');
      final inputFile = File('${tempDir.path}/input.txt');
      final outputFile = File('${tempDir.path}/output.txt');
      
      await inputFile.writeAsString(text);
      
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
            args.addAll(['--hash', hashName, '--hash-rounds', config['rounds'].toString()]);
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
                if (config['rounds'] != null && config['rounds'] > 0) {
                  args.addAll(['--kdf', 'pbkdf2', '--kdf-rounds', config['rounds'].toString()]);
                }
                break;
              case 'scrypt':
                args.add('--kdf');
                args.add('scrypt');
                break;
              case 'argon2':
                args.add('--kdf');
                args.add('argon2');
                break;
              case 'hkdf':
                args.add('--kdf');
                args.add('hkdf');
                break;
              case 'balloon':
                args.add('--kdf');
                args.add('balloon');
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
      
      _outputDebugLog('CLI encrypt command: ${args.join(' ')}');
      
      final result = await _runCLICommand(args);
      
      if (result.exitCode != 0) {
        throw Exception('Encryption failed: ${result.stderr}');
      }
      
      // Read encrypted output
      final encryptedContent = await outputFile.readAsString();
      
      // Cleanup temporary files
      await tempDir.delete(recursive: true);
      
      return encryptedContent.trim();
    } catch (e) {
      _outputDebugLog('Encryption error: $e');
      throw Exception('Encryption failed: $e');
    }
  }
  
  /// Decrypt text using CLI
  static Future<String> decryptText(String encryptedData, String password) async {
    try {
      // Create temporary input file
      final tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_');
      final inputFile = File('${tempDir.path}/input.txt');
      final outputFile = File('${tempDir.path}/output.txt');
      
      await inputFile.writeAsString(encryptedData);
      
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
      
      _outputDebugLog('CLI decrypt command: ${args.join(' ')}');
      
      final result = await _runCLICommand(args);
      
      if (result.exitCode != 0) {
        throw Exception('Decryption failed: ${result.stderr}');
      }
      
      // Read decrypted output
      final decryptedContent = await outputFile.readAsString();
      
      // Cleanup temporary files
      await tempDir.delete(recursive: true);
      
      return decryptedContent.trim();
    } catch (e) {
      _outputDebugLog('Decryption error: $e');
      throw Exception('Decryption failed: $e');
    }
  }
  
  /// Run CLI command with appropriate executable path
  static Future<ProcessResult> _runCLICommand(List<String> args) async {
    // Use Flatpak CLI path when in production
    if (await File(_cliPath).exists()) {
      return await Process.run(_cliPath, args);
    }
    
    // For development, use Python module from parent directory
    final pythonArgs = ['-m', 'openssl_encrypt.cli', ...args];
    return await Process.run('python', pythonArgs, 
      workingDirectory: '/home/work/private/git/openssl_encrypt');
  }
  
  /// Debug logging utility - internal use
  static void _outputDebugLog(String message) {
    if (debugEnabled) {
      print('[CLI-SERVICE] $message');
    }
  }
  
  /// Public debug logging utility for other components  
  static void outputDebugLog(String message) {
    if (debugEnabled) {
      print('[DEBUG] $message');
    }
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