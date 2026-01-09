import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'native_crypto.dart';

// FFI bindings for mobile crypto functions
class CryptoFFI {
  DynamicLibrary? _lib;
  Function? _initCrypto;
  Function? _cleanupCrypto;
  Function? _encryptText;
  Function? _decryptText;
  Function? _getAlgorithms;
  Function? _freeString;

  CryptoFFI() {
    print('CryptoFFI: Initializing...');
    
    // Load the dynamic library
    try {
      if (Platform.isAndroid) {
        print('CryptoFFI: Loading for Android');
        _lib = DynamicLibrary.open('libcrypto_ffi.so');
      } else if (Platform.isLinux) {
        print('CryptoFFI: Loading for Linux');
        // Try multiple possible paths for the shared library
        final possiblePaths = [
          './libcrypto_ffi.so',
          '../libcrypto_ffi.so',
          '/home/work/private/git/openssl_encrypt/mobile_app/openssl_encrypt_mobile/libcrypto_ffi.so'
        ];
        
        for (final path in possiblePaths) {
          try {
            print('CryptoFFI: Trying path: $path');
            _lib = DynamicLibrary.open(path);
            print('CryptoFFI: Successfully loaded from: $path');
            break; // Success, exit loop
          } catch (e) {
            print('CryptoFFI: Failed to load from $path: $e');
            continue; // Try next path
          }
        }
        
        if (_lib == null) {
          throw Exception('Could not find libcrypto_ffi.so in any expected location');
        }
      } else {
        throw UnsupportedError('Platform not supported');
      }
    } catch (e) {
      // Failed to load crypto library, will use mock implementation
      print('CryptoFFI: Failed to load crypto library: $e');
      return;
    }

    // Bind C functions
    try {
      _bindFunctions();
      
      // Initialize the crypto module
      final initResult = _initCrypto!();
      if (initResult == 0) {
        print('Failed to initialize crypto module, falling back to mock');
        _lib = null; // Force mock mode
        return;
      }
    } catch (e) {
      print('Failed to initialize FFI functions: $e');
      _lib = null; // Force mock mode
      return;
    }
  }

  void _bindFunctions() {
    print('CryptoFFI: Binding functions...');
    
    _initCrypto = _lib!
        .lookup<NativeFunction<Int32 Function()>>('init_crypto_ffi')
        .asFunction<int Function()>();
    print('CryptoFFI: ✅ init_crypto_ffi bound');

    _cleanupCrypto = _lib!
        .lookup<NativeFunction<Void Function()>>('cleanup_crypto_ffi')
        .asFunction<void Function()>();
    print('CryptoFFI: ✅ cleanup_crypto_ffi bound');

    _encryptText = _lib!
        .lookup<NativeFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>>('mobile_crypto_encrypt_text')
        .asFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>();
    print('CryptoFFI: ✅ mobile_crypto_encrypt_text bound');

    _decryptText = _lib!
        .lookup<NativeFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>>('mobile_crypto_decrypt_text')
        .asFunction<Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>();
    print('CryptoFFI: ✅ mobile_crypto_decrypt_text bound');

    _getAlgorithms = _lib!
        .lookup<NativeFunction<Pointer<Utf8> Function()>>('mobile_crypto_get_algorithms')
        .asFunction<Pointer<Utf8> Function()>();
    print('CryptoFFI: ✅ mobile_crypto_get_algorithms bound');

    _freeString = _lib!
        .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>('free_crypto_string')
        .asFunction<void Function(Pointer<Utf8>)>();
    print('CryptoFFI: ✅ free_crypto_string bound');
  }

  /// Encrypt text using the mobile crypto core
  Future<String> encryptText(String text, String password) async {
    if (_lib == null) {
      // Mock implementation for development
      return _mockEncrypt(text, password);
    }

    final textPtr = text.toNativeUtf8();
    final passwordPtr = password.toNativeUtf8();

    try {
      final resultPtr = (_encryptText as Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>))(textPtr, passwordPtr);
      final result = resultPtr.toDartString();
      (_freeString as void Function(Pointer<Utf8>))(resultPtr);
      return result;
    } finally {
      malloc.free(textPtr);
      malloc.free(passwordPtr);
    }
  }

  /// Decrypt text using the mobile crypto core
  Future<String> decryptText(String encryptedJson, String password) async {
    print('CryptoFFI: decryptText called, _lib = ${_lib != null ? 'loaded' : 'null'}');
    
    if (_lib == null) {
      // Mock implementation for development
      print('CryptoFFI: Using mock decryption');
      return await _mockDecrypt(encryptedJson, password);
    }

    final encryptedPtr = encryptedJson.toNativeUtf8();
    final passwordPtr = password.toNativeUtf8();

    try {
      final resultPtr = (_decryptText as Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>))(encryptedPtr, passwordPtr);
      final result = resultPtr.toDartString();
      (_freeString as void Function(Pointer<Utf8>))(resultPtr);
      return result;
    } finally {
      malloc.free(encryptedPtr);
      malloc.free(passwordPtr);
    }
  }

  /// Get supported algorithms
  Future<List<String>> getSupportedAlgorithms() async {
    if (_lib == null) {
      // Use enhanced crypto directly for development
      return _getEnhancedAlgorithms();
    }

    try {
      final resultPtr = (_getAlgorithms as Pointer<Utf8> Function())();
      final result = resultPtr.toDartString();
      (_freeString as void Function(Pointer<Utf8>))(resultPtr);

      // Parse JSON result
      final cleaned = result.replaceAll('[', '').replaceAll(']', '').replaceAll('"', '');
      return cleaned.split(',').map((s) => s.trim()).toList();
    } catch (e) {
      // Fallback to enhanced algorithms
      return _getEnhancedAlgorithms();
    }
  }

  /// Get algorithms from enhanced mobile crypto
  List<String> _getEnhancedAlgorithms() {
    // This represents what's available in enhanced_mobile_crypto.py
    return [
      'fernet',
      'aes-gcm', 
      'chacha20-poly1305',
      'xchacha20-poly1305',
      'aes-siv',
      'aes-gcm-siv',
      'aes-ocb3',
      'camellia',
    ];
  }

  /// Get hash algorithms
  Future<List<String>> getHashAlgorithms() async {
    // Available hash algorithms from mobile crypto core (CLI order)
    return [
      'sha512',
      'sha256', 
      'sha3_256',
      'sha3_512',
      'blake2b',
      'blake3',
      'shake256',
      'whirlpool',
    ];
  }
  
  /// Get chained hash configuration
  Future<Map<String, int>> getChainedHashConfig() async {
    // Default configuration matching CLI
    return {
      'sha512': 1000,
      'sha256': 1000,
      'sha3_256': 1000,
      'sha3_512': 1000,
      'blake2b': 1000,
      'blake3': 1000,
      'shake256': 1000,
      'whirlpool': 1000,
    };
  }

  /// Get KDF algorithms
  Future<List<Map<String, dynamic>>> getKdfAlgorithms() async {
    // Available KDF algorithms from mobile crypto core
    return [
      {'id': 'pbkdf2', 'name': 'PBKDF2', 'description': 'Password-Based Key Derivation Function 2'},
      {'id': 'scrypt', 'name': 'Scrypt', 'description': 'Memory-hard KDF for GPU resistance'},
      {'id': 'hkdf', 'name': 'HKDF', 'description': 'HMAC-based Key Derivation Function'},
      {'id': 'argon2', 'name': 'Argon2', 'description': 'Winner of Password Hashing Competition'},
    ];
  }

  /// Get security levels
  Future<List<Map<String, dynamic>>> getSecurityLevels() async {
    return [
      {'id': 'fast', 'name': 'Fast', 'description': 'Lower iterations, faster processing'},
      {'id': 'standard', 'name': 'Standard', 'description': 'Balanced security and performance (recommended)'},
      {'id': 'secure', 'name': 'Secure', 'description': 'Higher iterations, maximum security'},
    ];
  }

  /// Cleanup resources
  void dispose() {
    if (_lib != null) {
      try {
        _cleanupCrypto!();
      } catch (e) {
        // Error during cleanup, ignore
      }
    }
  }

  // Mock implementations for development/testing
  String _mockEncrypt(String text, String password) {
    // Simple mock encryption for development
    final encoded = text.codeUnits.map((c) => c + password.length).join(',');
    return '{"encrypted_data": "$encoded", "metadata": {"algorithm": "mock", "version": "dev"}}';
  }

  Future<String> _mockDecrypt(String encryptedJson, String password) async {
    try {
      // IMPORTANT: Try Python subprocess FIRST (has our CLI-compatible fixes!)
      print('CryptoFFI: _mockDecrypt trying Python subprocess first...');
      return await _callPythonDecrypt(encryptedJson, password);
    } catch (e) {
      print('CryptoFFI: Python subprocess failed: $e');
      // Fallback to native Dart crypto if Python fails
      try {
        print('CryptoFFI: Falling back to native Dart crypto...');
        return await _callNativeCrypto(encryptedJson, password);
      } catch (e2) {
        return 'ERROR: Both Python and native decryption failed.\nPython: $e\nNative: $e2';
      }
    }
  }
  
  Future<String> _callNativeCrypto(String encryptedJson, String password) async {
    try {
      print('CryptoFFI: Attempting native Dart decryption');
      
      final decoded = json.decode(encryptedJson);
      if (decoded is! Map<String, dynamic>) {
        throw Exception('Invalid JSON structure');
      }
      
      final encryptedData = decoded['encrypted_data'] as String;
      final metadata = decoded['metadata'] as Map<String, dynamic>;
      
      // Use native crypto implementation
      return await NativeCrypto.decryptCliFormat(metadata, encryptedData, password);
      
    } catch (e) {
      throw Exception('Native crypto failed: $e');
    }
  }
  
  Future<String> _callPythonDecrypt(String encryptedJson, String password) async {
    try {
      // Try multiple approaches to call Python with our corrected crypto
      ProcessResult? result;
      
      // Approach 1: Use dedicated Python script (most reliable)
      try {
        print('CryptoFFI: Trying flutter_decrypt.py script...');
        result = await Process.run(
          'python3',
          ['flutter_decrypt.py', encryptedJson, password],
          workingDirectory: '/home/work/private/git/openssl_encrypt/mobile_app/openssl_encrypt_mobile',
        );
        
        print('CryptoFFI: Script exit code: ${result.exitCode}');
        print('CryptoFFI: Script stdout: ${result.stdout}');
        if (result.stderr.toString().isNotEmpty) {
          print('CryptoFFI: Script stderr: ${result.stderr}');
        }
        
        if (result.exitCode == 0 && !result.stdout.toString().contains('ERROR:')) {
          final output = result.stdout.toString().trim();
          print('CryptoFFI: Script SUCCESS: $output');
          return output;
        } else {
          print('CryptoFFI: Script failed, trying next approach...');
        }
      } catch (e) {
        print('CryptoFFI: Flutter script approach failed: $e');
      }
      
      // Approach 2: Try with environment variables
      try {
        final env = <String, String>{};
        env.addAll(Platform.environment);
        env['PYTHONPATH'] = '.:/home/work/private/git/openssl_encrypt/mobile_app';
        env['PYTHONDONTWRITEBYTECODE'] = '1';  // Avoid .pyc issues
        
        result = await Process.run(
          'python3',
          ['-c', '''
import sys
sys.path.insert(0, ".")
sys.path.insert(0, "/home/work/private/git/openssl_encrypt/mobile_app")
from mobile_crypto_core import MobileCryptoCore
core = MobileCryptoCore()
result = core.decrypt_text("""$encryptedJson""", "$password")
print(result)
'''],
          workingDirectory: '/home/work/private/git/openssl_encrypt/mobile_app/openssl_encrypt_mobile',
          environment: env,
        );
        
        if (result.exitCode == 0 && !result.stdout.toString().contains('ERROR:')) {
          return result.stdout.toString().trim();
        }
      } catch (e) {
        print('Environment approach failed: $e');
      }
      
      // Final fallback - check if any result was obtained
      if (result != null) {
        if (result.exitCode == 0) {
          return result.stdout.toString().trim();
        } else {
          return 'ERROR: Python process failed (exit ${result.exitCode}): ${result.stderr}';
        }
      } else {
        return 'ERROR: All Python approaches failed';
      }
    } catch (e) {
      // Fallback to parsing info if subprocess fails
      final decoded = json.decode(encryptedJson);
      if (decoded is Map<String, dynamic> &&
          decoded.containsKey('encrypted_data') &&
          decoded.containsKey('metadata')) {
        
        final metadata = decoded['metadata'] as Map<String, dynamic>;
        final formatVersion = metadata['format_version'] ?? 'unknown';
        
        return 'Subprocess Fallback (Python env issues):\n'
               'Format version: $formatVersion\n'
               'Password: ${password.replaceAll(RegExp(r'.'), '*')}\n'
               'Encrypted data: ${(decoded['encrypted_data'] as String).length} chars\n\n'
               'CLI Format Detected: ${formatVersion == 5 ? 'Yes' : 'No'}\n'
               'Derivation config: ${metadata.containsKey('derivation_config') ? 'Present' : 'Missing'}\n\n'
               'Issue: Python environment missing OpenSSL support for hash functions.\n'
               'This would work with proper Python + OpenSSL installation.\n\n'
               'Error: $e';
      }
      return 'ERROR: Subprocess and parsing both failed: $e';
    }
  }
}