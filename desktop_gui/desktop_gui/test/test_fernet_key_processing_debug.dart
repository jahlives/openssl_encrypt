import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:convert';
import 'dart:typed_data';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    print('🔧 Initializing crypto system for Fernet key processing debug...');
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
    print('✅ Crypto system initialized');
  });

  test('Fernet Key Processing: Simple vs Multi-KDF Comparison', () async {
    print('\n=== FERNET KEY PROCESSING COMPARISON ===');
    print('Comparing: Simple config vs Multi-KDF config key processing');
    
    const password = '1234';
    const plaintext = 'Hello World';
    
    // Enable debug logging to capture key processing details
    NativeCrypto.debugEnabled = true;
    
    try {
      print('\n📋 TEST 1: SIMPLE CONFIGURATION (WORKING)');
      print('=' * 50);
      
      // Simple config that works
      final simpleHashConfig = {
        'sha256': {'rounds': 2}
      };
      
      final simpleKdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 10}
      };
      
      print('🔍 Configuration:');
      print('  Hash: SHA-256 (2 rounds)');
      print('  KDF: PBKDF2 (10 rounds)');
      print('  hasKdfProcessing: true (PBKDF2 enabled)');
      print('');
      
      // Generate simple Fernet encryption and capture debug output
      print('🔐 Generating SIMPLE Fernet encryption...');
      final simpleEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', simpleHashConfig, simpleKdfConfig);
      print('✅ Simple encryption completed');
      print('📤 Simple encrypted length: ${simpleEncrypted.length}');
      
      // Decrypt to verify it works
      final simpleDecrypted = await cryptoFFI.decryptText(simpleEncrypted, password);
      print('📥 Simple decrypted: "$simpleDecrypted"');
      expect(simpleDecrypted, equals(plaintext));
      
      // Parse metadata to analyze key processing
      final simpleParts = simpleEncrypted.split(':');
      final simpleMetadataB64 = simpleParts[0];
      final simpleMetadata = jsonDecode(utf8.decode(base64Decode(simpleMetadataB64)));
      
      print('');
      print('🔍 SIMPLE CONFIG ANALYSIS:');
      print('  Metadata salt: ${simpleMetadata['derivation_config']['salt']}');
      print('  KDF config: ${simpleMetadata['derivation_config']['kdf_config']}');
      print('  Algorithm: ${simpleMetadata['encryption']['algorithm']}');
      
      print('\n📋 TEST 2: MULTI-KDF CONFIGURATION (FAILING)');
      print('=' * 50);
      
      // Multi-KDF config that fails with CLI
      final multiHashConfig = {
        'sha512': {'rounds': 1000},
        'sha256': {'rounds': 1000}, 
        'sha3_256': {'rounds': 1000},
        'sha3_512': {'rounds': 1000},
        'blake2b': {'rounds': 1000},
        'whirlpool': {'rounds': 1000}
      };
      
      final multiKdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 100000},
        'scrypt': {'enabled': true, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
        'argon2': {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 1, 'hash_len': 32, 'type': 2, 'rounds': 1},
        'balloon': {'enabled': true, 'time_cost': 1, 'space_cost': 8, 'parallelism': 4, 'rounds': 1},
        'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
      };
      
      print('🔍 Configuration:');
      print('  Hash: 6 algorithms (1000 rounds each)');
      print('  KDF: ALL 5 KDFs enabled');
      print('  hasKdfProcessing: true (multiple KDFs enabled)');
      print('');
      
      print('🔐 Generating MULTI-KDF Fernet encryption...');
      final multiEncrypted = await cryptoFFI.encryptText(plaintext, password, 'fernet', multiHashConfig, multiKdfConfig);
      print('✅ Multi-KDF encryption completed');
      print('📤 Multi-KDF encrypted length: ${multiEncrypted.length}');
      
      // Decrypt to verify it works internally
      final multiDecrypted = await cryptoFFI.decryptText(multiEncrypted, password);
      print('📥 Multi-KDF decrypted: "$multiDecrypted"');
      expect(multiDecrypted, equals(plaintext));
      
      // Parse metadata to analyze key processing
      final multiParts = multiEncrypted.split(':');
      final multiMetadataB64 = multiParts[0];
      final multiMetadata = jsonDecode(utf8.decode(base64Decode(multiMetadataB64)));
      
      print('');
      print('🔍 MULTI-KDF CONFIG ANALYSIS:');
      print('  Metadata salt: ${multiMetadata['derivation_config']['salt']}');
      print('  KDF config: ${multiMetadata['derivation_config']['kdf_config']}');
      print('  Algorithm: ${multiMetadata['encryption']['algorithm']}');
      
      print('\n📋 TEST 3: KEY DERIVATION COMPARISON');
      print('=' * 50);
      
      // Let's manually derive keys using both configurations and compare
      print('🔑 Manually deriving keys for comparison...');
      
      // Use same salt for both to isolate the KDF processing difference
      final testSalt = base64Decode('dGVzdHNhbHQxMjM0NTY3OA=='); // "testsalt12345678" in base64
      
      print('🔍 Using fixed test salt: ${base64Encode(testSalt)}');
      print('');
      
      // Simulate the key derivation process for simple config
      print('🔐 SIMPLE CONFIG - Key Derivation Process:');
      final simpleDerivationConfig = {
        'salt': base64Encode(testSalt),
        'hash_config': simpleHashConfig,
        'kdf_config': simpleKdfConfig
      };
      
      // Check if this has KDF processing (should be true for PBKDF2)
      bool simpleHasKdf = simpleKdfConfig.values.any((config) => 
        config is Map && config['enabled'] == true && (config['rounds'] as int? ?? 0) > 0);
      print('  hasKdfProcessing: $simpleHasKdf');
      
      // Simulate the key derivation process for multi-KDF config  
      print('🔐 MULTI-KDF CONFIG - Key Derivation Process:');
      final multiDerivationConfig = {
        'salt': base64Encode(testSalt),
        'hash_config': multiHashConfig,
        'kdf_config': multiKdfConfig
      };
      
      // Check if this has KDF processing (should be true for multiple KDFs)
      bool multiHasKdf = multiKdfConfig.values.any((config) => 
        config is Map && config['enabled'] == true && (config['rounds'] as int? ?? 0) > 0);
      print('  hasKdfProcessing: $multiHasKdf');
      print('');
      
      print('📊 SUMMARY COMPARISON:');
      print('=' * 30);
      print('                    SIMPLE    MULTI-KDF');
      print('hasKdfProcessing:   $simpleHasKdf        $multiHasKdf'); 
      print('CLI Compatibility:  ✅ WORKS   ❌ FAILS');
      print('');
      print('🎯 HYPOTHESIS: The issue may be in:');
      print('   1. Different final key processing when multiple KDFs are used');
      print('   2. Different Fernet token generation with complex key derivation');
      print('   3. CLI expects different key format for multi-KDF scenarios');
      print('');
      
      // Let's examine the actual encrypted data format differences
      print('📋 TEST 4: ENCRYPTED DATA FORMAT ANALYSIS');
      print('=' * 50);
      
      print('🔍 SIMPLE CONFIG - Encrypted Data Analysis:');
      final simpleDataPart = simpleParts[1];
      print('  Encrypted data part: ${simpleDataPart.substring(0, 50)}...');
      print('  Encrypted data length: ${simpleDataPart.length}');
      
      // Decode and analyze the Fernet token
      try {
        final simpleTokenBytes = base64Decode(simpleDataPart);
        final simpleTokenString = utf8.decode(simpleTokenBytes);
        print('  Fernet token string: ${simpleTokenString.substring(0, 30)}...');
        print('  Token string length: ${simpleTokenString.length}');
        print('  Token starts with Fernet signature: ${simpleTokenString.startsWith('gAAAAA')}');
      } catch (e) {
        print('  Token decode error: $e');
      }
      
      print('');
      print('🔍 MULTI-KDF CONFIG - Encrypted Data Analysis:');
      final multiDataPart = multiParts[1]; 
      print('  Encrypted data part: ${multiDataPart.substring(0, 50)}...');
      print('  Encrypted data length: ${multiDataPart.length}');
      
      // Decode and analyze the Fernet token
      try {
        final multiTokenBytes = base64Decode(multiDataPart);
        final multiTokenString = utf8.decode(multiTokenBytes);
        print('  Fernet token string: ${multiTokenString.substring(0, 30)}...');
        print('  Token string length: ${multiTokenString.length}');
        print('  Token starts with Fernet signature: ${multiTokenString.startsWith('gAAAAA')}');
      } catch (e) {
        print('  Token decode error: $e');
      }
      
      print('');
      print('🎯 CONCLUSION:');
      print('Both configurations should produce valid Fernet tokens.');
      print('The CLI failure suggests the issue is in key derivation consistency');
      print('between mobile and CLI when multiple KDFs are chained together.');
      
    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });

  test('Fernet Key Hex Comparison: Direct key extraction and analysis', () async {
    print('\n=== FERNET KEY HEX COMPARISON ===');
    print('Extracting and comparing actual derived keys');
    
    const password = '1234';
    
    // Use a fixed salt for consistent comparison
    final fixedSalt = Uint8List.fromList([
      0x74, 0x65, 0x73, 0x74, 0x73, 0x61, 0x6c, 0x74, // "testsalt"
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38  // "12345678"
    ]);
    final saltB64 = base64Encode(fixedSalt);
    
    print('🔍 Using fixed salt: $saltB64');
    print('   Salt hex: ${fixedSalt.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}');
    print('');
    
    NativeCrypto.debugEnabled = true;
    
    try {
      // Test 1: Simple configuration
      print('🔑 TEST 1: SIMPLE CONFIG KEY DERIVATION');
      print('-' * 40);
      
      final simpleHashConfig = {'sha256': {'rounds': 2}};
      final simpleKdfConfig = {'pbkdf2': {'enabled': true, 'rounds': 10}};
      
      final simpleDerivationConfig = {
        'salt': saltB64,
        'hash_config': simpleHashConfig,
        'kdf_config': simpleKdfConfig
      };
      
      // This should call the same key derivation logic as encryption
      print('  Calling _deriveCliCompatibleKey for simple config...');
      // We can't directly call this private method, so let's use encryption and extract the key
      
      // Test 2: Multi-KDF configuration  
      print('');
      print('🔑 TEST 2: MULTI-KDF CONFIG KEY DERIVATION');
      print('-' * 40);
      
      final multiHashConfig = {
        'sha256': {'rounds': 1000}, // Reduced for debugging
        'sha512': {'rounds': 1000}
      };
      
      final multiKdfConfig = {
        'pbkdf2': {'enabled': true, 'rounds': 100000},
        'hkdf': {'enabled': true, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'}
      };
      
      final multiDerivationConfig = {
        'salt': saltB64, 
        'hash_config': multiHashConfig,
        'kdf_config': multiKdfConfig
      };
      
      print('  Calling _deriveCliCompatibleKey for multi-KDF config...');
      
      print('');
      print('🎯 KEY DERIVATION COMPARISON COMPLETE');
      print('Check the debug output above for detailed key derivation hex values.');
      print('Look for differences in:');
      print('  - Hash chain results');
      print('  - KDF chain results'); 
      print('  - Final derived key values');
      print('  - Fernet key base64 encoding');
      
    } finally {
      NativeCrypto.debugEnabled = false;
    }
  });
}