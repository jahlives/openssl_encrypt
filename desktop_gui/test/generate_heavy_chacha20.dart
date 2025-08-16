import 'dart:io';
import '../lib/crypto_ffi.dart';
import '../lib/native_crypto.dart';

void main() async {
  await NativeCrypto.initialize();
  final cryptoFFI = CryptoFFI();
  
  const password = '1234';
  const plaintext = 'Test';
  
  print('🔍 Generating ChaCha20 with heavy multi-KDF config...');
  
  // Heavy multi-KDF config matching the failing CLI command
  final hashConfig = {
    'sha512': {'rounds': 1000},
    'sha256': {'rounds': 1000},
    'sha3_256': {'rounds': 1000},
    'sha3_512': {'rounds': 1000},
    'blake2b': {'rounds': 1000},
    'whirlpool': {'rounds': 1000}
  };
  final kdfConfig = {
    'argon2': {'enabled': true, 'time_cost': 2, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 2},
    'balloon': {'enabled': true, 'time_cost': 2, 'space_cost': 65536, 'parallelism': 4, 'rounds': 2},
    'scrypt': {'enabled': true, 'n': 128, 'r': 8, 'p': 1, 'rounds': 2},
    'pbkdf2': {'enabled': true, 'rounds': 100}
  };
  
  print('📱 Mobile ChaCha20 heavy multi-KDF encryption...');
  final mobileEncrypted = await cryptoFFI.encryptText(plaintext, password, 'chacha20-poly1305', hashConfig, kdfConfig);
  
  // Save to known location
  final outputFile = File('/tmp/heavy_chacha20_test.txt');
  await outputFile.writeAsString(mobileEncrypted);
  
  print('✅ Mobile encryption completed and saved to: ${outputFile.path}');
  print('📏 File size: ${await outputFile.length()} bytes');
  
  // Quick self-test
  print('🔍 Mobile self-test...');
  final decrypted = await cryptoFFI.decryptText(mobileEncrypted, password);
  if (decrypted == plaintext) {
    print('✅ Mobile self-test PASSED');
  } else {
    print('❌ Mobile self-test FAILED');
  }
}