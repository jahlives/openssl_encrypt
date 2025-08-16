import 'package:flutter_test/flutter_test.dart';
import 'package:openssl_encrypt_mobile/crypto_ffi.dart';
import 'package:openssl_encrypt_mobile/native_crypto.dart';
import 'dart:io';

void main() {
  late CryptoFFI cryptoFFI;

  setUpAll(() async {
    print('🔧 Initializing crypto system for tests...');
    await NativeCrypto.initialize();
    cryptoFFI = CryptoFFI();
    print('✅ Crypto system initialized');
  });

  test('Extract CLI Key for Direct Comparison', () async {
    print('\n=== CLI KEY EXTRACTION FOR DEBUG COMPARISON ===');
    
    // Use the original CLI-generated data for key extraction
    const cliData = 'eyJmb3JtYXRfdmVyc2lvbiI6NSwiZGVyaXZhdGlvbl9jb25maWciOnsic2FsdCI6InV1L2ZyREpObEVKS1VFdFc0Uys1Rnc9PSIsImhhc2hfY29uZmlnIjp7InNoYTUxMiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhMzg0Ijp7InJvdW5kcyI6MH0sInNoYTI1NiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhMjI0Ijp7InJvdW5kcyI6MH0sInNoYTNfNTEyIjp7InJvdW5kcyI6MTAwMDB9LCJzaGEzXzM4NCI6eyJyb3VuZHMiOjB9LCJzaGEzXzI1NiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhM18yMjQiOnsicm91bmRzIjowfSwiYmxha2UyYiI6eyJyb3VuZHMiOjEwMDAwfSwiYmxha2UzIjp7InJvdW5kcyI6MH0sInNoYWtlMjU2Ijp7InJvdW5kcyI6MH0sInNoYWtlMTI4Ijp7InJvdW5kcyI6MH0sIndoaXJscG9vbCI6eyJyb3VuZHMiOjEwMDAwfX0sImtkZl9jb25maWciOnsicGJrZGYyIjp7InJvdW5kcyI6MTAwMDAwfSwic2NyeXB0Ijp7ImVuYWJsZWQiOmZhbHNlLCJuIjoxMjgsInIiOjgsInAiOjEsInJvdW5kcyI6MH0sImFyZ29uMiI6eyJlbmFibGVkIjpmYWxzZSwidGltZV9jb3N0IjozLCJtZW1vcnlfY29zdCI6NjU1MzYsInBhcmFsbGVsaXNtIjo0LCJoYXNoX2xlbiI6MzIsInR5cGUiOjIsInJvdW5kcyI6MH0sImJhbGxvb24iOnsiZW5hYmxlZCI6ZmFsc2UsInRpbWVfY29zdCI6Mywic3BhY2VfY29zdCI6NjU1MzYsInBhcmFsbGVsaXNtIjo0LCJyb3VuZHMiOjB9LCJoa2RmIjp7ImVuYWJsZWQiOmZhbHNlLCJyb3VuZHMiOjEsImFsZ29yaXRobSI6InNoYTI1NiIsImluZm8iOiJvcGVuc3NsX2VuY3J5cHRfaGtkZiJ9fX0sImhhc2hlcyI6eyJvcmlnaW5hbF9oYXNoIjoiYTU5MWE2ZDQwYmY0MjA0MDRhMDExNzMzY2ZiN2IxOTBkNjJjNjViZjBiY2RhMzJiNTdiMjc3ZDlhZDlmMTQ2ZSIsImVuY3J5cHRlZF9oYXNoIjoiNzhlNTJlNjIwNjNkODhlODYwODBiMGQxYTAxZmQ5MjZjZTgyZmFjMGQ3MzE5ZWNkNGEzMjFlZjRhZjI1MGYzOCJ9LCJlbmNyeXB0aW9uIjp7ImFsZ29yaXRobSI6ImZlcm5ldCIsImVuY3J5cHRpb25fZGF0YSI6ImFlcy1nY20ifX0=:Z0FBQUFBQm9uaEhyY3BQSHZ3ODBjZGpyNGh4cjJhVmJYRFlVaHVhY0p3NE1abnlVSkZCTGlVNXJieHNiZFlNUHZxWnkxWWNDeTdZNTBJZXQ2Ylk4NVZWd05fYUZpRWtCWlE9PQ==';
    const password = '1234';
    
    print('🔑 Testing with CLI-generated data to extract mobile key derivation');
    print('This will show us exactly where mobile and CLI keys diverge');
    
    try {
      // This will fail but show us the mobile-derived key in debug logs
      await cryptoFFI.decryptText(cliData, password);
    } catch (e) {
      print('Expected failure - we just wanted the key extraction debug logs');
    }
    
    // Now let's also get the CLI key for the same salt/password
    final tempDir = Directory.systemTemp.createTempSync();
    final tempFile = File('${tempDir.path}/debug_key.txt');
    
    print('\\n🖥️ EXTRACTING CLI KEY for comparison...');
    
    // Create a Python script to extract the CLI key
    const pythonScript = '''
import base64
import json
from openssl_encrypt.crypt import derive_key
from cryptography.fernet import Fernet
import binascii

# Parse the CLI data
metadata_b64 = "eyJmb3JtYXRfdmVyc2lvbiI6NSwiZGVyaXZhdGlvbl9jb25maWciOnsic2FsdCI6InV1L2ZyREpObEVKS1VFdFc0Uys1Rnc9PSIsImhhc2hfY29uZmlnIjp7InNoYTUxMiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhMzg0Ijp7InJvdW5kcyI6MH0sInNoYTI1NiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhMjI0Ijp7InJvdW5kcyI6MH0sInNoYTNfNTEyIjp7InJvdW5kcyI6MTAwMDB9LCJzaGEzXzM4NCI6eyJyb3VuZHMiOjB9LCJzaGEzXzI1NiI6eyJyb3VuZHMiOjEwMDAwfSwic2hhM18yMjQiOnsicm91bmRzIjowfSwiYmxha2UyYiI6eyJyb3VuZHMiOjEwMDAwfSwiYmxha2UzIjp7InJvdW5kcyI6MH0sInNoYWtlMjU2Ijp7InJvdW5kcyI6MH0sInNoYWtlMTI4Ijp7InJvdW5kcyI6MH0sIndoaXJscG9vbCI6eyJyb3VuZHMiOjEwMDAwfX0sImtkZl9jb25maWciOnsicGJrZGYyIjp7InJvdW5kcyI6MTAwMDAwfSwic2NyeXB0Ijp7ImVuYWJsZWQiOmZhbHNlLCJuIjoxMjgsInIiOjgsInAiOjEsInJvdW5kcyI6MH0sImFyZ29uMiI6eyJlbmFibGVkIjpmYWxzZSwidGltZV9jb3N0IjozLCJtZW1vcnlfY29zdCI6NjU1MzYsInBhcmFsbGVsaXNtIjo0LCJoYXNoX2xlbiI6MzIsInR5cGUiOjIsInJvdW5kcyI6MH0sImJhbGxvb24iOnsiZW5hYmxlZCI6ZmFsc2UsInRpbWVfY29zdCI6Mywic3BhY2VfY29zdCI6NjU1MzYsInBhcmFsbGVsaXNtIjo0LCJyb3VuZHMiOjB9LCJoa2RmIjp7ImVuYWJsZWQiOmZhbHNlLCJyb3VuZHMiOjEsImFsZ29yaXRobSI6InNoYTI1NiIsImluZm8iOiJvcGVuc3NsX2VuY3J5cHRfaGtkZiJ9fX0sImhhc2hlcyI6eyJvcmlnaW5hbF9oYXNoIjoiYTU5MWE2ZDQwYmY0MjA0MDRhMDExNzMzY2ZiN2IxOTBkNjJjNjViZjBiY2RhMzJiNTdiMjc3ZDlhZDlmMTQ2ZSIsImVuY3J5cHRlZF9oYXNoIjoiNzhlNTJlNjIwNjNkODhlODYwODBiMGQxYTAxZmQ5MjZjZTgyZmFjMGQ3MzE5ZWNkNGEzMjFlZjRhZjI1MGYzOCJ9LCJlbmNyeXB0aW9uIjp7ImFsZ29yaXRobSI6ImZlcm5ldCIsImVuY3J5cHRpb25fZGF0YSI6ImFlcy1nY20ifX0="
metadata = json.loads(base64.b64decode(metadata_b64).decode())
derivation_config = metadata["derivation_config"]

password = "1234"
salt = base64.b64decode(derivation_config["salt"])

print(f"CLI SALT (hex): {salt.hex()}")
print(f"CLI PASSWORD: {password}")

# Derive the key using CLI logic
key = derive_key(password, salt, derivation_config, "fernet")

print(f"CLI DERIVED KEY (hex): {key.hex()}")
print(f"CLI KEY LENGTH: {len(key)}")

# Verify key is valid for Fernet
try:
    fernet_key = base64.urlsafe_b64encode(key)
    fernet = Fernet(fernet_key)
    print(f"CLI FERNET KEY (base64): {fernet_key.decode()}")
except Exception as e:
    print(f"CLI key Fernet validation failed: {e}")
''';
    
    // Write and execute the Python script
    final scriptFile = File('${tempDir.path}/extract_cli_key.py');
    await scriptFile.writeAsString(pythonScript);
    
    final result = await Process.run('python3', [scriptFile.path],
        workingDirectory: '/tmp');
    
    if (result.exitCode == 0) {
      print('CLI Key Extraction Output:');
      print(result.stdout);
    } else {
      print('CLI key extraction failed:');
      print('STDOUT: ${result.stdout}');  
      print('STDERR: ${result.stderr}');
    }
    
    // Cleanup
    await tempDir.delete(recursive: true);
    
    print('\\n🔍 COMPARISON ANALYSIS:');
    print('Compare the mobile key (from debug logs above) with CLI key (from Python output)');
    print('Look for differences in:');
    print('1. Salt values (should be identical)');
    print('2. Hash chain results (after all hash algorithms)');
    print('3. Final derived keys (after KDF chain)');
  });
}