import 'dart:convert';
import 'lib/native_crypto.dart';

void main() async {
  // Test the PointyCastle implementation
  
  final metadata = {
    "format_version": 5,
    "derivation_config": {
      "salt": "dGVzdF9zYWx0XzE2X2J5dGVzX2V4YWN0bHlcIVwh", // base64 encoded salt
      "hash_config": {"sha512": 1000},
      "kdf_config": {"pbkdf2": {"rounds": 10000}},
      "encryption_algorithm": "fernet"
    }
  };
  
  final encryptedData = "gAAAAABolmoZ818vUVhTsFOEvPC0PFg2Tt5Wp82uld5nI7NCOkkcDqvTkqAD56IldtNIh41ZlC7aDld2VJytFdSBer4wajgOZDmzlJ56rfVRbjKxU9RkrTE=";
  final password = "test123";
  
  print("Testing native PointyCastle decryption...");
  
  try {
    final result = await NativeCrypto.decryptCliFormat(metadata, encryptedData, password);
    print("SUCCESS: $result");
  } catch (e) {
    print("ERROR: $e");
  }
}