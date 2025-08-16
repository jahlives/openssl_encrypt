import 'dart:convert';
import 'dart:typed_data';
import 'package:fernet/fernet.dart';

void main() {
  print('=== Testing Fernet Library API ===');
  
  // Test what the Fernet library actually does
  final testKey = 'tRv3nNLCqZOs6ZAhgB0wH8VDFDPC4moAwMhP--XDm8s='; // 44 char base64
  final testText = 'Hello World';
  
  print('Test key: $testKey');
  print('Test key length: ${testKey.length}');
  print('Test text: $testText');
  
  try {
    // Create Fernet instance
    final fernet = Fernet(testKey);
    print('✅ Fernet object created successfully');
    
    // Test encryption
    final textBytes = utf8.encode(testText);
    print('Text bytes: $textBytes');
    print('Text bytes length: ${textBytes.length}');
    
    final encryptedResult = fernet.encrypt(textBytes);
    print('Encrypted result type: ${encryptedResult.runtimeType}');
    print('Encrypted result: $encryptedResult');
    
    if (encryptedResult is Uint8List) {
      print('Encrypted result length: ${encryptedResult.length}');
      print('Encrypted result hex: ${encryptedResult.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}');
      
      // Try to decode as base64 URL-safe
      try {
        final asString = base64Url.encode(encryptedResult);
        print('As base64 URL-safe string: $asString');
        print('String length: ${asString.length}');
        
        // Test if this starts with Fernet signature
        if (asString.startsWith('gAAAAA')) {
          print('✅ Looks like proper Fernet token');
        } else {
          print('❌ Does not start with Fernet signature');
        }
      } catch (e) {
        print('Failed to encode as base64: $e');
      }
      
      // Test decryption with the raw bytes
      try {
        print('\n=== Testing Decryption ===');
        final decryptedBytes = fernet.decrypt(encryptedResult);
        print('Decrypted bytes type: ${decryptedBytes.runtimeType}');
        print('Decrypted bytes: $decryptedBytes');
        
        final decryptedText = utf8.decode(decryptedBytes);
        print('Decrypted text: "$decryptedText"');
        
        if (decryptedText == testText) {
          print('✅ Round-trip successful!');
        } else {
          print('❌ Round-trip failed!');
        }
      } catch (e) {
        print('❌ Decryption failed: $e');
      }
      
    } else if (encryptedResult is String) {
      print('Encrypted result as string: $encryptedResult');
      print('String length: ${encryptedResult.length}');
      
      // Test decryption with string
      try {
        print('\n=== Testing String Decryption ===');
        final decryptedBytes = fernet.decrypt(encryptedResult);
        final decryptedText = utf8.decode(decryptedBytes);
        print('Decrypted text: "$decryptedText"');
        
        if (decryptedText == testText) {
          print('✅ String round-trip successful!');
        } else {
          print('❌ String round-trip failed!');
        }
      } catch (e) {
        print('❌ String decryption failed: $e');
      }
    }
    
  } catch (e) {
    print('❌ Fernet test failed: $e');
  }
}