import 'dart:convert';

void main() {
  final testData = "Z0FBQUFBQm9sbW5SeTQ1Z3dBNGVfTTl2MU5mcHdObi1WcGxTaFdHZUdFM2ZWMUtrY3RZcVM5VlJlOUxXQXNiaE5RODlYNklWbnhZcnYwQlRURVpXZHY4T3hncFNxdjVXbWg4WkdLT1FtUklYTXVyMGdWYjl3VkU9";
  
  try {
    print("Trying standard base64 decode...");
    final decoded = base64Decode(testData);
    print("Success! First byte: 0x${decoded[0].toRadixString(16)}");
    print("Length: ${decoded.length}");
  } catch (e) {
    print("Standard base64 failed: $e");
  }
  
  try {
    print("Trying base64url decode...");
    final decoded = base64Url.decode(testData);
    print("Success! First byte: 0x${decoded[0].toRadixString(16)}");
    print("Length: ${decoded.length}");
  } catch (e) {
    print("Base64url failed: $e");
  }
}