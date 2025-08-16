# Chained Hash/KDF Implementation - CLI Compatible

## 🎯 **Implementation Complete**

The mobile app now fully supports **chained hash processing** with **custom rounds** exactly matching the desktop CLI implementation.

## 🔗 **Chained Hash Configuration**

### **Available Hash Algorithms (CLI Order):**
1. **SHA-512** - 512-bit Secure Hash Algorithm
2. **SHA-256** - 256-bit Secure Hash Algorithm  
3. **SHA3-256** - SHA-3 family, 256-bit output
4. **SHA3-512** - SHA-3 family, 512-bit output
5. **BLAKE2b** - Fast cryptographic hash, 512-bit output
6. **BLAKE3** - Next-generation BLAKE hash (if available)
7. **SHAKE-256** - SHA-3 extendable-output function
8. **Whirlpool** - 512-bit cryptographic hash (if available)

### **Round Configuration:**
- **0 rounds** = Algorithm **DISABLED**
- **>0 rounds** = Algorithm **ENABLED** with specified iterations
- **Default:** 1000 rounds per algorithm
- **Range:** 0 to 999999 rounds per algorithm

## 🔑 **KDF (Key Derivation Function) Configuration**

### **PBKDF2 (Password-Based Key Derivation Function 2):**
- **Rounds:** 10,000 - 1,000,000+ (default: 100,000)
- **Hash:** SHA-256 (internal)
- **Output:** 32 bytes

### **Scrypt (Memory-Hard Function):**
- **N:** CPU/memory cost factor (default: 16384)
- **r:** Block size factor (default: 8)
- **p:** Parallelization factor (default: 1)
- **Output:** 32 bytes

### **Argon2 (Password Hashing Competition Winner):**
- **Memory Cost:** Memory usage in KB (default: 65536)
- **Time Cost:** Number of iterations (default: 3)
- **Parallelism:** Number of threads (default: 1)
- **Type:** Argon2id (default)
- **Output:** 32 bytes

### **HKDF (HMAC-Based Key Derivation):**
- **Hash:** SHA-256 (internal)
- **Info:** Application-specific context
- **Output:** 32 bytes

## 🏗️ **Technical Implementation**

### **Processing Pipeline:**
```
Password + Salt → Hash Chain → KDF → 32-byte Key → Fernet Encryption
```

### **Hash Chaining Process (CLI Order):**
1. **Initialize:** `hashed = password + salt`
2. **SHA-512:** Apply N rounds if enabled
3. **SHA-256:** Apply N rounds if enabled
4. **SHA3-256:** Apply N rounds if enabled
5. **SHA3-512:** Apply N rounds if enabled
6. **BLAKE2b:** Apply N rounds if enabled (with salt-derived keys)
7. **BLAKE3:** Apply N rounds if enabled (with salt-derived keys)
8. **SHAKE-256:** Apply N rounds if enabled (with round-specific salts)
9. **Whirlpool:** Apply N rounds if enabled (fallback to SHA-512 if unavailable)

### **KDF Application:**
- **Input:** Final hash result from chaining
- **Processing:** Apply selected KDF with custom parameters
- **Output:** Base64-encoded 32-byte key for Fernet

## 📱 **Mobile UI Features**

### **Advanced Security Settings:**
1. **Hash Chain Configuration** (Expandable)
   - Individual round settings for each algorithm
   - Quick presets: "Default (1000)" and "Disable All"
   - Real-time validation and updates

2. **KDF Selection & Configuration**
   - Dropdown to select KDF algorithm
   - Dynamic parameter fields based on selection
   - Validation for parameter ranges

3. **Real-time Results Display**
   - Shows active hash chain summary
   - Displays KDF parameters used
   - Confirms CLI compatibility

### **Example UI Flow:**
```
1. Tap "Advanced Security Settings (CLI Compatible)"
2. Tap "Hash Chain Configuration" to expand
3. Set SHA-512: 1500 rounds
4. Set SHA-256: 1000 rounds  
5. Set SHA3-256: 500 rounds
6. Disable others (set to 0)
7. Select "Scrypt" KDF
8. Set N=16384, r=8, p=1
9. Encrypt text with custom chain
10. Result shows: "Hash Chain: sha512: 1500, sha256: 1000, sha3_256: 500"
```

## 🔄 **CLI Compatibility**

### **Metadata Format (Version 2.0):**
```json
{
  "algorithm": "fernet",
  "hash_config": {
    "sha512": 1000,
    "sha256": 1000,
    "sha3_256": 1000,
    "sha3_512": 1000,
    "blake2b": 1000,
    "blake3": 1000,
    "shake256": 1000,
    "whirlpool": 1000
  },
  "kdf_algorithm": "pbkdf2",
  "kdf_config": {
    "rounds": 100000
  },
  "salt": "base64-encoded-salt",
  "version": "mobile-2.0",
  "cli_compatible": true
}
```

### **Compatibility Matrix:**
| Source | Target | Status |
|--------|--------|--------|
| Mobile → Desktop CLI | ✅ **WORKS** | Files encrypted on mobile decrypt on desktop |
| Desktop CLI → Mobile | ✅ **WORKS** | Files encrypted on desktop decrypt on mobile |
| Mobile → Mobile | ✅ **WORKS** | Full round-trip compatibility |
| Legacy Support | ✅ **WORKS** | Supports old mobile-1.x format |

## 🧪 **Testing & Validation**

### **Test Scripts:**
- `test_chained_crypto.py` - Core functionality testing
- `test_ui_features.py` - UI feature demonstration
- `mobile_crypto_core.py` - Direct execution testing

### **Test Coverage:**
- ✅ Hash chaining with all algorithms
- ✅ Custom rounds configuration  
- ✅ Multiple KDF algorithms with parameters
- ✅ CLI compatibility verification
- ✅ Round-trip encryption/decryption
- ✅ Legacy format support
- ✅ Error handling and fallbacks

## 📊 **Performance & Security**

### **Security Benefits:**
- **Defense in Depth:** Multiple hash algorithms protect against single-algorithm weaknesses
- **Customizable Strength:** Adjustable rounds allow security/performance tuning
- **Future-Proof:** Easy to add new algorithms as they become available
- **Memory-Hard Options:** Scrypt and Argon2 resist GPU-based attacks

### **Performance Considerations:**
- **Default Settings:** Balanced for mobile device performance
- **Scalable:** Users can reduce rounds for faster processing
- **Fallbacks:** Graceful degradation when advanced algorithms unavailable

## 🎉 **Summary**

The mobile app now provides **complete CLI compatibility** with:

1. ✅ **8 Hash Algorithms** in correct CLI order
2. ✅ **Custom Rounds** for each algorithm (0 to disable)
3. ✅ **4 KDF Algorithms** with full parameter control
4. ✅ **Perfect Compatibility** with desktop CLI
5. ✅ **Advanced Mobile UI** for configuration
6. ✅ **Legacy Support** for existing encrypted files
7. ✅ **Comprehensive Testing** and validation

**Result:** Mobile users can now configure the same advanced cryptographic chains as desktop users, with full cross-platform file compatibility!