# OpenSSL Encrypt Desktop GUI - Development TODO

**Project Status**: Cloned from mobile project, ready for desktop GUI development  
**Location**: `/home/work/private/git/openssl_encrypt/desktop_gui`  
**Parent CLI Project**: `/home/work/private/git/openssl_encrypt`  

## 🎯 **Project Overview**

This is a **cloned and adapted version** of the mobile Flutter UI, specifically for desktop integration with the OpenSSL Encrypt CLI. The goal is to create a professional desktop GUI that provides access to **all CLI features** without the limitations of pure Dart crypto implementations.

### **Key Advantages of Desktop GUI:**
- **Direct CLI integration** - No crypto limitations, all algorithms available
- **Professional desktop UX** - Mouse/keyboard optimized, advanced configurations
- **Post-quantum crypto support** - ML-KEM algorithms via CLI
- **All hash functions** - Blake3, Shake256, Whirlpool via CLI
- **Advanced KDF tuning** - Full parameter control for Argon2, Scrypt, Balloon
- **Flatpak integration** - Unified packaging with CLI

## 📋 **Development Roadmap**

### **Phase 1: Desktop Foundation** ⏳ IN PROGRESS
- [x] **Clone mobile project** - Completed
- [x] **Enable Linux desktop support** - Completed
- [ ] **Test initial desktop build** - NEXT STEP
- [ ] **Update project metadata** (pubspec.yaml - rename, description)
- [ ] **Remove mobile-specific dependencies** (Android/iOS build files)
- [ ] **Clean up mobile-only test files** (keep compatibility tests)

### **Phase 2: CLI Integration Architecture** 🔄 PENDING
- [ ] **Create CLI wrapper service** - Replace pure Dart crypto with CLI calls
- [ ] **Design CLI process management** - Async CLI calls, progress handling
- [ ] **Implement error handling** - CLI stderr parsing, user-friendly messages
- [ ] **Add CLI path discovery** - Find CLI executable in Flatpak environment
- [ ] **Progress indicators** - Real-time CLI operation feedback

### **Phase 3: Desktop UI/UX Adaptation** 🔄 PENDING
- [ ] **Desktop layout patterns** - Replace mobile tab/drawer with desktop patterns
- [ ] **Menu bar integration** - File, Edit, Tools, Help menus
- [ ] **Keyboard shortcuts** - Ctrl+O (Open), Ctrl+S (Save), etc.
- [ ] **Window management** - Proper sizing, resizing, state persistence
- [ ] **Drag & drop support** - File drag & drop for encryption/decryption
- [ ] **Context menus** - Right-click operations

### **Phase 4: Advanced Algorithm Support** 🔄 PENDING
- [ ] **Post-quantum algorithms UI** - ML-KEM selection and configuration
- [ ] **Extended hash functions** - Blake3, Shake256, Whirlpool options
- [ ] **Advanced KDF panels** - Full parameter tuning for all KDFs
- [ ] **Algorithm recommendation engine** - Security level suggestions
- [ ] **Performance profiling** - Algorithm benchmarking and recommendations

### **Phase 5: Professional Features** 🔄 PENDING
- [ ] **Batch operations** - Multiple file encryption/decryption
- [ ] **CLI command preview** - Show equivalent CLI command before execution
- [ ] **Configuration profiles** - Save/load encryption configurations
- [ ] **Audit logging** - Operation history and logs
- [ ] **Import/export settings** - Configuration backup/restore

### **Phase 6: Flatpak Integration** 🔄 PENDING
- [ ] **Build system integration** - Add to parent CLI Flatpak
- [ ] **Desktop file creation** - System menu integration
- [ ] **Icon and branding** - Desktop-appropriate icons
- [ ] **Permission configuration** - File system access, CLI integration
- [ ] **Testing and packaging** - Complete Flatpak build

## 🔧 **Technical Architecture**

### **Current Mobile Architecture** (Pure Dart):
```
Mobile UI → Pure Dart Crypto → Direct encryption/decryption
```

### **Target Desktop Architecture** (CLI Integration):
```
Desktop UI → CLI Service Layer → OpenSSL Encrypt CLI → All algorithms
```

### **Key Technical Components:**

#### **CLI Service Layer** (`lib/cli_service.dart`):
```dart
class CLIService {
  Future<String> encrypt(String input, CLIConfig config);
  Future<String> decrypt(String input, String password);
  Stream<String> getProgress(); // Real-time CLI output
  Future<List<String>> getSupportedAlgorithms();
  Future<List<String>> getSupportedHashFunctions();
}
```

#### **Desktop UI Components**:
- **Advanced Algorithm Picker** - All CLI algorithms including PQC
- **Professional Parameter Panels** - Full KDF/hash configuration
- **Progress Monitoring** - Real-time CLI operation feedback
- **Desktop File Operations** - Native file dialogs, drag & drop

## 📊 **Current Capabilities Status**

### **Inherited from Mobile** ✅:
- Fernet, ChaCha20, XChaCha20, AES-GCM algorithms
- Basic KDF support (PBKDF2, Argon2, Scrypt, Balloon)
- Core hash functions (SHA-256, SHA-512, BLAKE2b)
- CLI compatibility (mobile↔CLI verified working)
- Comprehensive test suite
- Debug logging and troubleshooting

### **Desktop Enhancements Planned** 🔄:
- **All CLI algorithms** (15+ including post-quantum)
- **All hash functions** (Blake3, Shake256, Whirlpool)
- **Advanced KDF tuning** (full parameter control)
- **Professional desktop UX** (menus, shortcuts, window management)
- **CLI integration layer** (direct CLI calls, no Dart crypto limitations)

## 🚨 **Important Notes**

### **Mobile Project Relationship**:
- **Keep mobile project separate** - This is an independent desktop adaptation
- **Mobile stays pure Dart** - Continue mobile development independently
- **Share compatibility knowledge** - Algorithm compatibility matrix applies to both
- **Different target users** - Mobile (simplicity) vs Desktop (power users)

### **CLI Integration Points**:
- **CLI executable location**: `/app/bin/openssl-encrypt` (in Flatpak)
- **CLI debug output**: New detailed debug logging available for integration
- **CLI compatibility**: All mobile algorithms work, plus many more on desktop
- **Error handling**: Parse CLI stderr for user-friendly error messages

### **Development Environment**:
- **Flutter version**: 3.32.8 (stable channel)
- **Linux desktop support**: Enabled ✅
- **Parent CLI project**: `/home/work/private/git/openssl_encrypt`
- **Build target**: Flatpak integration with CLI project

## 🔗 **Quick Start Commands**

```bash
# Navigate to desktop GUI project
cd /home/work/private/git/openssl_encrypt/desktop_gui

# Test desktop build (first step)
flutter build linux --release

# Run desktop app locally
flutter run -d linux

# Test CLI integration manually
cd /home/work/private/git/openssl_encrypt
python ./openssl_encrypt/crypt.py --help

# View CLI debug output
python ./openssl_encrypt/crypt.py decrypt -i file.txt --password test --debug
```

## 📚 **Reference Documentation**

- **ALGORITHM_COMPATIBILITY_MATRIX.md** - Full algorithm compatibility reference
- **Mobile project location**: `/home/work/private/git/openssl_encrypt_mobile`
- **CLI project root**: `/home/work/private/git/openssl_encrypt`
- **Flutter Linux docs**: https://docs.flutter.dev/platform-integration/linux
- **Flatpak docs**: https://docs.flatpak.org/en/latest/

---

**Last Updated**: December 15, 2024  
**Next Session Priority**: Test desktop build and begin CLI integration architecture  
**Current Phase**: Phase 1 - Desktop Foundation  