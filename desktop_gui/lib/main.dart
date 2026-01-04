import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:path/path.dart' as path;
import 'cli_service.dart';
import 'file_manager.dart';
import 'settings_service.dart';
import 'settings_screen.dart';
import 'configuration_profiles_screen.dart';
import 'identity_management_screen.dart';
import 'fido2_management_screen.dart';
import 'input_validation.dart';
import 'tabs/encrypt_tab.dart';
import 'tabs/decrypt_tab.dart';

// Intent classes for keyboard shortcuts
class OpenFileIntent extends Intent {
  const OpenFileIntent();
}

class CopyResultIntent extends Intent {
  const CopyResultIntent();
}

class ClearAllIntent extends Intent {
  const ClearAllIntent();
}

class ShowHelpIntent extends Intent {
  const ShowHelpIntent();
}

class ExitAppIntent extends Intent {
  const ExitAppIntent();
}

// Encryption modes for the application
enum EncryptionMode {
  symmetric,   // Traditional password-based encryption (V3-V6)
  asymmetric,  // Identity-based encryption with ML-KEM + ML-DSA (V7)
  cascade,     // Multi-layer encryption chaining (V8)
}

void main() async {
  // Initialize Flutter framework
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize settings service
  await SettingsService.initialize();

  // Initialize CLI service
  final cliAvailable = await CLIService.initialize();
  if (!cliAvailable) {
    print('WARNING: OpenSSL Encrypt CLI not found. Some features may not work.');
  }

  // Apply debug mode from settings
  if (SettingsService.getDebugMode()) {
    await CLIService.enableDebugLogging();
  }

  runApp(const OpenSSLEncryptApp());
}

class OpenSSLEncryptApp extends StatefulWidget {
  const OpenSSLEncryptApp({super.key});

  @override
  State<OpenSSLEncryptApp> createState() => _OpenSSLEncryptAppState();
}

class _OpenSSLEncryptAppState extends State<OpenSSLEncryptApp> {
  bool _showDebugBanner = false;

  void _updateDebugBanner(bool showBanner) {
    setState(() {
      _showDebugBanner = showBanner;
    });
  }

  ThemeMode _getThemeMode() {
    final themeString = SettingsService.getThemeMode();
    switch (themeString) {
      case 'light':
        return ThemeMode.light;
      case 'dark':
        return ThemeMode.dark;
      case 'system':
      default:
        return ThemeMode.system;
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OpenSSL Encrypt Desktop',
      debugShowCheckedModeBanner: _showDebugBanner,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      themeMode: _getThemeMode(),
      home: LayoutBuilder(
        builder: (context, constraints) {
          return Scaffold(
            body: ConstrainedBox(
              constraints: const BoxConstraints(
                minWidth: 900,
                minHeight: 600,
              ),
              child: MainScreen(
                onDebugChanged: _updateDebugBanner,
                onThemeChanged: () => setState(() {}),
              ),
            ),
          );
        },
      ),
    );
  }
}

class MainScreen extends StatefulWidget {
  final Function(bool) onDebugChanged;
  final VoidCallback onThemeChanged;

  const MainScreen({
    super.key,
    required this.onDebugChanged,
    required this.onThemeChanged,
  });

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  final FileManager _fileManager = FileManager();
  final GlobalKey<_BatchOperationsTabState> _batchOperationsTabKey = GlobalKey<_BatchOperationsTabState>();
  int _selectedIndex = 0;
  bool _isDragOver = false;
  bool _debugWindowVisible = false;
  OverlayEntry? _debugOverlayEntry;

  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    _hideDebugWindow(); // Clean up debug overlay if shown
    super.dispose();
  }

  // Menu action methods
  void _openFile() async {
    final file = await _fileManager.pickFile();
    if (file != null) {
      // Switch to file tab and load the file
      setState(() {
        _selectedIndex = 1;
      });
      // TODO: Pass file to FileCryptoTab
    }
  }

  void _copyToClipboard() async {
    // Get result from current active tab
    String? currentResult;

    if (_selectedIndex == 2) {
      // Batch operations tab
      final batchTabState = _batchOperationsTabKey.currentState;
      currentResult = batchTabState?.result;
    }
    // Note: Encrypt/Decrypt tabs (indices 0-1) use internal copy functionality

    if (currentResult != null && currentResult.isNotEmpty) {
      await Clipboard.setData(ClipboardData(text: currentResult));

      // Schedule secure clipboard clearing after 30 seconds
      Timer(const Duration(seconds: 30), () async {
        await Clipboard.setData(const ClipboardData(text: ''));
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Result copied to clipboard (will auto-clear in 30s)'),
            duration: Duration(seconds: 3),
          ),
        );
      }
    } else {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('No result to copy'),
            backgroundColor: Colors.orange,
            duration: Duration(seconds: 2),
          ),
        );
      }
    }
  }

  void _clearAll() {
    // TODO: Clear all fields
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('All fields cleared')),
    );
  }

  void _exitApp(BuildContext context) {
    // Close the application
    Navigator.of(context).pop();
  }

  void _showAlgorithmInfo(BuildContext context) {
    setState(() {
      _selectedIndex = 2; // Switch to info tab
    });
  }

  void _showSecuritySettings(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Security Settings'),
        content: const Text('Advanced security settings will be available in a future version.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  void _showConfigurationProfiles(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const ConfigurationProfilesScreen(isSelectionMode: true),
      ),
    );
  }

  void _showManageProfiles(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const ConfigurationProfilesScreen(),
      ),
    );
  }

  void _showAbout(BuildContext context) {
    showAboutDialog(
      context: context,
      applicationName: 'OpenSSL Encrypt Desktop',
      applicationVersion: '1.0.0 (Desktop Development)',
      applicationIcon: const Icon(Icons.security, size: 48),
      children: [
        const Text('Professional desktop GUI for OpenSSL Encrypt CLI'),
        const SizedBox(height: 8),
        const Text('Features:'),
        const Text('• Full CLI integration - all algorithms available'),
        const Text('• Post-quantum cryptography support'),
        const Text('• Advanced hash and KDF configurations'),
        const Text('• Professional desktop interface'),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            border: Border.all(color: Theme.of(context).colorScheme.outline),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.info_outline, color: Theme.of(context).colorScheme.primary, size: 16),
                  const SizedBox(width: 6),
                  const Text(
                    'CLI Backend Information',
                    style: TextStyle(
                      fontWeight: FontWeight.w600,
                      color: Colors.blue,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                CLIService.getVersionInfo(),
                style: TextStyle(
                  fontFamily: 'Courier',
                  fontSize: 11,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              if (CLIService.shouldHideLegacyAlgorithms()) ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.tertiaryContainer,
                    border: Border.all(color: Theme.of(context).colorScheme.outline),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.info, color: Theme.of(context).colorScheme.onTertiaryContainer, size: 14),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          'Legacy algorithms (Whirlpool, PBKDF2) hidden due to CLI v1.2+ deprecation',
                          style: TextStyle(
                            fontSize: 10,
                            color: Theme.of(context).colorScheme.onTertiaryContainer,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }

  void _showCLIDocs(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('CLI Documentation'),
        content: const SingleChildScrollView(
          child: Text(
            'This desktop GUI integrates with the OpenSSL Encrypt CLI.\n\n'
            'Available CLI commands:\n'
            '• encrypt - Encrypt files with password protection\n'
            '• decrypt - Decrypt previously encrypted files\n'
            '• security-info - Display security information\n'
            '• generate-password - Generate secure passwords\n\n'
            'The GUI provides access to all CLI features through an intuitive interface.',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  // Debug window methods
  void _toggleDebugWindow() {
    if (_debugWindowVisible) {
      _hideDebugWindow();
    } else {
      _showDebugWindow();
    }
  }

  void _showDebugWindow() {
    if (_debugOverlayEntry != null) return; // Already shown

    _debugOverlayEntry = _createDebugOverlayEntry();
    Overlay.of(context).insert(_debugOverlayEntry!);
    setState(() {
      _debugWindowVisible = true;
    });
  }

  void _hideDebugWindow() {
    _debugOverlayEntry?.remove();
    _debugOverlayEntry = null;
    setState(() {
      _debugWindowVisible = false;
    });
  }

  OverlayEntry _createDebugOverlayEntry() {
    return OverlayEntry(
      builder: (context) => _DraggableDebugWindow(
        onClose: _hideDebugWindow,
        onRefresh: () => _debugOverlayEntry?.markNeedsBuild(),
      ),
    );
  }

  void _handleFileDrop(DropDoneDetails details) async {
    // Handle only the first file if multiple files are dropped
    if (details.files.isEmpty) return;

    final file = details.files.first;

    // Switch to Decrypt tab
    setState(() {
      _selectedIndex = 1;
      _isDragOver = false;
    });

    // Show guidance message
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('File detected: ${file.name}\nPlease use the file picker to select it for decryption.'),
          duration: const Duration(seconds: 3),
          backgroundColor: Colors.blue,
        ),
      );
    }
  }

  Widget _getSelectedPage() {
    switch (_selectedIndex) {
      case 0:
        return EncryptTab(fileManager: _fileManager);
      case 1:
        return DecryptTab(fileManager: _fileManager);
      case 2:
        return BatchOperationsTab(key: _batchOperationsTabKey, fileManager: _fileManager, onDebugChanged: widget.onDebugChanged);
      case 3:
        return const InfoTab();
      case 4:
        return SettingsTab(onThemeChanged: widget.onThemeChanged);
      case 5:
        return const IdentityManagementScreen();
      case 6:
        return const Fido2ManagementScreen();
      default:
        return EncryptTab(fileManager: _fileManager);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Shortcuts(
      shortcuts: {
        LogicalKeySet(LogicalKeyboardKey.control, LogicalKeyboardKey.keyO): const OpenFileIntent(),
        LogicalKeySet(LogicalKeyboardKey.control, LogicalKeyboardKey.keyC): const CopyResultIntent(),
        LogicalKeySet(LogicalKeyboardKey.control, LogicalKeyboardKey.keyL): const ClearAllIntent(),
        LogicalKeySet(LogicalKeyboardKey.f1): const ShowHelpIntent(),
        LogicalKeySet(LogicalKeyboardKey.control, LogicalKeyboardKey.keyQ): const ExitAppIntent(),
      },
      child: Actions(
        actions: {
          OpenFileIntent: CallbackAction<OpenFileIntent>(
            onInvoke: (intent) => _openFile(),
          ),
          CopyResultIntent: CallbackAction<CopyResultIntent>(
            onInvoke: (intent) => _copyToClipboard(),
          ),
          ClearAllIntent: CallbackAction<ClearAllIntent>(
            onInvoke: (intent) => _clearAll(),
          ),
          ShowHelpIntent: CallbackAction<ShowHelpIntent>(
            onInvoke: (intent) => _showAbout(context),
          ),
          ExitAppIntent: CallbackAction<ExitAppIntent>(
            onInvoke: (intent) => _exitApp(context),
          ),
        },
        child: Scaffold(
      appBar: AppBar(
        title: const Text('OpenSSL Encrypt Desktop'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        elevation: 1,
        actions: [
          // Desktop Menu Bar
          MenuBar(
            children: [
              SubmenuButton(
                menuChildren: [
                  MenuItemButton(
                    child: const Text('Open File...'),
                    onPressed: () => _openFile(),
                  ),
                  const MenuItemButton(
                    onPressed: null, // TODO: Implement recent files
                    child: Text('Recent Files'),
                  ),
                  const Divider(),
                  MenuItemButton(
                    child: const Text('Exit'),
                    onPressed: () => _exitApp(context),
                  ),
                ],
                child: const Text('File'),
              ),
              SubmenuButton(
                menuChildren: [
                  MenuItemButton(
                    child: const Text('Copy Result'),
                    onPressed: () => _copyToClipboard(),
                  ),
                  MenuItemButton(
                    child: const Text('Clear All'),
                    onPressed: () => _clearAll(),
                  ),
                ],
                child: const Text('Edit'),
              ),
              SubmenuButton(
                menuChildren: [
                  MenuItemButton(
                    child: const Text('Apply Profile Settings'),
                    onPressed: () => _showConfigurationProfiles(context),
                  ),
                  MenuItemButton(
                    child: const Text('Manage Profiles'),
                    onPressed: () => _showManageProfiles(context),
                  ),
                  const Divider(),
                  MenuItemButton(
                    child: const Text('Algorithm Info'),
                    onPressed: () => _showAlgorithmInfo(context),
                  ),
                  MenuItemButton(
                    child: const Text('Security Settings'),
                    onPressed: () => _showSecuritySettings(context),
                  ),
                ],
                child: const Text('Tools'),
              ),
              SubmenuButton(
                menuChildren: [
                  MenuItemButton(
                    child: const Text('About'),
                    onPressed: () => _showAbout(context),
                  ),
                  MenuItemButton(
                    child: const Text('CLI Documentation'),
                    onPressed: () => _showCLIDocs(context),
                  ),
                ],
                child: const Text('Help'),
              ),
            ],
          ),
        ],
      ),
      body: Row(
        children: [
          // Sidebar Navigation
          NavigationRail(
            selectedIndex: _selectedIndex,
            onDestinationSelected: (int index) {
              setState(() {
                _selectedIndex = index;
              });
            },
            labelType: NavigationRailLabelType.all,
            backgroundColor: Theme.of(context).colorScheme.surface,
            destinations: const [
              NavigationRailDestination(
                icon: Icon(Icons.lock_outline),
                selectedIcon: Icon(Icons.lock),
                label: Text('Encrypt'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.lock_open_outlined),
                selectedIcon: Icon(Icons.lock_open),
                label: Text('Decrypt'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.file_copy_outlined),
                selectedIcon: Icon(Icons.file_copy),
                label: Text('Batch Operations'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.info_outline),
                selectedIcon: Icon(Icons.info),
                label: Text('Information'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.settings_outlined),
                selectedIcon: Icon(Icons.settings),
                label: Text('Settings'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.badge_outlined),
                selectedIcon: Icon(Icons.badge),
                label: Text('Identities'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.fingerprint),
                selectedIcon: Icon(Icons.fingerprint),
                label: Text('FIDO2 Keys'),
              ),
            ],
          ),
          const VerticalDivider(thickness: 1, width: 1),
          // Main Content Area with Drag & Drop
          Expanded(
            child: DropTarget(
              onDragDone: _handleFileDrop,
              onDragEntered: (details) {
                setState(() {
                  _isDragOver = true;
                });
              },
              onDragExited: (details) {
                setState(() {
                  _isDragOver = false;
                });
              },
              child: Container(
                decoration: _isDragOver ? BoxDecoration(
                  border: Border.all(color: Theme.of(context).colorScheme.primary, width: 2),
                  borderRadius: BorderRadius.circular(8),
                  color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
                ) : null,
                child: _isDragOver ?
                  Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.file_upload, size: 64, color: Theme.of(context).colorScheme.primary),
                        const SizedBox(height: 16),
                        Text(
                          'Drop file here to encrypt/decrypt',
                          style: TextStyle(fontSize: 18, color: Theme.of(context).colorScheme.primary),
                        ),
                      ],
                    ),
                  ) : _getSelectedPage(),
              ),
            ),
          ),
        ],
      ),
        ),
      ),
    );
  }
}

// Info tab
class InfoTab extends StatefulWidget {
  const InfoTab({super.key});

  @override
  State<InfoTab> createState() => _InfoTabState();
}

class _InfoTabState extends State<InfoTab> {
  List<String> _algorithms = [];
  final Map<String, String> _algorithmDescriptions = {
    'fernet': 'AES-128-CBC with HMAC authentication (Default)',
    'aes-gcm': 'AES-256-GCM authenticated encryption',
    'chacha20-poly1305': 'ChaCha20 stream cipher with Poly1305 MAC',
    'xchacha20-poly1305': 'Extended ChaCha20-Poly1305 with 192-bit nonce',
    'aes-siv': 'AES-SIV synthetic IV mode',
    'aes-gcm-siv': 'AES-GCM-SIV misuse-resistant encryption',
    'threefish-512': '512-bit block cipher, 256-bit PQ security, CTR+Poly1305',
    'threefish-1024': '1024-bit block cipher, 512-bit PQ security, CTR+Poly1305',
  };

  /// Check if algorithm is available on current platform
  bool _isAlgorithmAvailable(String algorithm) {
    // All algorithms are available via CLI backend
    return true;
  }

  /// Get platform-specific description for algorithm
  String _getAlgorithmDescription(String algorithm) {
    return _algorithmDescriptions[algorithm] ?? algorithm;
  }

  @override
  void initState() {
    super.initState();
    _loadAlgorithms();
  }

  @override
  void dispose() {
    super.dispose();
  }

  void _loadAlgorithms() async {
    // Performance optimization: Only load if not already loaded
    if (_algorithms.isNotEmpty) return;

    try {
      final algorithms = await CLIService.getSupportedAlgorithmsList();
      setState(() {
        _algorithms = algorithms;
      });
    } catch (e) {
      setState(() {
        _algorithms = ['Error loading algorithms'];
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Supported Algorithms',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  ..._algorithms.map((algo) => Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Icon(Icons.check_circle, color: Colors.green, size: 16),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    algo,
                                    style: const TextStyle(fontWeight: FontWeight.bold),
                                  ),
                                  if (_algorithmDescriptions.containsKey(algo))
                                    Text(
                                      _getAlgorithmDescription(algo),
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: _isAlgorithmAvailable(algo)
                                            ? Colors.grey[600]
                                            : Colors.orange[600],
                                      ),
                                    ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      )),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'App Information',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  const Text('Version: 1.0.0 (Desktop Development)'),
                  const Text('Build: Desktop GUI Prototype'),
                  Text('Crypto Backend: ${CLIService.isFlatpakVersion ? 'Flatpak' : 'Development (Python Module)'}'),
                  const Text('Hash Chaining: CLI Compatible Order'),
                  const Text('Platform: Flutter'),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Security Features',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  SizedBox(height: 8),
                  Row(
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 16),
                      SizedBox(width: 8),
                      Text('AES-128-CBC Encryption (Fernet)'),
                    ],
                  ),
                  Row(
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 16),
                      SizedBox(width: 8),
                      Text('Chained Hash/KDF (CLI Compatible)'),
                    ],
                  ),
                  Row(
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 16),
                      SizedBox(width: 8),
                      Text('Multi-Hash Password Processing'),
                    ],
                  ),
                  Row(
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'PBKDF2, Scrypt, Argon2, HKDF, Balloon KDFs',
                          style: TextStyle(fontSize: 14),
                        ),
                      ),
                    ],
                  ),
                  Row(
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Post-Quantum Algorithms (ML-KEM, MAYO, CROSS via CLI)',
                        ),
                      ),
                    ],
                  ),
                  Row(
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Complete CLI Algorithm Support (AES-SIV, AES-GCM-SIV, AES-OCB3)',
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
        ),
      ),
    );
  }
}

// =============================================================================
// Algorithm Recommendation Engine Data Structures
// =============================================================================

/// Represents a complete algorithm recommendation
class AlgorithmRecommendation {
  final String algorithm;
  final String profileName;
  final String explanation;
  final Map<String, Map<String, dynamic>> hashConfig;
  final Map<String, Map<String, dynamic>> kdfConfig;

  AlgorithmRecommendation({
    required this.algorithm,
    required this.profileName,
    required this.explanation,
    required this.hashConfig,
    required this.kdfConfig,
  });
}

/// Use case categories for recommendation engine
enum UseCase {
  generalPurpose,
  highSecurity,
  fastPerformance,
  postQuantum,
  compatibility,
  research,
}

/// Security level preferences
enum SecurityLevel {
  standard,
  high,
  maximum,
  futureProof,
}

/// Performance preferences
enum PerformanceLevel {
  fastest,
  balanced,
  security,
}

// =============================================================================
// Recommendation Wizard Dialog
// =============================================================================

class RecommendationWizardDialog extends StatefulWidget {
  const RecommendationWizardDialog({super.key});

  @override
  State<RecommendationWizardDialog> createState() => _RecommendationWizardDialogState();
}

class _RecommendationWizardDialogState extends State<RecommendationWizardDialog> {
  int _currentStep = 0;
  UseCase _selectedUseCase = UseCase.generalPurpose;
  SecurityLevel _selectedSecurityLevel = SecurityLevel.standard;
  PerformanceLevel _selectedPerformanceLevel = PerformanceLevel.balanced;
  bool _needsCompatibility = false;
  bool _futureProofing = false;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Row(
        children: [
          Icon(Icons.auto_awesome, color: Colors.green),
          SizedBox(width: 8),
          Text('Algorithm Recommendation Wizard'),
        ],
      ),
      content: SizedBox(
        width: double.maxFinite,
        height: 500,
        child: Stepper(
          currentStep: _currentStep,
          onStepTapped: (step) => setState(() => _currentStep = step),
          controlsBuilder: (context, details) {
            return Row(
              children: [
                if (details.onStepContinue != null)
                  ElevatedButton(
                    onPressed: details.onStepContinue,
                    child: Text(_currentStep == 3 ? 'Get Recommendation' : 'Next'),
                  ),
                const SizedBox(width: 8),
                if (details.onStepCancel != null)
                  TextButton(
                    onPressed: details.onStepCancel,
                    child: const Text('Back'),
                  ),
              ],
            );
          },
          onStepContinue: () {
            if (_currentStep < 3) {
              setState(() => _currentStep++);
            } else {
              _generateRecommendation();
            }
          },
          onStepCancel: () {
            if (_currentStep > 0) {
              setState(() => _currentStep--);
            }
          },
          steps: [
            _buildUseCaseStep(),
            _buildSecurityStep(),
            _buildPerformanceStep(),
            _buildPreferencesStep(),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
      ],
    );
  }

  Step _buildUseCaseStep() {
    return Step(
      title: const Text('Use Case'),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('What will you primarily use this encryption for?'),
          const SizedBox(height: 16),
          ...UseCase.values.map((useCase) {
            return RadioListTile<UseCase>(
              title: Text(_getUseCaseTitle(useCase)),
              subtitle: Text(_getUseCaseDescription(useCase)),
              value: useCase,
              groupValue: _selectedUseCase,
              onChanged: (value) => setState(() => _selectedUseCase = value!),
            );
          }),
        ],
      ),
      isActive: _currentStep >= 0,
    );
  }

  Step _buildSecurityStep() {
    return Step(
      title: const Text('Security Level'),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('What level of security do you need?'),
          const SizedBox(height: 16),
          ...SecurityLevel.values.map((level) {
            return RadioListTile<SecurityLevel>(
              title: Text(_getSecurityLevelTitle(level)),
              subtitle: Text(_getSecurityLevelDescription(level)),
              value: level,
              groupValue: _selectedSecurityLevel,
              onChanged: (value) => setState(() => _selectedSecurityLevel = value!),
            );
          }),
        ],
      ),
      isActive: _currentStep >= 1,
    );
  }

  Step _buildPerformanceStep() {
    return Step(
      title: const Text('Performance Priority'),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('How important is processing speed?'),
          const SizedBox(height: 16),
          ...PerformanceLevel.values.map((level) {
            return RadioListTile<PerformanceLevel>(
              title: Text(_getPerformanceLevelTitle(level)),
              subtitle: Text(_getPerformanceLevelDescription(level)),
              value: level,
              groupValue: _selectedPerformanceLevel,
              onChanged: (value) => setState(() => _selectedPerformanceLevel = value!),
            );
          }),
        ],
      ),
      isActive: _currentStep >= 2,
    );
  }

  Step _buildPreferencesStep() {
    return Step(
      title: const Text('Additional Preferences'),
      content: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Any special requirements?'),
          const SizedBox(height: 16),
          CheckboxListTile(
            title: const Text('Compatibility Priority'),
            subtitle: const Text('Need to work with older systems or Python implementations'),
            value: _needsCompatibility,
            onChanged: (value) => setState(() => _needsCompatibility = value ?? false),
          ),
          CheckboxListTile(
            title: const Text('Future-Proofing'),
            subtitle: const Text('Protection against quantum computers and future threats'),
            value: _futureProofing,
            onChanged: (value) => setState(() => _futureProofing = value ?? false),
          ),
        ],
      ),
      isActive: _currentStep >= 3,
    );
  }

  void _generateRecommendation() {
    final recommendation = _computeRecommendation();
    Navigator.of(context).pop(recommendation);
  }

  AlgorithmRecommendation _computeRecommendation() {
    // Intelligent recommendation logic based on user preferences

    String algorithm;
    String profileName;
    String explanation;
    Map<String, Map<String, dynamic>> hashConfig;
    Map<String, Map<String, dynamic>> kdfConfig;

    if (_futureProofing || _selectedUseCase == UseCase.postQuantum) {
      // Post-quantum recommendation
      algorithm = _selectedSecurityLevel == SecurityLevel.maximum
        ? 'ml-kem-1024-hybrid'
        : 'ml-kem-768-hybrid';
      profileName = 'Post-Quantum Security';
      explanation = 'ML-KEM provides protection against both classical and quantum computer attacks';

      hashConfig = {
        'blake3': {'enabled': true, 'rounds': 10000},
        'sha256': {'enabled': true, 'rounds': 5000},
      };

      kdfConfig = {
        'argon2': {
          'enabled': true,
          'time_cost': 4,
          'memory_cost': 131072,
          'parallelism': 4,
          'hash_len': 32,
          'type': 2,
          'rounds': 15,
        },
        'pbkdf2': {'enabled': false, 'iterations': 0},
      };

    } else if (_selectedPerformanceLevel == PerformanceLevel.fastest) {
      // Performance-optimized recommendation
      algorithm = 'chacha20-poly1305';
      profileName = 'High Performance';
      explanation = 'ChaCha20 provides excellent security with superior performance on all platforms';

      hashConfig = {
        'blake2b': {'enabled': true, 'rounds': 1000},
      };

      kdfConfig = {
        'hkdf': {
          'enabled': true,
          'rounds': 2,
          'algorithm': 'sha256',
          'info': 'openssl_encrypt_hkdf',
        },
        if (!CLIService.shouldHideLegacyAlgorithms()) 'pbkdf2': {'enabled': true, 'iterations': 50000},
      };

    } else if (_selectedSecurityLevel == SecurityLevel.maximum) {
      // Maximum security recommendation
      algorithm = 'aes-gcm';
      profileName = 'Maximum Security';
      explanation = 'AES-256-GCM with Argon2 provides military-grade security with robust key derivation';

      hashConfig = {
        'sha512': {'enabled': true, 'rounds': 10000},
        'blake3': {'enabled': true, 'rounds': 5000},
        'shake256': {'enabled': true, 'rounds': 2000},
      };

      kdfConfig = {
        'argon2': {
          'enabled': true,
          'time_cost': 5,
          'memory_cost': 262144, // 256MB
          'parallelism': 8,
          'hash_len': 64,
          'type': 2,
          'rounds': 20,
        },
        if (!CLIService.shouldHideLegacyAlgorithms()) 'pbkdf2': {'enabled': true, 'iterations': 500000},
      };

    } else if (_needsCompatibility) {
      // Compatibility-focused recommendation
      algorithm = 'fernet';
      profileName = 'Universal Compatibility';
      explanation = 'Fernet is Python-compatible and works everywhere with solid security';

      hashConfig = {
        'sha256': {'enabled': true, 'rounds': 2000},
      };

      kdfConfig = {
        if (!CLIService.shouldHideLegacyAlgorithms()) 'pbkdf2': {'enabled': true, 'iterations': 200000},
      };

    } else {
      // Balanced general-purpose recommendation
      algorithm = 'aes-gcm';
      profileName = 'Balanced General Use';
      explanation = 'AES-GCM with PBKDF2 provides excellent security and performance for most applications';

      hashConfig = {
        'sha256': {'enabled': true, 'rounds': 5000},
        'blake2b': {'enabled': true, 'rounds': 3000},
      };

      kdfConfig = {
        if (!CLIService.shouldHideLegacyAlgorithms()) 'pbkdf2': {'enabled': true, 'iterations': 200000},
        'argon2': {
          'enabled': false,
          'time_cost': 3,
          'memory_cost': 65536,
          'parallelism': 4,
          'hash_len': 32,
          'type': 2,
          'rounds': 10,
        },
      };
    }

    return AlgorithmRecommendation(
      algorithm: algorithm,
      profileName: profileName,
      explanation: explanation,
      hashConfig: hashConfig,
      kdfConfig: kdfConfig,
    );
  }

  String _getUseCaseTitle(UseCase useCase) {
    switch (useCase) {
      case UseCase.generalPurpose: return '🏠 General Purpose';
      case UseCase.highSecurity: return '🛡️ High Security';
      case UseCase.fastPerformance: return '⚡ Fast Performance';
      case UseCase.postQuantum: return '🔬 Post-Quantum';
      case UseCase.compatibility: return '🔗 Compatibility';
      case UseCase.research: return '🧪 Research';
    }
  }

  String _getUseCaseDescription(UseCase useCase) {
    switch (useCase) {
      case UseCase.generalPurpose: return 'Personal files, documents, everyday encryption needs';
      case UseCase.highSecurity: return 'Sensitive business data, confidential information';
      case UseCase.fastPerformance: return 'Large files, real-time processing, performance critical';
      case UseCase.postQuantum: return 'Future-proof against quantum computer attacks';
      case UseCase.compatibility: return 'Need to work with Python, legacy systems, or other tools';
      case UseCase.research: return 'Experimental algorithms, cutting-edge cryptography';
    }
  }

  String _getSecurityLevelTitle(SecurityLevel level) {
    switch (level) {
      case SecurityLevel.standard: return '📋 Standard Security';
      case SecurityLevel.high: return '🔒 High Security';
      case SecurityLevel.maximum: return '🛡️ Maximum Security';
      case SecurityLevel.futureProof: return '🚀 Future-Proof';
    }
  }

  String _getSecurityLevelDescription(SecurityLevel level) {
    switch (level) {
      case SecurityLevel.standard: return 'Good security for most applications (128-bit equivalent)';
      case SecurityLevel.high: return 'Strong security for sensitive data (192-bit equivalent)';
      case SecurityLevel.maximum: return 'Military-grade security (256-bit equivalent)';
      case SecurityLevel.futureProof: return 'Quantum-resistant, long-term protection';
    }
  }

  String _getPerformanceLevelTitle(PerformanceLevel level) {
    switch (level) {
      case PerformanceLevel.fastest: return '🏃 Speed Priority';
      case PerformanceLevel.balanced: return '⚖️ Balanced';
      case PerformanceLevel.security: return '🛡️ Security Priority';
    }
  }

  String _getPerformanceLevelDescription(PerformanceLevel level) {
    switch (level) {
      case PerformanceLevel.fastest: return 'Optimize for fastest encryption/decryption';
      case PerformanceLevel.balanced: return 'Good balance of security and performance';
      case PerformanceLevel.security: return 'Maximum security, performance secondary';
    }
  }
}

class CommandPreviewDialog extends StatelessWidget {
  final String algorithm;
  final Map<String, Map<String, dynamic>> hashConfig;
  final Map<String, Map<String, dynamic>> kdfConfig;
  final String password;
  final String inputText;

  const CommandPreviewDialog({
    super.key,
    required this.algorithm,
    required this.hashConfig,
    required this.kdfConfig,
    required this.password,
    required this.inputText,
  });

  @override
  Widget build(BuildContext context) {
    // Generate the encrypt and decrypt commands
    final encryptCommand = CLIService.previewEncryptCommand(
      inputText,
      password,
      algorithm,
      hashConfig,
      kdfConfig,
    );

    final decryptCommand = CLIService.previewDecryptCommand(password);

    return Dialog(
      child: Container(
        width: MediaQuery.of(context).size.width * 0.8,
        height: MediaQuery.of(context).size.height * 0.7,
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.code, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 12),
                const Text(
                  'CLI Command Preview',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                ),
                const Spacer(),
                IconButton(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.close),
                  tooltip: 'Close',
                ),
              ],
            ),
            const Divider(),
            const SizedBox(height: 16),

            // Encrypt command section
            Row(
              children: [
                Icon(Icons.lock, color: Colors.green.shade600, size: 20),
                const SizedBox(width: 8),
                Text(
                  'Encryption Command',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                    color: Colors.green.shade700,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainer,
                border: Border.all(color: Theme.of(context).colorScheme.outline),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                encryptCommand,
                style: TextStyle(
                  fontFamily: 'Courier',
                  fontSize: 12,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton.icon(
                  onPressed: () => _copyToClipboard(context, encryptCommand),
                  icon: const Icon(Icons.copy, size: 16),
                  label: const Text('Copy'),
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Decrypt command section
            Row(
              children: [
                Icon(Icons.lock_open, color: Colors.orange.shade600, size: 20),
                const SizedBox(width: 8),
                Text(
                  'Decryption Command',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                    color: Colors.orange.shade700,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainer,
                border: Border.all(color: Theme.of(context).colorScheme.outline),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                decryptCommand,
                style: TextStyle(
                  fontFamily: 'Courier',
                  fontSize: 12,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton.icon(
                  onPressed: () => _copyToClipboard(context, decryptCommand),
                  icon: const Icon(Icons.copy, size: 16),
                  label: const Text('Copy'),
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Usage notes section
            Expanded(
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primaryContainer,
                  border: Border.all(color: Theme.of(context).colorScheme.outline),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.info_outline, color: Theme.of(context).colorScheme.primary, size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'Usage Notes',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                            color: Theme.of(context).colorScheme.onPrimaryContainer,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Expanded(
                      child: SingleChildScrollView(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            _buildUsageNote(context, '• Replace [input-file] with the actual path to your input file'),
                            _buildUsageNote(context, '• Replace [output-file] with the desired path for the output file'),
                            _buildUsageNote(context, '• Replace [password] with your actual password (use quotes if it contains spaces)'),
                            _buildUsageNote(context, '• Replace [encrypted-file] with the path to the file you want to decrypt'),
                            const SizedBox(height: 12),
                            _buildUsageNote(context, 'Algorithm: $algorithm', isHighlight: true),
                            if (_hasActiveHashConfig())
                              _buildUsageNote(context, 'Active hash functions: ${_getActiveHashFunctions()}', isHighlight: true),
                            if (_hasActiveKdfConfig())
                              _buildUsageNote(context, 'Active KDF functions: ${_getActiveKdfFunctions()}', isHighlight: true),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildUsageNote(BuildContext context, String text, {bool isHighlight = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Text(
        text,
        style: TextStyle(
          fontSize: 12,
          color: isHighlight ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.onSurfaceVariant,
          fontWeight: isHighlight ? FontWeight.w600 : FontWeight.normal,
        ),
      ),
    );
  }

  bool _hasActiveHashConfig() {
    return hashConfig.values.any((config) =>
        config['enabled'] == true &&
        config['rounds'] != null &&
        config['rounds'] > 0
    );
  }

  bool _hasActiveKdfConfig() {
    return kdfConfig.values.any((config) => config['enabled'] == true);
  }

  String _getActiveHashFunctions() {
    return hashConfig.entries
        .where((entry) => entry.value['enabled'] == true &&
                         entry.value['rounds'] != null &&
                         entry.value['rounds'] > 0)
        .map((entry) => '${entry.key} (${entry.value['rounds']} rounds)')
        .join(', ');
  }

  String _getActiveKdfFunctions() {
    return kdfConfig.entries
        .where((entry) => entry.value['enabled'] == true)
        .map((entry) => entry.key)
        .join(', ');
  }

  void _copyToClipboard(BuildContext context, String text) async {
    await Clipboard.setData(ClipboardData(text: text));

    // Schedule secure clipboard clearing after 60 seconds for commands (less sensitive)
    Timer(const Duration(seconds: 60), () async {
      await Clipboard.setData(const ClipboardData(text: ''));
    });

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('Command copied to clipboard (will auto-clear in 60s)'),
          backgroundColor: Colors.green.shade600,
          duration: const Duration(seconds: 3),
        ),
      );
    }
  }
}

/// Draggable debug window that can be moved around within the app bounds
class _DraggableDebugWindow extends StatefulWidget {
  final VoidCallback onClose;
  final VoidCallback onRefresh;

  const _DraggableDebugWindow({
    required this.onClose,
    required this.onRefresh,
  });

  @override
  State<_DraggableDebugWindow> createState() => _DraggableDebugWindowState();
}

class _DraggableDebugWindowState extends State<_DraggableDebugWindow> {
  double _x = 100.0;
  double _y = 100.0;

  @override
  void initState() {
    super.initState();
    // Set up real-time callback for debug log updates
    CLIService.setDebugLogCallback(() {
      if (mounted) {
        setState(() {
          // This triggers a rebuild to show new debug logs immediately
        });
      }
    });
  }

  @override
  void dispose() {
    // Remove the callback to prevent memory leaks
    CLIService.setDebugLogCallback(null);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Positioned(
      left: _x,
      top: _y,
      child: Draggable(
        feedback: _buildWindow(theme, isDragging: true),
        childWhenDragging: Container(), // Hide original while dragging
        onDragEnd: (details) {
          setState(() {
            // Keep window within screen bounds
            final screenSize = MediaQuery.of(context).size;
            _x = details.offset.dx.clamp(0.0, screenSize.width - 600);
            _y = details.offset.dy.clamp(0.0, screenSize.height - 500);
          });
        },
        child: _buildWindow(theme),
      ),
    );
  }

  Widget _buildWindow(ThemeData theme, {bool isDragging = false}) {
    return Material(
      elevation: isDragging ? 12 : 8,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        width: 600,
        height: 500,
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: theme.colorScheme.outline),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Draggable header
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: theme.colorScheme.primaryContainer,
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(8),
                  topRight: Radius.circular(8),
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.bug_report,
                    color: theme.colorScheme.onPrimaryContainer,
                    size: 20,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Live Debug Logs (Draggable Window)',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: theme.colorScheme.onPrimaryContainer,
                      ),
                    ),
                  ),
                  Icon(
                    Icons.open_with,
                    color: theme.colorScheme.onPrimaryContainer,
                    size: 16,
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    onPressed: () {
                      CLIService.clearDebugLogs();
                      widget.onRefresh();
                    },
                    icon: Icon(
                      Icons.clear_all,
                      color: theme.colorScheme.onPrimaryContainer,
                    ),
                    tooltip: 'Clear logs',
                    iconSize: 20,
                  ),
                  IconButton(
                    onPressed: widget.onClose,
                    icon: Icon(
                      Icons.close,
                      color: theme.colorScheme.onPrimaryContainer,
                    ),
                    tooltip: 'Close window',
                    iconSize: 20,
                  ),
                ],
              ),
            ),
            // Log content
            Expanded(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Container(
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surfaceContainerHighest,
                    border: Border.all(color: theme.colorScheme.outline),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: RepaintBoundary(
                    child: ListView.builder(
                      key: const Key('floating_debug_logs_listview'),
                      itemCount: CLIService.getDebugLogs().length,
                      itemBuilder: (context, index) {
                        final logs = CLIService.getDebugLogs();
                        return Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                          child: Text(
                            logs[index],
                            style: TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 11,
                              color: theme.colorScheme.onSurface,
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                ),
              ),
            ),
            // Footer info
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Live logs: ${CLIService.getDebugLogs().length} entries (updates automatically)',
                    style: TextStyle(
                      fontSize: 10,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(height: 4),
                  if (CLIService.getDebugLogFile() != null)
                    Text(
                      'Full logs saved to: ${CLIService.getDebugLogFile()}',
                      style: TextStyle(
                        fontSize: 10,
                        color: theme.colorScheme.onSurfaceVariant,
                        fontFamily: 'monospace',
                      ),
                    ),
                  const SizedBox(height: 4),
                  Text(
                    'Drag the header to move this window around',
                    style: TextStyle(
                      fontSize: 9,
                      color: theme.colorScheme.primary,
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Auto-repeat button widget that continues executing action when held down
class AutoRepeatButton extends StatefulWidget {
  final IconData icon;
  final MaterialColor color;
  final bool enabled;
  final VoidCallback onAction;
  final double size;
  final double iconSize;

  const AutoRepeatButton({
    super.key,
    required this.icon,
    required this.color,
    required this.enabled,
    required this.onAction,
    this.size = 32,
    this.iconSize = 16,
  });

  @override
  State<AutoRepeatButton> createState() => _AutoRepeatButtonState();
}

class _AutoRepeatButtonState extends State<AutoRepeatButton> {
  Timer? _repeatTimer;
  bool _isPressed = false;

  @override
  void dispose() {
    _repeatTimer?.cancel();
    super.dispose();
  }

  void _onPointerDown(PointerDownEvent event) {
    if (!widget.enabled) return;

    setState(() {
      _isPressed = true;
    });

    // Execute immediately
    widget.onAction();

    // Start repeating after a short delay
    _repeatTimer = Timer(const Duration(milliseconds: 300), () {
      if (_isPressed && mounted) {
        _startRepeating();
      }
    });
  }

  void _startRepeating() {
    _repeatTimer = Timer.periodic(const Duration(milliseconds: 100), (timer) {
      if (_isPressed && mounted && widget.enabled) {
        widget.onAction();
      } else {
        timer.cancel();
        _repeatTimer = null;
      }
    });
  }

  void _onPointerUp(PointerUpEvent event) {
    setState(() {
      _isPressed = false;
    });
    _repeatTimer?.cancel();
    _repeatTimer = null;
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      onPointerDown: _onPointerDown,
      onPointerUp: _onPointerUp,
      child: Container(
        width: widget.size,
        height: widget.size,
        decoration: BoxDecoration(
          color: widget.enabled
              ? (_isPressed ? widget.color.shade200 : widget.color.shade100)
              : Theme.of(context).colorScheme.surfaceContainer,
          borderRadius: BorderRadius.circular(4),
          border: Border.all(
            color: widget.enabled ? widget.color.shade300 : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
        child: Icon(
          widget.icon,
          size: widget.iconSize,
          color: widget.enabled ? widget.color.shade700 : Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}

/// Settings tab wrapper that integrates the SettingsScreen
class SettingsTab extends StatelessWidget {
  final VoidCallback onThemeChanged;

  const SettingsTab({super.key, required this.onThemeChanged});

  @override
  Widget build(BuildContext context) {
    return Navigator(
      onGenerateRoute: (settings) => MaterialPageRoute(
        builder: (context) => SettingsScreenWrapper(onThemeChanged: onThemeChanged),
      ),
    );
  }
}

/// Wrapper for SettingsScreen that handles theme change notifications
class SettingsScreenWrapper extends StatefulWidget {
  final VoidCallback onThemeChanged;

  const SettingsScreenWrapper({super.key, required this.onThemeChanged});

  @override
  State<SettingsScreenWrapper> createState() => _SettingsScreenWrapperState();
}

class _SettingsScreenWrapperState extends State<SettingsScreenWrapper> {
  @override
  Widget build(BuildContext context) {
    return SettingsScreen(
      onSettingChanged: (key, value) {
        // Handle settings changes
        if (key == 'theme_mode') {
          // Notify parent to refresh theme
          widget.onThemeChanged();
        }
      },
    );
  }

  bool _isPostQuantumAlgorithm(String algorithm) {
    return algorithm.contains('ml-kem') ||
           algorithm.contains('kyber') ||
           algorithm.contains('hqc') ||
           algorithm.contains('mayo') ||
           algorithm.contains('cross');
  }

  List<String> _getNonPostQuantumAlgorithms() {
    return [
      'aes-gcm',
      'aes-gcm-siv',
      'aes-siv',
      'chacha20-poly1305',
      'xchacha20-poly1305',
    ];
  }
}

/// Batch Operations tab for processing multiple files
class BatchOperationsTab extends StatefulWidget {
  final FileManager fileManager;
  final Function(bool) onDebugChanged;

  const BatchOperationsTab({
    super.key,
    required this.fileManager,
    required this.onDebugChanged,
  });

  @override
  State<BatchOperationsTab> createState() => _BatchOperationsTabState();
}

class _BatchOperationsTabState extends State<BatchOperationsTab> {
  List<FileInfo> _selectedFiles = [];
  bool _isLoading = false;
  String _selectedAlgorithm = 'aes-gcm';
  String _selectedEncryptData = 'aes-gcm';  // For PQC algorithms
  String _password = '';
  String _confirmPassword = '';
  String _selectedOperation = 'encrypt'; // 'encrypt', 'decrypt', or 'verify-integrity'
  final List<BatchOperationResult> _results = [];
  String result = ''; // Add result field for clipboard copying

  // Progress tracking
  int _currentFileIndex = 0;
  String _currentStatus = '';

  // Integrity settings
  bool _enableIntegrity = false;      // For encrypt mode: register hash
  bool _verifyIntegrity = false;      // For decrypt mode: verify before decrypt

  // Advanced settings
  bool _showAdvanced = false;

  // Encryption mode selection
  EncryptionMode _encryptionMode = EncryptionMode.symmetric;

  // Asymmetric encryption state
  List<String> _selectedRecipients = [];
  String? _signingIdentity;
  String? _decryptionIdentity;
  String? _verifyFrom;
  bool _skipVerification = false;
  bool _useKeyserver = false;
  List<Map<String, dynamic>> _ownIdentities = [];
  List<Map<String, dynamic>> _contacts = [];

  // Cascade encryption state
  String _cascadePreset = 'standard';
  List<String> _cascadeAlgorithms = ['aes-256-gcm', 'chacha20-poly1305'];
  String _cascadeHash = 'sha256';
  List<Map<String, dynamic>> _diversityWarnings = [];

  // Cached dropdown items for algorithms (performance optimization)
  static final Map<String, List<DropdownMenuItem<String>>> _dropdownCache = {};

  @override
  void initState() {
    super.initState();
    _loadIdentities();
  }

  /// Load identities for asymmetric encryption
  void _loadIdentities() async {
    try {
      final identities = await CLIService.listIdentities();
      setState(() {
        _ownIdentities = identities['own'] ?? [];
        _contacts = identities['contacts'] ?? [];
      });
    } catch (e) {
      CLIService.outputDebugLog('Failed to load identities: $e');
      setState(() {
        _ownIdentities = [];
        _contacts = [];
      });
    }
  }

  List<DropdownMenuItem<String>> _getCachedAlgorithmDropdownItems(List<String> algorithms) {
    final key = algorithms.join(',');
    if (!_dropdownCache.containsKey(key)) {
      _dropdownCache[key] = algorithms.map((algorithm) => DropdownMenuItem<String>(
        value: algorithm,
        child: Text(algorithm),
      )).toList();
    }
    return _dropdownCache[key]!;
  }

  /// Build asymmetric encryption UI section (for encrypt mode)
  Widget _buildAsymmetricEncryptSection() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.vpn_key),
                const SizedBox(width: 8),
                const Text('Asymmetric Encryption Settings', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ],
            ),
            const SizedBox(height: 12),
            if (_ownIdentities.isEmpty && _contacts.isEmpty) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orange.shade50,
                  border: Border.all(color: Colors.orange),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.warning, color: Colors.orange.shade700),
                        const SizedBox(width: 8),
                        const Expanded(
                          child: Text(
                            'No identities available',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text('You need to create an identity before using asymmetric encryption.'),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(
                      onPressed: () {
                        final mainScreenState = context.findAncestorStateOfType<_MainScreenState>();
                        mainScreenState?.setState(() {
                          mainScreenState._selectedIndex = 5;
                        });
                      },
                      icon: const Icon(Icons.badge),
                      label: const Text('Go to Identity Management'),
                    ),
                  ],
                ),
              ),
            ] else ...[
              const Text('Recipients (who can decrypt):', style: TextStyle(fontWeight: FontWeight.w500)),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  ..._selectedRecipients.map((recipient) => Chip(
                    label: Text(recipient),
                    deleteIcon: const Icon(Icons.close, size: 18),
                    onDeleted: () {
                      setState(() {
                        _selectedRecipients.remove(recipient);
                      });
                    },
                  )),
                  ActionChip(
                    avatar: const Icon(Icons.add, size: 18),
                    label: const Text('Add Recipient'),
                    onPressed: () => _showAddRecipientDialog(),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              const Text('Sign with (optional):', style: TextStyle(fontWeight: FontWeight.w500)),
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                value: _signingIdentity,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  hintText: 'Select signing identity',
                  helperText: 'Digitally sign the encrypted data with your identity',
                ),
                items: [
                  const DropdownMenuItem<String>(
                    value: null,
                    child: Text('None (unsigned)'),
                  ),
                  ..._ownIdentities.map((identity) => DropdownMenuItem<String>(
                    value: identity['name'] as String,
                    child: Text(identity['name'] as String),
                  )),
                ],
                onChanged: (value) {
                  setState(() {
                    _signingIdentity = value;
                  });
                },
              ),
              const SizedBox(height: 16),
              CheckboxListTile(
                value: _useKeyserver,
                onChanged: (value) {
                  setState(() {
                    _useKeyserver = value ?? false;
                  });
                },
                title: const Text('Use keyserver for recipient lookup'),
                subtitle: const Text('Automatically fetch recipient public keys from keyserver', style: TextStyle(fontSize: 11)),
                contentPadding: EdgeInsets.zero,
                dense: true,
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build asymmetric decryption UI section (for decrypt mode)
  Widget _buildAsymmetricDecryptSection() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.vpn_key),
                const SizedBox(width: 8),
                const Text('Asymmetric Decryption Settings', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ],
            ),
            const SizedBox(height: 12),
            if (_ownIdentities.isEmpty) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orange.shade50,
                  border: Border.all(color: Colors.orange),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.warning, color: Colors.orange.shade700),
                        const SizedBox(width: 8),
                        const Expanded(
                          child: Text(
                            'No identities available',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text('You need an identity to decrypt asymmetrically encrypted data.'),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(
                      onPressed: () {
                        final mainScreenState = context.findAncestorStateOfType<_MainScreenState>();
                        mainScreenState?.setState(() {
                          mainScreenState._selectedIndex = 5;
                        });
                      },
                      icon: const Icon(Icons.badge),
                      label: const Text('Go to Identity Management'),
                    ),
                  ],
                ),
              ),
            ] else ...[
              const Text('Decrypt with identity:', style: TextStyle(fontWeight: FontWeight.w500)),
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                value: _decryptionIdentity,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  hintText: 'Select decryption identity',
                  helperText: 'The identity that was specified as a recipient',
                ),
                items: _ownIdentities.map((identity) => DropdownMenuItem<String>(
                  value: identity['name'] as String,
                  child: Text(identity['name'] as String),
                )).toList(),
                onChanged: (value) {
                  setState(() {
                    _decryptionIdentity = value;
                  });
                },
              ),
              const SizedBox(height: 16),
              const Text('Verify signature from (optional):', style: TextStyle(fontWeight: FontWeight.w500)),
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                value: _verifyFrom,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  hintText: 'Select sender to verify',
                  helperText: 'Verify the digital signature from the sender',
                ),
                items: [
                  const DropdownMenuItem<String>(
                    value: null,
                    child: Text('Don\'t verify signature'),
                  ),
                  ..._ownIdentities.map((identity) => DropdownMenuItem<String>(
                    value: identity['name'] as String,
                    child: Text('${identity['name']} (own)'),
                  )),
                  ..._contacts.map((contact) => DropdownMenuItem<String>(
                    value: contact['name'] as String,
                    child: Text('${contact['name']} (contact)'),
                  )),
                ],
                onChanged: (value) {
                  setState(() {
                    _verifyFrom = value;
                  });
                },
              ),
              if (_showAdvanced) ...[
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.red.shade50,
                    border: Border.all(color: Colors.red.shade200),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: CheckboxListTile(
                    value: _skipVerification,
                    onChanged: (value) {
                      setState(() {
                        _skipVerification = value ?? false;
                      });
                    },
                    title: const Text('Skip signature verification (dangerous)', style: TextStyle(color: Colors.red)),
                    subtitle: const Text('Only use if you understand the security implications', style: TextStyle(fontSize: 11)),
                    contentPadding: EdgeInsets.zero,
                    dense: true,
                  ),
                ),
              ],
            ],
          ],
        ),
      ),
    );
  }

  /// Show dialog to add recipient
  void _showAddRecipientDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add Recipient'),
        content: SizedBox(
          width: 400,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Select a recipient who will be able to decrypt this data:'),
              const SizedBox(height: 16),
              ...(_ownIdentities.isEmpty && _contacts.isEmpty)
                  ? [const Text('No identities or contacts available')]
                  : [
                      ..._ownIdentities.map((identity) {
                        final name = identity['name'] as String;
                        final isSelected = _selectedRecipients.contains(name);
                        return ListTile(
                          leading: const Icon(Icons.badge),
                          title: Text('$name (own)'),
                          subtitle: identity['email'] != null ? Text(identity['email'] as String) : null,
                          trailing: isSelected ? const Icon(Icons.check, color: Colors.green) : null,
                          onTap: isSelected
                              ? null
                              : () {
                                  setState(() {
                                    _selectedRecipients.add(name);
                                  });
                                  Navigator.pop(context);
                                },
                        );
                      }),
                      ..._contacts.map((contact) {
                        final name = contact['name'] as String;
                        final isSelected = _selectedRecipients.contains(name);
                        return ListTile(
                          leading: const Icon(Icons.contact_mail),
                          title: Text('$name (contact)'),
                          subtitle: contact['email'] != null ? Text(contact['email'] as String) : null,
                          trailing: isSelected ? const Icon(Icons.check, color: Colors.green) : null,
                          onTap: isSelected
                              ? null
                              : () {
                                  setState(() {
                                    _selectedRecipients.add(name);
                                  });
                                  Navigator.pop(context);
                                },
                        );
                      }),
                    ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }

  /// Build encryption mode selector widget
  /// Build cascade encryption UI section
  Widget _buildCascadeSection() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.layers),
                const SizedBox(width: 8),
                const Text('Cascade Encryption Settings', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Cascade Encryption'),
                        content: const SingleChildScrollView(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text('Cascade encryption chains multiple algorithms together for defense-in-depth security.\n'),
                              Text('Presets:', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('• Standard: AES-256-GCM + ChaCha20-Poly1305'),
                              Text('• Paranoia: AES-256-GCM + ChaCha20-Poly1305 + Threefish-512\n'),
                              Text('Custom allows you to build your own algorithm chain with any combination.'),
                            ],
                          ),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: const Text('OK'),
                          ),
                        ],
                      ),
                    );
                  },
                  tooltip: 'Cascade Information',
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text('Cascade Preset:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            Center(
              child: SegmentedButton<String>(
                segments: const [
                  ButtonSegment(value: 'standard', label: Text('Standard'), icon: Icon(Icons.shield)),
                  ButtonSegment(value: 'paranoia', label: Text('Paranoia'), icon: Icon(Icons.security)),
                  ButtonSegment(value: 'custom', label: Text('Custom'), icon: Icon(Icons.tune)),
                ],
                selected: {_cascadePreset},
                onSelectionChanged: (Set<String> newSelection) async {
                  setState(() {
                    _cascadePreset = newSelection.first;
                    if (_cascadePreset == 'standard') {
                      _cascadeAlgorithms = ['aes-256-gcm', 'chacha20-poly1305'];
                    } else if (_cascadePreset == 'paranoia') {
                      _cascadeAlgorithms = ['aes-256-gcm', 'chacha20-poly1305', 'threefish-512'];
                    }
                  });
                  if (_cascadePreset == 'custom') {
                    final warnings = await CLIService.validateCascade(_cascadeAlgorithms);
                    setState(() { _diversityWarnings = warnings; });
                  } else {
                    setState(() { _diversityWarnings = []; });
                  }
                },
              ),
            ),
            const SizedBox(height: 16),
            if (_cascadePreset != 'custom') ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.blue.shade50,
                  border: Border.all(color: Colors.blue.shade200),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Algorithm Chain:', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    ..._cascadeAlgorithms.asMap().entries.map((entry) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 2),
                        child: Row(
                          children: [
                            Container(
                              width: 24,
                              height: 24,
                              decoration: const BoxDecoration(color: Colors.blue, shape: BoxShape.circle),
                              child: Center(
                                child: Text('${entry.key + 1}', style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Text(entry.value),
                          ],
                        ),
                      );
                    }),
                  ],
                ),
              ),
            ],
            if (_cascadePreset == 'custom') ...[
              const Text('Custom Algorithm Chain:', style: TextStyle(fontWeight: FontWeight.w500)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  border: Border.all(color: Theme.of(context).colorScheme.outline),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  children: [
                    if (_cascadeAlgorithms.isEmpty)
                      const Padding(padding: EdgeInsets.all(16.0), child: Text('No algorithms added. Add at least 2 algorithms.'))
                    else
                      ReorderableListView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        itemCount: _cascadeAlgorithms.length,
                        onReorder: (oldIndex, newIndex) async {
                          setState(() {
                            if (newIndex > oldIndex) { newIndex -= 1; }
                            final item = _cascadeAlgorithms.removeAt(oldIndex);
                            _cascadeAlgorithms.insert(newIndex, item);
                          });
                          final warnings = await CLIService.validateCascade(_cascadeAlgorithms);
                          setState(() { _diversityWarnings = warnings; });
                        },
                        itemBuilder: (context, index) {
                          final algorithm = _cascadeAlgorithms[index];
                          return ListTile(
                            key: ValueKey(algorithm + index.toString()),
                            dense: true,
                            leading: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Container(
                                  width: 24,
                                  height: 24,
                                  decoration: const BoxDecoration(color: Colors.blue, shape: BoxShape.circle),
                                  child: Center(child: Text('${index + 1}', style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold))),
                                ),
                                const SizedBox(width: 8),
                                const Icon(Icons.drag_handle),
                              ],
                            ),
                            title: Text(algorithm),
                            trailing: IconButton(
                              icon: const Icon(Icons.delete_outline),
                              onPressed: () async {
                                setState(() { _cascadeAlgorithms.removeAt(index); });
                                final warnings = await CLIService.validateCascade(_cascadeAlgorithms);
                                setState(() { _diversityWarnings = warnings; });
                              },
                            ),
                          );
                        },
                      ),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(onPressed: () => _showAddCascadeAlgorithmDialog(), icon: const Icon(Icons.add), label: const Text('Add Algorithm')),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 16),
            const Text('HKDF Hash Function:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            DropdownButtonFormField<String>(
              value: _cascadeHash,
              decoration: const InputDecoration(border: OutlineInputBorder(), helperText: 'Hash function for key derivation between layers'),
              items: const [
                DropdownMenuItem(value: 'sha256', child: Text('SHA-256')),
                DropdownMenuItem(value: 'sha384', child: Text('SHA-384')),
                DropdownMenuItem(value: 'sha512', child: Text('SHA-512')),
                DropdownMenuItem(value: 'blake2b', child: Text('BLAKE2b')),
                DropdownMenuItem(value: 'blake2s', child: Text('BLAKE2s')),
              ],
              onChanged: (value) { setState(() { _cascadeHash = value ?? 'sha256'; }); },
            ),
            if (_diversityWarnings.isNotEmpty) ...[
              const SizedBox(height: 16),
              const Text('Security Warnings:', style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              ..._diversityWarnings.map((warning) {
                final level = warning['level'] as String;
                final message = warning['message'] as String;
                final suggestion = warning['suggestion'] as String;
                final color = level == 'ERROR' ? Colors.red : Colors.orange;
                return Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(color: color.shade50, border: Border.all(color: color), borderRadius: BorderRadius.circular(8)),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.warning, color: color.shade700, size: 20),
                          const SizedBox(width: 8),
                          Expanded(child: Text(message, style: TextStyle(fontWeight: FontWeight.bold, color: color.shade900))),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(suggestion, style: TextStyle(fontSize: 12, color: color.shade800)),
                    ],
                  ),
                );
              }),
            ],
          ],
        ),
      ),
    );
  }

  void _showAddCascadeAlgorithmDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add Algorithm'),
        content: SizedBox(
          width: 400,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Select an algorithm to add to the cascade chain:'),
              const SizedBox(height: 16),
              const Text('AES Family:', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
              ..._buildAlgorithmTiles(['aes-256-gcm', 'aes-gcm-siv', 'aes-siv', 'aes-ocb3']),
              const SizedBox(height: 8),
              const Text('ChaCha Family:', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
              ..._buildAlgorithmTiles(['chacha20-poly1305', 'xchacha20-poly1305']),
              const SizedBox(height: 8),
              const Text('Threefish Family:', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
              ..._buildAlgorithmTiles(['threefish-512', 'threefish-1024']),
            ],
          ),
        ),
        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel'))],
      ),
    );
  }

  List<Widget> _buildAlgorithmTiles(List<String> algorithms) {
    return algorithms.map((algorithm) {
      final isAlreadyAdded = _cascadeAlgorithms.contains(algorithm);
      return ListTile(
        dense: true,
        title: Text(algorithm),
        trailing: isAlreadyAdded ? const Icon(Icons.check, color: Colors.green) : null,
        enabled: !isAlreadyAdded,
        onTap: isAlreadyAdded ? null : () async {
          setState(() { _cascadeAlgorithms.add(algorithm); });
          Navigator.pop(context);
          final warnings = await CLIService.validateCascade(_cascadeAlgorithms);
          setState(() { _diversityWarnings = warnings; });
        },
      );
    }).toList();
  }

  Widget _buildEncryptionModeSelector() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.security_outlined),
                const SizedBox(width: 8),
                const Text('Encryption Mode', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Encryption Mode Information'),
                        content: const SingleChildScrollView(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text('Symmetric (Password-Based)', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('Traditional encryption using a password. The same password is used for encryption and decryption.\n'),
                              Text('Asymmetric (Identity-Based)', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('Post-quantum secure encryption using ML-KEM and ML-DSA. Encrypt for specific identities without sharing passwords.\n'),
                              Text('Cascade (Multi-Layer)', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('Chain multiple encryption algorithms together for defense-in-depth. If one algorithm is broken, others remain secure.'),
                            ],
                          ),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: const Text('OK'),
                          ),
                        ],
                      ),
                    );
                  },
                  tooltip: 'Encryption Mode Information',
                ),
              ],
            ),
            const SizedBox(height: 12),
            Center(
              child: SegmentedButton<EncryptionMode>(
                segments: const [
                  ButtonSegment(
                    value: EncryptionMode.symmetric,
                    label: Text('Symmetric'),
                    icon: Icon(Icons.lock),
                  ),
                  ButtonSegment(
                    value: EncryptionMode.asymmetric,
                    label: Text('Asymmetric'),
                    icon: Icon(Icons.vpn_key),
                  ),
                  ButtonSegment(
                    value: EncryptionMode.cascade,
                    label: Text('Cascade'),
                    icon: Icon(Icons.layers),
                  ),
                ],
                selected: {_encryptionMode},
                onSelectionChanged: (Set<EncryptionMode> newSelection) {
                  setState(() {
                    _encryptionMode = newSelection.first;
                  });
                },
              ),
            ),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Icon(Icons.file_copy, size: 28, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 12),
              const Expanded(
                child: Text(
                  'Batch Operations',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Process multiple files with the same encryption settings',
            style: TextStyle(
              fontSize: 14,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),

          // File Selection Section
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.folder_open, color: Theme.of(context).colorScheme.primary),
                      const SizedBox(width: 8),
                      const Text(
                        'File Selection',
                        style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                      ),
                      const Spacer(),
                      ElevatedButton.icon(
                        onPressed: _isLoading ? null : _selectFiles,
                        icon: const Icon(Icons.add),
                        label: const Text('Select Files'),
                      ),
                      if (_selectedFiles.isNotEmpty) ...[
                        const SizedBox(width: 8),
                        TextButton.icon(
                          onPressed: _isLoading ? null : _clearFiles,
                          icon: const Icon(Icons.clear),
                          label: const Text('Clear'),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 12),
                  if (_selectedFiles.isEmpty)
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(32),
                      decoration: BoxDecoration(
                        border: Border.all(
                          color: Theme.of(context).colorScheme.outline,
                          style: BorderStyle.solid,
                        ),
                        borderRadius: BorderRadius.circular(8),
                        color: Theme.of(context).colorScheme.surfaceContainer,
                      ),
                      child: Column(
                        children: [
                          Icon(
                            Icons.file_upload,
                            size: 48,
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'No files selected',
                            style: TextStyle(
                              fontSize: 16,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Click "Select Files" to choose multiple files for batch processing',
                            style: TextStyle(
                              fontSize: 12,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    )
                  else
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${_selectedFiles.length} file(s) selected:',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w500,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Container(
                          constraints: const BoxConstraints(maxHeight: 200),
                          child: RepaintBoundary(
                            child: ListView.builder(
                              shrinkWrap: true,
                              itemCount: _selectedFiles.length,
                            itemBuilder: (context, index) {
                              final file = _selectedFiles[index];
                              return Card(
                                margin: const EdgeInsets.symmetric(vertical: 2),
                                child: ListTile(
                                  dense: true,
                                  leading: Icon(
                                    _getFileIcon(file.extension),
                                    color: Theme.of(context).colorScheme.primary,
                                  ),
                                  title: Text(
                                    file.name,
                                    style: const TextStyle(fontSize: 13),
                                  ),
                                  subtitle: Text(
                                    '${file.sizeFormatted} • ${file.extension.isEmpty ? 'No extension' : file.extension}',
                                    style: const TextStyle(fontSize: 11),
                                  ),
                                  trailing: IconButton(
                                    icon: const Icon(Icons.remove_circle_outline, size: 20),
                                    onPressed: _isLoading ? null : () => _removeFile(index),
                                  ),
                                ),
                              );
                            },
                            ),
                          ),
                        ),
                      ],
                    ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 16),

          // Configuration Section
          if (_selectedFiles.isNotEmpty) ...[
            // Encryption Mode Selector
            _buildEncryptionModeSelector(),
            const SizedBox(height: 16),

            // Asymmetric mode section
            if (_encryptionMode == EncryptionMode.asymmetric) ...[
              if (_selectedOperation == 'encrypt')
                _buildAsymmetricEncryptSection()
              else if (_selectedOperation == 'decrypt')
                _buildAsymmetricDecryptSection(),
              const SizedBox(height: 16),
            ],

            // Cascade mode section
            if (_encryptionMode == EncryptionMode.cascade) ...[
              _buildCascadeSection(),
              const SizedBox(height: 16),
            ],

            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.settings, color: Theme.of(context).colorScheme.primary),
                        const SizedBox(width: 8),
                        const Text(
                          'Operation Settings',
                          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Operation Type
                    Column(
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: RadioListTile<String>(
                                title: const Text('Encrypt Files'),
                                subtitle: const Text('Encrypt all selected files'),
                                value: 'encrypt',
                                groupValue: _selectedOperation,
                                onChanged: _isLoading ? null : (value) {
                                  setState(() {
                                    _selectedOperation = value!;
                                  });
                                },
                              ),
                            ),
                            Expanded(
                              child: RadioListTile<String>(
                                title: const Text('Decrypt Files'),
                                subtitle: const Text('Decrypt all selected files'),
                                value: 'decrypt',
                                groupValue: _selectedOperation,
                                onChanged: _isLoading ? null : (value) {
                                  setState(() {
                                    _selectedOperation = value!;
                                  });
                                },
                              ),
                            ),
                          ],
                        ),
                        if (SettingsService.getIntegrityEnabled())
                          RadioListTile<String>(
                            title: const Text('Verify Integrity'),
                            subtitle: const Text('Verify file integrity against server'),
                            value: 'verify-integrity',
                            groupValue: _selectedOperation,
                            onChanged: _isLoading ? null : (value) {
                              setState(() {
                                _selectedOperation = value!;
                              });
                            },
                          ),
                      ],
                    ),

                    const SizedBox(height: 16),

                    // Algorithm Selection (only for encryption in symmetric mode)
                    if (_selectedOperation == 'encrypt' && _encryptionMode == EncryptionMode.symmetric) ...[
                      Row(
                        children: [
                          const SizedBox(width: 100, child: Text('Algorithm:')),
                          Expanded(
                            child: DropdownButton<String>(
                              key: ValueKey('algorithm_dropdown_$_selectedAlgorithm'),
                              value: _selectedAlgorithm,
                              isExpanded: true,
                              items: _getCachedAlgorithmDropdownItems([
                                // Classical symmetric algorithms
                                'fernet',
                                'aes-gcm',
                                'chacha20-poly1305',
                                'xchacha20-poly1305',
                                'aes-siv',
                                'aes-gcm-siv',

                                // ML-KEM (NIST Post-Quantum) algorithms
                                'ml-kem-512-hybrid',
                                'ml-kem-768-hybrid',
                                'ml-kem-1024-hybrid',
                                'ml-kem-512-chacha20',
                                'ml-kem-768-chacha20',
                                'ml-kem-1024-chacha20',

                                // Kyber (pre-NIST) algorithms
                                'kyber512-hybrid',
                                'kyber768-hybrid',
                                'kyber1024-hybrid',

                                // HQC algorithms
                                'hqc-128-hybrid',
                                'hqc-192-hybrid',
                                'hqc-256-hybrid',

                                // MAYO signature-based algorithms
                                'mayo-1-hybrid',
                                'mayo-3-hybrid',
                                'mayo-5-hybrid',

                                // CROSS signature-based algorithms
                                'cross-128-hybrid',
                                'cross-192-hybrid',
                                'cross-256-hybrid',
                              ]),
                              onChanged: _isLoading ? null : (value) {
                                setState(() {
                                  _selectedAlgorithm = value!;
                                });
                              },
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),

                      // Private Key Encryption for Post-Quantum Algorithms
                      if (_isPostQuantumAlgorithm(_selectedAlgorithm)) ...[
                        Card(
                          color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
                          child: Padding(
                            padding: const EdgeInsets.all(12.0),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(
                                  children: [
                                    Icon(Icons.vpn_key, color: Theme.of(context).colorScheme.primary),
                                    const SizedBox(width: 8),
                                    const Text('Private Key Encryption', style: TextStyle(fontWeight: FontWeight.bold)),
                                    const Spacer(),
                                    const Icon(Icons.security, color: Colors.purple, size: 18),
                                  ],
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  'Post-quantum algorithms require additional encryption of private key data',
                                  style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
                                ),
                                const SizedBox(height: 12),
                                Row(
                                  children: [
                                    const SizedBox(width: 100, child: Text('Encryption Method:')),
                                    Expanded(
                                      child: DropdownButton<String>(
                                        value: _selectedEncryptData,
                                        isExpanded: true,
                                        items: _getNonPostQuantumAlgorithms().map((algorithm) => DropdownMenuItem<String>(
                                          value: algorithm,
                                          child: Text(algorithm),
                                        )).toList(),
                                        onChanged: (String? newValue) {
                                          if (newValue != null) {
                                            setState(() {
                                              _selectedEncryptData = newValue;
                                            });
                                          }
                                        },
                                      ),
                                    ),
                                  ],
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                      ],
                    ],

                    // Password Fields
                    Row(
                      children: [
                        Expanded(
                          child: TextFormField(
                            obscureText: true,
                            enabled: !_isLoading,
                            onChanged: (value) => _password = value,
                            decoration: InputDecoration(
                              labelText: _selectedOperation == 'encrypt' ? 'Password' : 'Decryption Password',
                              border: const OutlineInputBorder(),
                              prefixIcon: const Icon(Icons.lock),
                              helperText: 'Maximum 1024 characters',
                            ),
                            validator: InputValidator.validatePassword,
                            // Security: Prevent excessively long passwords that could cause buffer overflow
                            inputFormatters: [
                              LengthLimitingTextInputFormatter(InputValidator.maxPasswordLength),
                              // Security: Filter out null bytes and dangerous control characters
                              FilteringTextInputFormatter.deny(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')),
                            ],
                          ),
                        ),
                        if (_selectedOperation == 'encrypt') ...[
                          const SizedBox(width: 16),
                          Expanded(
                            child: TextFormField(
                              obscureText: true,
                              enabled: !_isLoading,
                              onChanged: (value) => _confirmPassword = value,
                              decoration: InputDecoration(
                                labelText: 'Confirm Password',
                                border: const OutlineInputBorder(),
                                prefixIcon: const Icon(Icons.lock_outline),
                                helperText: 'Maximum 1024 characters',
                                errorText: _password.isNotEmpty && _confirmPassword.isNotEmpty && _password != _confirmPassword
                                    ? 'Passwords do not match'
                                    : null,
                              ),
                              validator: (value) {
                                final passwordValidation = InputValidator.validatePassword(value);
                                if (passwordValidation != null) return passwordValidation;
                                if (_password.isNotEmpty && value != _password) {
                                  return 'Passwords do not match';
                                }
                                return null;
                              },
                              // Security: Prevent excessively long passwords that could cause buffer overflow
                              inputFormatters: [
                                LengthLimitingTextInputFormatter(InputValidator.maxPasswordLength),
                                // Security: Filter out null bytes and dangerous control characters
                                FilteringTextInputFormatter.deny(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')),
                              ],
                            ),
                          ),
                        ],
                      ],
                    ),

                    // Integrity verification section (for encrypt/decrypt operations)
                    if (SettingsService.getIntegrityEnabled() && _selectedOperation != 'verify-integrity') ...[
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.teal.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: Colors.teal.withValues(alpha: 0.3)),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                const Icon(Icons.verified, size: 18, color: Colors.teal),
                                const SizedBox(width: 8),
                                const Text(
                                  'Integrity Verification',
                                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                                ),
                              ],
                            ),
                            const SizedBox(height: 8),
                            if (_selectedOperation == 'encrypt')
                              CheckboxListTile(
                                value: _enableIntegrity,
                                onChanged: (value) {
                                  setState(() {
                                    _enableIntegrity = value ?? false;
                                  });
                                },
                                title: const Text(
                                  'Register hash with integrity server',
                                  style: TextStyle(fontSize: 13),
                                ),
                                subtitle: const Text(
                                  'Upload encrypted file hashes to integrity server',
                                  style: TextStyle(fontSize: 11),
                                ),
                                dense: true,
                                contentPadding: EdgeInsets.zero,
                              )
                            else if (_selectedOperation == 'decrypt')
                              CheckboxListTile(
                                value: _verifyIntegrity,
                                onChanged: (value) {
                                  setState(() {
                                    _verifyIntegrity = value ?? false;
                                  });
                                },
                                title: const Text(
                                  'Verify integrity before decryption',
                                  style: TextStyle(fontSize: 13),
                                ),
                                subtitle: const Text(
                                  'Check if file hashes match registered hashes',
                                  style: TextStyle(fontSize: 11),
                                ),
                                dense: true,
                                contentPadding: EdgeInsets.zero,
                              ),
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),

            const SizedBox(height: 16),

            // Action Button
            SizedBox(
              width: double.infinity,
              height: 48,
              child: ElevatedButton.icon(
                onPressed: _canStartOperation() ? _startBatchOperation : null,
                icon: _isLoading
                    ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                    : Icon(_selectedOperation == 'encrypt'
                        ? Icons.lock
                        : _selectedOperation == 'decrypt'
                          ? Icons.lock_open
                          : Icons.verified),
                label: _isLoading
                    ? Text('${_selectedOperation == 'encrypt' ? 'Encrypting' : _selectedOperation == 'decrypt' ? 'Decrypting' : 'Verifying'} (${_currentFileIndex + 1}/${_selectedFiles.length})')
                    : Text('${_selectedOperation == 'encrypt' ? 'Encrypt' : _selectedOperation == 'decrypt' ? 'Decrypt' : 'Verify Integrity of'} ${_selectedFiles.length} file(s)'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: _selectedOperation == 'encrypt'
                      ? Colors.green
                      : _selectedOperation == 'decrypt'
                        ? Colors.blue
                        : Colors.teal,
                  foregroundColor: Colors.white,
                ),
              ),
            ),

            // Progress Indicator
            if (_isLoading) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          const Icon(Icons.hourglass_empty),
                          const SizedBox(width: 8),
                          const Text('Progress', style: TextStyle(fontWeight: FontWeight.bold)),
                          const Spacer(),
                          Text('${_currentFileIndex + 1} of ${_selectedFiles.length}'),
                        ],
                      ),
                      const SizedBox(height: 8),
                      LinearProgressIndicator(
                        value: _selectedFiles.isEmpty ? 0 : (_currentFileIndex + 1) / _selectedFiles.length,
                      ),
                      if (_currentStatus.isNotEmpty) ...[
                        const SizedBox(height: 8),
                        Text(
                          _currentStatus,
                          style: TextStyle(
                            fontSize: 12,
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],

            // Results Section
            if (_results.isNotEmpty) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            Icons.assessment,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                          const SizedBox(width: 8),
                          const Text(
                            'Operation Results',
                            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                          ),
                          const Spacer(),
                          TextButton.icon(
                            onPressed: () {
                              setState(() {
                                _results.clear();
                              });
                            },
                            icon: const Icon(Icons.clear),
                            label: const Text('Clear'),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Container(
                        constraints: const BoxConstraints(maxHeight: 300),
                        child: RepaintBoundary(
                          child: ListView.builder(
                            shrinkWrap: true,
                            itemCount: _results.length,
                          itemBuilder: (context, index) {
                            final result = _results[index];
                            return Card(
                              margin: const EdgeInsets.symmetric(vertical: 2),
                              color: result.success ? Colors.green.withValues(alpha: 0.1) : Colors.red.withValues(alpha: 0.1),
                              child: ListTile(
                                dense: true,
                                leading: Icon(
                                  result.success ? Icons.check_circle : Icons.error,
                                  color: result.success ? Colors.green : Colors.red,
                                  size: 20,
                                ),
                                title: Text(
                                  result.fileName,
                                  style: const TextStyle(fontSize: 13),
                                ),
                                subtitle: Text(
                                  result.success ? 'Success' : (result.errorMessage ?? 'Unknown error'),
                                  style: TextStyle(
                                    fontSize: 11,
                                    color: result.success ? Colors.green.shade700 : Colors.red.shade700,
                                  ),
                                ),
                                trailing: result.success && result.outputPath != null
                                    ? IconButton(
                                        icon: const Icon(Icons.folder_open, size: 16),
                                        onPressed: () => _showInFileManager(result.outputPath!),
                                        tooltip: 'Show in file manager',
                                      )
                                    : null,
                              ),
                            );
                          },
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Row(
                        children: [
                          const Icon(
                            Icons.check_circle,
                            color: Colors.green,
                            size: 16,
                          ),
                          Text(
                            ' ${_results.where((r) => r.success).length} successful',
                            style: const TextStyle(fontSize: 12),
                          ),
                          const SizedBox(width: 16),
                          const Icon(
                            Icons.error,
                            color: Colors.red,
                            size: 16,
                          ),
                          Text(
                            ' ${_results.where((r) => !r.success).length} failed',
                            style: const TextStyle(fontSize: 12),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ],
      ),
    );
  }

  // Helper methods
  IconData _getFileIcon(String extension) {
    switch (extension.toLowerCase()) {
      case '.txt':
      case '.md':
        return Icons.description;
      case '.pdf':
        return Icons.picture_as_pdf;
      case '.jpg':
      case '.jpeg':
      case '.png':
      case '.gif':
        return Icons.image;
      case '.zip':
      case '.rar':
      case '.7z':
        return Icons.archive;
      case '.doc':
      case '.docx':
        return Icons.article;
      case '.enc':
        return Icons.lock;
      default:
        return Icons.insert_drive_file;
    }
  }

  Future<void> _selectFiles() async {
    try {
      final files = await widget.fileManager.pickMultipleFiles();
      setState(() {
        _selectedFiles = files;
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error selecting files: $e')),
        );
      }
    }
  }

  void _clearFiles() {
    setState(() {
      _selectedFiles.clear();
      _results.clear();
    });
  }

  void _removeFile(int index) {
    setState(() {
      _selectedFiles.removeAt(index);
    });
  }

  bool _canStartOperation() {
    if (_selectedFiles.isEmpty || _isLoading) {
      return false;
    }

    // Verify integrity doesn't need a password
    if (_selectedOperation == 'verify-integrity') {
      return true;
    }

    // Encrypt and decrypt operations need a password
    if (_password.isEmpty) {
      return false;
    }

    if (_selectedOperation == 'encrypt') {
      return _password == _confirmPassword;
    }

    return true;
  }

  Future<void> _startBatchOperation() async {
    setState(() {
      _isLoading = true;
      _currentFileIndex = 0;
      _results.clear();
    });

    try {
      for (int i = 0; i < _selectedFiles.length; i++) {
        setState(() {
          _currentFileIndex = i;
          _currentStatus = 'Processing ${_selectedFiles[i].name}...';
        });

        final result = await _processFile(_selectedFiles[i]);
        setState(() {
          _results.add(result);
        });

        // Small delay to show progress
        await Future.delayed(const Duration(milliseconds: 100));
      }
    } finally {
      setState(() {
        _isLoading = false;
        _currentStatus = 'Completed';
      });

      // Show summary
      final successful = _results.where((r) => r.success).length;
      final failed = _results.where((r) => !r.success).length;

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Batch operation completed: $successful successful, $failed failed'),
            backgroundColor: failed > 0 ? Colors.orange : Colors.green,
          ),
        );
      }
    }
  }

  Future<BatchOperationResult> _processFile(FileInfo file) async {
    try {
      if (_selectedOperation == 'encrypt') {
        // Read file content
        final content = await widget.fileManager.readFileText(file.path);
        if (content == null) {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Could not read file content',
          );
        }

        // Encrypt based on encryption mode
        String encrypted;
        if (_encryptionMode == EncryptionMode.asymmetric) {
          // Asymmetric encryption mode
          encrypted = await CLIService.encryptTextWithProgress(
            content,
            _password,
            'aes-256-gcm',
            null,
            null,
            forIdentities: _selectedRecipients,
            signWith: _signingIdentity,
            useKeyserver: _useKeyserver,
            enableIntegrity: _enableIntegrity,
          );
        } else if (_encryptionMode == EncryptionMode.cascade) {
          // Cascade encryption mode
          encrypted = await CLIService.encryptTextWithProgress(
            content,
            _password,
            'aes-256-gcm',
            null,
            null,
            cascadePreset: _cascadePreset != 'custom' ? _cascadePreset : null,
            cascadeAlgorithms: _cascadePreset == 'custom' ? _cascadeAlgorithms : null,
            cascadeHash: _cascadeHash,
            enableIntegrity: _enableIntegrity,
          );
        } else {
          // Symmetric encryption mode (default)
          encrypted = await CLIService.encryptTextWithProgress(
            content,
            _password,
            _selectedAlgorithm,
            null,
            null,
            encryptData: _isPostQuantumAlgorithm(_selectedAlgorithm) ? _selectedEncryptData : null,
            enableIntegrity: _enableIntegrity,
          );
        }

        // Save encrypted file
        final outputPath = widget.fileManager.getEncryptedFileName(file.path);
        final writeSuccess = await widget.fileManager.writeFileText(outputPath, encrypted);

        if (writeSuccess) {
          return BatchOperationResult(
            fileName: file.name,
            success: true,
            outputPath: outputPath,
          );
        } else {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Could not write encrypted file',
          );
        }
      } else if (_selectedOperation == 'decrypt') {
        // Decrypt operation
        final content = await widget.fileManager.readFileText(file.path);
        if (content == null) {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Could not read file content',
          );
        }

        // Decrypt based on encryption mode
        String decrypted;
        if (_encryptionMode == EncryptionMode.asymmetric) {
          // Asymmetric decryption mode
          decrypted = await CLIService.decryptTextWithProgress(
            content,
            _password,
            withKey: _decryptionIdentity,
            verifyFrom: _verifyFrom,
            skipVerification: _skipVerification,
            verifyIntegrity: _verifyIntegrity,
          );
        } else {
          // Symmetric/Cascade decryption mode (cascade is auto-detected from metadata)
          decrypted = await CLIService.decryptTextWithProgress(
            content,
            _password,
            verifyIntegrity: _verifyIntegrity,
          );
        }

        // Save decrypted file
        final outputPath = widget.fileManager.getDecryptedFileName(file.path);
        final writeSuccess = await widget.fileManager.writeFileText(outputPath, decrypted);

        if (writeSuccess) {
          return BatchOperationResult(
            fileName: file.name,
            success: true,
            outputPath: outputPath,
          );
        } else {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Could not write decrypted file',
          );
        }
      } else if (_selectedOperation == 'verify-integrity') {
        // Verify integrity operation
        final content = await widget.fileManager.readFileText(file.path);
        if (content == null) {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Could not read file content',
          );
        }

        // Parse the encrypted file to get metadata
        // The file format is typically: metadata:encrypted_data
        // We need to extract file ID and hash for verification
        try {
          // Try to decode as JSON first (newer format)
          final Map<String, dynamic> data = jsonDecode(content);
          final String? fileId = data['file_id'];
          final String? metadataHash = data['metadata_hash'];

          if (fileId != null && metadataHash != null) {
            final verified = await CLIService.verifyFileIntegrity(
              fileId: fileId,
              metadataHash: metadataHash,
            );

            if (verified) {
              return BatchOperationResult(
                fileName: file.name,
                success: true,
                outputPath: 'Integrity verified ✓',
              );
            } else {
              return BatchOperationResult(
                fileName: file.name,
                success: false,
                errorMessage: 'Integrity verification failed - hash mismatch',
              );
            }
          } else {
            return BatchOperationResult(
              fileName: file.name,
              success: false,
              errorMessage: 'File not registered with integrity server',
            );
          }
        } catch (e) {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Invalid encrypted file format or not registered: $e',
          );
        }
      } else {
        return BatchOperationResult(
          fileName: file.name,
          success: false,
          errorMessage: 'Unknown operation: $_selectedOperation',
        );
      }
    } catch (e) {
      return BatchOperationResult(
        fileName: file.name,
        success: false,
        errorMessage: e.toString(),
      );
    }
  }

  Future<void> _showInFileManager(String filePath) async {
    try {
      await Process.start('xdg-open', [path.dirname(filePath)], mode: ProcessStartMode.detached);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Could not open file manager: $e')),
        );
      }
    }
  }

  bool _isPostQuantumAlgorithm(String algorithm) {
    return algorithm.contains('ml-kem') ||
           algorithm.contains('kyber') ||
           algorithm.contains('hqc') ||
           algorithm.contains('mayo') ||
           algorithm.contains('cross');
  }

  List<String> _getNonPostQuantumAlgorithms() {
    return [
      'aes-gcm',
      'aes-gcm-siv',
      'aes-siv',
      'chacha20-poly1305',
      'xchacha20-poly1305',
    ];
  }
}

/// Result of a single file operation in batch processing
class BatchOperationResult {
  final String fileName;
  final bool success;
  final String? errorMessage;
  final String? outputPath;

  BatchOperationResult({
    required this.fileName,
    required this.success,
    this.errorMessage,
    this.outputPath,
  });
}
