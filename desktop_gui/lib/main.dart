import 'dart:async';
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
  final GlobalKey<_FileCryptoTabState> _fileCryptoTabKey = GlobalKey<_FileCryptoTabState>();
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

  void _copyToClipboard() {
    // TODO: Copy current result to clipboard
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Result copied to clipboard')),
    );
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
    final filePath = file.path;
    
    // Switch to file tab first
    setState(() {
      _selectedIndex = 1;
    });
    
    // Wait a moment for the tab to be created if needed
    await Future.delayed(const Duration(milliseconds: 50));
    
    // Attempt to load the file in FileCryptoTab
    final fileCryptoTabState = _fileCryptoTabKey.currentState;
    if (fileCryptoTabState != null) {
      final success = await fileCryptoTabState.loadFileFromPath(filePath);
      
      if (success) {
        // Show success feedback
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('File loaded: ${file.name}'),
              duration: const Duration(seconds: 2),
              backgroundColor: Colors.green,
            ),
          );
        }
      } else {
        // Show error feedback
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to load file: ${file.name}'),
              duration: const Duration(seconds: 3),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } else {
      // Tab state not available, show fallback message
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Please wait and try dropping the file again'),
            duration: Duration(seconds: 2),
            backgroundColor: Colors.orange,
          ),
        );
      }
    }
  }

  Widget _getSelectedPage() {
    switch (_selectedIndex) {
      case 0:
        return TextCryptoTab(onDebugChanged: widget.onDebugChanged, onToggleDebugWindow: _toggleDebugWindow);
      case 1:
        return FileCryptoTab(key: _fileCryptoTabKey, fileManager: _fileManager, onDebugChanged: widget.onDebugChanged);
      case 2:
        return BatchOperationsTab(fileManager: _fileManager, onDebugChanged: widget.onDebugChanged);
      case 3:
        return const InfoTab();
      case 4:
        return SettingsTab(onThemeChanged: widget.onThemeChanged);
      default:
        return TextCryptoTab(onDebugChanged: widget.onDebugChanged, onToggleDebugWindow: _toggleDebugWindow);
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
                icon: Icon(Icons.text_fields_outlined),
                selectedIcon: Icon(Icons.text_fields),
                label: Text('Text Encryption'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.folder_outlined),
                selectedIcon: Icon(Icons.folder),
                label: Text('File Encryption'),
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

// Text encryption/decryption tab
class TextCryptoTab extends StatefulWidget {
  final Function(bool) onDebugChanged;
  final VoidCallback? onToggleDebugWindow;

  const TextCryptoTab({super.key, required this.onDebugChanged, this.onToggleDebugWindow});

  @override
  State<TextCryptoTab> createState() => _TextCryptoTabState();
}

class _TextCryptoTabState extends State<TextCryptoTab> {
  final TextEditingController _textController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  String _result = '';
  String _encryptedData = '';
  bool _isLoading = false;
  String _operationStatus = '';
  String _operationProgress = '';
  double _progressValue = 0.0;
  List<String> _algorithms = [];
  List<String> _hashAlgorithms = [];
  // Note: KDF algorithms and security levels are configured directly in _kdfConfig
  String _selectedAlgorithm = 'fernet';
  Map<String, Map<String, dynamic>> _hashConfig = {};  // Hash algorithm -> {enabled, rounds} mapping
  Map<String, Map<String, dynamic>> _kdfConfig = {};  // KDF chain configuration
  bool _showAdvanced = false;
  
  // Performance optimization caches
  static bool _algorithmsLoaded = false;
  static List<String>? _cachedAlgorithms;
  static List<String>? _cachedHashAlgorithms;
  
  bool _showHashConfig = false;
  bool _showKdfConfig = false;
  bool _debugLogging = false;

  @override
  void initState() {
    super.initState();
    _loadAlgorithms();
  }

  @override
  void dispose() {
    _textController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  /// Check if algorithm is available on current platform
  bool _isAlgorithmAvailable(String algorithm) {
    const Set<String> pythonOnlyAlgorithms = {
      'aes-siv',
      'aes-gcm-siv', 
      'aes-ocb3',
    };
    
    // These algorithms were only available with Python backend, now unavailable
    if (pythonOnlyAlgorithms.contains(algorithm)) {
      return false;
    }
    return true;
  }

  void _loadAlgorithms() async {
    // Performance optimization: Use static cache to avoid reloading
    if (_algorithmsLoaded && _cachedAlgorithms != null && _cachedHashAlgorithms != null) {
      setState(() {
        _algorithms = _cachedAlgorithms!;
        _hashAlgorithms = _cachedHashAlgorithms!;
      });
      return;
    }
    
    // Early return if already loaded in this instance
    if (_algorithms.isNotEmpty) return;
    
    try {
      final algorithmCategories = await CLIService.getSupportedAlgorithms();
      final hashCategories = await CLIService.getHashAlgorithms();
      
      // Store both flat and categorized versions
      final algorithms = <String>[];
      for (final category in algorithmCategories.values) {
        algorithms.addAll(category);
      }
      
      final hashAlgorithms = <String>[];
      for (final category in hashCategories.values) {
        hashAlgorithms.addAll(category);
      }
      // KDF algorithms are handled directly in _kdfConfig initialization
      
      setState(() {
        _algorithms = algorithms;
        _hashAlgorithms = hashAlgorithms;
        
        if (algorithms.isNotEmpty) {
          _selectedAlgorithm = algorithms.first;
        }
        if (hashAlgorithms.isNotEmpty) {
          // Initialize hash configuration with default values (CLI order)
          _hashConfig = {};
          for (String hash in hashAlgorithms) {
            _hashConfig[hash] = {
              'enabled': true,  // All hash functions enabled with CLI integration
              'rounds': 1000    // Default rounds for all hash functions (CLI supports all)
            };
          }
        }
        // Initialize KDF chain configuration (CLI order)
        _kdfConfig = {
          'pbkdf2': {'enabled': !CLIService.shouldHideLegacyAlgorithms(), 'rounds': 100000},
          'scrypt': {'enabled': false, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
          'argon2': {'enabled': false, 'memory_cost': 65536, 'time_cost': 3, 'parallelism': 1, 'rounds': 1},
          'hkdf': {'enabled': false, 'info': 'openssl_encrypt_hkdf', 'rounds': 1},
          'balloon': {'enabled': false, 'space_cost': 8, 'time_cost': 1, 'parallel_cost': 1, 'rounds': 1}
        };
      });
      
      // Cache the results for future use
      _cachedAlgorithms = algorithms;
      _cachedHashAlgorithms = hashAlgorithms;
      _algorithmsLoaded = true;
    } catch (e) {
      setState(() {
        _algorithms = ['fernet'];
        _hashAlgorithms = ['sha256'];
        _selectedAlgorithm = 'fernet';
        _hashConfig = {'sha256': {'enabled': true, 'rounds': 1000}};
        _kdfConfig = {
          'pbkdf2': {'enabled': !CLIService.shouldHideLegacyAlgorithms(), 'rounds': 100000},
          'hkdf': {'enabled': false, 'info': 'openssl_encrypt_hkdf', 'rounds': 1}
        };
      });
    }
  }

  void _encryptText() async {
    if (_textController.text.isEmpty || _passwordController.text.isEmpty) {
      setState(() {
        _result = 'Please enter both text and password';
      });
      return;
    }

    // Check if selected algorithm is available on current platform
    if (!_isAlgorithmAvailable(_selectedAlgorithm)) {
      setState(() {
        _result = 'Error: $_selectedAlgorithm is not available. This algorithm required the Python cryptography backend which has been removed in favor of pure Dart implementation.';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _operationStatus = 'Encrypting data...';
      _operationProgress = '';
      _progressValue = 0.0;
      _result = 'Encrypting...';
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      // Pass selected algorithm and UI configurations to CLI service with progress
      final encrypted = await CLIService.encryptTextWithProgress(
        _textController.text,
        _passwordController.text,
        _selectedAlgorithm, // Pass the selected algorithm
        _hashConfig,        // Pass hash configuration from UI
        _kdfConfig,         // Pass KDF configuration from UI
        onProgress: (progress) {
          setState(() {
            _operationProgress = progress;
          });
        },
        onStatus: (status) {
          setState(() {
            _operationStatus = status;
            // Update progress based on status
            if (status.contains('Initializing')) {
              _progressValue = 0.2;
            } else if (status.contains('Prepared')) {
              _progressValue = 0.4;
            } else if (status.contains('Executing')) {
              _progressValue = 0.7;
            } else if (status.contains('Reading')) {
              _progressValue = 0.9;
            } else if (status.contains('completed')) {
              _progressValue = 1.0;
            }
          });
        },
      );

      setState(() {
        _encryptedData = encrypted;
        _result = encrypted; // Show only the base64 encoded string
        _isLoading = false;
        _operationStatus = '';
        _operationProgress = '';
        _progressValue = 0.0;
      });
    } catch (e) {
      setState(() {
        _result = 'Encryption failed: $e';
        _isLoading = false;
        _operationStatus = '';
        _operationProgress = '';
        _progressValue = 0.0;
      });
    }
  }

  void _decryptText() async {
    // Use encrypted data from previous encryption, or from input field if user pasted encrypted data
    final inputData = _encryptedData.isEmpty ? _textController.text.trim() : _encryptedData;
    
    if (inputData.isEmpty || _passwordController.text.isEmpty) {
      setState(() {
        _result = 'Please encrypt some text first, paste encrypted data in the text field, or enter the password';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _operationStatus = 'Decrypting data...';
      _operationProgress = '';
      _progressValue = 0.0;
      _result = 'Decrypting...';
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      final decrypted = await CLIService.decryptTextWithProgress(
        inputData,
        _passwordController.text,
        onProgress: (progress) {
          setState(() {
            _operationProgress = progress;
          });
        },
        onStatus: (status) {
          setState(() {
            _operationStatus = status;
            // Update progress based on status
            if (status.contains('Initializing')) {
              _progressValue = 0.2;
            } else if (status.contains('Prepared')) {
              _progressValue = 0.4;
            } else if (status.contains('Executing')) {
              _progressValue = 0.7;
            } else if (status.contains('Reading')) {
              _progressValue = 0.9;
            } else if (status.contains('completed')) {
              _progressValue = 1.0;
            }
          });
        },
      );

      setState(() {
        _result = decrypted; // Show only the decrypted text
        _isLoading = false;
        _operationStatus = '';
        _operationProgress = '';
        _progressValue = 0.0;
      });
    } catch (e) {
      setState(() {
        _result = 'Decryption failed: $e';
        _isLoading = false;
        _operationStatus = '';
        _operationProgress = '';
        _progressValue = 0.0;
      });
    }
  }

  void _showCommandPreview() {
    final inputText = _textController.text.trim();
    final password = _passwordController.text.trim();
    
    if (inputText.isEmpty && password.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter text and password to preview command'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }
    
    // Show command preview dialog
    showDialog(
      context: context,
      builder: (context) => CommandPreviewDialog(
        algorithm: _selectedAlgorithm,
        hashConfig: _hashConfig,
        kdfConfig: _kdfConfig,
        password: password,
        inputText: inputText,
      ),
    );
  }

  void _openLogFile() {
    final logFile = CLIService.getDebugLogFile();
    if (logFile != null) {
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Debug Log File Location'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Debug log file saved to:'),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainer,
                  border: Border.all(color: Theme.of(context).colorScheme.outline),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: SelectableText(
                  logFile,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
              const SizedBox(height: 12),
              Text(
                'You can send this file to the developer for troubleshooting.',
                style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Close'),
            ),
          ],
        ),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No log file available')),
      );
    }
  }


  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: _textController,
              decoration: const InputDecoration(
                labelText: 'Text to encrypt',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.text_fields),
            ),
            maxLines: 3,
          ),
          const SizedBox(height: 16),
          // Advanced Algorithm Selection
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.security),
                      const SizedBox(width: 8),
                      const Text('Encryption Algorithm', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                      const Spacer(),
                      IconButton(
                        icon: const Icon(Icons.info_outline),
                        onPressed: () => _showAlgorithmInfo(context),
                        tooltip: 'Algorithm Information',
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      border: Border.all(color: Theme.of(context).colorScheme.primary),
                      borderRadius: BorderRadius.circular(8),
                      color: Theme.of(context).colorScheme.primaryContainer,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(Icons.check_circle, color: Theme.of(context).colorScheme.primary, size: 20),
                            const SizedBox(width: 8),
                            Text(
                              'Selected: $_selectedAlgorithm',
                              style: TextStyle(fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _getAlgorithmDescription(_selectedAlgorithm),
                          style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.primary),
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            ElevatedButton.icon(
                              onPressed: () => _showAlgorithmPicker(),
                              icon: const Icon(Icons.tune, size: 16),
                              label: const Text('Choose Algorithm'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                                foregroundColor: Theme.of(context).colorScheme.onPrimaryContainer,
                              ),
                            ),
                            const SizedBox(width: 8),
                            ElevatedButton.icon(
                              onPressed: () => _showRecommendationWizard(),
                              icon: const Icon(Icons.auto_awesome, size: 16),
                              label: const Text('Get Recommendations'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.green.withValues(alpha: 0.2),
                                foregroundColor: Colors.green.shade700,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          // Advanced Settings Toggle
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12.0),
              child: Column(
                children: [
                  InkWell(
                    onTap: () {
                      setState(() {
                        _showAdvanced = !_showAdvanced;
                      });
                    },
                    child: Row(
                      children: [
                        Icon(_showAdvanced ? Icons.expand_less : Icons.expand_more),
                        const SizedBox(width: 8),
                        const Expanded(
                          child: Text(
                            'Advanced Security Settings (CLI Compatible)',
                            style: TextStyle(fontSize: 14),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Icon(_showAdvanced ? Icons.security : Icons.tune),
                      ],
                    ),
                  ),
                  if (_showAdvanced) ...[
                    const SizedBox(height: 16),
                    // Hash Chain Configuration
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(12.0),
                        child: Column(
                          children: [
                            InkWell(
                              onTap: () {
                                setState(() {
                                  _showHashConfig = !_showHashConfig;
                                });
                              },
                              child: Row(
                                children: [
                                  Icon(_showHashConfig ? Icons.expand_less : Icons.expand_more),
                                  const SizedBox(width: 8),
                                  const Text('Hash Chain Configuration'),
                                  const Spacer(),
                                  const Icon(Icons.link),
                                ],
                              ),
                            ),
                            if (_showHashConfig) ...[ 
                              const SizedBox(height: 12),
                              Text(
                                'Configure hash algorithms and rounds (CLI order)',
                                style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
                              ),
                              const SizedBox(height: 12),
                              ..._hashAlgorithms.map((hash) {
                                return Padding(
                                  padding: const EdgeInsets.only(bottom: 8.0),
                                  child: _buildHashConfig(hash, hash),
                                );
                              }),
                              const SizedBox(height: 8),
                              Wrap(
                                spacing: 8,
                                runSpacing: 8,
                                alignment: WrapAlignment.center,
                                children: [
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String hash in _hashAlgorithms) {
                                          // All algorithms now supported with CLI integration
                                          _hashConfig[hash] = {
                                            'enabled': true, 
                                            'rounds': 1000
                                          };
                                        }
                                      });
                                    },
                                    child: const Text('Enable All', style: TextStyle(fontSize: 12)),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String hash in _hashAlgorithms) {
                                          if (_hashConfig[hash] != null) {
                                            _hashConfig[hash]!['enabled'] = false;
                                          }
                                        }
                                      });
                                    },
                                    child: const Text('Disable All', style: TextStyle(fontSize: 12)),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String hash in _hashAlgorithms) {
                                          // All algorithms now supported with CLI integration
                                          _hashConfig[hash] = {
                                            'enabled': false,
                                            'rounds': 1000
                                          };
                                        }
                                      });
                                    },
                                    child: const Text('Reset (1000)', style: TextStyle(fontSize: 12)),
                                  ),
                                ],
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    // KDF Chain Configuration
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(12.0),
                        child: Column(
                          children: [
                            InkWell(
                              onTap: () {
                                setState(() {
                                  _showKdfConfig = !_showKdfConfig;
                                });
                              },
                              child: Row(
                                children: [
                                  Icon(_showKdfConfig ? Icons.expand_less : Icons.expand_more),
                                  const SizedBox(width: 8),
                                  const Text('KDF Chain Configuration'),
                                  const Spacer(),
                                  const Icon(Icons.vpn_key),
                                ],
                              ),
                            ),
                            if (_showKdfConfig) ...[
                              const SizedBox(height: 12),
                              Row(
                                children: [
                                  Text(
                                    'Professional Key Derivation Configuration',
                                    style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
                                  ),
                                  const Spacer(),
                                  IconButton(
                                    icon: const Icon(Icons.info_outline, size: 16),
                                    onPressed: () => _showKDFInfo(),
                                    tooltip: 'KDF Information',
                                  ),
                                ],
                              ),
                              const SizedBox(height: 12),
                              
                              // PBKDF2 Panel (hidden in CLI v1.2+)
                              if (!CLIService.shouldHideLegacyAlgorithms()) ...[
                                _buildPBKDF2Panel(),
                                const SizedBox(height: 8),
                              ],
                              
                              // Argon2 Panel  
                              _buildArgon2Panel(),
                              const SizedBox(height: 8),
                              
                              // Scrypt Panel
                              _buildScryptPanel(),
                              const SizedBox(height: 8),
                              
                              // HKDF Panel
                              _buildHKDFPanel(),
                              const SizedBox(height: 8),
                              
                              // Balloon Panel
                              _buildBalloonPanel(),
                              const SizedBox(height: 8),
                              // Quick presets
                              Wrap(
                                spacing: 8,
                                runSpacing: 8,
                                alignment: WrapAlignment.center,
                                children: [
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        if (!CLIService.shouldHideLegacyAlgorithms()) {
                                          _kdfConfig['pbkdf2']?['enabled'] = true;
                                        }
                                        _kdfConfig['scrypt']?['enabled'] = false;
                                        _kdfConfig['argon2']?['enabled'] = false;
                                        _kdfConfig['hkdf']?['enabled'] = false;
                                        _kdfConfig['balloon']?['enabled'] = false;
                                      });
                                    },
                                    child: const Text('PBKDF2 Only', style: TextStyle(fontSize: 12)),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        _kdfConfig['pbkdf2']?['enabled'] = false;
                                        _kdfConfig['pbkdf2']?['rounds'] = 0; // Set rounds to 0 when disabled
                                        _kdfConfig['scrypt']?['enabled'] = false;
                                        _kdfConfig['argon2']?['enabled'] = false;
                                        _kdfConfig['hkdf']?['enabled'] = false;
                                        _kdfConfig['balloon']?['enabled'] = true;
                                      });
                                    },
                                    child: const Text('Balloon Only', style: TextStyle(fontSize: 12)),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String kdf in _kdfConfig.keys) {
                                          _kdfConfig[kdf]?['enabled'] = false;
                                          // Special case for PBKDF2: set rounds to 0 when disabled
                                          if (kdf == 'pbkdf2') {
                                            _kdfConfig[kdf]?['rounds'] = 0;
                                          }
                                        }
                                      });
                                    },
                                    child: const Text('Disable All', style: TextStyle(fontSize: 12)),
                                  ),
                                ],
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                  ],
                  
                  // Debug Logging Toggle
                  const SizedBox(height: 16),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(12.0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Icon(
                                _debugLogging ? Icons.bug_report : Icons.bug_report_outlined,
                                color: _debugLogging ? Colors.orange : Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                              const SizedBox(width: 8),
                              const Expanded(
                                child: Text(
                                  'Debug Logging',
                                  style: TextStyle(fontWeight: FontWeight.bold),
                                ),
                              ),
                              Switch(
                                value: _debugLogging,
                                onChanged: (bool value) async {
                                  setState(() {
                                    _debugLogging = value;
                                    // Update debug banner visibility
                                    widget.onDebugChanged(value);
                                  });
                                  
                                  // Enable/disable debug logging with file initialization
                                  if (value) {
                                    await CLIService.enableDebugLogging();
                                  } else {
                                    CLIService.disableDebugLogging();
                                  }
                                },
                              ),
                            ],
                          ),
                          const SizedBox(height: 8),
                          Text(
                            _debugLogging 
                              ? '🟢 Debug logging enabled - logs captured in-app and saved to file' 
                              : '🔲 Debug logging disabled - only basic status messages',
                            style: TextStyle(
                              fontSize: 12,
                              color: _debugLogging ? Colors.orange.shade700 : Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                          ),
                          if (_debugLogging) ...[
                            const SizedBox(height: 8),
                            Row(
                              children: [
                                Expanded(
                                  child: Text(
                                    'Debug logs are being captured',
                                    style: TextStyle(
                                      fontSize: 10,
                                      color: Colors.orange.shade600,
                                      fontFamily: 'monospace',
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                ElevatedButton.icon(
                                  onPressed: widget.onToggleDebugWindow,
                                  icon: const Icon(Icons.visibility, size: 16),
                                  label: const Text('View Logs'),
                                  style: ElevatedButton.styleFrom(
                                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                    minimumSize: const Size(0, 28),
                                  ),
                                ),
                                const SizedBox(width: 4),
                                ElevatedButton.icon(
                                  onPressed: _openLogFile,
                                  icon: const Icon(Icons.folder_open, size: 16),
                                  label: const Text('Open File'),
                                  style: ElevatedButton.styleFrom(
                                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                    minimumSize: const Size(0, 28),
                                  ),
                                ),
                              ],
                            ),
                          ],
                          if (_debugLogging) ...[
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: Theme.of(context).colorScheme.errorContainer,
                                borderRadius: BorderRadius.circular(4),
                                border: Border.all(color: Theme.of(context).colorScheme.error),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    children: [
                                      Icon(Icons.warning, size: 16, color: Theme.of(context).colorScheme.error),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Text(
                                          'SECURITY WARNING',
                                          style: TextStyle(
                                            fontSize: 12,
                                            fontWeight: FontWeight.bold,
                                            color: Theme.of(context).colorScheme.error,
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    'Debug logs may contain sensitive information including passwords, keys, and decrypted content. Only use with test files and non-sensitive data. Never share debug logs containing real passwords or personal data.',
                                    style: TextStyle(
                                      fontSize: 11,
                                      color: Theme.of(context).colorScheme.error,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _passwordController,
            decoration: const InputDecoration(
              labelText: 'Password',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.lock),
            ),
            obscureText: true,
          ),
          const SizedBox(height: 16),
          if (_isLoading)
            Card(
              color: Theme.of(context).colorScheme.tertiaryContainer,
              elevation: 8,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    // Progress bar
                    LinearProgressIndicator(
                      value: _progressValue,
                      backgroundColor: Theme.of(context).colorScheme.surfaceContainer,
                      valueColor: AlwaysStoppedAnimation<Color>(Theme.of(context).colorScheme.primary),
                    ),
                    const SizedBox(height: 12),
                    // Circular progress indicator
                    CircularProgressIndicator(color: Theme.of(context).colorScheme.primary),
                    const SizedBox(height: 12),
                    // Operation status
                    Text(
                      _operationStatus.isNotEmpty ? _operationStatus : 'Crypto operation in progress...',
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.onTertiaryContainer),
                      textAlign: TextAlign.center,
                    ),
                    // CLI progress output
                    if (_operationProgress.isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(8.0),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.tertiaryContainer,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: Theme.of(context).colorScheme.outline),
                        ),
                        child: Text(
                          _operationProgress,
                          style: TextStyle(
                            fontSize: 12,
                            fontFamily: 'monospace',
                            color: Theme.of(context).colorScheme.onTertiaryContainer,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ],
                    // Progress percentage
                    if (_progressValue > 0) ...[
                      const SizedBox(height: 8),
                      Text(
                        '${(_progressValue * 100).toInt()}%',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                          color: Theme.of(context).colorScheme.onTertiaryContainer,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          if (_isLoading)
            const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _encryptText,
                  icon: const Icon(Icons.lock),
                  label: const Text('Encrypt'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _decryptText,
                  icon: const Icon(Icons.lock_open),
                  label: const Text('Decrypt'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              onPressed: _isLoading ? null : _showCommandPreview,
              icon: const Icon(Icons.code, size: 16),
              label: const Text('Preview CLI Command'),
              style: OutlinedButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.primary,
                side: BorderSide(color: Theme.of(context).colorScheme.outline),
              ),
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: Stack(
              children: [
                Container(
                  width: double.infinity,
                  height: 200,
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    border: Border.all(color: Theme.of(context).colorScheme.outline),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: SingleChildScrollView(
                    child: SelectableText(
                      _result.isEmpty ? 'Results will appear here...' : _result,
                      style: const TextStyle(fontFamily: 'monospace'),
                    ),
                  ),
                ),
              if (_result.isNotEmpty)
                Positioned(
                  top: 8,
                  right: 8,
                  child: FloatingActionButton.small(
                    heroTag: "copy_text_result",
                    onPressed: () async {
                      await Clipboard.setData(ClipboardData(text: _result));
                      if (mounted) {
                        // ignore: use_build_context_synchronously
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Result copied to clipboard'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      }
                    },
                    backgroundColor: Theme.of(context).colorScheme.primary,
                    child: Icon(Icons.copy, size: 16, color: Theme.of(context).colorScheme.onPrimary),
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

  // Helper method to build KDF configuration sections
  // ignore: unused_element
  Widget _buildKdfConfig(String kdfId, String kdfName, List<Widget> paramFields) {
    final isEnabled = _kdfConfig[kdfId]?['enabled'] ?? false;
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(color: isEnabled ? Colors.green : Theme.of(context).colorScheme.outline),
        borderRadius: BorderRadius.circular(8),
        color: isEnabled ? Colors.green.withValues(alpha: 0.1) : Theme.of(context).colorScheme.surfaceContainer,
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: isEnabled,
                onChanged: (bool? value) {
                  setState(() {
                    if (_kdfConfig[kdfId] == null) {
                      _kdfConfig[kdfId] = {};
                    }
                    _kdfConfig[kdfId]!['enabled'] = value;
                    
                    // Special case for PBKDF2: set rounds to 0 when disabled
                    // This ensures CLI compatibility (CLI uses rounds > 0 for enablement)
                    if (kdfId == 'pbkdf2' && !(value ?? false)) {
                      _kdfConfig[kdfId]!['rounds'] = 0;
                    } else if (kdfId == 'pbkdf2' && (value ?? false)) {
                      // When re-enabling PBKDF2, restore default rounds
                      _kdfConfig[kdfId]!['rounds'] = 100000;
                    }
                  });
                },
              ),
              const SizedBox(width: 8),
              Text(
                kdfName,
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: isEnabled ? Colors.green.shade700 : Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
          if (isEnabled) ...paramFields,
        ],
      ),
    );
  }

  // Helper method to build hash configuration sections
  Widget _buildHashConfig(String hashId, String hashName) {
    final isEnabled = _hashConfig[hashId]?['enabled'] ?? false;
    final rounds = _hashConfig[hashId]?['rounds'] ?? 1000;
    
    // All hash functions now supported with CLI integration
    final effectiveEnabled = isEnabled;
    
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(color: effectiveEnabled ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.outline),
        borderRadius: BorderRadius.circular(8),
        color: effectiveEnabled ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: effectiveEnabled,
                onChanged: (bool? value) {
                  setState(() {
                    if (_hashConfig[hashId] == null) {
                      _hashConfig[hashId] = {'rounds': 1000};
                    }
                    _hashConfig[hashId]!['enabled'] = value;
                  });
                },
              ),
              const SizedBox(width: 8),
              SizedBox(
                width: 80,
                child: Text(
                  hashName.toUpperCase(),
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                    color: effectiveEnabled ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              if (effectiveEnabled)
                Expanded(
                  child: _buildHashRoundsSlider(
                    hashId,
                    rounds,
                    (int newRounds) {
                      setState(() {
                        _hashConfig[hashId]!['rounds'] = newRounds;
                      });
                    },
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  // Helper method to build number input fields  
  // ignore: unused_element
  Widget _buildNumberField(String kdfId, String paramId, String label, int defaultValue) {
    return Padding(
      padding: const EdgeInsets.only(top: 8.0),
      child: TextFormField(
        initialValue: defaultValue.toString(),
        keyboardType: TextInputType.number,
        decoration: InputDecoration(
          labelText: label,
          isDense: true,
          border: const OutlineInputBorder(),
        ),
        onChanged: (value) {
          final numValue = int.tryParse(value) ?? defaultValue;
          setState(() {
            _kdfConfig[kdfId] ??= {};
            _kdfConfig[kdfId]![paramId] = numValue;
          });
        },
      ),
    );
  }

  // Helper method to build text input fields
  
  /// Get detailed description for algorithm
  String _getAlgorithmDescription(String algorithm) {
    final descriptions = {
      // Classical Symmetric
      'fernet': 'AES-128-CBC with HMAC authentication - Python-compatible standard (Recommended for general use)',
      'aes-gcm': 'AES-256-GCM authenticated encryption - High performance, military-grade',
      'chacha20-poly1305': 'ChaCha20 stream cipher with Poly1305 MAC - Modern, fast, secure',
      'xchacha20-poly1305': 'Extended ChaCha20 with 192-bit nonce - Enhanced security for large files',
      'aes-siv': 'AES-SIV synthetic IV mode - Misuse-resistant encryption',
      'aes-gcm-siv': 'AES-GCM-SIV - Combines speed of GCM with misuse resistance',
      'aes-ocb3': 'AES-OCB3 high-performance authenticated encryption',
      'camellia': 'Camellia block cipher - International standard, alternative to AES',
      
      // Post-Quantum ML-KEM
      'ml-kem-512-hybrid': 'ML-KEM-512 hybrid - Post-quantum with 128-bit classical security',
      'ml-kem-768-hybrid': 'ML-KEM-768 hybrid - Post-quantum with 192-bit classical security (Recommended PQC)',
      'ml-kem-1024-hybrid': 'ML-KEM-1024 hybrid - Post-quantum with 256-bit classical security',
      
      // Post-Quantum Kyber Legacy  
      'kyber512-hybrid': 'Kyber-512 hybrid - Legacy PQC algorithm, use ML-KEM instead',
      'kyber768-hybrid': 'Kyber-768 hybrid - Legacy PQC algorithm, use ML-KEM instead',
      'kyber1024-hybrid': 'Kyber-1024 hybrid - Legacy PQC algorithm, use ML-KEM instead',
      
      // Post-Quantum ChaCha20
      'ml-kem-512-chacha20': 'ML-KEM-512 + ChaCha20 - Post-quantum with stream cipher',
      'ml-kem-768-chacha20': 'ML-KEM-768 + ChaCha20 - Post-quantum with stream cipher',  
      'ml-kem-1024-chacha20': 'ML-KEM-1024 + ChaCha20 - Post-quantum with stream cipher',
      
      // Post-Quantum HQC
      'hqc-128-hybrid': 'HQC-128 hybrid - Alternative post-quantum KEM (128-bit security)',
      'hqc-192-hybrid': 'HQC-192 hybrid - Alternative post-quantum KEM (192-bit security)',
      'hqc-256-hybrid': 'HQC-256 hybrid - Alternative post-quantum KEM (256-bit security)',
      
      // Post-Quantum Signatures
      'mayo-1-hybrid': 'MAYO-1 hybrid - Post-quantum signatures (128-bit security)',
      'mayo-3-hybrid': 'MAYO-3 hybrid - Post-quantum signatures (192-bit security)',
      'mayo-5-hybrid': 'MAYO-5 hybrid - Post-quantum signatures (256-bit security)',
      'cross-128-hybrid': 'CROSS-128 hybrid - Post-quantum signatures (128-bit security)',
      'cross-192-hybrid': 'CROSS-192 hybrid - Post-quantum signatures (192-bit security)',
      'cross-256-hybrid': 'CROSS-256 hybrid - Post-quantum signatures (256-bit security)',
    };
    
    return descriptions[algorithm] ?? 'Advanced encryption algorithm - see CLI documentation for details';
  }
  
  /// Show algorithm picker dialog
  void _showAlgorithmPicker() async {
    final algorithmCategories = await CLIService.getSupportedAlgorithms();
    
    if (!mounted) return;
    
    final selectedAlgorithm = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Choose Encryption Algorithm'),
        content: SizedBox(
          width: double.maxFinite,
          height: 600,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Select an encryption algorithm. Post-quantum algorithms provide protection against quantum computers.',
                  style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
                ),
                const SizedBox(height: 16),
                ...algorithmCategories.entries.map((entry) {
                  final category = entry.key;
                  final algorithms = entry.value;
                  
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Text(
                          category,
                          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                        ),
                      ),
                      ...algorithms.map((algorithm) {
                        final isSelected = algorithm == _selectedAlgorithm;
                        final isPostQuantum = category.contains('Post-Quantum');
                        
                        return Card(
                          color: isSelected ? Theme.of(context).colorScheme.primaryContainer : null,
                          child: ListTile(
                            leading: Icon(
                              isPostQuantum ? Icons.science : Icons.security,
                              color: isPostQuantum ? Colors.purple : Theme.of(context).colorScheme.primary,
                            ),
                            title: Row(
                              children: [
                                Text(
                                  algorithm,
                                  style: TextStyle(
                                    fontWeight: isSelected ? FontWeight.bold : null,
                                  ),
                                ),
                                if (isPostQuantum) ...[
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: Colors.purple,
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: const Text(
                                      'PQC',
                                      style: TextStyle(color: Colors.white, fontSize: 10),
                                    ),
                                  ),
                                ],
                                if (algorithm == 'fernet' || algorithm == 'ml-kem-768-hybrid') ...[
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: Colors.green,
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: const Text(
                                      'RECOMMENDED',
                                      style: TextStyle(color: Colors.white, fontSize: 10),
                                    ),
                                  ),
                                ],
                              ],
                            ),
                            subtitle: Text(
                              _getAlgorithmDescription(algorithm),
                              style: TextStyle(fontSize: 11, color: Theme.of(context).colorScheme.onSurfaceVariant),
                            ),
                            trailing: isSelected ? Icon(Icons.check_circle, color: Theme.of(context).colorScheme.primary) : null,
                            onTap: () => Navigator.of(context).pop(algorithm),
                          ),
                        );
                      }),
                      const SizedBox(height: 12),
                    ],
                  );
                }),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
    
    if (selectedAlgorithm != null) {
      setState(() {
        _selectedAlgorithm = selectedAlgorithm;
      });
    }
  }
  
  /// Show algorithm info dialog - redirects to info tab  
  void _showAlgorithmInfo(BuildContext context) {
    // This method is called from the menu, but we want to show the picker instead
    _showAlgorithmPicker();
  }
  
  /// Get hash function description
  // ignore: unused_element
  String _getHashDescription(String hashName) {
    final descriptions = {
      // SHA-2 Family
      'sha224': 'SHA-224 - Truncated SHA-256, good for legacy compatibility',
      'sha256': 'SHA-256 - Most common secure hash, excellent balance of speed and security',
      'sha384': 'SHA-384 - Truncated SHA-512, good for high-security applications',
      'sha512': 'SHA-512 - Large output hash, maximum traditional security',
      
      // SHA-3 Family
      'sha3-224': 'SHA-3-224 - New generation hash with different design from SHA-2',
      'sha3-256': 'SHA-3-256 - Alternative to SHA-256 with different security properties',
      'sha3-384': 'SHA-3-384 - Alternative to SHA-384 with sponge construction',
      'sha3-512': 'SHA-3-512 - Alternative to SHA-512 with sponge construction',
      
      // SHAKE Functions
      'shake128': 'SHAKE-128 - Extendable-output function, configurable length',
      'shake256': 'SHAKE-256 - Extendable-output function, higher security level',
      
      // Modern Hash Functions
      'blake2b': 'BLAKE2b - Ultra-fast cryptographic hash, faster than MD5 but secure',
      'blake3': 'BLAKE3 - Newest generation hash, extremely fast with tree structure',
      
      // Legacy Hash Functions
      'whirlpool': 'Whirlpool - ISO standard hash, mainly for specialized applications',
    };
    
    return descriptions[hashName] ?? 'Cryptographic hash function';
  }
  
  /// Get maximum recommended rounds for hash function
  int _getMaxRounds(String hashName) {
    // Hash functions use maximum of 1,000,000 rounds but with better precision control
    return 1000000;
  }

  /// Build an auto-repeat button that continues action when held down
  Widget _buildAutoRepeatButton({
    required IconData icon,
    required MaterialColor color,
    required bool enabled,
    required VoidCallback onAction,
    double size = 32,
    double iconSize = 16,
  }) {
    return AutoRepeatButton(
      icon: icon,
      color: color,
      enabled: enabled,
      onAction: onAction,
      size: size,
      iconSize: iconSize,
    );
  }
  
  /// Show hash information dialog
  // ignore: unused_element
  void _showHashInfo() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Hash Functions Guide'),
        content: const SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('🔰 Recommended for most users:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• SHA-256: Standard, well-tested, universal compatibility'),
              Text('• BLAKE2b: Modern, extremely fast, excellent security'),
              SizedBox(height: 12),
              Text('🚀 Modern high-performance:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• BLAKE3: Newest generation, tree structure, parallelizable'),
              Text('• SHAKE-256: Flexible output length, quantum-resistant design'),
              SizedBox(height: 12),
              Text('🛡️ Maximum security:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• SHA-512: Large output, traditional maximum security'),
              Text('• SHA-3-256: Alternative design, NIST standard'),
              SizedBox(height: 12),
              Text('ℹ️ About rounds:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('Higher rounds = more security but slower processing. Most applications work well with 1,000-10,000 rounds.'),
            ],
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
  
  /// Show KDF information dialog
  void _showKDFInfo() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Key Derivation Functions (KDF) Guide'),
        content: const SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('🔰 PBKDF2 (Most Compatible):', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Standard KDF, universally supported'),
              Text('• Good security with sufficient iterations (100,000+)'),
              Text('• Default choice for general use'),
              SizedBox(height: 12),
              Text('🛡️ Argon2 (Maximum Security):', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Winner of Password Hashing Competition'),
              Text('• Memory-hard function, resistant to hardware attacks'),
              Text('• Best choice for high-security applications'),
              SizedBox(height: 12),
              Text('⚡ Scrypt (Balanced):', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Memory-hard function, cryptocurrency standard'),
              Text('• Good balance of security and performance'),
              Text('• Configurable memory and CPU parameters'),
              SizedBox(height: 12),
              Text('🔗 HKDF (Key Expansion):', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Designed for key expansion and derivation'),
              Text('• Efficient, suitable for low-latency applications'),
              Text('• Often used with other KDFs'),
              SizedBox(height: 12),
              Text('🎈 Balloon (Research):', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Newer memory-hard function'),
              Text('• Configurable time/space tradeoffs'),
              Text('• Still under academic evaluation'),
            ],
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

  // =============================================================================
  // KDF Panel Builders
  // =============================================================================

  /// Build PBKDF2 configuration panel
  Widget _buildPBKDF2Panel() {
    final config = _kdfConfig['pbkdf2'] ?? {'enabled': true, 'iterations': 100000};
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('PBKDF2', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.green,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('RECOMMENDED', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Password-Based Key Derivation Function 2 - Industry standard, widely supported'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['pbkdf2'] = {
                    'enabled': value ?? false,
                    'iterations': config['iterations'] ?? 100000,
                  };
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const SizedBox(width: 100, child: Text('Iterations:')),
                    Expanded(
                      child: Slider(
                        value: (config['iterations'] ?? 100000).toDouble(),
                        min: 0,
                        max: 1000000,
                        divisions: 100,
                        label: (config['iterations'] ?? 100000).toString(),
                        onChanged: (double value) {
                          setState(() {
                            _kdfConfig['pbkdf2']!['iterations'] = value.toInt();
                          });
                        },
                      ),
                    ),
                    SizedBox(width: 80, child: Text('${config['iterations'] ?? 100000}')),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Text(
                  'Higher iterations = more security but slower processing. 100,000+ recommended.',
                  style: TextStyle(fontSize: 11, color: Theme.of(context).colorScheme.onSurfaceVariant),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build Argon2 configuration panel
  Widget _buildArgon2Panel() {
    final config = _kdfConfig['argon2'] ?? {
      'enabled': false,
      'time_cost': 3,
      'memory_cost': 65536,
      'parallelism': 4,
      'hash_len': 32,
      'type': 2,
      'rounds': 10,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.secondaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('Argon2', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.purple,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('MAX SECURITY', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Memory-hard function, winner of Password Hashing Competition - best against hardware attacks'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['argon2'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ...[ 
                _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) => 
                  setState(() => _kdfConfig['argon2']!['time_cost'] = v)),
                _buildKDFSlider('Memory (MB)', ((config['memory_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) => 
                  setState(() => _kdfConfig['argon2']!['memory_cost'] = v * 1024)),
                _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) => 
                  setState(() => _kdfConfig['argon2']!['parallelism'] = v)),
                _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 128, (v) => 
                  setState(() => _kdfConfig['argon2']!['hash_len'] = v)),
                _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) => 
                  setState(() => _kdfConfig['argon2']!['rounds'] = v)),
              ],
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const Text('Type: '),
                    DropdownButton<int>(
                      value: config['type'] ?? 2,
                      items: const [
                        DropdownMenuItem(value: 0, child: Text('Argon2d')),
                        DropdownMenuItem(value: 1, child: Text('Argon2i')),
                        DropdownMenuItem(value: 2, child: Text('Argon2id (recommended)')),
                      ],
                      onChanged: (int? value) {
                        setState(() {
                          _kdfConfig['argon2']!['type'] = value ?? 2;
                        });
                      },
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build Scrypt configuration panel
  Widget _buildScryptPanel() {
    final config = _kdfConfig['scrypt'] ?? {
      'enabled': false,
      'n': 16384,
      'r': 8,
      'p': 1,
      'rounds': 10,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('Scrypt', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.orange,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('BALANCED', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Memory-hard function used in cryptocurrencies - good balance of security and performance'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['scrypt'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ...[
                _buildKDFSlider('N (CPU/Memory)', (config['n'] ?? 16384) ~/ 1024, 1, 1024, (v) => 
                  setState(() => _kdfConfig['scrypt']!['n'] = v * 1024)),
                _buildKDFSlider('R (Block Size)', config['r'] ?? 8, 1, 32, (v) => 
                  setState(() => _kdfConfig['scrypt']!['r'] = v)),
                _buildKDFSlider('P (Parallelism)', config['p'] ?? 1, 1, 16, (v) => 
                  setState(() => _kdfConfig['scrypt']!['p'] = v)),
                _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) => 
                  setState(() => _kdfConfig['scrypt']!['rounds'] = v)),
              ],
            ],
          ],
        ),
      ),
    );
  }

  /// Build HKDF configuration panel
  Widget _buildHKDFPanel() {
    final config = _kdfConfig['hkdf'] ?? {
      'enabled': false,
      'rounds': 1,
      'algorithm': 'sha256',
      'info': 'openssl_encrypt_hkdf',
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('HKDF', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.teal,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('EFFICIENT', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('HMAC-based Key Derivation Function - efficient key expansion, suitable for low-latency applications'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['hkdf'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 0, 1000000, (v) => 
                setState(() => _kdfConfig['hkdf']!['rounds'] = v)),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const Text('Hash Algorithm: '),
                    DropdownButton<String>(
                      key: ValueKey('hash_algorithm_${config['algorithm'] ?? 'sha256'}'),
                      value: config['algorithm'] ?? 'sha256',
                      items: const [
                        DropdownMenuItem(value: 'sha224', child: Text('SHA-224')),
                        DropdownMenuItem(value: 'sha256', child: Text('SHA-256')),
                        DropdownMenuItem(value: 'sha384', child: Text('SHA-384')),
                        DropdownMenuItem(value: 'sha512', child: Text('SHA-512')),
                      ],
                      onChanged: (String? value) {
                        setState(() {
                          _kdfConfig['hkdf']!['algorithm'] = value ?? 'sha256';
                        });
                      },
                    ),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: TextFormField(
                  initialValue: config['info'] ?? 'openssl_encrypt_hkdf',
                  decoration: const InputDecoration(
                    labelText: 'Info String',
                    isDense: true,
                  ),
                  onChanged: (value) {
                    _kdfConfig['hkdf']!['info'] = value;
                  },
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build Balloon configuration panel
  Widget _buildBalloonPanel() {
    final config = _kdfConfig['balloon'] ?? {
      'enabled': false,
      'time_cost': 3,
      'space_cost': 65536,
      'parallelism': 4,
      'rounds': 2,
      'hash_len': 32,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.errorContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('Balloon', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.pink,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('RESEARCH', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Newer memory-hard function with configurable time/space tradeoffs - still under academic evaluation'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['balloon'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ...[
                _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) => 
                  setState(() => _kdfConfig['balloon']!['time_cost'] = v)),
                _buildKDFSlider('Space Cost (KB)', ((config['space_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) => 
                  setState(() => _kdfConfig['balloon']!['space_cost'] = v * 1024)),
                _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) => 
                  setState(() => _kdfConfig['balloon']!['parallelism'] = v)),
                _buildKDFSlider('Rounds', config['rounds'] ?? 2, 0, 1000000, (v) => 
                  setState(() => _kdfConfig['balloon']!['rounds'] = v)),
                _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 128, (v) => 
                  setState(() => _kdfConfig['balloon']!['hash_len'] = v)),
              ],
            ],
          ],
        ),
      ),
    );
  }

  /// Helper to build KDF slider
  Widget _buildKDFSlider(String label, int value, int min, int max, Function(int) onChanged) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
      child: Row(
        children: [
          SizedBox(width: 120, child: Text('$label:', style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurface))),
          // Decrement button with auto-repeat
          _buildAutoRepeatButton(
            icon: Icons.remove,
            color: Colors.orange,
            enabled: value > min,
            onAction: () => onChanged((value - 1).clamp(min, max)),
            size: 28,
            iconSize: 14,
          ),
          const SizedBox(width: 4),
          // Slider
          Expanded(
            child: Slider(
              value: value.toDouble(),
              min: min.toDouble(),
              max: max.toDouble(),
              divisions: (max - min) > 1000 ? max ~/ 100 : max - min, // Smart divisions
              label: value.toString(),
              onChanged: (double v) => onChanged(v.toInt()),
            ),
          ),
          const SizedBox(width: 4),
          // Increment button with auto-repeat
          _buildAutoRepeatButton(
            icon: Icons.add,
            color: Colors.orange,
            enabled: value < max,
            onAction: () => onChanged((value + 1).clamp(min, max)),
            size: 28,
            iconSize: 14,
          ),
          const SizedBox(width: 8),
          SizedBox(width: 60, child: Text(value.toString(), style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurface))),
        ],
      ),
    );
  }

  Widget _buildHashRoundsSlider(String hashId, int currentRounds, Function(int) onChanged) {
    // Get appropriate min/max values based on hash function
    int minRounds = 0;  // Allow 0 to disable hash function
    int maxRounds = _getMaxRounds(hashId);
    
    // Ensure current value is within bounds
    int clampedRounds = currentRounds.clamp(minRounds, maxRounds);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Rounds: $clampedRounds',
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w500,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(height: 4),
        Row(
          children: [
            // Decrement button with auto-repeat
            _buildAutoRepeatButton(
              icon: Icons.remove,
              color: Colors.blue,
              enabled: clampedRounds > minRounds,
              onAction: () => onChanged((clampedRounds - 1).clamp(minRounds, maxRounds)),
            ),
            const SizedBox(width: 8),
            // Slider
            Expanded(
              child: Slider(
                value: clampedRounds.toDouble(),
                min: minRounds.toDouble(),
                max: maxRounds.toDouble(),
                divisions: maxRounds ~/ 100, // Coarser divisions for slider
                label: clampedRounds.toString(),
                activeColor: Theme.of(context).colorScheme.primary,
                inactiveColor: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                onChanged: (double value) => onChanged(value.toInt()),
              ),
            ),
            const SizedBox(width: 8),
            // Increment button with auto-repeat
            _buildAutoRepeatButton(
              icon: Icons.add,
              color: Colors.blue,
              enabled: clampedRounds < maxRounds,
              onAction: () => onChanged((clampedRounds + 1).clamp(minRounds, maxRounds)),
            ),
          ],
        ),
      ],
    );
  }

  // =============================================================================
  // Algorithm Recommendation Engine
  // =============================================================================

  /// Show intelligent algorithm recommendation wizard
  void _showRecommendationWizard() async {
    if (!mounted) return;
    
    final recommendation = await showDialog<AlgorithmRecommendation>(
      context: context,
      builder: (context) => const RecommendationWizardDialog(),
    );
    
    if (recommendation != null) {
      // Apply the recommendation
      setState(() {
        _selectedAlgorithm = recommendation.algorithm;
        
        // Apply hash configuration
        for (final hashEntry in recommendation.hashConfig.entries) {
          final hashName = hashEntry.key;
          final config = hashEntry.value;
          if (_hashConfig.containsKey(hashName)) {
            _hashConfig[hashName] = Map.from(config);
          }
        }
        
        // Apply KDF configuration
        for (final kdfEntry in recommendation.kdfConfig.entries) {
          final kdfName = kdfEntry.key;
          final config = kdfEntry.value;
          if (_kdfConfig.containsKey(kdfName)) {
            _kdfConfig[kdfName] = Map.from(config);
          }
        }
      });
      
      // Show success message with explanation
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('✨ Applied ${recommendation.profileName} configuration'),
                Text(recommendation.explanation, style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant)),
              ],
            ),
            duration: const Duration(seconds: 5),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    }
  }
}

// File encryption/decryption tab
class FileCryptoTab extends StatefulWidget {
  final FileManager fileManager;
  final Function(bool) onDebugChanged;

  const FileCryptoTab({super.key, required this.fileManager, required this.onDebugChanged});

  @override
  State<FileCryptoTab> createState() => _FileCryptoTabState();
}

class _FileCryptoTabState extends State<FileCryptoTab> {
  final TextEditingController _passwordController = TextEditingController();
  FileInfo? _selectedFile;
  String _result = '';
  bool _isLoading = false;
  String? _decryptedContent; // Store decrypted content for optional saving
  bool _debugLogging = false;
  bool _forceOverwrite = false; // Force overwrite source file with --force flag
  
  // Progress tracking
  String _operationStatus = '';
  String _operationProgress = '';
  double _progressValue = 0.0;
  
  // Algorithm and configuration (same as TextCryptoTab)
  List<String> _algorithms = [];
  List<String> _hashAlgorithms = [];
  String _selectedAlgorithm = 'fernet';
  Map<String, Map<String, dynamic>> _hashConfig = {};
  Map<String, Map<String, dynamic>> _kdfConfig = {};
  bool _showAdvanced = false;
  bool _showHashConfig = false;
  bool _showKdfConfig = false;

  @override
  void initState() {
    super.initState();
    _loadAlgorithms();
  }

  Future<void> _loadAlgorithms() async {
    try {
      final algorithmMap = await CLIService.getSupportedAlgorithms();
      final algorithms = algorithmMap.values.expand((list) => list).toList();
      final hashAlgorithmsList = await CLIService.getHashAlgorithmsList();
      
      setState(() {
        _algorithms = algorithms;
        _hashAlgorithms = hashAlgorithmsList;
        
        if (algorithms.isNotEmpty) {
          _selectedAlgorithm = algorithms.first;
        }
        if (hashAlgorithmsList.isNotEmpty) {
          // Initialize hash configuration with default values (CLI order)
          _hashConfig = {};
          for (String hash in hashAlgorithmsList) {
            _hashConfig[hash] = {
              'enabled': true,  // All hash functions enabled with CLI integration
              'rounds': 1000    // Default rounds for all hash functions (CLI supports all)
            };
          }
        }
        // Initialize KDF chain configuration (CLI order)
        _kdfConfig = {
          'pbkdf2': {'enabled': !CLIService.shouldHideLegacyAlgorithms(), 'rounds': 100000},
          'scrypt': {'enabled': false, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
          'argon2': {'enabled': false, 'memory_cost': 65536, 'time_cost': 3, 'parallelism': 1, 'rounds': 1},
          'hkdf': {'enabled': false, 'info': 'openssl_encrypt_hkdf', 'rounds': 1},
          'balloon': {'enabled': false, 'space_cost': 65536, 'time_cost': 3, 'parallelism': 4, 'rounds': 2, 'hash_len': 32},
        };
      });
    } catch (e) {
      setState(() {
        _algorithms = ['fernet'];
        _hashAlgorithms = ['sha256'];
        _selectedAlgorithm = 'fernet';
        _hashConfig = {'sha256': {'enabled': true, 'rounds': 1000}};
        _kdfConfig = {
          'pbkdf2': {'enabled': !CLIService.shouldHideLegacyAlgorithms(), 'rounds': 100000},
          'hkdf': {'enabled': false, 'info': 'openssl_encrypt_hkdf', 'rounds': 1}
        };
      });
    }
  }

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  void _pickFile() async {
    final file = await widget.fileManager.pickFile();
    if (file != null) {
      setState(() {
        _selectedFile = file;
        _result = 'Selected file: ${file.name}\nSize: ${file.sizeFormatted}';
      });
    }
  }

  /// Load a file from a given path (for drag & drop support)
  Future<bool> loadFileFromPath(String filePath) async {
    try {
      final fileInfo = await widget.fileManager.createFileInfoFromPath(filePath);
      if (fileInfo != null) {
        setState(() {
          _selectedFile = fileInfo;
          _result = 'Selected file: ${fileInfo.name}\nSize: ${fileInfo.sizeFormatted}';
        });
        return true;
      }
    } catch (e) {
      setState(() {
        _result = 'Error loading file: $e';
      });
    }
    return false;
  }

  void _pickTestFile() async {
    final testFileNames = await widget.fileManager.getTestFileNames();
    
    if (!mounted) return;
    
    final selectedFileName = await showDialog<String>(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('Select Test File'),
          content: SizedBox(
            width: double.maxFinite,
            height: 400,
            child: RepaintBoundary(
              child: ListView.builder(
                key: const Key('test_files_listview'),
                itemCount: testFileNames.length,
                itemBuilder: (context, index) {
                final fileName = testFileNames[index];
                final isEncrypted = fileName.contains('test1_');
                
                // Determine format version and algorithm
                String formatInfo = '';
                String algorithmName = '';
                if (fileName.startsWith('v3/')) {
                  formatInfo = 'v3';
                } else if (fileName.startsWith('v4/')) {
                  formatInfo = 'v4';
                } else if (fileName.startsWith('v5/')) {
                  formatInfo = 'v5';
                }
                
                // Extract algorithm name from filename
                final baseName = fileName.split('/').last;
                if (baseName.contains('fernet_balloon')) {
                  algorithmName = 'Fernet + Balloon KDF';
                } else if (baseName.contains('fernet')) {
                  algorithmName = 'Fernet';
                } else if (baseName.contains('aes-gcm')) {
                  algorithmName = 'AES-GCM';
                } else if (baseName.contains('xchacha20')) {
                  algorithmName = 'XChaCha20-Poly1305';
                } else if (baseName.contains('chacha20')) {
                  algorithmName = 'ChaCha20-Poly1305';
                } else if (baseName.contains('mobile_generated')) {
                  algorithmName = 'Mobile Generated Test';
                } else {
                  algorithmName = 'Unknown';
                }
                
                return ListTile(
                  leading: Icon(
                    isEncrypted ? Icons.lock : Icons.description,
                    color: formatInfo == 'v5' ? Colors.green : 
                           formatInfo == 'v4' ? Colors.orange : 
                           formatInfo == 'v3' ? Colors.red : Colors.blue,
                  ),
                  title: Text(baseName),
                  subtitle: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        algorithmName,
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                          color: Colors.grey[700],
                        ),
                      ),
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (formatInfo.isNotEmpty) ...[
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: formatInfo == 'v5' ? Colors.green : 
                                       formatInfo == 'v4' ? Colors.orange : 
                                       formatInfo == 'v3' ? Colors.red : Colors.grey,
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                formatInfo.toUpperCase(),
                                style: const TextStyle(
                                  fontSize: 10,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                          ],
                          Flexible(
                            child: Text(
                              'Password: 1234',
                              style: TextStyle(
                                fontSize: 11,
                                color: Colors.grey[600],
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                  onTap: () {
                    Navigator.of(context).pop(fileName);
                  },
                );
              },
            ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
          ],
        );
      },
    );

    if (selectedFileName != null) {
      final fileInfo = await widget.fileManager.getTestFileInfo(selectedFileName);
      if (fileInfo != null) {
        setState(() {
          _selectedFile = fileInfo;
          _result = 'Selected test file: ${fileInfo.name}\nSize: ${fileInfo.sizeFormatted}\nNote: Test password is "1234"';
        });
      }
    }
  }

  void _encryptFile() async {
    if (_selectedFile == null || _passwordController.text.isEmpty) {
      setState(() {
        _result = 'Please select a file and enter a password';
      });
      return;
    }

    // Use selected algorithm, hash, and KDF configuration
    setState(() {
      _isLoading = true;
      _result = 'Encrypting file with $_selectedAlgorithm...';
      _operationStatus = 'Preparing encryption...';
      _operationProgress = '';
      _progressValue = 0.0;
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      // Read file content
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      // Encrypt file content using CLI service with selected configurations
      final encrypted = await CLIService.encryptTextWithProgress(
        fileContent,
        _passwordController.text,
        _selectedAlgorithm, // Use selected algorithm
        _hashConfig,        // Use hash configuration from UI
        _kdfConfig,         // Use KDF configuration from UI
        onProgress: (progress) {
          setState(() {
            _operationStatus = 'Encrypting with $_selectedAlgorithm...';
            _operationProgress = progress;
            _progressValue = progress.contains('%') 
              ? (double.tryParse(progress.split('%')[0]) ?? 0.0) / 100.0
              : 0.5;
          });
        },
      );

      if (encrypted.startsWith('ERROR:')) {
        throw Exception(encrypted.substring(7));
      }

      // Generate output filename - use original path if force overwrite is enabled
      final outputPath = _forceOverwrite 
          ? _selectedFile!.path 
          : widget.fileManager.getEncryptedFileName(_selectedFile!.path);
      
      // Save encrypted file
      final success = await widget.fileManager.writeFileText(outputPath, encrypted);

      if (success) {
        setState(() {
          if (_forceOverwrite) {
            _result = 'File encrypted successfully (source overwritten)!\n\n'
                'Original: ${_selectedFile!.name}\n'
                'Size: ${_selectedFile!.sizeFormatted}\n'
                'Status: Source file replaced with encrypted content\n'
                'Path: $outputPath\n\n'
                'Algorithm: $_selectedAlgorithm\n'
                'CLI Compatible: Yes\n'
                'Format: OpenSSL Encrypt Desktop GUI';
          } else {
            _result = 'File encrypted successfully!\n\n'
                'Original: ${_selectedFile!.name}\n'
                'Size: ${_selectedFile!.sizeFormatted}\n'
                'Encrypted: ${outputPath.split('/').last}\n'
                'Saved to: $outputPath\n\n'
                'Algorithm: $_selectedAlgorithm\n'
                'CLI Compatible: Yes\n'
                'Format: OpenSSL Encrypt Desktop GUI';
          }
          _isLoading = false;
        });
      } else {
        throw Exception('Failed to save encrypted file');
      }
    } catch (e) {
      setState(() {
        _result = 'File encryption failed: $e';
        _isLoading = false;
      });
    }
  }

  void _decryptFile() async {
    if (_selectedFile == null || _passwordController.text.isEmpty) {
      setState(() {
        _result = 'Please select an encrypted file and enter a password';
      });
      return;
    }

    // Check if file is encrypted by reading metadata
    bool fileIsEncrypted = await _selectedFile!.isEncrypted;
    if (!fileIsEncrypted) {
      setState(() {
        _result = 'Selected file does not appear to be encrypted.\n'
            'Expected: CLI format (base64_metadata:base64_data) or JSON format with encrypted_data and metadata fields.\n'
            'File: ${_selectedFile!.name}';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _result = 'Decrypting file...';
      _operationStatus = 'Starting decryption...';
      _operationProgress = '';
      _progressValue = 0.0;
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      // Read the encrypted file
      setState(() {
        _operationStatus = 'Reading encrypted file...';
        _progressValue = 0.2;
      });
      
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      setState(() {
        _operationStatus = 'File loaded, starting decryption...';
        _progressValue = 0.3;
      });

      // Decrypt using CLI service with progress callbacks
      final decrypted = await CLIService.decryptTextWithProgress(
        fileContent,  // Pass raw file content
        _passwordController.text,
        onProgress: (progress) {
          setState(() {
            _operationProgress = progress;
          });
        },
        onStatus: (status) {
          setState(() {
            _operationStatus = status;
            // Update progress based on status
            if (status.contains('Initializing')) {
              _progressValue = 0.4;
            } else if (status.contains('Prepared')) {
              _progressValue = 0.5;
            } else if (status.contains('Executing')) {
              _progressValue = 0.7;
            } else if (status.contains('Reading')) {
              _progressValue = 0.9;
            } else if (status.contains('completed')) {
              _progressValue = 1.0;
            }
          });
        },
      );

      if (decrypted.startsWith('ERROR:')) {
        throw Exception(decrypted.substring(7));
      }

      // Store decrypted content and optionally save directly if force overwrite is enabled
      if (_forceOverwrite) {
        // Save decrypted content directly to source file
        final success = await widget.fileManager.writeFileText(_selectedFile!.path, decrypted);
        
        if (success) {
          setState(() {
            _decryptedContent = decrypted;
            _result = 'File decrypted successfully (source overwritten)!\n\n'
                'Status: Source file replaced with decrypted content\n'
                'Path: ${_selectedFile!.path}\n'
                'File: ${_selectedFile!.name}\n\n'
                'Decrypted Content Preview:\n'
                '${decrypted.length > 200 ? '${decrypted.substring(0, 200)}...' : decrypted}';
            _isLoading = false;
            _operationStatus = '';
            _operationProgress = '';
            _progressValue = 0.0;
          });
        } else {
          throw Exception('Failed to save decrypted file');
        }
      } else {
        // Store for optional saving (existing behavior)
        setState(() {
          _decryptedContent = decrypted; // Store for optional saving
          _result = decrypted; // Show only the decrypted content
          _isLoading = false;
          _operationStatus = '';
          _operationProgress = '';
          _progressValue = 0.0;
        });
      }

    } catch (e) {
      setState(() {
        _result = 'File decryption failed: $e';
        _isLoading = false;
        _operationStatus = '';
        _operationProgress = '';
        _progressValue = 0.0;
      });
    }
  }

  void _saveDecryptedToFile() async {
    if (_decryptedContent == null || _selectedFile == null) {
      setState(() {
        _result = 'No decrypted content available to save';
      });
      return;
    }

    try {
      // Generate output filename
      final outputPath = widget.fileManager.getDecryptedFileName(_selectedFile!.path);
      final success = await widget.fileManager.writeFileText(outputPath, _decryptedContent!);

      if (success) {
        setState(() {
          _result += '\n\n✅ Content saved to file:\n$outputPath';
        });
      } else {
        setState(() {
          _result += '\n\n❌ Failed to save content to file';
        });
      }
    } catch (e) {
      setState(() {
        _result += '\n\n❌ Save failed: $e';
      });
    }
  }

  // Helper methods (copied from TextCryptoTab)
  String _getAlgorithmDescription(String algorithm) {
    final descriptions = {
      // Classical Symmetric
      'fernet': 'Fernet - Symmetric encryption with built-in MAC (most compatible)',
      'aes-gcm': 'AES-GCM - Modern authenticated encryption (high performance)',
      'chacha20-poly1305': 'ChaCha20-Poly1305 - Fast stream cipher with authentication',
      'xchacha20-poly1305': 'XChaCha20-Poly1305 - Extended nonce ChaCha20 variant',
      // Post-quantum Key Encapsulation
      'ml-kem-512': 'ML-KEM-512 - Post-quantum KEM (128-bit security)',
      'ml-kem-768': 'ML-KEM-768 - Post-quantum KEM (192-bit security)',
      'ml-kem-1024': 'ML-KEM-1024 - Post-quantum KEM (256-bit security)',
    };
    
    return descriptions[algorithm] ?? 'Advanced encryption algorithm - see CLI documentation for details';
  }

  void _showAlgorithmPicker() async {
    final selectedAlgorithm = await showDialog<String>(
      context: context,
      builder: (context) => _buildAlgorithmPicker(),
    );
    
    if (selectedAlgorithm != null) {
      setState(() {
        _selectedAlgorithm = selectedAlgorithm;
      });
    }
  }

  Widget _buildAlgorithmPicker() {
    final algorithmCategories = {
      'Classical Symmetric': [
        'fernet', 'aes-gcm', 'chacha20-poly1305', 'xchacha20-poly1305', 
        'aes-siv', 'aes-gcm-siv', 'aes-ocb3', 'camellia'
      ].where((a) => _algorithms.contains(a)).toList(),
      'ML-KEM Post-Quantum': [
        'ml-kem-512-hybrid', 'ml-kem-768-hybrid', 'ml-kem-1024-hybrid',
        'ml-kem-512-chacha20', 'ml-kem-768-chacha20', 'ml-kem-1024-chacha20'
      ].where((a) => _algorithms.contains(a)).toList(),
      'Kyber Legacy': [
        'kyber512-hybrid', 'kyber768-hybrid', 'kyber1024-hybrid'
      ].where((a) => _algorithms.contains(a)).toList(),
      'HQC Code-Based': [
        'hqc-128-hybrid', 'hqc-192-hybrid', 'hqc-256-hybrid'
      ].where((a) => _algorithms.contains(a)).toList(),
      'MAYO Signature': [
        'mayo-1-hybrid', 'mayo-3-hybrid', 'mayo-5-hybrid'
      ].where((a) => _algorithms.contains(a)).toList(),
      'CROSS Signature': [
        'cross-128-hybrid', 'cross-192-hybrid', 'cross-256-hybrid'
      ].where((a) => _algorithms.contains(a)).toList(),
    };

    return AlertDialog(
      title: const Text('Select Encryption Algorithm'),
      content: SizedBox(
        width: double.maxFinite,
        child: ListView(
          shrinkWrap: true,
          children: [
            Text(
              'Select an encryption algorithm. Post-quantum algorithms provide protection against quantum computers.',
              style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            ...algorithmCategories.entries.map((entry) {
              final category = entry.key;
              final algorithms = entry.value;
              
              if (algorithms.isEmpty) return const SizedBox.shrink();
              
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8.0),
                    child: Text(
                      category,
                      style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                    ),
                  ),
                  ...algorithms.map((algorithm) {
                    final isSelected = algorithm == _selectedAlgorithm;
                    
                    return Card(
                      color: isSelected ? Theme.of(context).colorScheme.primaryContainer : null,
                      child: ListTile(
                        leading: const Icon(Icons.security),
                        title: Text(algorithm),
                        subtitle: Text(_getAlgorithmDescription(algorithm)),
                        trailing: isSelected ? Icon(Icons.check_circle, color: Theme.of(context).colorScheme.primary) : null,
                        onTap: () => Navigator.of(context).pop(algorithm),
                      ),
                    );
                  }),
                  const SizedBox(height: 8),
                ],
              );
            }),
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

  void _showRecommendationWizard() {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Recommendation wizard: Use Fernet for compatibility or AES-GCM for performance'),
        duration: Duration(seconds: 3),
      ),
    );
  }

  Widget _buildHashConfigSection() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.tag),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'Hash Functions Configuration',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                Switch(
                  value: _showHashConfig,
                  onChanged: (bool? value) {
                    setState(() {
                      _showHashConfig = value ?? false;
                    });
                  },
                ),
              ],
            ),
            if (_showHashConfig) ...[
              const SizedBox(height: 12),
              ..._hashAlgorithms.map((hash) => _buildHashConfig(hash, hash.toUpperCase())),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildKDFConfigSection() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.security),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'Key Derivation Functions',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                Switch(
                  value: _showKdfConfig,
                  onChanged: (bool? value) {
                    setState(() {
                      _showKdfConfig = value ?? false;
                    });
                  },
                ),
              ],
            ),
            if (_showKdfConfig) ...[
              const SizedBox(height: 12),
              Text(
                'KDF configuration enabled - switch to TextCrypto tab for full parameter control',
                style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurfaceVariant),
              ),
              const SizedBox(height: 8),
              // PBKDF2 Panel
              _buildPBKDF2Panel(),
              const SizedBox(height: 8),
              
              // Argon2 Panel  
              _buildArgon2Panel(),
              const SizedBox(height: 8),
              
              // Scrypt Panel
              _buildScryptPanel(),
              const SizedBox(height: 8),
              
              // HKDF Panel
              _buildHKDFPanel(),
              const SizedBox(height: 8),
              
              // Balloon Panel
              _buildBalloonPanel(),
              const SizedBox(height: 8),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildHashConfig(String hashId, String hashName) {
    final isEnabled = _hashConfig[hashId]?['enabled'] ?? false;
    final rounds = _hashConfig[hashId]?['rounds'] ?? 1000;
    
    // All hash functions now supported with CLI integration
    final effectiveEnabled = isEnabled;
    
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(color: effectiveEnabled ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.outline),
        borderRadius: BorderRadius.circular(8),
        color: effectiveEnabled ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: effectiveEnabled,
                onChanged: (bool? value) {
                  setState(() {
                    if (_hashConfig[hashId] == null) {
                      _hashConfig[hashId] = {'rounds': 1000};
                    }
                    _hashConfig[hashId]!['enabled'] = value;
                  });
                },
              ),
              const SizedBox(width: 8),
              SizedBox(
                width: 80,
                child: Text(
                  hashName.toUpperCase(),
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                    color: effectiveEnabled ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              if (effectiveEnabled)
                Expanded(
                  child: _buildHashRoundsSlider(
                    hashId,
                    rounds,
                    (int newRounds) {
                      setState(() {
                        _hashConfig[hashId]!['rounds'] = newRounds;
                      });
                    },
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  // ignore: unused_element
  Widget _buildSimpleKDFConfig(String kdfId) {
    final isEnabled = _kdfConfig[kdfId]?['enabled'] ?? false;
    
    return Card(
      child: CheckboxListTile(
        title: Text(kdfId.toUpperCase()),
        subtitle: Text('Enable $kdfId key derivation'),
        value: isEnabled,
        onChanged: (bool? value) {
          setState(() {
            if (_kdfConfig[kdfId] != null) {
              _kdfConfig[kdfId]!['enabled'] = value;
            }
          });
        },
      ),
    );
  }

  Widget _buildHashRoundsSlider(String hashId, int currentRounds, Function(int) onChanged) {
    // Get appropriate min/max values based on hash function
    int minRounds = 0;  // Allow 0 to disable hash function
    int maxRounds = _getMaxRounds(hashId);
    
    // Ensure current value is within bounds
    int clampedRounds = currentRounds.clamp(minRounds, maxRounds);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Rounds: $clampedRounds',
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w500,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(height: 4),
        Row(
          children: [
            // Decrement button with auto-repeat
            _buildAutoRepeatButton(
              icon: Icons.remove,
              color: Colors.blue,
              enabled: clampedRounds > minRounds,
              onAction: () => onChanged((clampedRounds - 1).clamp(minRounds, maxRounds)),
            ),
            const SizedBox(width: 8),
            // Slider
            Expanded(
              child: Slider(
                value: clampedRounds.toDouble(),
                min: minRounds.toDouble(),
                max: maxRounds.toDouble(),
                divisions: maxRounds ~/ 100, // Coarser divisions for slider
                label: clampedRounds.toString(),
                activeColor: Theme.of(context).colorScheme.primary,
                inactiveColor: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                onChanged: (double value) => onChanged(value.toInt()),
              ),
            ),
            const SizedBox(width: 8),
            // Increment button with auto-repeat
            _buildAutoRepeatButton(
              icon: Icons.add,
              color: Colors.blue,
              enabled: clampedRounds < maxRounds,
              onAction: () => onChanged((clampedRounds + 1).clamp(minRounds, maxRounds)),
            ),
          ],
        ),
      ],
    );
  }

  /// Get maximum recommended rounds for hash function
  int _getMaxRounds(String hashName) {
    // Hash functions use maximum of 1,000,000 rounds but with better precision control
    return 1000000;
  }

  /// Build an auto-repeat button that continues action when held down
  Widget _buildAutoRepeatButton({
    required IconData icon,
    required MaterialColor color,
    required bool enabled,
    required VoidCallback onAction,
    double size = 32,
    double iconSize = 16,
  }) {
    return AutoRepeatButton(
      icon: icon,
      color: color,
      enabled: enabled,
      onAction: onAction,
      size: size,
      iconSize: iconSize,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Selected File',
                      style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  if (_selectedFile == null)
                    const Text('No file selected')
                  else
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Name: ${_selectedFile!.name}'),
                        Text('Size: ${_selectedFile!.sizeFormatted}'),
                        Text('Type: ${_selectedFile!.extension}'),
                      ],
                    ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: ElevatedButton.icon(
                          onPressed: _isLoading ? null : _pickFile,
                          icon: const Icon(Icons.folder_open),
                          label: const Text('Choose File'),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: ElevatedButton.icon(
                          onPressed: _isLoading ? null : _pickTestFile,
                          icon: const Icon(Icons.quiz),
                          label: const Text('Test Files'),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.blue,
                            foregroundColor: Colors.white,
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
          // Algorithm Selection Card (same as TextCryptoTab)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.security),
                      const SizedBox(width: 8),
                      const Text('Encryption Algorithm', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                      const Spacer(),
                      IconButton(
                        icon: Icon(_showAdvanced ? Icons.keyboard_arrow_up : Icons.keyboard_arrow_down),
                        onPressed: () => setState(() => _showAdvanced = !_showAdvanced),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      border: Border.all(color: Theme.of(context).colorScheme.primary),
                      borderRadius: BorderRadius.circular(8),
                      color: Theme.of(context).colorScheme.primaryContainer,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(Icons.check_circle, color: Theme.of(context).colorScheme.primary, size: 20),
                            const SizedBox(width: 8),
                            Text(
                              'Selected: $_selectedAlgorithm',
                              style: TextStyle(fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.primary),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _getAlgorithmDescription(_selectedAlgorithm),
                          style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.primary),
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            ElevatedButton.icon(
                              onPressed: () => _showAlgorithmPicker(),
                              icon: const Icon(Icons.tune, size: 16),
                              label: const Text('Choose Algorithm'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                                foregroundColor: Theme.of(context).colorScheme.onPrimaryContainer,
                              ),
                            ),
                            const SizedBox(width: 8),
                            ElevatedButton.icon(
                              onPressed: () => _showRecommendationWizard(),
                              icon: const Icon(Icons.auto_awesome, size: 16),
                              label: const Text('Get Recommendations'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.green.withValues(alpha: 0.2),
                                foregroundColor: Colors.green.shade700,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  if (_showAdvanced) ...[  
                    const SizedBox(height: 16),
                    ExpansionTile(
                      leading: const Icon(Icons.tag),
                      title: const Row(
                        children: [
                          Expanded(
                            child: Text(
                              'Advanced Security Settings (CLI Compatible)',
                              style: TextStyle(fontSize: 14),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                      children: [
                        _buildHashConfigSection(),
                        _buildKDFConfigSection(),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _passwordController,
            decoration: const InputDecoration(
              labelText: 'Password',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.lock),
            ),
            obscureText: true,
          ),
          const SizedBox(height: 16),
          // Debug Logging Toggle
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        _debugLogging ? Icons.bug_report : Icons.bug_report_outlined,
                        color: _debugLogging ? Colors.orange : Colors.grey,
                      ),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          'Debug Logging',
                          style: TextStyle(fontWeight: FontWeight.bold),
                        ),
                      ),
                      Switch(
                        value: _debugLogging,
                        onChanged: (bool value) async {
                          setState(() {
                            _debugLogging = value;
                            // Update CLI service debug flag
                            CLIService.debugEnabled = value;
                            // Update debug banner visibility
                            widget.onDebugChanged(value);
                          });
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _debugLogging 
                      ? '🟢 Debug logging enabled - logs written to console and file' 
                      : '🔲 Debug logging disabled - only basic status messages',
                    style: TextStyle(
                      fontSize: 12,
                      color: _debugLogging ? Colors.orange.shade700 : Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (_debugLogging) ...[
                    const SizedBox(height: 4),
                    Text(
                      'Debug output will be shown in console',
                      style: TextStyle(
                        fontSize: 10,
                        color: Colors.orange.shade600,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                  if (_debugLogging) ...[
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.red.shade50,
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Colors.red.shade300),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Icon(Icons.warning, size: 16, color: Colors.red.shade700),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  'SECURITY WARNING',
                                  style: TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.red.shade700,
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Debug logs may contain sensitive information including passwords, keys, and decrypted content. Only use with test files and non-sensitive data. Never share debug logs containing real passwords or personal data.',
                            style: TextStyle(
                              fontSize: 11,
                              color: Colors.red.shade600,
                            ),
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
          if (_isLoading)
            Card(
              color: Theme.of(context).colorScheme.tertiaryContainer,
              elevation: 8,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    // Progress bar
                    LinearProgressIndicator(
                      value: _progressValue,
                      backgroundColor: Theme.of(context).colorScheme.surfaceContainer,
                      valueColor: AlwaysStoppedAnimation<Color>(Theme.of(context).colorScheme.primary),
                    ),
                    const SizedBox(height: 12),
                    // Circular progress indicator
                    CircularProgressIndicator(color: Theme.of(context).colorScheme.primary),
                    const SizedBox(height: 12),
                    // Operation status
                    Text(
                      _operationStatus.isNotEmpty ? _operationStatus : 'Crypto operation in progress...',
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Theme.of(context).colorScheme.onTertiaryContainer),
                      textAlign: TextAlign.center,
                    ),
                    // CLI progress output
                    if (_operationProgress.isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(8.0),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.tertiaryContainer,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: Theme.of(context).colorScheme.outline),
                        ),
                        child: Text(
                          _operationProgress,
                          style: TextStyle(
                            fontSize: 12,
                            fontFamily: 'monospace',
                            color: Theme.of(context).colorScheme.onTertiaryContainer,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ],
                    // Progress percentage
                    if (_progressValue > 0) ...[
                      const SizedBox(height: 8),
                      Text(
                        '${(_progressValue * 100).toInt()}%',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                          color: Theme.of(context).colorScheme.onTertiaryContainer,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          const SizedBox(height: 16),
          // Force overwrite option
          Row(
            children: [
              Checkbox(
                value: _forceOverwrite,
                onChanged: _isLoading ? null : (value) {
                  setState(() {
                    _forceOverwrite = value ?? false;
                  });
                },
              ),
              GestureDetector(
                onTap: _isLoading ? null : () {
                  setState(() {
                    _forceOverwrite = !_forceOverwrite;
                  });
                },
                child: Text(
                  'Force overwrite source file (--force)',
                  style: TextStyle(
                    color: _isLoading ? Theme.of(context).colorScheme.onSurfaceVariant : null,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Tooltip(
                message: 'When enabled, replaces the original file with encrypted/decrypted content instead of creating a new file',
                child: Icon(
                  Icons.info_outline,
                  size: 16,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              const Spacer(), // Pushes everything else to the right, leaving space
            ],
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _encryptFile,
                  icon: Icon(Icons.lock, color: _isLoading ? Theme.of(context).colorScheme.onSurfaceVariant : null),
                  label: Text(_isLoading ? 'LOCKED - Encrypting...' : 'Encrypt File'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _isLoading ? Theme.of(context).colorScheme.surfaceContainer : null,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _decryptFile,
                  icon: Icon(Icons.lock_open, color: _isLoading ? Theme.of(context).colorScheme.onSurfaceVariant : null),
                  label: Text(_isLoading ? 'LOCKED - Decrypting...' : 'Decrypt File'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _isLoading ? Theme.of(context).colorScheme.surfaceContainer : null,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // Save to File button (only shown when decrypted content is available)
          if (_decryptedContent != null)
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _isLoading ? null : _saveDecryptedToFile,
                icon: const Icon(Icons.save),
                label: const Text('Save Decrypted Content to File'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.green,
                  foregroundColor: Colors.white,
                ),
              ),
            ),
          if (_decryptedContent != null)
            const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: Stack(
              children: [
                Container(
                  width: double.infinity,
                  height: 200,
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    border: Border.all(color: Theme.of(context).colorScheme.outline),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: SingleChildScrollView(
                    child: SelectableText(
                      _result.isEmpty ? 'File operation results will appear here...' : _result,
                      style: const TextStyle(fontFamily: 'monospace'),
                    ),
                  ),
                ),
              if (_result.isNotEmpty)
                Positioned(
                  top: 8,
                  right: 8,
                  child: FloatingActionButton.small(
                    heroTag: "copy_file_result",
                    onPressed: () async {
                      await Clipboard.setData(ClipboardData(text: _result));
                      if (mounted) {
                        // ignore: use_build_context_synchronously
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Result copied to clipboard'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      }
                    },
                    backgroundColor: Theme.of(context).colorScheme.primary,
                    child: Icon(Icons.copy, size: 16, color: Theme.of(context).colorScheme.onPrimary),
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

  // =============================================================================
  // KDF Panel Builders (copied from TextCryptoTabState for consistency)
  // =============================================================================

  /// Build PBKDF2 configuration panel
  Widget _buildPBKDF2Panel() {
    final config = _kdfConfig['pbkdf2'] ?? {'enabled': true, 'iterations': 100000};
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('PBKDF2', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.green,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('RECOMMENDED', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Password-Based Key Derivation Function 2 - Industry standard, widely supported'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['pbkdf2'] = {
                    'enabled': value ?? false,
                    'iterations': config['iterations'] ?? 100000,
                  };
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const SizedBox(width: 100, child: Text('Iterations:')),
                    Expanded(
                      child: Slider(
                        value: (config['iterations'] ?? 100000).toDouble(),
                        min: 0,
                        max: 1000000,
                        divisions: 100,
                        label: (config['iterations'] ?? 100000).toString(),
                        onChanged: (double value) {
                          setState(() {
                            _kdfConfig['pbkdf2']!['iterations'] = value.toInt();
                          });
                        },
                      ),
                    ),
                    SizedBox(width: 80, child: Text('${config['iterations'] ?? 100000}')),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Text(
                  'Higher iterations = more security but slower processing. 100,000+ recommended.',
                  style: TextStyle(fontSize: 11, color: Theme.of(context).colorScheme.onSurfaceVariant),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build Argon2 configuration panel
  Widget _buildArgon2Panel() {
    final config = _kdfConfig['argon2'] ?? {
      'enabled': false,
      'time_cost': 3,
      'memory_cost': 65536,
      'parallelism': 4,
      'hash_len': 32,
      'type': 2,
      'rounds': 10,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.secondaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('Argon2', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.purple,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('MAX SECURITY', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Memory-hard function, winner of Password Hashing Competition - best against hardware attacks'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['argon2'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ...[ 
                _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) => 
                  setState(() => _kdfConfig['argon2']!['time_cost'] = v)),
                _buildKDFSlider('Memory (MB)', ((config['memory_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) => 
                  setState(() => _kdfConfig['argon2']!['memory_cost'] = v * 1024)),
                _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) => 
                  setState(() => _kdfConfig['argon2']!['parallelism'] = v)),
                _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 128, (v) => 
                  setState(() => _kdfConfig['argon2']!['hash_len'] = v)),
                _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) => 
                  setState(() => _kdfConfig['argon2']!['rounds'] = v)),
              ],
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const Text('Type: '),
                    DropdownButton<int>(
                      value: config['type'] ?? 2,
                      items: const [
                        DropdownMenuItem(value: 0, child: Text('Argon2d')),
                        DropdownMenuItem(value: 1, child: Text('Argon2i')),
                        DropdownMenuItem(value: 2, child: Text('Argon2id (recommended)')),
                      ],
                      onChanged: (int? value) {
                        setState(() {
                          _kdfConfig['argon2']!['type'] = value ?? 2;
                        });
                      },
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build Scrypt configuration panel
  Widget _buildScryptPanel() {
    final config = _kdfConfig['scrypt'] ?? {
      'enabled': false,
      'n': 16384,
      'r': 8,
      'p': 1,
      'rounds': 10,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('Scrypt', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.orange,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('BALANCED', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Memory-hard function used in cryptocurrencies - good balance of security and performance'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['scrypt'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ...[
                _buildKDFSlider('N (CPU/Memory)', (config['n'] ?? 16384) ~/ 1024, 1, 1024, (v) => 
                  setState(() => _kdfConfig['scrypt']!['n'] = v * 1024)),
                _buildKDFSlider('R (Block Size)', config['r'] ?? 8, 1, 32, (v) => 
                  setState(() => _kdfConfig['scrypt']!['r'] = v)),
                _buildKDFSlider('P (Parallelism)', config['p'] ?? 1, 1, 16, (v) => 
                  setState(() => _kdfConfig['scrypt']!['p'] = v)),
                _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) => 
                  setState(() => _kdfConfig['scrypt']!['rounds'] = v)),
              ],
            ],
          ],
        ),
      ),
    );
  }

  /// Build HKDF configuration panel
  Widget _buildHKDFPanel() {
    final config = _kdfConfig['hkdf'] ?? {
      'enabled': false,
      'rounds': 1,
      'algorithm': 'sha256',
      'info': 'openssl_encrypt_hkdf',
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('HKDF', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.teal,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('EFFICIENT', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('HMAC-based Key Derivation Function - efficient key expansion, suitable for low-latency applications'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['hkdf'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 0, 1000000, (v) => 
                setState(() => _kdfConfig['hkdf']!['rounds'] = v)),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const Text('Hash Algorithm: '),
                    DropdownButton<String>(
                      key: ValueKey('hash_algorithm_${config['algorithm'] ?? 'sha256'}'),
                      value: config['algorithm'] ?? 'sha256',
                      items: const [
                        DropdownMenuItem(value: 'sha224', child: Text('SHA-224')),
                        DropdownMenuItem(value: 'sha256', child: Text('SHA-256')),
                        DropdownMenuItem(value: 'sha384', child: Text('SHA-384')),
                        DropdownMenuItem(value: 'sha512', child: Text('SHA-512')),
                      ],
                      onChanged: (String? value) {
                        setState(() {
                          _kdfConfig['hkdf']!['algorithm'] = value ?? 'sha256';
                        });
                      },
                    ),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: TextFormField(
                  initialValue: config['info'] ?? 'openssl_encrypt_hkdf',
                  decoration: const InputDecoration(
                    labelText: 'Info String',
                    isDense: true,
                  ),
                  onChanged: (value) {
                    _kdfConfig['hkdf']!['info'] = value;
                  },
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Build Balloon configuration panel
  Widget _buildBalloonPanel() {
    final config = _kdfConfig['balloon'] ?? {
      'enabled': false,
      'time_cost': 3,
      'space_cost': 65536,
      'parallelism': 4,
      'rounds': 2,
      'hash_len': 32,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.errorContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('Balloon', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.pink,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('RESEARCH', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Newer memory-hard function with configurable time/space tradeoffs - still under academic evaluation'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['balloon'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ...[
                _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) => 
                  setState(() => _kdfConfig['balloon']!['time_cost'] = v)),
                _buildKDFSlider('Space Cost (KB)', ((config['space_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) => 
                  setState(() => _kdfConfig['balloon']!['space_cost'] = v * 1024)),
                _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) => 
                  setState(() => _kdfConfig['balloon']!['parallelism'] = v)),
                _buildKDFSlider('Rounds', config['rounds'] ?? 2, 0, 1000000, (v) => 
                  setState(() => _kdfConfig['balloon']!['rounds'] = v)),
                _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 128, (v) => 
                  setState(() => _kdfConfig['balloon']!['hash_len'] = v)),
              ],
            ],
          ],
        ),
      ),
    );
  }

  /// Helper to build KDF slider
  Widget _buildKDFSlider(String label, int value, int min, int max, Function(int) onChanged) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
      child: Row(
        children: [
          SizedBox(width: 120, child: Text('$label:', style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurface))),
          // Decrement button with auto-repeat
          _buildAutoRepeatButton(
            icon: Icons.remove,
            color: Colors.orange,
            enabled: value > min,
            onAction: () => onChanged((value - 1).clamp(min, max)),
            size: 28,
            iconSize: 14,
          ),
          const SizedBox(width: 4),
          // Slider
          Expanded(
            child: Slider(
              value: value.toDouble(),
              min: min.toDouble(),
              max: max.toDouble(),
              divisions: (max - min) > 1000 ? max ~/ 100 : max - min, // Smart divisions
              label: value.toString(),
              onChanged: (double v) => onChanged(v.toInt()),
            ),
          ),
          const SizedBox(width: 4),
          // Increment button with auto-repeat
          _buildAutoRepeatButton(
            icon: Icons.add,
            color: Colors.orange,
            enabled: value < max,
            onAction: () => onChanged((value + 1).clamp(min, max)),
            size: 28,
            iconSize: 14,
          ),
          const SizedBox(width: 8),
          SizedBox(width: 60, child: Text(value.toString(), style: TextStyle(fontSize: 12, color: Theme.of(context).colorScheme.onSurface))),
        ],
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
    'aes-ocb3': 'AES-OCB3 high-performance authenticated encryption',
    'camellia': 'Camellia block cipher (International standard)',
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

  void _copyToClipboard(BuildContext context, String text) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Command copied to clipboard'),
        backgroundColor: Colors.green.shade600,
        duration: const Duration(seconds: 2),
      ),
    );
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
  String _password = '';
  String _confirmPassword = '';
  String _selectedOperation = 'encrypt'; // 'encrypt' or 'decrypt'
  final List<BatchOperationResult> _results = [];
  
  // Progress tracking
  int _currentFileIndex = 0;
  String _currentStatus = '';
  
  // Cached dropdown items for algorithms (performance optimization)
  static final Map<String, List<DropdownMenuItem<String>>> _dropdownCache = {};
  
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
                    
                    const SizedBox(height: 16),
                    
                    // Algorithm Selection (only for encryption)
                    if (_selectedOperation == 'encrypt') ...[
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
                                'aes-ocb3',
                                'camellia',
                                
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
                    ],
                    
                    // Password Fields
                    Row(
                      children: [
                        Expanded(
                          child: TextField(
                            obscureText: true,
                            enabled: !_isLoading,
                            onChanged: (value) => _password = value,
                            decoration: InputDecoration(
                              labelText: _selectedOperation == 'encrypt' ? 'Password' : 'Decryption Password',
                              border: const OutlineInputBorder(),
                              prefixIcon: const Icon(Icons.lock),
                            ),
                          ),
                        ),
                        if (_selectedOperation == 'encrypt') ...[
                          const SizedBox(width: 16),
                          Expanded(
                            child: TextField(
                              obscureText: true,
                              enabled: !_isLoading,
                              onChanged: (value) => _confirmPassword = value,
                              decoration: InputDecoration(
                                labelText: 'Confirm Password',
                                border: const OutlineInputBorder(),
                                prefixIcon: const Icon(Icons.lock_outline),
                                errorText: _password.isNotEmpty && _confirmPassword.isNotEmpty && _password != _confirmPassword
                                    ? 'Passwords do not match'
                                    : null,
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
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
                    : Icon(_selectedOperation == 'encrypt' ? Icons.lock : Icons.lock_open),
                label: _isLoading
                    ? Text('${_selectedOperation == 'encrypt' ? 'Encrypting' : 'Decrypting'} (${_currentFileIndex + 1}/${_selectedFiles.length})')
                    : Text('${_selectedOperation == 'encrypt' ? 'Encrypt' : 'Decrypt'} ${_selectedFiles.length} file(s)'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: _selectedOperation == 'encrypt' ? Colors.green : Colors.blue,
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
    if (_selectedFiles.isEmpty || _isLoading || _password.isEmpty) {
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
        
        // Encrypt using CLI service
        final encrypted = await CLIService.encryptText(content, _password, _selectedAlgorithm, null, null);
        
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
      } else {
        // Decrypt operation
        final content = await widget.fileManager.readFileText(file.path);
        if (content == null) {
          return BatchOperationResult(
            fileName: file.name,
            success: false,
            errorMessage: 'Could not read file content',
          );
        }
        
        // Decrypt using CLI service
        final decrypted = await CLIService.decryptText(content, _password);
        
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