import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'cli_service.dart';
import 'file_manager.dart';

void main() async {
  // Initialize Flutter framework
  WidgetsFlutterBinding.ensureInitialized();
  
  // Initialize CLI service
  final cliAvailable = await CLIService.initialize();
  if (!cliAvailable) {
    print('WARNING: OpenSSL Encrypt CLI not found. Some features may not work.');
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

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OpenSSL Encrypt Desktop',
      debugShowCheckedModeBanner: _showDebugBanner,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: MainScreen(onDebugChanged: _updateDebugBanner),
    );
  }
}

class MainScreen extends StatefulWidget {
  final Function(bool) onDebugChanged;
  
  const MainScreen({super.key, required this.onDebugChanged});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final FileManager _fileManager = FileManager();

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenSSL Encrypt Desktop'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(icon: Icon(Icons.text_fields), text: 'Text'),
            Tab(icon: Icon(Icons.folder), text: 'Files'),
            Tab(icon: Icon(Icons.info), text: 'Info'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          TextCryptoTab(onDebugChanged: widget.onDebugChanged),
          FileCryptoTab(fileManager: _fileManager, onDebugChanged: widget.onDebugChanged),
          const InfoTab(),
        ],
      ),
    );
  }
}

// Text encryption/decryption tab
class TextCryptoTab extends StatefulWidget {
  final Function(bool) onDebugChanged;

  const TextCryptoTab({super.key, required this.onDebugChanged});

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
  List<String> _algorithms = [];
  List<String> _hashAlgorithms = [];
  // Note: KDF algorithms and security levels are configured directly in _kdfConfig
  String _selectedAlgorithm = 'fernet';
  Map<String, Map<String, dynamic>> _hashConfig = {};  // Hash algorithm -> {enabled, rounds} mapping
  Map<String, Map<String, dynamic>> _kdfConfig = {};  // KDF chain configuration
  bool _showAdvanced = false;
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
    try {
      final algorithms = await CLIService.getSupportedAlgorithms();
      final hashAlgorithms = await CLIService.getHashAlgorithms();
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
              'enabled': hash != 'blake3' && hash != 'shake256',  // BLAKE3 and SHAKE256 disabled (not yet supported), others enabled for CLI compatibility
              'rounds': (hash == 'blake3' || hash == 'shake256') ? 0 : 1000    // Unsupported algorithms get 0 rounds, others get default CLI rounds
            };
          }
        }
        // Initialize KDF chain configuration (CLI order)
        _kdfConfig = {
          'pbkdf2': {'enabled': true, 'rounds': 100000},
          'scrypt': {'enabled': false, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
          'argon2': {'enabled': false, 'memory_cost': 65536, 'time_cost': 3, 'parallelism': 1, 'rounds': 1},
          'hkdf': {'enabled': false, 'info': 'openssl_encrypt_hkdf', 'rounds': 1},
          'balloon': {'enabled': false, 'space_cost': 8, 'time_cost': 1, 'parallel_cost': 1, 'rounds': 1}
        };
      });
    } catch (e) {
      setState(() {
        _algorithms = ['fernet'];
        _hashAlgorithms = ['sha256'];
        _selectedAlgorithm = 'fernet';
        _hashConfig = {'sha256': {'enabled': true, 'rounds': 1000}};
        _kdfConfig = {
          'pbkdf2': {'enabled': true, 'rounds': 100000},
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
      _result = 'Encrypting...';
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      // Pass selected algorithm and UI configurations to CLI service
      final encrypted = await CLIService.encryptText(
        _textController.text,
        _passwordController.text,
        _selectedAlgorithm, // Pass the selected algorithm
        _hashConfig,        // Pass hash configuration from UI
        _kdfConfig,         // Pass KDF configuration from UI
      );

      setState(() {
        _encryptedData = encrypted;
        _result = encrypted; // Show only the base64 encoded string
        _isLoading = false;
        _operationStatus = '';
      });
    } catch (e) {
      setState(() {
        _result = 'Encryption failed: $e';
        _isLoading = false;
        _operationStatus = '';
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
      _result = 'Decrypting...';
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      final decrypted = await CLIService.decryptText(
        inputData,
        _passwordController.text,
      );

      setState(() {
        _result = decrypted; // Show only the decrypted text
        _isLoading = false;
        _operationStatus = '';
      });
    } catch (e) {
      setState(() {
        _result = 'Decryption failed: $e';
        _isLoading = false;
        _operationStatus = '';
      });
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
          if (_algorithms.isNotEmpty)
            DropdownButtonFormField<String>(
              value: _selectedAlgorithm,
              decoration: const InputDecoration(
                labelText: 'Encryption Algorithm',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.security),
              ),
              items: _algorithms.map((String algorithm) {
                final isAvailable = _isAlgorithmAvailable(algorithm);
                return DropdownMenuItem<String>(
                  value: algorithm,
                  enabled: isAvailable,
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Flexible(
                        child: Text(
                          algorithm,
                          style: TextStyle(
                            color: isAvailable ? null : Colors.grey,
                            fontStyle: isAvailable ? null : FontStyle.italic,
                          ),
                        ),
                      ),
                      if (!isAvailable) ...[
                        const SizedBox(width: 4),
                        const Icon(
                          Icons.info_outline,
                          size: 16,
                          color: Colors.orange,
                        ),
                      ],
                    ],
                  ),
                );
              }).toList(),
              onChanged: (String? newValue) {
                if (newValue != null) {
                  setState(() {
                    _selectedAlgorithm = newValue;
                  });
                }
              },
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
                              const Text(
                                'Configure hash algorithms and rounds (CLI order)',
                                style: TextStyle(fontSize: 12, color: Colors.grey),
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
                                          // Only enable supported algorithms (exclude BLAKE3 and SHAKE256)
                                          final isSupported = hash != 'blake3' && hash != 'shake256';
                                          _hashConfig[hash] = {
                                            'enabled': isSupported, 
                                            'rounds': isSupported ? 1000 : 0
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
                                          // Only enable supported algorithms (exclude BLAKE3 and SHAKE256)  
                                          final isSupported = hash != 'blake3' && hash != 'shake256';
                                          _hashConfig[hash] = {
                                            'enabled': isSupported,
                                            'rounds': isSupported ? 1000 : 0
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
                              const Text(
                                'Configure KDF algorithms and parameters (CLI order)',
                                style: TextStyle(fontSize: 12, color: Colors.grey),
                              ),
                              const SizedBox(height: 12),
                              // PBKDF2
                              _buildKdfConfig('pbkdf2', 'PBKDF2', [
                                _buildNumberField('pbkdf2', 'rounds', 'Rounds', _kdfConfig['pbkdf2']?['rounds'] ?? 100000)
                              ]),
                              const SizedBox(height: 8),
                              // Scrypt  
                              _buildKdfConfig('scrypt', 'Scrypt', [
                                _buildNumberField('scrypt', 'rounds', 'Rounds', _kdfConfig['scrypt']?['rounds'] ?? 1),
                              ]),
                              const SizedBox(height: 8),
                              // Argon2
                              _buildKdfConfig('argon2', 'Argon2', [
                                _buildNumberField('argon2', 'rounds', 'Rounds', _kdfConfig['argon2']?['rounds'] ?? 1),
                              ]),
                              const SizedBox(height: 8),
                              // HKDF
                              _buildKdfConfig('hkdf', 'HKDF', [
                                _buildNumberField('hkdf', 'rounds', 'Rounds', _kdfConfig['hkdf']?['rounds'] ?? 1),
                              ]),
                              const SizedBox(height: 8),
                              // Balloon
                              _buildKdfConfig('balloon', 'Balloon', [
                                _buildNumberField('balloon', 'rounds', 'Rounds', _kdfConfig['balloon']?['rounds'] ?? 1),
                              ]),
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
                                        _kdfConfig['pbkdf2']?['enabled'] = true;
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
                              color: _debugLogging ? Colors.orange.shade700 : Colors.grey.shade600,
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
              color: Colors.orange.shade100,
              elevation: 8,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    const CircularProgressIndicator(color: Colors.orange),
                    const SizedBox(height: 12),
                    Text(
                      _operationStatus.isNotEmpty ? _operationStatus : 'Crypto operation in progress...',
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.orange.shade800),
                    ),
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
                    border: Border.all(color: Colors.grey.shade300),
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
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Result copied to clipboard'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      }
                    },
                    backgroundColor: Colors.blue,
                    child: const Icon(Icons.copy, size: 16, color: Colors.white),
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
  Widget _buildKdfConfig(String kdfId, String kdfName, List<Widget> paramFields) {
    final isEnabled = _kdfConfig[kdfId]?['enabled'] ?? false;
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(color: isEnabled ? Colors.green : Colors.grey.shade300),
        borderRadius: BorderRadius.circular(8),
        color: isEnabled ? Colors.green.shade50 : Colors.grey.shade50,
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: isEnabled,
                onChanged: (bool value) {
                  setState(() {
                    if (_kdfConfig[kdfId] == null) {
                      _kdfConfig[kdfId] = {};
                    }
                    _kdfConfig[kdfId]!['enabled'] = value;
                    
                    // Special case for PBKDF2: set rounds to 0 when disabled
                    // This ensures CLI compatibility (CLI uses rounds > 0 for enablement)
                    if (kdfId == 'pbkdf2' && !value) {
                      _kdfConfig[kdfId]!['rounds'] = 0;
                    } else if (kdfId == 'pbkdf2' && value) {
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
                  color: isEnabled ? Colors.green.shade700 : Colors.grey.shade600,
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
    
    // BLAKE3 and SHAKE256 are not yet supported in mobile app
    final isBlake3 = hashId == 'blake3';
    final isShake256 = hashId == 'shake256';
    final isUnsupported = isBlake3 || isShake256;
    final effectiveEnabled = isUnsupported ? false : isEnabled;
    
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(color: effectiveEnabled ? Colors.blue : (isUnsupported ? Colors.orange.shade300 : Colors.grey.shade300)),
        borderRadius: BorderRadius.circular(8),
        color: effectiveEnabled ? Colors.blue.shade50 : (isUnsupported ? Colors.orange.shade50 : Colors.grey.shade50),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: effectiveEnabled,
                onChanged: isUnsupported ? null : (bool value) {
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
                    color: effectiveEnabled ? Colors.blue.shade700 : (isUnsupported ? Colors.orange.shade700 : Colors.grey.shade600),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              if (effectiveEnabled)
                Expanded(
                  child: TextFormField(
                    initialValue: rounds.toString(),
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: 'Rounds',
                      isDense: true,
                      border: OutlineInputBorder(),
                    ),
                    onChanged: (value) {
                      final newRounds = int.tryParse(value) ?? 1000;
                      setState(() {
                        _hashConfig[hashId]!['rounds'] = newRounds;
                      });
                    },
                  ),
                ),
              if (isUnsupported)
                Expanded(
                  child: Text(
                    'Not yet supported',
                    style: TextStyle(
                      fontSize: 12,
                      fontStyle: FontStyle.italic,
                      color: Colors.orange.shade700,
                    ),
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  // Helper method to build number input fields  
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
            child: ListView.builder(
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

    // File encryption uses default algorithm (fernet) which is available on all platforms

    setState(() {
      _isLoading = true;
      _result = 'Encrypting file...';
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      // Read file content
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      // Encrypt file content using CLI service
      final encrypted = await CLIService.encryptText(
        fileContent,
        _passwordController.text,
        'fernet', // Default algorithm
        null,     // No hash config
        null,     // No KDF config
      );

      if (encrypted.startsWith('ERROR:')) {
        throw Exception(encrypted.substring(7));
      }

      // Generate output filename
      final outputPath = widget.fileManager.getEncryptedFileName(_selectedFile!.path);
      
      // Save encrypted file
      final success = await widget.fileManager.writeFileText(outputPath, encrypted);

      if (success) {
        setState(() {
          _result = 'File encrypted successfully!\n\n'
              'Original: ${_selectedFile!.name}\n'
              'Size: ${_selectedFile!.sizeFormatted}\n'
              'Encrypted: ${outputPath.split('/').last}\n'
              'Saved to: $outputPath\n\n'
              'CLI Compatible: Yes\n'
              'Format: OpenSSL Encrypt Mobile v2.1';
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
    });

    // Give UI a moment to update before heavy crypto operations
    await Future.delayed(const Duration(milliseconds: 50));

    try {
      // Read the encrypted file
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      // Decrypt using CLI service
      final decrypted = await CLIService.decryptText(
        fileContent,  // Pass raw file content
        _passwordController.text,
      );

      if (decrypted.startsWith('ERROR:')) {
        throw Exception(decrypted.substring(7));
      }

      // Store decrypted content and display it without saving to disk
      setState(() {
        _decryptedContent = decrypted; // Store for optional saving
        _result = decrypted; // Show only the decrypted content
        _isLoading = false;
      });

    } catch (e) {
      setState(() {
        _result = 'File decryption failed: $e';
        _isLoading = false;
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
                      color: _debugLogging ? Colors.orange.shade700 : Colors.grey.shade600,
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
              color: Colors.orange.shade100,
              elevation: 8,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    const CircularProgressIndicator(color: Colors.orange),
                    const SizedBox(height: 12),
                    Text(
                      'Crypto operation in progress...',
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.orange.shade800),
                    ),
                  ],
                ),
              ),
            ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _encryptFile,
                  icon: Icon(Icons.lock, color: _isLoading ? Colors.grey : null),
                  label: Text(_isLoading ? 'LOCKED - Encrypting...' : 'Encrypt File'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _isLoading ? Colors.grey.shade300 : null,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _decryptFile,
                  icon: Icon(Icons.lock_open, color: _isLoading ? Colors.grey : null),
                  label: Text(_isLoading ? 'LOCKED - Decrypting...' : 'Decrypt File'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _isLoading ? Colors.grey.shade300 : null,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // Save to File button (only shown when decrypted content is available)
          if (_decryptedContent != null)
            Container(
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
                    border: Border.all(color: Colors.grey.shade300),
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
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Result copied to clipboard'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      }
                    },
                    backgroundColor: Colors.blue,
                    child: const Icon(Icons.copy, size: 16, color: Colors.white),
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

// Info tab
class InfoTab extends StatefulWidget {
  const InfoTab({super.key});

  @override
  State<InfoTab> createState() => _InfoTabState();
}

class _InfoTabState extends State<InfoTab> {
  List<String> _algorithms = [];
  Map<String, String> _algorithmDescriptions = {
    'fernet': 'AES-128-CBC with HMAC authentication (Default)',
    'aes-gcm': 'AES-256-GCM authenticated encryption',
    'chacha20-poly1305': 'ChaCha20 stream cipher with Poly1305 MAC',
    'xchacha20-poly1305': 'Extended ChaCha20-Poly1305 with 192-bit nonce',
    'aes-siv': 'AES-SIV synthetic IV mode',
    'aes-gcm-siv': 'AES-GCM-SIV misuse-resistant encryption',
    'aes-ocb3': 'AES-OCB3 high-performance authenticated encryption',
    'camellia': 'Camellia block cipher (International standard)',
  };

  // Python-only algorithms that are no longer available
  static const Set<String> _pythonOnlyAlgorithms = {
    'aes-siv',
    'aes-gcm-siv', 
    'aes-ocb3',
  };

  /// Check if algorithm is available on current platform
  bool _isAlgorithmAvailable(String algorithm) {
    // These algorithms were only available with Python backend, now unavailable
    if (_pythonOnlyAlgorithms.contains(algorithm)) {
      return false;
    }
    return true;
  }

  /// Get platform-specific description for algorithm
  String _getAlgorithmDescription(String algorithm) {
    final baseDescription = _algorithmDescriptions[algorithm] ?? algorithm;
    if (_pythonOnlyAlgorithms.contains(algorithm)) {
      return '$baseDescription (Requires Python backend - not available)';
    }
    return baseDescription;
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
    try {
      final algorithms = await CLIService.getSupportedAlgorithms();
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
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'App Information',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  SizedBox(height: 8),
                  Text('Version: 1.0.0 (Desktop Development)'),
                  Text('Build: Desktop GUI Prototype'),
                  Text('Crypto Backend: CLI Integration'),
                  Text('Hash Chaining: CLI Compatible Order'),
                  Text('Platform: Flutter'),
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
                      Icon(Icons.pending, color: Colors.orange, size: 16),
                      SizedBox(width: 8),
                      Text('Biometric Authentication (Planned)'),
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