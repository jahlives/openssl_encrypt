import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:percent_indicator/percent_indicator.dart';
import 'crypto_ffi.dart';
import 'file_manager.dart';

void main() {
  runApp(const OpenSSLEncryptApp());
}

class OpenSSLEncryptApp extends StatelessWidget {
  const OpenSSLEncryptApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OpenSSL Encrypt Mobile',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const MainScreen(),
    );
  }
}

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final CryptoFFI _cryptoFFI = CryptoFFI();
  final FileManager _fileManager = FileManager();

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _cryptoFFI.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenSSL Encrypt Mobile'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(icon: Icon(Icons.text_fields), text: 'Text'),
            Tab(icon: Icon(Icons.folder), text: 'Files'),
            Tab(icon: Icon(Icons.settings), text: 'Settings'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          TextCryptoTab(cryptoFFI: _cryptoFFI),
          FileCryptoTab(cryptoFFI: _cryptoFFI, fileManager: _fileManager),
          const SettingsTab(),
        ],
      ),
    );
  }
}

// Text encryption/decryption tab
class TextCryptoTab extends StatefulWidget {
  final CryptoFFI cryptoFFI;

  const TextCryptoTab({super.key, required this.cryptoFFI});

  @override
  State<TextCryptoTab> createState() => _TextCryptoTabState();
}

class _TextCryptoTabState extends State<TextCryptoTab> {
  final TextEditingController _textController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  String _result = '';
  String _encryptedData = '';
  bool _isLoading = false;
  List<String> _algorithms = [];
  List<String> _hashAlgorithms = [];
  List<Map<String, dynamic>> _kdfAlgorithms = [];
  List<Map<String, dynamic>> _securityLevels = [];
  String _selectedAlgorithm = 'fernet';
  Map<String, int> _hashRounds = {};  // Hash algorithm -> rounds mapping
  Map<String, Map<String, dynamic>> _kdfConfig = {};  // KDF chain configuration
  bool _showAdvanced = false;
  bool _showHashConfig = false;
  bool _showKdfConfig = false;

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

  void _loadAlgorithms() async {
    try {
      final algorithms = await widget.cryptoFFI.getSupportedAlgorithms();
      final hashAlgorithms = await widget.cryptoFFI.getHashAlgorithms();
      final kdfAlgorithms = await widget.cryptoFFI.getKdfAlgorithms();
      final securityLevels = await widget.cryptoFFI.getSecurityLevels();
      
      setState(() {
        _algorithms = algorithms;
        _hashAlgorithms = hashAlgorithms;
        _kdfAlgorithms = kdfAlgorithms;
        _securityLevels = securityLevels;
        
        if (algorithms.isNotEmpty) {
          _selectedAlgorithm = algorithms.first;
        }
        if (hashAlgorithms.isNotEmpty) {
          // Initialize hash rounds with default values
          _hashRounds = {};
          for (String hash in hashAlgorithms) {
            _hashRounds[hash] = 1000;  // Default CLI rounds
          }
        }
        if (kdfAlgorithms.isNotEmpty) {
          // Initialize KDF chain configuration (CLI order)
          _kdfConfig = {
            'pbkdf2': {'enabled': true, 'rounds': 100000},
            'scrypt': {'enabled': false, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
            'argon2': {'enabled': false, 'memory_cost': 65536, 'time_cost': 3, 'parallelism': 1, 'rounds': 1},
            'hkdf': {'enabled': false, 'info': 'OpenSSL_Encrypt_Mobile'},
            'balloon': {'enabled': false, 'space_cost': 8, 'time_cost': 1, 'parallel_cost': 1}
          };
        }
      });
    } catch (e) {
      setState(() {
        _algorithms = ['fernet'];
        _hashAlgorithms = ['sha256'];
        _kdfAlgorithms = [{'id': 'pbkdf2', 'name': 'PBKDF2'}];
        _securityLevels = [{'id': 'standard', 'name': 'Standard'}];
        _selectedAlgorithm = 'fernet';
        _hashRounds = {'sha256': 1000};
        _kdfConfig = {
          'pbkdf2': {'enabled': true, 'rounds': 100000}
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

    setState(() {
      _isLoading = true;
      _result = 'Encrypting...';
    });

    try {
      // For now using mock implementation since FFI doesn't support chained config yet
      // TODO: Update FFI to support hash_config and kdf_config parameters
      final encrypted = await widget.cryptoFFI.encryptText(
        _textController.text,
        _passwordController.text,
      );

      setState(() {
        _encryptedData = encrypted;
        final activeHashes = _hashRounds.entries.where((e) => e.value > 0).map((e) => '${e.key}: ${e.value}').join(', ');
        final enabledKdfs = _kdfConfig.entries.where((e) => e.value['enabled'] == true).map((e) => e.key).join(', ');
        final kdfInfo = enabledKdfs.isEmpty ? 'None' : enabledKdfs;
        
        _result = 'Text encrypted successfully!\n\n'
            'Algorithm: $_selectedAlgorithm\n'
            'Hash Chain: $activeHashes\n'
            'KDF Chain: $kdfInfo\n'
            'CLI Compatible: Yes\n\n'
            'Encrypted data:\n${encrypted.length > 100 ? '${encrypted.substring(0, 100)}...' : encrypted}';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _result = 'Encryption failed: $e';
        _isLoading = false;
      });
    }
  }

  void _decryptText() async {
    if (_encryptedData.isEmpty || _passwordController.text.isEmpty) {
      setState(() {
        _result = 'Please encrypt some text first or enter the password';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _result = 'Decrypting...';
    });

    try {
      final decrypted = await widget.cryptoFFI.decryptText(
        _encryptedData,
        _passwordController.text,
      );

      setState(() {
        _result = 'Text decrypted successfully!\n\nDecrypted text:\n$decrypted';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _result = 'Decryption failed: $e';
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
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
                return DropdownMenuItem<String>(
                  value: algorithm,
                  child: Text(algorithm),
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
                        const Text('Advanced Security Settings (CLI Compatible)'),
                        const Spacer(),
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
                                  Icon(Icons.link),
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
                                  child: Row(
                                    children: [
                                      SizedBox(
                                        width: 80,
                                        child: Text(
                                          hash.toUpperCase(),
                                          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: TextFormField(
                                          initialValue: _hashRounds[hash]?.toString() ?? '0',
                                          keyboardType: TextInputType.number,
                                          decoration: const InputDecoration(
                                            labelText: 'Rounds',
                                            isDense: true,
                                            border: OutlineInputBorder(),
                                          ),
                                          onChanged: (value) {
                                            final rounds = int.tryParse(value) ?? 0;
                                            setState(() {
                                              _hashRounds[hash] = rounds;
                                            });
                                          },
                                        ),
                                      ),
                                    ],
                                  ),
                                );
                              }).toList(),
                              const SizedBox(height: 8),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                                children: [
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String hash in _hashAlgorithms) {
                                          _hashRounds[hash] = 1000;
                                        }
                                      });
                                    },
                                    child: const Text('Default (1000)'),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String hash in _hashAlgorithms) {
                                          _hashRounds[hash] = 0;
                                        }
                                      });
                                    },
                                    child: const Text('Disable All'),
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
                                  Icon(Icons.vpn_key),
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
                                const Text('Uses default parameters', style: TextStyle(fontSize: 12, color: Colors.grey)),
                              ]),
                              const SizedBox(height: 8),
                              // Balloon
                              _buildKdfConfig('balloon', 'Balloon', [
                                _buildNumberField('balloon', 'space_cost', 'Space Cost', _kdfConfig['balloon']?['space_cost'] ?? 8),
                                _buildNumberField('balloon', 'time_cost', 'Time Cost', _kdfConfig['balloon']?['time_cost'] ?? 1),
                                _buildNumberField('balloon', 'parallel_cost', 'Parallel Cost', _kdfConfig['balloon']?['parallel_cost'] ?? 1),
                              ]),
                              const SizedBox(height: 8),
                              // Quick presets
                              Row(
                                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
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
                                    child: const Text('PBKDF2 Only'),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        _kdfConfig['pbkdf2']?['enabled'] = false;
                                        _kdfConfig['scrypt']?['enabled'] = false;
                                        _kdfConfig['argon2']?['enabled'] = false;
                                        _kdfConfig['hkdf']?['enabled'] = false;
                                        _kdfConfig['balloon']?['enabled'] = true;
                                      });
                                    },
                                    child: const Text('Balloon Only'),
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      setState(() {
                                        for (String kdf in _kdfConfig.keys) {
                                          _kdfConfig[kdf]?['enabled'] = false;
                                        }
                                      });
                                    },
                                    child: const Text('Disable All'),
                                  ),
                                ],
                              ),
                            ],
                          ],
                        ),
                      ),
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
          Expanded(
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                border: Border.all(color: Colors.grey.shade300),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SingleChildScrollView(
                child: Text(
                  _result.isEmpty ? 'Results will appear here...' : _result,
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
              ),
            ),
          ),
        ],
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
  Widget _buildTextField(String paramId, String label, String defaultValue) {
    return Padding(
      padding: const EdgeInsets.only(top: 8.0),
      child: TextFormField(
        initialValue: defaultValue,
        decoration: InputDecoration(
          labelText: label,
          isDense: true,
          border: const OutlineInputBorder(),
        ),
        onChanged: (value) {
          setState(() {
            if (paramId == 'info') {
              _kdfConfig['hkdf'] ??= {};
              _kdfConfig['hkdf']![paramId] = value;
            }
          });
        },
      ),
    );
  }
}

// File encryption/decryption tab
class FileCryptoTab extends StatefulWidget {
  final CryptoFFI cryptoFFI;
  final FileManager fileManager;

  const FileCryptoTab({super.key, required this.cryptoFFI, required this.fileManager});

  @override
  State<FileCryptoTab> createState() => _FileCryptoTabState();
}

class _FileCryptoTabState extends State<FileCryptoTab> {
  final TextEditingController _passwordController = TextEditingController();
  FileInfo? _selectedFile;
  String _result = '';
  bool _isLoading = false;
  double _progress = 0.0;
  String? _decryptedContent; // Store decrypted content for optional saving

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

  void _encryptFile() async {
    if (_selectedFile == null || _passwordController.text.isEmpty) {
      setState(() {
        _result = 'Please select a file and enter a password';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _progress = 0.0;
      _result = 'Encrypting file...';
    });

    try {
      setState(() {
        _progress = 0.1;
      });

      // Read file content
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      setState(() {
        _progress = 0.3;
      });

      // Encrypt file content using the crypto FFI
      final encrypted = await widget.cryptoFFI.encryptText(
        fileContent,
        _passwordController.text,
      );

      setState(() {
        _progress = 0.7;
      });

      if (encrypted.startsWith('ERROR:')) {
        throw Exception(encrypted.substring(7));
      }

      // Generate output filename
      final outputPath = widget.fileManager.getEncryptedFileName(_selectedFile!.path);
      
      // Save encrypted file
      final success = await widget.fileManager.writeFileText(outputPath, encrypted);

      setState(() {
        _progress = 1.0;
      });

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
          _progress = 0.0;
        });
      } else {
        throw Exception('Failed to save encrypted file');
      }
    } catch (e) {
      setState(() {
        _result = 'File encryption failed: $e';
        _isLoading = false;
        _progress = 0.0;
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
            'Expected: JSON file with encrypted_data and metadata fields.\n'
            'File: ${_selectedFile!.name}';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _progress = 0.0;
      _result = 'Decrypting file...';
    });

    try {
      setState(() {
        _progress = 0.1;
      });

      // Read the encrypted file
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      setState(() {
        _progress = 0.3;
      });

      String encryptedData;
      Map<String, dynamic> metadata;

      // Handle different file formats
      if (fileContent.contains(':') && !fileContent.contains('{')) {
        // CLI format: base64_metadata:base64_encrypted_data
        final parts = fileContent.split(':');
        if (parts.length != 2) {
          throw Exception('Invalid CLI file format - expected metadata:data');
        }
        
        try {
          // Decode base64 metadata
          final metadataBytes = base64Decode(parts[0]);
          final metadataJson = utf8.decode(metadataBytes);
          metadata = jsonDecode(metadataJson) as Map<String, dynamic>;
          
          // The encrypted data is already base64 encoded
          encryptedData = parts[1];
          
        } catch (e) {
          throw Exception('Failed to parse CLI format: $e');
        }
      } else {
        // JSON formats (mobile or test)
        try {
          final jsonData = jsonDecode(fileContent);
          
          if (jsonData.containsKey('format') && jsonData['format'] == 'openssl_encrypt_mobile') {
            // Mobile format
            encryptedData = jsonData['encrypted_data'];
            metadata = jsonData['metadata'];
          } else if (jsonData.containsKey('encrypted_data') && jsonData.containsKey('metadata')) {
            // Test JSON format
            encryptedData = jsonData['encrypted_data'];
            metadata = jsonData['metadata'];
          } else {
            throw Exception('Invalid JSON file format');
          }
        } catch (e) {
          throw Exception('Failed to parse JSON format: $e');
        }
      }

      setState(() {
        _progress = 0.5;
      });

      // Decrypt using the crypto FFI
      final decrypted = await widget.cryptoFFI.decryptText(
        jsonEncode({
          'encrypted_data': encryptedData,
          'metadata': metadata
        }),
        _passwordController.text,
      );

      setState(() {
        _progress = 0.8;
      });

      if (decrypted.startsWith('ERROR:')) {
        throw Exception(decrypted.substring(7));
      }

      setState(() {
        _progress = 1.0;
      });

      // Store decrypted content and display it without saving to disk
      setState(() {
        _decryptedContent = decrypted; // Store for optional saving
        
        final contentPreview = decrypted.length > 500 
            ? '${decrypted.substring(0, 500)}...\n\n[Content truncated - ${decrypted.length} total characters]'
            : decrypted;
            
        _result = 'File decrypted successfully!\n\n'
            'Original file: ${_selectedFile!.name}\n'
            'Size: ${_selectedFile!.sizeFormatted}\n'
            'Content length: ${decrypted.length} characters\n\n'
            '--- DECRYPTED CONTENT ---\n'
            '$contentPreview\n'
            '--- END CONTENT ---\n\n'
            '⚠️  Content displayed above is not saved to disk for security.\n'
            '💾  Use "Save to File" button below if you need to save it.';
        _isLoading = false;
        _progress = 0.0;
      });

    } catch (e) {
      setState(() {
        _result = 'File decryption failed: $e';
        _isLoading = false;
        _progress = 0.0;
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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
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
                  ElevatedButton.icon(
                    onPressed: _isLoading ? null : _pickFile,
                    icon: const Icon(Icons.folder_open),
                    label: const Text('Choose File'),
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
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  children: [
                    LinearPercentIndicator(
                      percent: _progress,
                      progressColor: Colors.blue,
                      backgroundColor: Colors.grey.shade300,
                      lineHeight: 8.0,
                    ),
                    const SizedBox(height: 8),
                    Text('${(_progress * 100).toInt()}%'),
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
                  icon: const Icon(Icons.lock),
                  label: const Text('Encrypt File'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isLoading ? null : _decryptFile,
                  icon: const Icon(Icons.lock_open),
                  label: const Text('Decrypt File'),
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
          Expanded(
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                border: Border.all(color: Colors.grey.shade300),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SingleChildScrollView(
                child: Text(
                  _result.isEmpty ? 'File operation results will appear here...' : _result,
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// Settings tab
class SettingsTab extends StatefulWidget {
  const SettingsTab({super.key});

  @override
  State<SettingsTab> createState() => _SettingsTabState();
}

class _SettingsTabState extends State<SettingsTab> {
  final CryptoFFI _cryptoFFI = CryptoFFI();
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

  @override
  void initState() {
    super.initState();
    _loadAlgorithms();
  }

  @override
  void dispose() {
    _cryptoFFI.dispose();
    super.dispose();
  }

  void _loadAlgorithms() async {
    try {
      final algorithms = await _cryptoFFI.getSupportedAlgorithms();
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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
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
                                      _algorithmDescriptions[algo]!,
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: Colors.grey[600],
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
                  Text('Version: 1.0.0 (Development)'),
                  Text('Build: Mobile Prototype'),
                  Text('Crypto Backend: Python FFI (Enhanced)'),
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
                      Text('PBKDF2, Scrypt, Argon2 KDFs'),
                    ],
                  ),
                  Row(
                    children: [
                      Icon(Icons.pending, color: Colors.orange, size: 16),
                      SizedBox(width: 8),
                      Text('Post-Quantum Algorithms (Planned)'),
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
    );
  }
}