import 'package:flutter/material.dart';
import '../cli_service.dart';
import '../file_manager.dart';
import '../widgets/crypto_widgets.dart';

class EncryptTab extends StatefulWidget {
  final FileManager fileManager;

  const EncryptTab({super.key, required this.fileManager});

  @override
  State<EncryptTab> createState() => _EncryptTabState();
}

class _EncryptTabState extends State<EncryptTab> {
  // Input mode toggle
  bool _isFileMode = false;

  // Text input controllers
  final TextEditingController _textController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  // File input
  FileInfo? _selectedFile;

  // Encryption mode
  EncryptionMode _encryptionMode = EncryptionMode.symmetric;

  // Algorithm (for symmetric mode)
  String _selectedAlgorithm = 'aes-gcm';

  // Loading state
  bool _isLoading = false;
  String result = '';

  // Hash configuration
  bool _showHashConfig = false;
  Map<String, Map<String, dynamic>> _hashConfig = {};
  Map<String, List<String>> _hashAlgorithms = {};

  // KDF configuration
  bool _showKdfConfig = false;
  Map<String, Map<String, dynamic>> _kdfConfig = {
    'argon2': {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 10},
    'scrypt': {'enabled': false, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 10},
    'hkdf': {'enabled': false, 'rounds': 1, 'algorithm': 'sha256', 'info': 'openssl_encrypt_hkdf'},
    'balloon': {'enabled': false, 'time_cost': 3, 'space_cost': 65536, 'parallelism': 4, 'rounds': 2, 'hash_len': 32},
    'randomx': {'enabled': false, 'mode': 'light', 'rounds': 1, 'height': 1, 'hash_len': 32},
  };

  // HSM settings
  String _hsmType = 'none';
  int _yubikeySlot = 1;

  // Integrity
  bool _enableIntegrity = false;

  // File-specific options
  bool _forceOverwrite = false;

  // Asymmetric encryption options
  final List<String> _recipientIdentities = [];
  final TextEditingController _recipientIdentityController = TextEditingController();
  final TextEditingController _identityStorePathController = TextEditingController();
  String _signingIdentity = '';
  bool _useKeyserver = false;

  @override
  void initState() {
    super.initState();
    _loadHashAlgorithms();
  }

  @override
  void dispose() {
    _textController.dispose();
    _passwordController.dispose();
    _recipientIdentityController.dispose();
    _identityStorePathController.dispose();
    super.dispose();
  }

  Future<void> _loadHashAlgorithms() async {
    try {
      final algorithms = await CLIService.getHashAlgorithms();
      setState(() {
        _hashAlgorithms = algorithms;
        // Initialize hash config with default values
        for (final group in algorithms.values) {
          for (final algo in group) {
            // Enable sha3-512 by default with 100000 rounds
            if (algo == 'sha3-512') {
              _hashConfig[algo] = {'enabled': true, 'rounds': 100000};
            } else {
              _hashConfig[algo] = {'enabled': false, 'rounds': 1000};
            }
          }
        }
      });
    } catch (e) {
      CLIService.outputDebugLog('Failed to load hash algorithms: $e');
    }
  }

  Future<void> _pickFile() async {
    final file = await widget.fileManager.pickFile();
    if (file != null) {
      setState(() {
        _selectedFile = file;
      });
    }
  }

  Future<void> _encrypt() async {
    if (_isFileMode) {
      await _encryptFile();
    } else {
      await _encryptText();
    }
  }

  Future<void> _encryptText() async {
    if (_textController.text.isEmpty || _passwordController.text.isEmpty) {
      setState(() {
        result = 'Please enter both text and password';
      });
      return;
    }

    // Validate asymmetric mode requirements
    if (_encryptionMode == EncryptionMode.asymmetric) {
      if (_signingIdentity.isEmpty) {
        setState(() {
          result = 'Please enter a signing identity for asymmetric encryption';
        });
        return;
      }
      if (_recipientIdentities.isEmpty) {
        setState(() {
          result = 'Please add at least one recipient identity for asymmetric encryption';
        });
        return;
      }
    }

    setState(() {
      _isLoading = true;
      result = 'Encrypting...';
    });

    try {
      final encrypted = await CLIService.encryptTextWithProgress(
        _textController.text,
        _passwordController.text,
        _selectedAlgorithm,
        _encryptionMode == EncryptionMode.symmetric ? _buildHashConfigMap() : null,
        _encryptionMode == EncryptionMode.symmetric ? _buildKdfConfigMap() : null,
        hsmPlugin: _hsmType != 'none' ? _hsmType : null,
        hsmSlot: _hsmType == 'yubikey' ? _yubikeySlot : null,
        enableIntegrity: _enableIntegrity,
        forIdentities: _encryptionMode == EncryptionMode.asymmetric ? _recipientIdentities : null,
        signWith: _encryptionMode == EncryptionMode.asymmetric ? _signingIdentity : null,
        useKeyserver: _encryptionMode == EncryptionMode.asymmetric ? _useKeyserver : false,
        identityStore: _encryptionMode == EncryptionMode.asymmetric && _identityStorePathController.text.isNotEmpty ? _identityStorePathController.text : null,
      );

      setState(() {
        result = 'Encrypted successfully!\n\n$encrypted';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        result = 'Encryption failed: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _encryptFile() async {
    if (_selectedFile == null || _passwordController.text.isEmpty) {
      setState(() {
        result = 'Please select a file and enter a password';
      });
      return;
    }

    // Validate asymmetric mode requirements
    if (_encryptionMode == EncryptionMode.asymmetric) {
      if (_signingIdentity.isEmpty) {
        setState(() {
          result = 'Please enter a signing identity for asymmetric encryption';
        });
        return;
      }
      if (_recipientIdentities.isEmpty) {
        setState(() {
          result = 'Please add at least one recipient identity for asymmetric encryption';
        });
        return;
      }
    }

    setState(() {
      _isLoading = true;
      result = 'Encrypting file...';
    });

    try {
      // Read file content
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      // Encrypt content
      final encrypted = await CLIService.encryptTextWithProgress(
        fileContent,
        _passwordController.text,
        _selectedAlgorithm,
        _encryptionMode == EncryptionMode.symmetric ? _buildHashConfigMap() : null,
        _encryptionMode == EncryptionMode.symmetric ? _buildKdfConfigMap() : null,
        hsmPlugin: _hsmType != 'none' ? _hsmType : null,
        hsmSlot: _hsmType == 'yubikey' ? _yubikeySlot : null,
        enableIntegrity: _enableIntegrity,
        forIdentities: _encryptionMode == EncryptionMode.asymmetric ? _recipientIdentities : null,
        signWith: _encryptionMode == EncryptionMode.asymmetric ? _signingIdentity : null,
        useKeyserver: _encryptionMode == EncryptionMode.asymmetric ? _useKeyserver : false,
        identityStore: _encryptionMode == EncryptionMode.asymmetric && _identityStorePathController.text.isNotEmpty ? _identityStorePathController.text : null,
      );

      // Save encrypted file
      final outputPath = _forceOverwrite
          ? _selectedFile!.path
          : widget.fileManager.getEncryptedFileName(_selectedFile!.path);

      final success = await widget.fileManager.writeFileText(outputPath, encrypted);

      if (success) {
        setState(() {
          result = 'File encrypted successfully!\n\nSaved to: $outputPath';
          _isLoading = false;
        });
      } else {
        throw Exception('Failed to save encrypted file');
      }
    } catch (e) {
      setState(() {
        result = 'File encryption failed: $e';
        _isLoading = false;
      });
    }
  }

  /// Build hash config Map for CLI (filter enabled only)
  Map<String, Map<String, dynamic>>? _buildHashConfigMap() {
    final enabledHashes = Map<String, Map<String, dynamic>>.fromEntries(
      _hashConfig.entries.where((entry) => entry.value['enabled'] == true)
    );

    if (enabledHashes.isEmpty) return null;
    return enabledHashes;
  }

  /// Build KDF config Map for CLI (filter enabled only)
  Map<String, Map<String, dynamic>>? _buildKdfConfigMap() {
    final enabledKdfs = Map<String, Map<String, dynamic>>.fromEntries(
      _kdfConfig.entries.where((entry) => entry.value['enabled'] == true)
    );

    if (enabledKdfs.isEmpty) return null;
    return enabledKdfs;
  }

  /// Helper to build KDF parameter sliders
  Widget _buildKDFSlider(String label, int value, int min, int max, Function(int) onChanged) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
      child: Row(
        children: [
          SizedBox(width: 120, child: Text('$label:')),
          Expanded(
            child: Slider(
              value: value.toDouble().clamp(min.toDouble(), max.toDouble()),
              min: min.toDouble(),
              max: max.toDouble(),
              divisions: (max - min) > 100 ? 100 : (max - min),
              label: value.toString(),
              onChanged: (v) => onChanged(v.toInt()),
            ),
          ),
          SizedBox(width: 60, child: Text(value.toString())),
        ],
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
      color: enabled ? Theme.of(context).colorScheme.secondaryContainer : Theme.of(context).colorScheme.surfaceContainerHighest,
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
              subtitle: const Text('Memory-hard function - best against hardware attacks'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['argon2'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
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
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainerHighest,
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
              subtitle: const Text('Memory-hard function - good balance of security and performance'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['scrypt'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('N (CPU/Memory)', ((config['n'] ?? 16384) / 1024).round(), 1, 1024, (v) =>
                setState(() => _kdfConfig['scrypt']!['n'] = v * 1024)),
              _buildKDFSlider('R (Block Size)', config['r'] ?? 8, 1, 32, (v) =>
                setState(() => _kdfConfig['scrypt']!['r'] = v)),
              _buildKDFSlider('P (Parallelism)', config['p'] ?? 1, 1, 16, (v) =>
                setState(() => _kdfConfig['scrypt']!['p'] = v)),
              _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) =>
                setState(() => _kdfConfig['scrypt']!['rounds'] = v)),
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
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainerHighest,
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
              subtitle: const Text('HMAC-based Key Derivation - efficient key expansion'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['hkdf'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 0, 1000000, (v) =>
                setState(() => _kdfConfig['hkdf']!['rounds'] = v)),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
                child: Row(
                  children: [
                    const SizedBox(width: 120, child: Text('Hash Algorithm:')),
                    DropdownButton<String>(
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
                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
                child: TextFormField(
                  initialValue: config['info'] ?? 'openssl_encrypt_hkdf',
                  decoration: const InputDecoration(
                    labelText: 'Info String',
                    border: OutlineInputBorder(),
                  ),
                  onChanged: (value) {
                    setState(() {
                      _kdfConfig['hkdf']!['info'] = value;
                    });
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
      color: enabled ? Theme.of(context).colorScheme.errorContainer : Theme.of(context).colorScheme.surfaceContainerHighest,
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
              subtitle: const Text('Newer memory-hard function - under academic evaluation'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['balloon'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
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
        ),
      ),
    );
  }

  /// Build RandomX configuration panel
  Widget _buildRandomXPanel() {
    final config = _kdfConfig['randomx'] ?? {
      'enabled': false,
      'mode': 'light',
      'rounds': 1,
      'height': 1,
      'hash_len': 32,
    };
    final enabled = config['enabled'] ?? false;

    return Card(
      color: enabled ? Theme.of(context).colorScheme.errorContainer : Theme.of(context).colorScheme.surfaceContainerHighest,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('RandomX', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.purple,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('CPU-HARD', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Memory-hard KDF based on cryptocurrency mining'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['randomx'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
                child: Row(
                  children: [
                    const SizedBox(width: 120, child: Text('Mode:')),
                    DropdownButton<String>(
                      value: config['mode'] ?? 'light',
                      items: const [
                        DropdownMenuItem(value: 'light', child: Text('Light (256MB RAM)')),
                        DropdownMenuItem(value: 'fast', child: Text('Fast (2GB RAM)')),
                      ],
                      onChanged: (String? value) {
                        setState(() {
                          _kdfConfig['randomx']!['mode'] = value ?? 'light';
                        });
                      },
                    ),
                  ],
                ),
              ),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 1, 10, (v) =>
                setState(() => _kdfConfig['randomx']!['rounds'] = v)),
              _buildKDFSlider('Block Height', config['height'] ?? 1, 1, 1000, (v) =>
                setState(() => _kdfConfig['randomx']!['height'] = v)),
              _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 64, (v) =>
                setState(() => _kdfConfig['randomx']!['hash_len'] = v)),
            ],
          ],
        ),
      ),
    );
  }

  /// Check if a hash algorithm is a legacy SHA (not SHA3)
  bool _isLegacySha(String hashId) {
    final lowerHashId = hashId.toLowerCase().replaceAll('-', '').replaceAll('_', '');
    // Legacy SHA hashes: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
    // NOT SHA3 variants
    return (lowerHashId == 'sha1' ||
            lowerHashId == 'sha224' ||
            lowerHashId == 'sha256' ||
            lowerHashId == 'sha384' ||
            lowerHashId == 'sha512');
  }

  /// Build hash configuration widget for individual hash algorithm
  Widget _buildHashConfig(String hashId, String hashName) {
    final isEnabled = _hashConfig[hashId]?['enabled'] ?? false;
    final rounds = (_hashConfig[hashId]?['rounds'] ?? 1000) as int;

    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(
          color: isEnabled
              ? Theme.of(context).colorScheme.primary
              : Theme.of(context).colorScheme.outline,
        ),
        borderRadius: BorderRadius.circular(8),
        color: isEnabled
            ? Theme.of(context).colorScheme.primaryContainer
            : Theme.of(context).colorScheme.surfaceContainerHighest,
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: isEnabled,
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
                    color: isEnabled
                        ? Theme.of(context).colorScheme.primary
                        : Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              // Add LEGACY badge for non-SHA3 SHA hashes
              if (_isLegacySha(hashId)) ...[
                const SizedBox(width: 4),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                  decoration: BoxDecoration(
                    color: Colors.grey,
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: const Text(
                    'LEGACY',
                    style: TextStyle(color: Colors.white, fontSize: 8, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
              if (isEnabled)
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Rounds: $rounds',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w500,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                      Slider(
                        value: rounds.toDouble(),
                        min: 100,
                        max: 1000000,
                        divisions: 100,
                        label: rounds.toString(),
                        onChanged: (value) {
                          setState(() {
                            _hashConfig[hashId]!['rounds'] = value.toInt();
                          });
                        },
                      ),
                    ],
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  /// Build hash chain configuration section
  Widget _buildHashChainSection() {
    return Column(
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
              const Text('Hash Chain Configuration', style: TextStyle(fontWeight: FontWeight.w500)),
              const Spacer(),
              const Icon(Icons.link),
            ],
          ),
        ),
        if (_showHashConfig) ...[
          const SizedBox(height: 12),
          Text(
            'Configure hash algorithms and rounds (CLI order)',
            style: TextStyle(
              fontSize: 12,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 12),
          ..._hashAlgorithms.entries.expand((entry) {
            final groupName = entry.key;
            final hashes = entry.value;
            return [
              Padding(
                padding: const EdgeInsets.only(top: 12, bottom: 8),
                child: Text(
                  groupName,
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                    color: Theme.of(context).colorScheme.secondary,
                  ),
                ),
              ),
              ...hashes.map((hash) {
                return Padding(
                  padding: const EdgeInsets.only(bottom: 8.0, left: 8.0),
                  child: _buildHashConfig(hash, hash),
                );
              }),
            ];
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
                    for (final group in _hashAlgorithms.values) {
                      for (String hash in group) {
                        _hashConfig[hash] = {
                          'enabled': true,
                          'rounds': 1000
                        };
                      }
                    }
                  });
                },
                child: const Text('Enable All', style: TextStyle(fontSize: 12)),
              ),
              TextButton(
                onPressed: () {
                  setState(() {
                    for (final group in _hashAlgorithms.values) {
                      for (String hash in group) {
                        if (_hashConfig[hash] != null) {
                          _hashConfig[hash]!['enabled'] = false;
                        }
                      }
                    }
                  });
                },
                child: const Text('Disable All', style: TextStyle(fontSize: 12)),
              ),
              TextButton(
                onPressed: () {
                  setState(() {
                    for (final group in _hashAlgorithms.values) {
                      for (String hash in group) {
                        _hashConfig[hash] = {
                          'enabled': false,
                          'rounds': 1000
                        };
                      }
                    }
                  });
                },
                child: const Text('Reset (1000)', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ],
      ],
    );
  }

  /// Build KDF chain configuration section
  Widget _buildKdfChainSection() {
    return Column(
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
              const Text('KDF Chain Configuration', style: TextStyle(fontWeight: FontWeight.w500)),
              const Spacer(),
              const Icon(Icons.vpn_key),
            ],
          ),
        ),
        if (_showKdfConfig) ...[
          const SizedBox(height: 12),
          Text(
            'Configure key derivation functions for enhanced security',
            style: TextStyle(
              fontSize: 12,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 12),
          _buildArgon2Panel(),
          const SizedBox(height: 8),
          _buildScryptPanel(),
          const SizedBox(height: 8),
          _buildHKDFPanel(),
          const SizedBox(height: 8),
          _buildBalloonPanel(),
          const SizedBox(height: 8),
          _buildRandomXPanel(),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            alignment: WrapAlignment.center,
            children: [
              TextButton(
                onPressed: () {
                  setState(() {
                    _kdfConfig['argon2'] = {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 10};
                    _kdfConfig['scrypt']!['enabled'] = false;
                    _kdfConfig['hkdf']!['enabled'] = false;
                    _kdfConfig['balloon']!['enabled'] = false;
                    _kdfConfig['randomx']!['enabled'] = false;
                  });
                },
                child: const Text('Argon2 Only', style: TextStyle(fontSize: 12)),
              ),
              TextButton(
                onPressed: () {
                  setState(() {
                    _kdfConfig['argon2']!['enabled'] = false;
                    _kdfConfig['scrypt']!['enabled'] = false;
                    _kdfConfig['hkdf']!['enabled'] = false;
                    _kdfConfig['balloon']!['enabled'] = false;
                    _kdfConfig['randomx']!['enabled'] = false;
                  });
                },
                child: const Text('Disable All', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ],
      ],
    );
  }

  /// Build asymmetric encryption configuration widget
  Widget _buildAsymmetricConfig() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.people),
                const SizedBox(width: 8),
                const Text('Asymmetric Encryption Configuration',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ],
            ),
            const SizedBox(height: 16),

            // Signing Identity
            TextFormField(
              initialValue: _signingIdentity,
              decoration: const InputDecoration(
                labelText: 'Signing Identity (required)',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.draw),
                helperText: 'Your identity for signing (uses ML-DSA-65)',
              ),
              enabled: !_isLoading,
              onChanged: (value) {
                setState(() {
                  _signingIdentity = value;
                });
              },
            ),
            const SizedBox(height: 16),

            // Recipient Identities
            const Text('Recipient Identities (Encryption)',
                style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            if (_recipientIdentities.isNotEmpty) ...[
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _recipientIdentities.map((identity) {
                  return Chip(
                    label: Text(identity),
                    deleteIcon: const Icon(Icons.close),
                    onDeleted: _isLoading ? null : () {
                      setState(() {
                        _recipientIdentities.remove(identity);
                      });
                    },
                  );
                }).toList(),
              ),
              const SizedBox(height: 8),
            ],
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _recipientIdentityController,
                    decoration: const InputDecoration(
                      labelText: 'Add recipient identity',
                      border: OutlineInputBorder(),
                      hintText: 'user@example.com',
                    ),
                    enabled: !_isLoading,
                    onSubmitted: (value) {
                      if (value.isNotEmpty && !_recipientIdentities.contains(value)) {
                        setState(() {
                          _recipientIdentities.add(value);
                          _recipientIdentityController.clear();
                        });
                      }
                    },
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.add),
                  onPressed: _isLoading ? null : () {
                    final value = _recipientIdentityController.text.trim();
                    if (value.isNotEmpty && !_recipientIdentities.contains(value)) {
                      setState(() {
                        _recipientIdentities.add(value);
                        _recipientIdentityController.clear();
                      });
                    }
                  },
                  tooltip: 'Add recipient',
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Identity Store Path with Browse Button
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: TextField(
                    controller: _identityStorePathController,
                    decoration: InputDecoration(
                      labelText: 'Identity Store Path (optional)',
                      border: const OutlineInputBorder(),
                      prefixIcon: const Icon(Icons.folder),
                      helperText: 'Custom path to identity store directory',
                      enabled: !_useKeyserver,
                    ),
                    enabled: !_isLoading && !_useKeyserver,
                  ),
                ),
                const SizedBox(width: 8),
                Padding(
                  padding: const EdgeInsets.only(top: 8.0),
                  child: ElevatedButton.icon(
                    onPressed: (_isLoading || _useKeyserver) ? null : () async {
                      final selectedPath = await widget.fileManager.pickDirectory();
                      if (selectedPath != null) {
                        setState(() {
                          _identityStorePathController.text = selectedPath;
                        });
                      }
                    },
                    icon: const Icon(Icons.folder_open),
                    label: const Text('Browse'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Keyserver checkbox (mutually exclusive with identity store)
            CheckboxListTile(
              value: _useKeyserver,
              onChanged: _isLoading ? null : (value) {
                setState(() {
                  _useKeyserver = value ?? false;
                  if (_useKeyserver) {
                    _identityStorePathController.clear(); // Clear identity store path when keyserver is enabled
                  }
                });
              },
              title: const Text('Use Keyserver'),
              subtitle: const Text('Fetch public keys from configured keyserver (opt-in)'),
              contentPadding: EdgeInsets.zero,
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Input Type Toggle
            InputTypeToggle(
              isFileMode: _isFileMode,
              onToggle: (value) {
                setState(() {
                  _isFileMode = value;
                  result = ''; // Clear result when switching modes
                });
              },
            ),
            const SizedBox(height: 16),

            // Input Area (Text or File)
            if (!_isFileMode) ...[
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.text_fields),
                          SizedBox(width: 8),
                          Text('Text Input', style: TextStyle(fontWeight: FontWeight.bold)),
                        ],
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _textController,
                        decoration: const InputDecoration(
                          labelText: 'Text to encrypt',
                          border: OutlineInputBorder(),
                          hintText: 'Enter your text here...',
                        ),
                        maxLines: 5,
                        enabled: !_isLoading,
                      ),
                    ],
                  ),
                ),
              ),
            ] else ...[
              FilePickerWidget(
                selectedFile: _selectedFile,
                onPickFile: _pickFile,
                onClearFile: () => setState(() => _selectedFile = null),
                enabled: !_isLoading,
              ),
            ],
            const SizedBox(height: 16),

            // Password Input
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: TextField(
                  controller: _passwordController,
                  decoration: const InputDecoration(
                    labelText: 'Password',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.lock),
                  ),
                  obscureText: true,
                  enabled: !_isLoading,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Encryption Mode Selector
            EncryptionModeSelector(
              selectedMode: _encryptionMode,
              onModeChanged: (mode) {
                setState(() {
                  _encryptionMode = mode;
                });
              },
            ),
            const SizedBox(height: 16),

            // Algorithm Selection (for symmetric mode)
            if (_encryptionMode == EncryptionMode.symmetric)
              AlgorithmSelector(
                selectedAlgorithm: _selectedAlgorithm,
                onAlgorithmChanged: (algorithm) {
                  setState(() {
                    _selectedAlgorithm = algorithm;
                  });
                },
                enabled: !_isLoading,
              ),

            // Asymmetric Encryption Configuration (for asymmetric mode)
            if (_encryptionMode == EncryptionMode.asymmetric)
              _buildAsymmetricConfig(),

            const SizedBox(height: 16),

            // Key Stretching Section (only for symmetric mode)
            if (_encryptionMode == EncryptionMode.symmetric)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.vpn_key),
                        const SizedBox(width: 8),
                        const Text('Key Stretching', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                      ],
                    ),
                    const SizedBox(height: 12),

                    // Hash Chain Configuration
                    _buildHashChainSection(),

                    const SizedBox(height: 12),

                    // KDF Chain Configuration
                    _buildKdfChainSection(),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 16),

            // Advanced Options (Collapsible)
            ExpansionTile(
              title: const Text('Advanced Options'),
              leading: const Icon(Icons.settings),
              children: [
                // HSM Configuration
                HsmConfigSection(
                  hsmType: _hsmType,
                  yubikeySlot: _yubikeySlot,
                  onHsmTypeChanged: (type) => setState(() => _hsmType = type),
                  onYubikeySlotChanged: (slot) => setState(() => _yubikeySlot = slot),
                ),
                const SizedBox(height: 12),

                // Integrity Configuration
                IntegrityConfigSection(
                  enableIntegrity: _enableIntegrity,
                  verifyIntegrity: false,
                  isEncryptMode: true,
                  onEnableIntegrityChanged: (value) => setState(() => _enableIntegrity = value),
                  onVerifyIntegrityChanged: (_) {},
                ),
                const SizedBox(height: 12),

                // File-specific options
                if (_isFileMode)
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(12.0),
                      child: CheckboxListTile(
                        title: const Text('Force Overwrite'),
                        subtitle: const Text('Replace source file with encrypted version'),
                        value: _forceOverwrite,
                        onChanged: (value) => setState(() => _forceOverwrite = value ?? false),
                        contentPadding: EdgeInsets.zero,
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 24),

            // Encrypt Button
            ElevatedButton.icon(
              onPressed: _isLoading ? null : _encrypt,
              icon: _isLoading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.lock),
              label: Text(_isLoading ? 'Encrypting...' : 'ENCRYPT'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.all(20),
                textStyle: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
            ),
            const SizedBox(height: 24),

            // Result Area
            if (result.isNotEmpty)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.info_outline),
                          SizedBox(width: 8),
                          Text('Result', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                        ],
                      ),
                      const SizedBox(height: 12),
                      SelectableText(
                        result,
                        style: const TextStyle(fontFamily: 'monospace'),
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
