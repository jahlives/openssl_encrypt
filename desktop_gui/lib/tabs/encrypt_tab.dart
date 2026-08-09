import 'package:flutter/material.dart';
import '../cli_service.dart';
import '../input_validation.dart';
import '../file_manager.dart';
import '../widgets/crypto_widgets.dart';
import '../widgets/password_strength_meter.dart';

class EncryptTab extends StatefulWidget {
  final FileManager fileManager;
  final bool isProMode;

  const EncryptTab({super.key, required this.fileManager, this.isProMode = false});

  @override
  State<EncryptTab> createState() => _EncryptTabState();
}

class _EncryptTabState extends State<EncryptTab> {
  // Input mode toggle
  bool _isFileMode = true;

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
  String _operationStatus = '';
  bool _showProgress = false;

  // Hash configuration
  bool _showHashConfig = false;
  final Map<String, Map<String, dynamic>> _hashConfig = {};
  Map<String, List<String>> _hashAlgorithms = {};

  // KDF configuration
  bool _showKdfConfig = false;
  final Map<String, Map<String, dynamic>> _kdfConfig = {
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

  // Pepper plugin options
  bool _enablePepper = false;
  String _pepperMode = 'auto'; // 'auto' or 'named'
  final TextEditingController _pepperNameController = TextEditingController();

  // File-specific options
  bool _forceOverwrite = false;

  // Password options
  bool _forcePassword = false;

  // Asymmetric encryption options
  final List<String> _recipientIdentities = [];
  final TextEditingController _recipientIdentityController = TextEditingController();
  final TextEditingController _identityStorePathController = TextEditingController();
  String _signingIdentity = '';
  bool _useKeyserver = false;

  // Cascade encryption options
  String _cascadePreset = 'standard';
  List<String> _cascadeAlgorithms = ['aes-256-gcm', 'chacha20-poly1305'];
  String _cascadeHash = 'sha256';
  final TextEditingController _cascadeAlgorithmsTextController = TextEditingController();
  bool _disableDiversityCheck = false;
  bool _strictDiversity = false;


  // Cascade presets
  static const Map<String, List<String>> _cascadePresets = {
    'standard': ['aes-256-gcm', 'chacha20-poly1305'],
    'paranoia': ['aes-256-gcm', 'chacha20-poly1305', 'threefish-512'],
  };

  // Classical symmetric ciphers (non-PQS)
  static const Map<String, List<String>> _classicalCipherFamilies = {
    'Fernet': ['fernet'],
    'AES Family': ['aes-gcm', 'aes-gcm-siv', 'aes-ocb3', 'aes-siv'],
    'ChaCha Family': ['chacha20-poly1305', 'xchacha20-poly1305'],
    'Threefish': ['threefish-512', 'threefish-1024'],
  };

  // Cascade hash options
  static const List<String> _cascadeHashes = [
    'sha256',
    'sha384',
    'sha512',
    'sha3-256',
    'sha3-384',
    'sha3-512',
    'blake2b',
    'blake2s',
  ];


  // Format detection by extension

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
    _cascadeAlgorithmsTextController.dispose();
    _pepperNameController.dispose();
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

    // Validate cascade mode requirements
    if (_encryptionMode == EncryptionMode.cascade) {
      if (_cascadeAlgorithms.length < 2) {
        setState(() {
          result = 'Cascade encryption requires at least 2 algorithms';
        });
        return;
      }
    }

    setState(() {
      _isLoading = true;
      result = 'Encrypting...';
      _operationStatus = '';
    });

    try {
      final encrypted = await CLIService.encryptTextWithProgress(
        _textController.text,
        _passwordController.text,
        _selectedAlgorithm,
        _encryptionMode == EncryptionMode.symmetric ? _buildHashConfigMap() : null,
        _encryptionMode == EncryptionMode.symmetric ? _buildKdfConfigMap() : null,
        template: widget.isProMode ? null : 'standard',
        hsmPlugin: _hsmType != 'none' ? _hsmType : null,
        hsmSlot: _hsmType == 'yubikey' ? _yubikeySlot : null,
        enableIntegrity: _enableIntegrity,
        forIdentities: _encryptionMode == EncryptionMode.asymmetric ? _recipientIdentities : null,
        signWith: _encryptionMode == EncryptionMode.asymmetric ? _signingIdentity : null,
        useKeyserver: _encryptionMode == EncryptionMode.asymmetric ? _useKeyserver : false,
        identityStore: _encryptionMode == EncryptionMode.asymmetric && _identityStorePathController.text.isNotEmpty ? _identityStorePathController.text : null,
        cascadePreset: _encryptionMode == EncryptionMode.cascade && _cascadePreset != 'custom' ? _cascadePreset : null,
        cascadeAlgorithms: _encryptionMode == EncryptionMode.cascade && _cascadePreset == 'custom' ? _cascadeAlgorithms : null,
        cascadeHash: _encryptionMode == EncryptionMode.cascade ? _cascadeHash : 'sha256',
        noDiversityCheck: _encryptionMode == EncryptionMode.cascade ? _disableDiversityCheck : false,
        strictDiversity: _encryptionMode == EncryptionMode.cascade ? _strictDiversity : false,
        forcePassword: _forcePassword,
        enablePepper: _enablePepper,
        pepperName: _pepperMode == 'named' ? _pepperNameController.text : null,
        showProgress: _showProgress,
        onProgress: (progress) {
          setState(() {
            _operationStatus = progress;
          });
        },
        onStatus: (status) {
          setState(() {
            final lowerStatus = status.toLowerCase();
            // Only show YubiKey prompt if we're WAITING for touch (not if touch was registered)
            if ((lowerStatus.contains('touch') ||
                 lowerStatus.contains('yubikey') ||
                 lowerStatus.contains('press')) &&
                !lowerStatus.contains('registered') &&
                !lowerStatus.contains('derived') &&
                !lowerStatus.contains('executed')) {
              _operationStatus = 'Please touch your YubiKey...';
            } else {
              _operationStatus = status;
            }
          });
        },
      );

      setState(() {
        result = 'Encrypted successfully!\n\n$encrypted';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        // Sanitize: the exception embeds raw CLI stderr.
        result = InputValidator.sanitizeForDisplay('Encryption failed: $e');
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

    // Validate cascade mode requirements
    if (_encryptionMode == EncryptionMode.cascade) {
      if (_cascadeAlgorithms.length < 2) {
        setState(() {
          result = 'Cascade encryption requires at least 2 algorithms';
        });
        return;
      }
    }

    setState(() {
      _isLoading = true;
      result = 'Encrypting file...';
      _operationStatus = '';
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
        template: widget.isProMode ? null : 'standard',
        hsmPlugin: _hsmType != 'none' ? _hsmType : null,
        hsmSlot: _hsmType == 'yubikey' ? _yubikeySlot : null,
        enableIntegrity: _enableIntegrity,
        forIdentities: _encryptionMode == EncryptionMode.asymmetric ? _recipientIdentities : null,
        signWith: _encryptionMode == EncryptionMode.asymmetric ? _signingIdentity : null,
        useKeyserver: _encryptionMode == EncryptionMode.asymmetric ? _useKeyserver : false,
        identityStore: _encryptionMode == EncryptionMode.asymmetric && _identityStorePathController.text.isNotEmpty ? _identityStorePathController.text : null,
        cascadePreset: _encryptionMode == EncryptionMode.cascade && _cascadePreset != 'custom' ? _cascadePreset : null,
        cascadeAlgorithms: _encryptionMode == EncryptionMode.cascade && _cascadePreset == 'custom' ? _cascadeAlgorithms : null,
        cascadeHash: _encryptionMode == EncryptionMode.cascade ? _cascadeHash : 'sha256',
        noDiversityCheck: _encryptionMode == EncryptionMode.cascade ? _disableDiversityCheck : false,
        strictDiversity: _encryptionMode == EncryptionMode.cascade ? _strictDiversity : false,
        forcePassword: _forcePassword,
        enablePepper: _enablePepper,
        pepperName: _pepperMode == 'named' ? _pepperNameController.text : null,
        showProgress: _showProgress,
        onProgress: (progress) {
          setState(() {
            _operationStatus = progress;
          });
        },
        onStatus: (status) {
          setState(() {
            final lowerStatus = status.toLowerCase();
            // Only show YubiKey prompt if we're WAITING for touch (not if touch was registered)
            if ((lowerStatus.contains('touch') ||
                 lowerStatus.contains('yubikey') ||
                 lowerStatus.contains('press')) &&
                !lowerStatus.contains('registered') &&
                !lowerStatus.contains('derived') &&
                !lowerStatus.contains('executed')) {
              _operationStatus = 'Please touch your YubiKey...';
            } else {
              _operationStatus = status;
            }
          });
        },
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
        result = InputValidator.sanitizeForDisplay('File encryption failed: $e');
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

  /// Build cascade encryption configuration widget
  Widget _buildCascadeConfig() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Row(
              children: [
                const Icon(Icons.layers),
                const SizedBox(width: 8),
                const Text('Cascade Encryption Configuration',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ],
            ),
            const SizedBox(height: 16),

            // Preset Selector
            const Text('Preset:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            Center(
              child: SegmentedButton<String>(
                segments: const [
                  ButtonSegment(
                    value: 'standard',
                    label: Text('Standard'),
                    icon: Icon(Icons.shield),
                  ),
                  ButtonSegment(
                    value: 'paranoia',
                    label: Text('Paranoia'),
                    icon: Icon(Icons.security),
                  ),
                  ButtonSegment(
                    value: 'custom',
                    label: Text('Custom'),
                    icon: Icon(Icons.tune),
                  ),
                ],
                selected: {_cascadePreset},
                onSelectionChanged: (Set<String> newSelection) {
                  final preset = newSelection.first;
                  setState(() {
                    _cascadePreset = preset;
                    if (preset == 'custom') {
                      // Clear the list when switching to custom
                      _cascadeAlgorithms = [];
                      _syncCascadeTextFromAlgorithms();
                    } else if (_cascadePresets.containsKey(preset)) {
                      // Load preset algorithms
                      _cascadeAlgorithms = List.from(_cascadePresets[preset]!);
                      _syncCascadeTextFromAlgorithms();
                    }
                  });
                },
              ),
            ),

            // Show preset info when not custom
            if (_cascadePreset != 'custom') ...[
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
                  border: Border.all(color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.5)),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _cascadePreset == 'standard'
                      ? 'Standard preset provides balanced security with two diverse algorithms.'
                      : 'Paranoia preset offers maximum security with three layers from different families.',
                  style: TextStyle(
                    fontSize: 12,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ],
            const SizedBox(height: 16),

            // Algorithm Chain Display
            Row(
              children: [
                const Text('Algorithm Chain:', style: TextStyle(fontWeight: FontWeight.w500)),
                const Spacer(),
                if (_cascadePreset == 'custom')
                  TextButton.icon(
                    onPressed: _isLoading ? null : _showCascadeAlgorithmPicker,
                    icon: const Icon(Icons.add, size: 18),
                    label: const Text('Add'),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                border: Border.all(color: Theme.of(context).colorScheme.outline),
                borderRadius: BorderRadius.circular(8),
              ),
              child: _cascadeAlgorithms.isEmpty
                  ? const Padding(
                      padding: EdgeInsets.all(16.0),
                      child: Center(
                        child: Text(
                          'No algorithms selected. Add at least 2 algorithms for cascade encryption.',
                          style: TextStyle(color: Colors.grey),
                        ),
                      ),
                    )
                  : Column(
                      children: _cascadeAlgorithms.asMap().entries.map((entry) {
                        final index = entry.key;
                        final algorithm = entry.value;
                        return Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4),
                          child: Row(
                            children: [
                              // Number badge
                              Container(
                                width: 28,
                                height: 28,
                                decoration: BoxDecoration(
                                  color: Theme.of(context).colorScheme.primary,
                                  shape: BoxShape.circle,
                                ),
                                child: Center(
                                  child: Text(
                                    '${index + 1}',
                                    style: const TextStyle(
                                      color: Colors.white,
                                      fontSize: 12,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 12),
                              // Algorithm name
                              Expanded(
                                child: Text(
                                  algorithm,
                                  style: const TextStyle(fontWeight: FontWeight.w500),
                                ),
                              ),
                              // Family badge
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                                decoration: BoxDecoration(
                                  color: _getCascadeFamilyColor(algorithm).withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  _getCascadeCipherFamily(algorithm),
                                  style: TextStyle(
                                    fontSize: 10,
                                    color: _getCascadeFamilyColor(algorithm),
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                              // Delete button (only for custom mode)
                              if (_cascadePreset == 'custom') ...[
                                const SizedBox(width: 8),
                                IconButton(
                                  icon: const Icon(Icons.delete_outline, size: 18),
                                  onPressed: _isLoading
                                      ? null
                                      : () {
                                          setState(() {
                                            _cascadeAlgorithms.removeAt(index);
                                            _syncCascadeTextFromAlgorithms();
                                          });
                                        },
                                  tooltip: 'Remove',
                                  constraints: const BoxConstraints(),
                                  padding: const EdgeInsets.all(4),
                                ),
                              ],
                            ],
                          ),
                        );
                      }).toList(),
                    ),
            ),
            const SizedBox(height: 16),

            // Manual Text Input
            const Text('Manual Entry:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            TextField(
              controller: _cascadeAlgorithmsTextController,
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                labelText: 'Algorithms (comma or space separated)',
                hintText: 'aes-gcm, chacha20-poly1305, threefish-512',
                helperText: 'Enter algorithm names separated by comma or space',
                suffixIcon: IconButton(
                  icon: const Icon(Icons.refresh),
                  onPressed: _parseCascadeAlgorithmsFromText,
                  tooltip: 'Parse and apply',
                ),
              ),
              enabled: !_isLoading && _cascadePreset == 'custom',
              onSubmitted: (_) => _parseCascadeAlgorithmsFromText(),
            ),
            const SizedBox(height: 16),

            // Cascade Hash Dropdown
            const Text('HKDF Hash Function:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            DropdownButtonFormField<String>(
              initialValue: _cascadeHash,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                helperText: 'Hash function for key derivation between encryption layers',
              ),
              items: _cascadeHashes.map((hash) {
                return DropdownMenuItem(
                  value: hash,
                  child: Text(_formatCascadeHashName(hash)),
                );
              }).toList(),
              onChanged: _isLoading
                  ? null
                  : (value) {
                      setState(() {
                        _cascadeHash = value ?? 'sha256';
                      });
                    },
            ),
            const SizedBox(height: 16),

            // Diversity Options
            const Text('Diversity Validation:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(height: 8),
            CheckboxListTile(
              value: _disableDiversityCheck,
              onChanged: _isLoading
                  ? null
                  : (value) {
                      setState(() {
                        _disableDiversityCheck = value ?? false;
                        if (_disableDiversityCheck) {
                          _strictDiversity = false;
                        }
                      });
                    },
              title: const Text('Disable diversity warnings'),
              subtitle: const Text('Skip cipher family diversity checks (--no-diversity-check)'),
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              dense: true,
            ),
            CheckboxListTile(
              value: _strictDiversity,
              onChanged: (_isLoading || _disableDiversityCheck)
                  ? null
                  : (value) {
                      setState(() {
                        _strictDiversity = value ?? false;
                        if (_strictDiversity) {
                          _disableDiversityCheck = false;
                        }
                      });
                    },
              title: const Text('Strict diversity'),
              subtitle: const Text('Require all ciphers from different families (--strict-diversity)'),
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              dense: true,
            ),
          ],
        ),
      ),
    );
  }

  /// Show cascade algorithm picker dialog
  void _showCascadeAlgorithmPicker() {
    showDialog(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) {
          return AlertDialog(
            title: const Text('Select Cascade Algorithms'),
            content: SizedBox(
              width: 500,
              height: 500,
              child: SingleChildScrollView(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Select classical symmetric ciphers only (no post-quantum). '
                      'Order matters - algorithms are applied in selection sequence.',
                      style: TextStyle(fontSize: 12, color: Colors.grey.shade300),
                    ),
                    const SizedBox(height: 16),

                    // Quick Presets Section
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.grey.shade900,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('Quick Presets:',
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                color: Colors.white,
                              )),
                          const SizedBox(height: 8),
                          Wrap(
                            spacing: 8,
                            runSpacing: 8,
                            children: [
                              ActionChip(
                                avatar: const Icon(Icons.shield, size: 18),
                                label: const Text('Standard'),
                                onPressed: () {
                                  setState(() {
                                    _cascadePreset = 'standard';
                                    _cascadeAlgorithms = List.from(_cascadePresets['standard']!);
                                    _syncCascadeTextFromAlgorithms();
                                  });
                                  Navigator.pop(dialogContext);
                                },
                              ),
                              ActionChip(
                                avatar: const Icon(Icons.security, size: 18),
                                label: const Text('Paranoia'),
                                onPressed: () {
                                  setState(() {
                                    _cascadePreset = 'paranoia';
                                    _cascadeAlgorithms = List.from(_cascadePresets['paranoia']!);
                                    _syncCascadeTextFromAlgorithms();
                                  });
                                  Navigator.pop(dialogContext);
                                },
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                    const Divider(),
                    const SizedBox(height: 8),

                    // Individual Algorithm Selection by Family
                    ..._classicalCipherFamilies.entries.map((familyEntry) {
                      final familyName = familyEntry.key;
                      final algorithms = familyEntry.value;
                      return Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Padding(
                            padding: const EdgeInsets.symmetric(vertical: 8),
                            child: Text(
                              familyName,
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
                                color: _getCascadeFamilyColor(algorithms.first),
                              ),
                            ),
                          ),
                          ...algorithms.map((algorithm) {
                            final orderIndex = _cascadeAlgorithms.indexOf(algorithm);
                            final isSelected = orderIndex >= 0;

                            return Card(
                              color: isSelected
                                  ? Theme.of(context).colorScheme.primaryContainer
                                  : null,
                              child: ListTile(
                                dense: true,
                                leading: isSelected
                                    ? Container(
                                        width: 28,
                                        height: 28,
                                        decoration: BoxDecoration(
                                          color: Theme.of(context).colorScheme.primary,
                                          shape: BoxShape.circle,
                                        ),
                                        child: Center(
                                          child: Text(
                                            '${orderIndex + 1}',
                                            style: const TextStyle(
                                              color: Colors.white,
                                              fontSize: 12,
                                              fontWeight: FontWeight.bold,
                                            ),
                                          ),
                                        ),
                                      )
                                    : Icon(
                                        Icons.add_circle_outline,
                                        color: Theme.of(context).colorScheme.primary,
                                      ),
                                title: Text(
                                  algorithm,
                                  style: TextStyle(
                                    fontWeight: isSelected ? FontWeight.bold : null,
                                  ),
                                ),
                                subtitle: Text(
                                  _getCascadeAlgorithmDescription(algorithm),
                                  style: const TextStyle(fontSize: 11),
                                ),
                                trailing: isSelected
                                    ? IconButton(
                                        icon: const Icon(Icons.remove_circle, color: Colors.red),
                                        onPressed: () {
                                          setDialogState(() {});
                                          setState(() {
                                            _cascadeAlgorithms.remove(algorithm);
                                            _cascadePreset = 'custom';
                                            _syncCascadeTextFromAlgorithms();
                                          });
                                        },
                                      )
                                    : null,
                                onTap: () {
                                  setDialogState(() {});
                                  setState(() {
                                    if (isSelected) {
                                      _cascadeAlgorithms.remove(algorithm);
                                    } else {
                                      _cascadeAlgorithms.add(algorithm);
                                    }
                                    _cascadePreset = 'custom';
                                    _syncCascadeTextFromAlgorithms();
                                  });
                                },
                              ),
                            );
                          }),
                        ],
                      );
                    }),
                  ],
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(dialogContext),
                child: const Text('Cancel'),
              ),
              ElevatedButton(
                onPressed: () {
                  Navigator.pop(dialogContext);
                },
                child: Text('Done (${_cascadeAlgorithms.length} selected)'),
              ),
            ],
          );
        },
      ),
    );
  }

  /// Helper methods for cascade encryption

  /// Sync text controller from cascade algorithms list
  void _syncCascadeTextFromAlgorithms() {
    _cascadeAlgorithmsTextController.text = _cascadeAlgorithms.join(', ');
  }

  /// Parse algorithms from text input
  void _parseCascadeAlgorithmsFromText() {
    final text = _cascadeAlgorithmsTextController.text.trim();
    if (text.isEmpty) {
      setState(() {
        _cascadeAlgorithms = [];
      });
      return;
    }

    // Split by comma or space, filter empty entries
    final parsed = text
        .split(RegExp(r'[,\s]+'))
        .map((s) => s.trim().toLowerCase())
        .where((s) => s.isNotEmpty)
        .toList();

    // Validate against known classical ciphers
    final allValid = _classicalCipherFamilies.values.expand((e) => e).toSet();
    final validAlgorithms = parsed.where((a) => allValid.contains(a)).toList();

    setState(() {
      _cascadeAlgorithms = validAlgorithms;
      _cascadePreset = 'custom';
      _syncCascadeTextFromAlgorithms();
    });
  }

  /// Get cipher family for display
  String _getCascadeCipherFamily(String algorithm) {
    if (algorithm == 'fernet') return 'Fernet';
    if (algorithm.startsWith('aes-')) return 'AES';
    if (algorithm.contains('chacha')) return 'ChaCha';
    if (algorithm.startsWith('threefish')) return 'Threefish';
    return 'Other';
  }

  /// Get family color
  Color _getCascadeFamilyColor(String algorithm) {
    switch (_getCascadeCipherFamily(algorithm)) {
      case 'Fernet':
        return Colors.purple;
      case 'AES':
        return Colors.blue;
      case 'ChaCha':
        return Colors.green;
      case 'Threefish':
        return Colors.orange;
      default:
        return Colors.grey;
    }
  }

  /// Format cascade hash name for display
  String _formatCascadeHashName(String hash) {
    switch (hash) {
      case 'sha256':
        return 'SHA-256';
      case 'sha384':
        return 'SHA-384';
      case 'sha512':
        return 'SHA-512';
      case 'sha3-256':
        return 'SHA3-256';
      case 'sha3-384':
        return 'SHA3-384';
      case 'sha3-512':
        return 'SHA3-512';
      case 'blake2b':
        return 'BLAKE2b';
      case 'blake2s':
        return 'BLAKE2s';
      default:
        return hash.toUpperCase();
    }
  }

  /// Get algorithm description for picker
  String _getCascadeAlgorithmDescription(String algorithm) {
    const descriptions = {
      'fernet': 'AES-128-CBC with HMAC - Python standard',
      'aes-gcm': 'AES-256-GCM - Fast, hardware accelerated',
      'aes-gcm-siv': 'AES-GCM-SIV - Misuse resistant',
      'aes-ocb3': 'AES-OCB3 - High performance',
      'aes-siv': 'AES-SIV - Deterministic encryption',
      'chacha20-poly1305': 'ChaCha20-Poly1305 - Modern stream cipher',
      'xchacha20-poly1305': 'XChaCha20 - Extended nonce',
      'threefish-512': '512-bit block, 256-bit PQ security',
      'threefish-1024': '1024-bit block, 512-bit PQ security',
    };
    return descriptions[algorithm] ?? 'Symmetric cipher';
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
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    TextField(
                      controller: _passwordController,
                      decoration: const InputDecoration(
                        labelText: 'Password',
                        border: OutlineInputBorder(),
                        prefixIcon: Icon(Icons.lock),
                      ),
                      obscureText: true,
                      enabled: !_isLoading,
                    ),
                    // Live strength meter (gitlab#141): a password is being
                    // CHOSEN here, so pattern-aware scoring is meaningful (the
                    // Decrypt tab enters an existing one; the Password
                    // Generator already reports entropy).
                    PasswordStrengthMeter(controller: _passwordController),
                    if (widget.isProMode) ...[
                      const SizedBox(height: 8),
                      CheckboxListTile(
                        value: _forcePassword,
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _forcePassword = value ?? false;
                          });
                        },
                        title: const Text('Force password'),
                        subtitle: const Text('Accept weak passwords (use with caution)'),
                        contentPadding: EdgeInsets.zero,
                        controlAffinity: ListTileControlAffinity.leading,
                        dense: true,
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Simple mode info banner
            if (!widget.isProMode)
              Card(
                color: Theme.of(context).colorScheme.primaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12.0),
                  child: Row(
                    children: [
                      Icon(Icons.info_outline, color: Theme.of(context).colorScheme.onPrimaryContainer),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Using standard security template. Switch to Pro mode in Settings for advanced options.',
                          style: TextStyle(color: Theme.of(context).colorScheme.onPrimaryContainer),
                        ),
                      ),
                    ],
                  ),
                ),
              ),

            if (widget.isProMode) ...[
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

              // Cascade Encryption Configuration (for cascade mode)
              if (_encryptionMode == EncryptionMode.cascade)
                _buildCascadeConfig(),

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

                  // Pepper Configuration
                  PepperConfigSection(
                    enablePepper: _enablePepper,
                    pepperMode: _pepperMode,
                    pepperNameController: _pepperNameController,
                    onEnablePepperChanged: (value) => setState(() => _enablePepper = value),
                    onPepperModeChanged: (mode) => setState(() => _pepperMode = mode),
                  ),
                  const SizedBox(height: 12),

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
            ],
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

            // Progress checkbox
            CheckboxListTile(
              value: _showProgress,
              onChanged: _isLoading ? null : (value) {
                setState(() {
                  _showProgress = value ?? false;
                });
              },
              title: const Text('Show progress'),
              subtitle: const Text('Display real-time progress during operation'),
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              dense: true,
            ),

            // Operation Status Display (YubiKey touch prompts, etc.)
            if (_isLoading && _operationStatus.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Card(
                  color: _operationStatus.contains('YubiKey')
                      ? Colors.amber.shade900
                      : Colors.grey.shade900,
                  child: Padding(
                    padding: const EdgeInsets.all(12.0),
                    child: Row(
                      children: [
                        if (_operationStatus.contains('YubiKey'))
                          Icon(Icons.touch_app, color: Colors.amber.shade100)
                        else
                          SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                            ),
                          ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            _operationStatus,
                            style: TextStyle(
                              color: _operationStatus.contains('YubiKey')
                                  ? Colors.amber.shade100
                                  : Colors.white,
                              fontWeight: _operationStatus.contains('YubiKey')
                                  ? FontWeight.bold
                                  : FontWeight.normal,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
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
