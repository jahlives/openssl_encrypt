import 'package:flutter/material.dart';
import 'package:path/path.dart' as path;
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

  /// Securely delete the source file after a successful encryption (gitlab#151).
  /// Off by default: it destroys the user's only plaintext copy.
  bool _shredSourceAfterEncrypt = false;
  int _shredPasses = 3;

  // Encrypt-tab flag gaps (gitlab#153). Default off/empty so behaviour is
  // unchanged unless the user opts in.
  //
  // Deliberately NOT exposed, because on this code path they do nothing:
  //  - --keyring-store/-load: the CLI reads args.password, which is only the
  //    -p value; the GUI passes the password via CRYPT_PASSWORD, so the store
  //    never runs. Surfacing it would invite a user to discard their only copy
  //    of a password that was never saved (gitlab#156).
  //  - --pqc-store-key: already emitted unconditionally for every PQC
  //    algorithm, so a toggle could not turn it off (gitlab#157).
  final TextEditingController _pqcKeyfileController = TextEditingController();
  /// Opt in to the legacy sequential composition (pins format v13).
  bool _useSequentialXor = false;
  bool _parallelKdf = false;
  int _kdfWorkers = 4;

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
  final Map<String, Map<String, dynamic>> _hashConfig = {};
  Map<String, List<String>> _hashAlgorithms = {};

  // KDF configuration
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

  // Steganography options
  bool _useSteganography = false;
  FileInfo? _coverMediaFile;
  String _stegoMethod = 'lsb';
  final TextEditingController _stegoPasswordController = TextEditingController();
  int _stegoBitsPerChannel = 1;
  bool _stegoRandomizePixels = false;
  bool _stegoDecoyData = false;

  // JPEG-specific steganography
  int _jpegQuality = 85;

  // Video-specific steganography (MP4)
  double _videoQuantizationStep = 8.0;
  double _videoAdaptationFactor = 1.2;
  double _videoCompensationFactor = 0.5;
  int _videoBitsPerCoefficient = 2;
  bool _videoTemporalSpread = true;
  int _videoQualityPreservation = 8;

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

  // Steganography methods by format type
  static const Map<String, List<String>> _stegoMethodsByFormat = {
    'jpeg': ['f5', 'outguess', 'basic'],
    'image': ['lsb', 'adaptive'],  // PNG, BMP, TIFF
    'audio': ['lsb'],              // WAV, FLAC, MP3
    'video': ['uniform', 'adaptive', 'distortion_comp', 'multi_level'],
  };

  // Format detection by extension
  static const Map<String, String> _stegoFormatByExtension = {
    '.jpg': 'jpeg', '.jpeg': 'jpeg',
    '.png': 'image', '.bmp': 'image', '.tiff': 'image', '.tif': 'image',
    '.wav': 'audio', '.flac': 'audio', '.mp3': 'audio',
    '.mp4': 'video',
  };

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
    _stegoPasswordController.dispose();
    _pepperNameController.dispose();
    _pqcKeyfileController.dispose();
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

    // Validate steganography requirements
    if (_useSteganography) {
      if (_coverMediaFile == null) {
        setState(() {
          result = 'Please select a cover media file for steganography';
        });
        return;
      }

      final format = _detectStegoFormat(_coverMediaFile!.path);
      if (format == null) {
        setState(() {
          result = 'Unsupported cover media format. Use PNG, BMP, TIFF, JPEG, WAV, FLAC, MP3, or MP4.';
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
      // Handle steganography path
      if (_useSteganography && _coverMediaFile != null) {
        // Get output path for stego file
        final outputPath = await widget.fileManager.getSaveLocation(
          suggestedName: '${path.basenameWithoutExtension(_coverMediaFile!.path)}_stego${path.extension(_coverMediaFile!.path)}',
        );
        if (outputPath == null) {
          setState(() {
            result = 'Steganography cancelled - no output location selected';
            _isLoading = false;
          });
          return;
        }

        await CLIService.encryptTextWithSteganography(
          text: _textController.text,
          coverMediaPath: _coverMediaFile!.path,
          outputPath: outputPath,
          password: _passwordController.text,
          stegoPassword: _stegoPasswordController.text.isNotEmpty ? _stegoPasswordController.text : null,
          algorithm: _selectedAlgorithm,
          stegoMethod: _stegoMethod,
          bitsPerChannel: _stegoBitsPerChannel,
          randomizePixels: _stegoRandomizePixels,
          addDecoyData: _stegoDecoyData,
          jpegQuality: _isCoverJpeg() ? _jpegQuality : null,
          videoQuantizationStep: _isCoverVideo() ? _videoQuantizationStep : null,
          videoAdaptationFactor: _isCoverVideo() ? _videoAdaptationFactor : null,
          videoCompensationFactor: _isCoverVideo() ? _videoCompensationFactor : null,
          videoBitsPerCoefficient: _isCoverVideo() ? _videoBitsPerCoefficient : null,
          videoTemporalSpread: _isCoverVideo() ? _videoTemporalSpread : true,
          videoQualityPreservation: _isCoverVideo() ? _videoQualityPreservation : null,
          hashConfig: _encryptionMode == EncryptionMode.symmetric ? _buildHashConfigMap() : null,
          kdfConfig: _encryptionMode == EncryptionMode.symmetric ? _buildKdfConfigMap() : null,
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
        );

        setState(() {
          result = 'Text encrypted and hidden in: $outputPath';
          _isLoading = false;
        });
        return;
      }

      // Normal encryption (no steganography)
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
        pqcKeyfile: _pqcKeyfileController.text.trim().isEmpty
            ? null
            : _pqcKeyfileController.text.trim(),
        useXorComposition: _useSequentialXor,
        parallelKdf: _parallelKdf,
        kdfWorkers: _parallelKdf ? _kdfWorkers : null,
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

  /// Securely delete the source file after a successful encryption.
  ///
  /// The GUI encrypts file-mode input by reading its text and passing it
  /// through the temp-file path, so the CLI's own `--shred` would wipe that
  /// temp file rather than the user's source. The source is therefore shredded
  /// as a separate step here, through the same CLI `shred` command the Secure
  /// Shred screen uses.
  ///
  /// Gated behind its own confirmation regardless of the toggle: this destroys
  /// the user's only plaintext copy, and afterwards the encrypted file plus its
  /// password are the only way back to the data.
  Future<void> _maybeShredSource(String outputPath) async {
    if (!_shredSourceAfterEncrypt || _selectedFile == null) return;
    final sourcePath = _selectedFile!.path;

    if (!mounted) return;
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: Colors.red.shade700),
            const SizedBox(width: 8),
            const Expanded(child: Text('Securely delete the source file?')),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('This overwrites and deletes:\n\n$sourcePath'),
            const SizedBox(height: 12),
            Text(
              'The encrypted file at $outputPath becomes the only copy. If its '
              'password is lost, the data cannot be recovered. This cannot be '
              'undone.',
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Keep the source file'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Shred it'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      await CLIService.shred(sourcePath, passes: _shredPasses);
      if (mounted) {
        setState(() {
          result = '$result\n\nSource file securely deleted: $sourcePath';
          _selectedFile = null;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          result = '$result\n\nThe source file was NOT deleted: $e';
        });
      }
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

    // Validate steganography requirements
    if (_useSteganography) {
      if (_coverMediaFile == null) {
        setState(() {
          result = 'Please select a cover media file for steganography';
        });
        return;
      }

      final format = _detectStegoFormat(_coverMediaFile!.path);
      if (format == null) {
        setState(() {
          result = 'Unsupported cover media format. Use PNG, BMP, TIFF, JPEG, WAV, FLAC, MP3, or MP4.';
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
      // Handle steganography path
      if (_useSteganography && _coverMediaFile != null) {
        // Get output path for stego file
        final outputPath = await widget.fileManager.getSaveLocation(
          suggestedName: '${path.basenameWithoutExtension(_coverMediaFile!.path)}_stego${path.extension(_coverMediaFile!.path)}',
        );
        if (outputPath == null) {
          setState(() {
            result = 'Steganography cancelled - no output location selected';
            _isLoading = false;
          });
          return;
        }

        await CLIService.encryptWithSteganography(
          inputPath: _selectedFile!.path,
          coverImagePath: _coverMediaFile!.path,
          outputPath: outputPath,
          password: _passwordController.text,
          stegoPassword: _stegoPasswordController.text.isNotEmpty ? _stegoPasswordController.text : null,
          algorithm: _selectedAlgorithm,
          stegoMethod: _stegoMethod,
          bitsPerChannel: _stegoBitsPerChannel,
          randomizePixels: _stegoRandomizePixels,
          addDecoyData: _stegoDecoyData,
          jpegQuality: _isCoverJpeg() ? _jpegQuality : null,
          videoQuantizationStep: _isCoverVideo() ? _videoQuantizationStep : null,
          videoAdaptationFactor: _isCoverVideo() ? _videoAdaptationFactor : null,
          videoCompensationFactor: _isCoverVideo() ? _videoCompensationFactor : null,
          videoBitsPerCoefficient: _isCoverVideo() ? _videoBitsPerCoefficient : null,
          videoTemporalSpread: _isCoverVideo() ? _videoTemporalSpread : true,
          videoQualityPreservation: _isCoverVideo() ? _videoQualityPreservation : null,
          hashConfig: _encryptionMode == EncryptionMode.symmetric ? _buildHashConfigMap() : null,
          kdfConfig: _encryptionMode == EncryptionMode.symmetric ? _buildKdfConfigMap() : null,
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
        );

        setState(() {
          result = 'File encrypted and hidden in: $outputPath';
          _isLoading = false;
        });
        return;
      }

      // Normal encryption (no steganography)
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
        pqcKeyfile: _pqcKeyfileController.text.trim().isEmpty
            ? null
            : _pqcKeyfileController.text.trim(),
        useXorComposition: _useSequentialXor,
        parallelKdf: _parallelKdf,
        kdfWorkers: _parallelKdf ? _kdfWorkers : null,
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
        // Only after the encrypted copy is confirmed written: shredding the
        // source is irreversible, so it must never run on a path where the
        // encryption or the save failed.
        await _maybeShredSource(outputPath);
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

  /// Build asymmetric encryption configuration widget
  Widget _buildAsymmetricConfig() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.people),
                SizedBox(width: 8),
                Text('Asymmetric Encryption Configuration',
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
            const Row(
              children: [
                Icon(Icons.layers),
                SizedBox(width: 8),
                Text('Cascade Encryption Configuration',
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

  /// Build steganography configuration widget
  Widget _buildSteganographyConfig() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header with checkbox
            Row(
              children: [
                const Icon(Icons.visibility_off),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'Steganography',
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                  ),
                ),
                Switch(
                  value: _useSteganography,
                  onChanged: _isLoading ? null : (value) {
                    setState(() {
                      _useSteganography = value;
                    });
                  },
                ),
              ],
            ),

            if (_useSteganography) ...[
              const SizedBox(height: 12),
              const Text(
                'Hide encrypted data inside image, audio, or video files',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
              const SizedBox(height: 16),

              // Cover Media File Picker
              const Row(
                children: [
                  Icon(Icons.image, size: 16),
                  SizedBox(width: 8),
                  Text('Cover Media', style: TextStyle(fontWeight: FontWeight.w500)),
                ],
              ),
              const SizedBox(height: 8),
              if (_coverMediaFile == null)
                OutlinedButton.icon(
                  onPressed: _isLoading ? null : () async {
                    final file = await widget.fileManager.pickFile(
                      allowedExtensions: ['png', 'bmp', 'jpg', 'jpeg', 'tiff', 'tif',
                                          'wav', 'flac', 'mp3', 'mp4'],
                    );
                    if (file != null) {
                      setState(() {
                        _coverMediaFile = file;
                        // Reset method to first available for new format
                        final methods = _getAvailableStegoMethods();
                        if (!methods.contains(_stegoMethod)) {
                          _stegoMethod = methods.first;
                        }
                      });
                    }
                  },
                  icon: const Icon(Icons.folder_open),
                  label: const Text('Select Cover Media'),
                )
              else
                Card(
                  child: ListTile(
                    leading: Icon(
                      _isCoverVideo() ? Icons.videocam :
                      _detectStegoFormat(_coverMediaFile?.path) == 'audio' ? Icons.audiotrack :
                      Icons.image,
                      color: Colors.blue.shade700,
                    ),
                    title: Text(_coverMediaFile!.name),
                    subtitle: Text(_coverMediaFile!.sizeFormatted),
                    trailing: IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: _isLoading ? null : () {
                        setState(() {
                          _coverMediaFile = null;
                        });
                      },
                    ),
                  ),
                ),

              if (_coverMediaFile != null) ...[
                const SizedBox(height: 16),

                // Method Dropdown
                DropdownButtonFormField<String>(
                  initialValue: _stegoMethod,
                  decoration: const InputDecoration(
                    labelText: 'Steganography Method',
                    border: OutlineInputBorder(),
                    helperText: 'Method auto-filtered based on cover file type',
                  ),
                  items: _getAvailableStegoMethods().map((method) {
                    return DropdownMenuItem(
                      value: method,
                      child: Text(_formatStegoMethodName(method)),
                    );
                  }).toList(),
                  onChanged: _isLoading ? null : (value) {
                    setState(() {
                      _stegoMethod = value ?? 'lsb';
                    });
                  },
                ),
                const SizedBox(height: 16),

                // Bits per Channel Slider
                Row(
                  children: [
                    Expanded(
                      child: Text('Bits per Channel: $_stegoBitsPerChannel'),
                    ),
                  ],
                ),
                Slider(
                  value: _stegoBitsPerChannel.toDouble(),
                  min: 1,
                  max: 3,
                  divisions: 2,
                  label: '$_stegoBitsPerChannel',
                  onChanged: _isLoading ? null : (value) {
                    setState(() {
                      _stegoBitsPerChannel = value.toInt();
                    });
                  },
                ),
                const Text(
                  'Higher values = more capacity, lower stealth',
                  style: TextStyle(fontSize: 11, color: Colors.grey),
                ),
                const SizedBox(height: 16),

                // Steganography Password
                TextField(
                  controller: _stegoPasswordController,
                  decoration: const InputDecoration(
                    labelText: 'Steganography Password (optional)',
                    border: OutlineInputBorder(),
                    helperText: 'Separate password for steg security',
                    prefixIcon: Icon(Icons.vpn_key),
                  ),
                  obscureText: true,
                  enabled: !_isLoading,
                ),
                const SizedBox(height: 12),

                // Randomize Pixels Checkbox
                CheckboxListTile(
                  title: const Text('Randomize pixel selection'),
                  subtitle: Text(_stegoPasswordController.text.isEmpty
                    ? 'Requires steganography password'
                    : 'Enhances security against detection'),
                  value: _stegoRandomizePixels,
                  onChanged: _stegoPasswordController.text.isEmpty || _isLoading
                    ? null
                    : (value) {
                        setState(() {
                          _stegoRandomizePixels = value ?? false;
                        });
                      },
                  contentPadding: EdgeInsets.zero,
                  controlAffinity: ListTileControlAffinity.leading,
                  dense: true,
                ),

                // Decoy Data Checkbox
                CheckboxListTile(
                  title: const Text('Fill with decoy data'),
                  subtitle: const Text('Fill unused capacity with random data'),
                  value: _stegoDecoyData,
                  onChanged: _isLoading ? null : (value) {
                    setState(() {
                      _stegoDecoyData = value ?? false;
                    });
                  },
                  contentPadding: EdgeInsets.zero,
                  controlAffinity: ListTileControlAffinity.leading,
                  dense: true,
                ),

                // JPEG Quality Slider (if JPEG)
                if (_isCoverJpeg()) ...[
                  const SizedBox(height: 16),
                  const Divider(),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      const Icon(Icons.photo, size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text('JPEG Quality: $_jpegQuality'),
                      ),
                    ],
                  ),
                  Slider(
                    value: _jpegQuality.toDouble(),
                    min: 70,
                    max: 100,
                    divisions: 30,
                    label: '$_jpegQuality',
                    onChanged: _isLoading ? null : (value) {
                      setState(() {
                        _jpegQuality = value.toInt();
                      });
                    },
                  ),
                  const Text(
                    'Higher quality = better image, lower capacity',
                    style: TextStyle(fontSize: 11, color: Colors.grey),
                  ),
                ],

                // Video Options (if MP4)
                if (_isCoverVideo()) ...[
                  const SizedBox(height: 16),
                  const Divider(),
                  ExpansionTile(
                    leading: const Icon(Icons.videocam),
                    title: const Text('Video Steganography Options'),
                    subtitle: const Text('DCT-based QIM embedding parameters'),
                    children: [
                      const SizedBox(height: 8),

                      // Quantization Step
                      Row(
                        children: [
                          Expanded(
                            child: Text('Quantization Step: ${_videoQuantizationStep.toStringAsFixed(1)}'),
                          ),
                        ],
                      ),
                      Slider(
                        value: _videoQuantizationStep,
                        min: 1.0,
                        max: 20.0,
                        divisions: 38,
                        label: _videoQuantizationStep.toStringAsFixed(1),
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _videoQuantizationStep = value;
                          });
                        },
                      ),
                      const Text(
                        'Lower = higher quality, less capacity',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                      const SizedBox(height: 12),

                      // Adaptation Factor
                      Row(
                        children: [
                          Expanded(
                            child: Text('Adaptation Factor: ${_videoAdaptationFactor.toStringAsFixed(1)}'),
                          ),
                        ],
                      ),
                      Slider(
                        value: _videoAdaptationFactor,
                        min: 0.5,
                        max: 3.0,
                        divisions: 50,
                        label: _videoAdaptationFactor.toStringAsFixed(1),
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _videoAdaptationFactor = value;
                          });
                        },
                      ),
                      const Text(
                        'For adaptive QIM algorithm (default: 1.2)',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                      const SizedBox(height: 12),

                      // Compensation Factor
                      Row(
                        children: [
                          Expanded(
                            child: Text('Compensation Factor: ${_videoCompensationFactor.toStringAsFixed(1)}'),
                          ),
                        ],
                      ),
                      Slider(
                        value: _videoCompensationFactor,
                        min: 0.0,
                        max: 1.0,
                        divisions: 20,
                        label: _videoCompensationFactor.toStringAsFixed(1),
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _videoCompensationFactor = value;
                          });
                        },
                      ),
                      const Text(
                        'For distortion-compensated QIM (default: 0.5)',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                      const SizedBox(height: 12),

                      // Bits per Coefficient
                      DropdownButtonFormField<int>(
                        initialValue: _videoBitsPerCoefficient,
                        decoration: const InputDecoration(
                          labelText: 'Bits per DCT Coefficient',
                          border: OutlineInputBorder(),
                          helperText: 'For multi-level QIM algorithm',
                        ),
                        items: [1, 2, 3, 4].map((bits) {
                          return DropdownMenuItem(
                            value: bits,
                            child: Text('$bits bit${bits > 1 ? "s" : ""}'),
                          );
                        }).toList(),
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _videoBitsPerCoefficient = value ?? 2;
                          });
                        },
                      ),
                      const SizedBox(height: 12),

                      // Temporal Spread Checkbox
                      CheckboxListTile(
                        title: const Text('Temporal spread'),
                        subtitle: const Text('Spread data across frames for redundancy'),
                        value: _videoTemporalSpread,
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _videoTemporalSpread = value ?? true;
                          });
                        },
                        contentPadding: EdgeInsets.zero,
                        controlAffinity: ListTileControlAffinity.leading,
                        dense: true,
                      ),

                      // Quality Preservation Slider
                      Row(
                        children: [
                          Expanded(
                            child: Text('Quality Preservation: $_videoQualityPreservation'),
                          ),
                        ],
                      ),
                      Slider(
                        value: _videoQualityPreservation.toDouble(),
                        min: 1,
                        max: 10,
                        divisions: 9,
                        label: '$_videoQualityPreservation',
                        onChanged: _isLoading ? null : (value) {
                          setState(() {
                            _videoQualityPreservation = value.toInt();
                          });
                        },
                      ),
                      const Text(
                        '1 = max capacity, 10 = max quality (default: 8)',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                      const SizedBox(height: 8),
                    ],
                  ),
                ],
              ],
            ],
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

  /// Detect cover media format from file extension
  String? _detectStegoFormat(String? filePath) {
    if (filePath == null) return null;
    final ext = path.extension(filePath).toLowerCase();
    return _stegoFormatByExtension[ext];
  }

  /// Get available stego methods for current cover file
  List<String> _getAvailableStegoMethods() {
    final format = _detectStegoFormat(_coverMediaFile?.path);
    if (format == null) return ['lsb']; // default
    return _stegoMethodsByFormat[format] ?? ['lsb'];
  }

  /// Check if current cover file is JPEG
  bool _isCoverJpeg() {
    return _detectStegoFormat(_coverMediaFile?.path) == 'jpeg';
  }

  /// Check if current cover file is MP4 video
  bool _isCoverVideo() {
    return _detectStegoFormat(_coverMediaFile?.path) == 'video';
  }

  /// Format steganography method name for display
  String _formatStegoMethodName(String method) {
    switch (method) {
      case 'lsb':
        return 'LSB (Least Significant Bit)';
      case 'adaptive':
        return 'Adaptive LSB';
      case 'f5':
        return 'F5 Algorithm';
      case 'outguess':
        return 'OutGuess';
      case 'basic':
        return 'Basic JPEG';
      case 'uniform':
        return 'Uniform QIM';
      case 'distortion_comp':
        return 'Distortion-Compensated QIM';
      case 'multi_level':
        return 'Multi-Level QIM';
      default:
        return method.toUpperCase();
    }
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
                    // Live strength meter (shells out to check-password --json,
                    // debounced). Shown while choosing a password to encrypt.
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
                      const Row(
                        children: [
                          Icon(Icons.vpn_key),
                          SizedBox(width: 8),
                          Text('Key Stretching', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                        ],
                      ),
                      const SizedBox(height: 12),

                      // Hash Chain Configuration
                      HashKdfConfigSection(
                        hashConfig: _hashConfig,
                        hashAlgorithms: _hashAlgorithms,
                        kdfConfig: _kdfConfig,
                      ),

                      const SizedBox(height: 12),

                      // KDF Chain Configuration
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

                  // Steganography Configuration
                  _buildSteganographyConfig(),
                  const SizedBox(height: 12),

                  // PQC keyfile / KDF composition (gitlab#153)
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(12.0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          TextField(
                            controller: _pqcKeyfileController,
                            decoration: const InputDecoration(
                              labelText: 'Load PQC key file',
                              helperText:
                                  'Optional path to an EXISTING post-quantum key '
                                  'file to encrypt with. Generating one is not '
                                  'available here.',
                              border: OutlineInputBorder(),
                            ),
                          ),
                          const Divider(height: 24),
                          Text('Key derivation',
                              style: Theme.of(context).textTheme.titleSmall),
                          const SizedBox(height: 8),
                          SwitchListTile(
                            title: const Text(
                                'Use legacy sequential key derivation'),
                            subtitle: const Text(
                              'Writes the older format version 13 instead of the '
                              'current default. The derived key is only as strong '
                              'as the weakest step in the chain, wide-key ciphers '
                              'are funnelled through a narrower intermediate, and '
                              'the newer transcript binding is not applied. Leave '
                              'off unless you need to interoperate with an older '
                              'release. Not available for files over 10 MB.',
                              style: TextStyle(color: Colors.orange),
                            ),
                            value: _useSequentialXor,
                            onChanged: (v) => setState(() {
                              _useSequentialXor = v;
                              // Parallel derivation applies to the independent
                              // composition only.
                              if (v) _parallelKdf = false;
                            }),
                            contentPadding: EdgeInsets.zero,
                          ),
                          SwitchListTile(
                            title: const Text('Parallel key derivation'),
                            subtitle: const Text(
                              'Derives the key chain in parallel. Uses more memory '
                              'at once, since the cost of each step is incurred '
                              'together rather than one after another.',
                            ),
                            value: _parallelKdf,
                            onChanged: _useSequentialXor
                                ? null
                                : (v) => setState(() => _parallelKdf = v),
                            contentPadding: EdgeInsets.zero,
                          ),
                          if (_parallelKdf)
                            Row(
                              children: [
                                const Text('Worker threads:'),
                                const SizedBox(width: 12),
                                DropdownButton<int>(
                                  value: _kdfWorkers,
                                  items: const [2, 4, 8, 16]
                                      .map((n) => DropdownMenuItem(
                                          value: n, child: Text('$n')))
                                      .toList(),
                                  onChanged: (v) =>
                                      setState(() => _kdfWorkers = v ?? 4),
                                ),
                              ],
                            ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),

                  // File-specific options
                  if (_isFileMode)
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(12.0),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            CheckboxListTile(
                              title: const Text('Force Overwrite'),
                              subtitle: const Text('Replace source file with encrypted version'),
                              value: _forceOverwrite,
                              onChanged: (value) =>
                                  setState(() => _forceOverwrite = value ?? false),
                              contentPadding: EdgeInsets.zero,
                            ),
                            const Divider(),
                            SwitchListTile(
                              title: const Text(
                                  'Securely delete the source file after encrypting'),
                              subtitle: const Text(
                                'Overwrites and deletes the original once the '
                                'encrypted copy is written. The encrypted file and '
                                'its password then become the only way back to the '
                                'data — if the password is lost it cannot be '
                                'recovered. You are asked to confirm each time.',
                              ),
                              value: _shredSourceAfterEncrypt,
                              onChanged: (value) =>
                                  setState(() => _shredSourceAfterEncrypt = value),
                              contentPadding: EdgeInsets.zero,
                            ),
                            if (_shredSourceAfterEncrypt)
                              Padding(
                                padding: const EdgeInsets.only(top: 8),
                                child: Row(
                                  children: [
                                    const Text('Overwrite passes:'),
                                    const SizedBox(width: 12),
                                    DropdownButton<int>(
                                      value: _shredPasses,
                                      items: const [1, 3, 7]
                                          .map((n) => DropdownMenuItem(
                                                value: n,
                                                child: Text('$n'),
                                              ))
                                          .toList(),
                                      onChanged: (v) =>
                                          setState(() => _shredPasses = v ?? 3),
                                    ),
                                  ],
                                ),
                              ),
                          ],
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
                          const SizedBox(
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
