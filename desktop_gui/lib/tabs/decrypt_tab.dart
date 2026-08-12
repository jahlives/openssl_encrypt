import 'dart:io';

import 'package:flutter/material.dart';
import '../cli_service.dart';
import '../input_validation.dart';
import '../file_manager.dart';
import '../widgets/crypto_widgets.dart';

class DecryptTab extends StatefulWidget {
  final FileManager fileManager;
  final bool isProMode;

  const DecryptTab({super.key, required this.fileManager, this.isProMode = false});

  @override
  State<DecryptTab> createState() => _DecryptTabState();
}

class _DecryptTabState extends State<DecryptTab> {
  // Input mode toggle
  bool _isFileMode = true;

  // Text input controllers
  final TextEditingController _textController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  // File input
  FileInfo? _selectedFile;

  // Steganography extraction (gitlab#217): the Encrypt tab can hide data in
  // cover media, but round-tripping needed the CLI. Image/audio formats
  // only -- the video flags are dead CLI surface until gitlab#170 is
  // decided, so the picker must not advertise them.
  bool _extractFromSteganography = false;
  FileInfo? _stegoMediaFile;
  final TextEditingController _stegoPasswordController = TextEditingController();
  int _stegoBitsPerChannel = 1;

  // Loading state
  bool _isLoading = false;
  String result = '';
  String? _decryptedContent;
  String _operationStatus = '';

  // Password options
  bool _forcePassword = false;

  // Optional decryption settings (mostly for asymmetric mode)
  String? _decryptionIdentity;
  String? _verifyFrom;
  bool _skipVerification = false;
  bool _verifyIntegrity = false;  // Remote server verification - off by default
  bool _showProgress = false;

  // Identities available for asymmetric decryption (--with-key / --verify-from)
  List<Map<String, dynamic>> _ownIdentities = [];
  List<Map<String, dynamic>> _contacts = [];
  // gitlab#215 item 6: a load FAILURE is not an empty store. The error and
  // the store entries the CLI reported as unreadable are kept so the UI can
  // say what actually happened instead of "create one".
  String? _identityLoadError;
  List<Map<String, dynamic>> _skippedIdentities = [];

  @override
  void initState() {
    super.initState();
    // The asymmetric section only renders in Pro mode; don't shell out to
    // the CLI (and read the identity store) for data Simple mode never shows.
    if (widget.isProMode) _loadIdentities();
  }

  @override
  void didUpdateWidget(DecryptTab oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.isProMode && !oldWidget.isProMode) _loadIdentities();
  }

  @override
  void dispose() {
    _textController.dispose();
    _passwordController.dispose();
    _stegoPasswordController.dispose();
    super.dispose();
  }

  /// Load identities (own + contacts) for asymmetric decryption controls.
  Future<void> _loadIdentities() async {
    try {
      final identities = await CLIService.listIdentities();
      if (!mounted) return;
      setState(() {
        _ownIdentities = (identities['own'] as List<Map<String, dynamic>>?) ?? [];
        _contacts = (identities['contacts'] as List<Map<String, dynamic>>?) ?? [];
        // Entries the CLI could not load are surfaced, not dropped: an
        // absent entry is not an absent identity (gitlab#215 item 6).
        _skippedIdentities =
            (identities['skipped'] as List<Map<String, dynamic>>?) ?? [];
        _identityLoadError = null;
      });
    } catch (e) {
      CLIService.outputDebugLog('Failed to load identities: $e');
      if (!mounted) return;
      setState(() {
        // Keep the failure distinct from an empty store: the "create one"
        // hint over an unreachable CLI sends the user in exactly the wrong
        // direction (gitlab#215 item 6).
        _ownIdentities = [];
        _contacts = [];
        _skippedIdentities = [];
        _identityLoadError = InputValidator.sanitizeForDisplay(e.toString());
      });
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

  Future<void> _decrypt() async {
    if (_isFileMode) {
      await _decryptFile();
    } else {
      await _decryptText();
    }
  }

  Future<void> _decryptText() async {
    final inputData = _textController.text.trim();

    if (inputData.isEmpty || _passwordController.text.isEmpty) {
      setState(() {
        result = 'Please enter both encrypted text and password';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      result = 'Decrypting...';
      _operationStatus = '';
    });

    try {
      final decrypted = await CLIService.decryptTextWithProgress(
        inputData,
        _passwordController.text,
        withKey: _decryptionIdentity,
        verifyFrom: _verifyFrom,
        skipVerification: _skipVerification,
        verifyIntegrity: _verifyIntegrity,
        forcePassword: _forcePassword,
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
        onIntegrityPrompt: _verifyIntegrity ? _showIntegrityWarningDialog : null,
      );

      setState(() {
        result = 'Decrypted successfully!\n\n$decrypted';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        // Sanitize: the exception embeds raw CLI stderr, which on the
        // asymmetric path can carry attacker-influenced signer text.
        result = InputValidator.sanitizeForDisplay('Decryption failed: $e');
        _isLoading = false;
      });
    }
  }

  Future<void> _decryptFile() async {
    if (_extractFromSteganography) {
      await _decryptFromStego();
      return;
    }
    if (_selectedFile == null || _passwordController.text.isEmpty) {
      setState(() {
        result = 'Please select an encrypted file and enter a password';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      result = 'Decrypting file...';
      _operationStatus = '';
    });

    try {
      // Read the encrypted file
      final fileContent = await widget.fileManager.readFileText(_selectedFile!.path);
      if (fileContent == null) {
        throw Exception('Could not read file');
      }

      // Decrypt using CLI service
      final decrypted = await CLIService.decryptTextWithProgress(
        fileContent,
        _passwordController.text,
        withKey: _decryptionIdentity,
        verifyFrom: _verifyFrom,
        skipVerification: _skipVerification,
        verifyIntegrity: _verifyIntegrity,
        forcePassword: _forcePassword,
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
        onIntegrityPrompt: _verifyIntegrity ? _showIntegrityWarningDialog : null,
      );

      // Store decrypted content
      setState(() {
        _decryptedContent = decrypted;
        // Status only; the plaintext preview renders in its own widget so a
        // crafted payload cannot forge status lines (review F11).
        result = 'File decrypted successfully!\n\n'
            'File: ${_selectedFile!.name}\n'
            'Size: ${_selectedFile!.sizeFormatted}';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        result = InputValidator.sanitizeForDisplay('File decryption failed: $e');
        _isLoading = false;
      });
    }
  }

  /// Extract + decrypt hidden data from cover media (gitlab#217).
  Future<void> _decryptFromStego() async {
    if (_stegoMediaFile == null || _passwordController.text.isEmpty) {
      setState(() {
        result = 'Please select the cover media file and enter a password';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      result = 'Extracting and decrypting hidden data...';
      _operationStatus = '';
    });

    Directory? tempDir;
    try {
      tempDir = await Directory.systemTemp.createTemp('openssl_encrypt_stego_');
      if (!Platform.isWindows) {
        try {
          await Process.run('chmod', ['700', tempDir.path]);
        } catch (_) {}
      }
      final outputPath = '${tempDir.path}/extracted.txt';

      final procResult = await CLIService.decryptFromSteganography(
        stegoImagePath: _stegoMediaFile!.path,
        outputPath: outputPath,
        password: _passwordController.text,
        stegoPassword: _stegoPasswordController.text.isEmpty
            ? null
            : _stegoPasswordController.text,
        bitsPerChannel: _stegoBitsPerChannel,
        verifyIntegrity: _verifyIntegrity,
        withKey: _decryptionIdentity,
        verifyFrom: _verifyFrom,
        skipVerification: _skipVerification,
      );

      if (procResult.exitCode != 0) {
        throw Exception(procResult.stderr.toString());
      }

      final decrypted = await File(outputPath).readAsString();
      if (!mounted) return;
      setState(() {
        _decryptedContent = decrypted;
        // Status only -- the extracted plaintext is untrusted data and must
        // not be concatenated into the trust-relevant status string (a
        // crafted payload can forge status lines via U+2028/bidi; review
        // F11). It is shown in its own preview widget below.
        result = 'Hidden data extracted and decrypted successfully!\n\n'
            'Cover media: ${_stegoMediaFile!.name}';
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        result =
            InputValidator.sanitizeForDisplay('Steganography extraction failed: $e');
        _isLoading = false;
      });
    } finally {
      try {
        await tempDir?.delete(recursive: true);
      } catch (_) {}
    }
  }

  Widget _buildStegoExtractionCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.visibility_off),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'Extract from steganography',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                Switch(
                  value: _extractFromSteganography,
                  onChanged: _isLoading
                      ? null
                      : (value) => setState(() {
                            _extractFromSteganography = value;
                            _decryptedContent = null;
                          }),
                ),
              ],
            ),
            if (_extractFromSteganography) ...[
              const SizedBox(height: 8),
              const Text(
                'Recover data hidden in an image or audio file by the Encrypt '
                'tab (LSB method).',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
              const SizedBox(height: 12),
              if (_stegoMediaFile == null)
                OutlinedButton.icon(
                  onPressed: _isLoading
                      ? null
                      : () async {
                          // Image/audio only: no video until gitlab#170.
                          final file = await widget.fileManager.pickFile(
                            allowedExtensions: [
                              'png', 'bmp', 'tiff', 'tif', 'wav', 'flac',
                            ],
                          );
                          if (file != null) {
                            setState(() => _stegoMediaFile = file);
                          }
                        },
                  icon: const Icon(Icons.image),
                  label: const Text('Select cover media'),
                )
              else
                ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.image),
                  title: Text(_stegoMediaFile!.name),
                  trailing: IconButton(
                    icon: const Icon(Icons.clear),
                    onPressed: _isLoading
                        ? null
                        : () => setState(() => _stegoMediaFile = null),
                  ),
                ),
              const SizedBox(height: 8),
              TextField(
                controller: _stegoPasswordController,
                decoration: const InputDecoration(
                  labelText: 'Steganography password (optional)',
                  border: OutlineInputBorder(),
                  isDense: true,
                  prefixIcon: Icon(Icons.visibility_off),
                ),
                obscureText: true,
                enabled: !_isLoading,
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  const Text('Bits per channel:'),
                  const SizedBox(width: 12),
                  DropdownButton<int>(
                    value: _stegoBitsPerChannel,
                    items: const [1, 2, 3]
                        .map((n) =>
                            DropdownMenuItem(value: n, child: Text('$n')))
                        .toList(),
                    onChanged: _isLoading
                        ? null
                        : (v) =>
                            setState(() => _stegoBitsPerChannel = v ?? 1),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _saveDecryptedFile() async {
    if (_decryptedContent == null) return;

    final source = _selectedFile ?? _stegoMediaFile;
    if (source == null) return;
    final outputPath = widget.fileManager.getDecryptedFileName(source.path);
    final success = await widget.fileManager.writeFileText(outputPath, _decryptedContent!);

    if (success && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Saved to: $outputPath'),
          backgroundColor: Colors.green,
        ),
      );
    } else if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Failed to save file'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  /// Show warning dialog when integrity verification fails
  Future<bool> _showIntegrityWarningDialog(String message) async {
    if (!mounted) return false;

    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,  // Force user to make a choice
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: Colors.orange.shade700, size: 28),
            const SizedBox(width: 8),
            const Text('Integrity Verification Failed'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'The file metadata may have been tampered with.',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            const Text(
              'Proceeding could expose you to a denial-of-service attack '
              'via malicious hash/KDF parameters that consume excessive '
              'CPU or memory.',
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.red.shade50,
                border: Border.all(color: Colors.red.shade200),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Row(
                children: [
                  Icon(Icons.info_outline, color: Colors.red),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Only proceed if you trust the source of this file.',
                      style: TextStyle(color: Colors.red, fontWeight: FontWeight.w500),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Abort'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.orange,
            ),
            child: const Text('Proceed Anyway', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    return result ?? false;  // Default to false (abort) if dialog dismissed
  }

  /// Build a dropdown label for an identity/contact map.
  String _identityLabel(Map<String, dynamic> id) {
    final name = id['name'] as String? ?? 'Unknown';
    final email = id['email'] as String?;
    return (email != null && email.isNotEmpty) ? '$name <$email>' : name;
  }

  /// Dropdown child for an identity: a leading structural source badge (own/
  /// contact) that cannot be spoofed or clipped by the untrusted email field
  /// (gitlab#215 item 7 / review F6 -- a suffix on '$name <$email>' could be
  /// forged via a crafted email), then the ellipsized label.
  Widget _identityMenuChild(Map<String, dynamic> id) {
    final source = id['_source'] as String?;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (source != null) ...[
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
            decoration: BoxDecoration(
              color: source == 'own'
                  ? Colors.blue.withValues(alpha: 0.15)
                  : Colors.teal.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(source,
                style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
          ),
          const SizedBox(width: 6),
        ],
        Flexible(
          child: Text(_identityLabel(id), overflow: TextOverflow.ellipsis),
        ),
      ],
    );
  }

  /// Drop entries with an empty/missing name and dedupe by name.
  ///
  /// The dropdowns use the identity name as their value; duplicate or null
  /// values (including a null name colliding with the null "None" sentinel)
  /// make DropdownButton assert and crash the tab. Names are unique in the
  /// identity store, but a contact can share a name with an own identity in
  /// the merged signer list, and imported contacts are untrusted input.
  // Count of signer entries dropped by the last _dedupeByName pass (empty
  // name, or a name colliding with an already-kept entry). These vanish from
  // the dropdowns silently, so the "not listed" banner adds them in (review
  // F7) rather than reporting only the CLI-reported skipped count.
  int _signerDedupeDrops = 0;

  List<Map<String, dynamic>> _dedupeByName(List<Map<String, dynamic>> ids) {
    final seen = <String>{};
    final out = <Map<String, dynamic>>[];
    var drops = 0;
    for (final id in ids) {
      final name = id['name'] as String?;
      if (name == null || name.isEmpty) {
        drops++;
        continue;
      }
      if (seen.add(name)) {
        out.add(id);
      } else {
        drops++;
      }
    }
    _signerDedupeDrops = drops;
    return out;
  }

  /// Advanced asymmetric-decryption controls (--with-key / --verify-from /
  /// --no-verify). Only relevant for files encrypted to an identity; symmetric
  /// files are auto-detected from metadata and need none of this.
  Widget _buildAsymmetricDecryptSection() {
    // Only own identities hold the private key needed to decrypt.
    final ownIds = _dedupeByName(_ownIdentities);
    // A signature can be verified against any known identity or contact.
    // gitlab#215 item 7: tag the merged signer entries with their source --
    // an own/contact name collision is otherwise undetectable in the UI
    // (gitlab#173 surface), and the dedupe silently keeps the own entry.
    final signerIds = _dedupeByName([
      ..._ownIdentities.map((i) => {...i, '_source': 'own'}),
      ..._contacts.map((i) => {...i, '_source': 'contact'}),
    ]);

    final identityItems = <DropdownMenuItem<String?>>[
      const DropdownMenuItem<String?>(
        value: null,
        child: Text('None (symmetric / auto-detect)'),
      ),
      ...ownIds.map((id) => DropdownMenuItem<String?>(
            value: id['name'] as String,
            child: Text(_identityLabel(id)),
          )),
    ];

    final signerItems = <DropdownMenuItem<String?>>[
      const DropdownMenuItem<String?>(
        value: null,
        child: Text('Any / not specified'),
      ),
      ...signerIds.map((id) => DropdownMenuItem<String?>(
            value: id['name'] as String,
            child: _identityMenuChild(id),
          )),
    ];

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.vpn_key, size: 20),
              SizedBox(width: 8),
              Text('Asymmetric Decryption',
                  style: TextStyle(fontWeight: FontWeight.bold)),
            ],
          ),
          const SizedBox(height: 4),
          const Text(
            'Only needed for files encrypted to an identity (ML-KEM). '
            'Symmetric files are auto-detected and need no selection.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
          const SizedBox(height: 12),
          const Text('Decryption identity'),
          const SizedBox(height: 4),
          DropdownButtonFormField<String?>(
            initialValue: _decryptionIdentity,
            isExpanded: true,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              isDense: true,
              prefixIcon: Icon(Icons.badge),
            ),
            items: identityItems,
            onChanged: _isLoading
                ? null
                : (value) {
                    setState(() {
                      _decryptionIdentity = value;
                      // Always re-derive the signature options for the newly
                      // selected identity: never carry a "skip verification"
                      // choice across a change of identity (or to symmetric).
                      _verifyFrom = null;
                      _skipVerification = false;
                    });
                  },
          ),
          if (_identityLoadError != null) ...[
            const SizedBox(height: 6),
            Text(
              'Could not load identities: $_identityLoadError',
              style: const TextStyle(fontSize: 12, color: Colors.red),
            ),
          ] else if (ownIds.isEmpty) ...[
            const SizedBox(height: 6),
            const Text(
              'No local identities found. Create one under Identity Management '
              'to decrypt asymmetric files.',
              style: TextStyle(fontSize: 12, color: Colors.orange),
            ),
          ],
          if (_skippedIdentities.isNotEmpty || _signerDedupeDrops > 0) ...[
            const SizedBox(height: 6),
            Builder(builder: (_) {
              final n = _skippedIdentities.length + _signerDedupeDrops;
              return Text(
                'At least $n identity store ${n == 1 ? "entry" : "entries"} '
                'could not be shown here (unreadable, unnamed, or a name '
                'collision) and ${n == 1 ? "is" : "are"} not listed.',
                style: const TextStyle(fontSize: 12, color: Colors.orange),
              );
            }),
          ],
          // --verify-from / --no-verify are only sent by CLIService when a
          // non-empty decryption identity is set (cli_service.dart:759-766),
          // so gate them behind exactly that condition — otherwise the warning
          // banner could imply verification is off while no flags are sent.
          if (_decryptionIdentity != null && _decryptionIdentity!.isNotEmpty) ...[
            const SizedBox(height: 16),
            DropdownButtonFormField<String?>(
              initialValue: _verifyFrom,
              isExpanded: true,
              decoration: const InputDecoration(
                labelText: 'Verify signature from',
                border: OutlineInputBorder(),
                isDense: true,
                prefixIcon: Icon(Icons.verified_user),
              ),
              items: signerItems,
              onChanged: (_isLoading || _skipVerification)
                  ? null
                  : (value) => setState(() => _verifyFrom = value),
            ),
            const SizedBox(height: 8),
            CheckboxListTile(
              value: _skipVerification,
              onChanged: _isLoading
                  ? null
                  : (value) {
                      setState(() {
                        _skipVerification = value ?? false;
                        // Verifying a specific signer is meaningless if
                        // verification is skipped entirely.
                        if (_skipVerification) _verifyFrom = null;
                      });
                    },
              title: const Text('Skip signature verification'),
              subtitle: const Text(
                'Do not verify the sender signature. Only use if you fully '
                'trust the file source — this removes authenticity protection.',
              ),
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              dense: true,
            ),
            if (_skipVerification)
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.red.shade50,
                  border: Border.all(color: Colors.red.shade200),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.warning_amber, color: Colors.red, size: 20),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Signature verification disabled — the sender\'s '
                        'authenticity will NOT be checked.',
                        style: TextStyle(
                            color: Colors.red,
                            fontSize: 12,
                            fontWeight: FontWeight.w500),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ],
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
            // Header info
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Row(
                  children: [
                    Icon(Icons.info_outline, color: Colors.blue.shade700),
                    const SizedBox(width: 12),
                    const Expanded(
                      child: Text(
                        'Decryption settings are auto-detected from encrypted file metadata. '
                        'Only password is required.',
                        style: TextStyle(fontSize: 13),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Input Type Toggle
            InputTypeToggle(
              isFileMode: _isFileMode,
              onToggle: (value) {
                setState(() {
                  _isFileMode = value;
                  result = ''; // Clear result when switching modes
                  _decryptedContent = null;
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
                          Text('Encrypted Text Input', style: TextStyle(fontWeight: FontWeight.bold)),
                        ],
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _textController,
                        decoration: const InputDecoration(
                          labelText: 'Encrypted text',
                          border: OutlineInputBorder(),
                          hintText: 'Paste encrypted text here...',
                        ),
                        maxLines: 5,
                        enabled: !_isLoading,
                      ),
                    ],
                  ),
                ),
              ),
            ] else ...[
              if (widget.isProMode) ...[
                _buildStegoExtractionCard(),
                const SizedBox(height: 16),
              ],
              if (!_extractFromSteganography)
                FilePickerWidget(
                  selectedFile: _selectedFile,
                  onPickFile: _pickFile,
                  onClearFile: () => setState(() {
                    _selectedFile = null;
                    _decryptedContent = null;
                  }),
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
                        prefixIcon: Icon(Icons.lock_open),
                      ),
                      obscureText: true,
                      enabled: !_isLoading,
                    ),
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

            if (widget.isProMode) ...[
              // Advanced Options (Rarely needed - collapsed by default)
              ExpansionTile(
                title: const Text('Advanced Options'),
                subtitle: const Text('Asymmetric decryption & integrity settings'),
                leading: const Icon(Icons.settings),
                children: [
                  // Asymmetric decryption identity / signature verification
                  _buildAsymmetricDecryptSection(),
                  const Divider(height: 24),
                  // Integrity Verification
                  IntegrityConfigSection(
                    enableIntegrity: false,
                    verifyIntegrity: _verifyIntegrity,
                    isEncryptMode: false,
                    onEnableIntegrityChanged: (_) {},
                    onVerifyIntegrityChanged: (value) => setState(() => _verifyIntegrity = value),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 24),

            // Decrypt Button
            ElevatedButton.icon(
              onPressed: _isLoading ? null : _decrypt,
              icon: _isLoading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.lock_open),
              label: Text(_isLoading ? 'Decrypting...' : 'DECRYPT'),
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

            // Save to File Button (for file mode)
            if (_isFileMode && _decryptedContent != null) ...[
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _saveDecryptedFile,
                icon: const Icon(Icons.save),
                label: const Text('Save Decrypted Content to File'),
              ),
            ],

            // Decrypted-content preview (file mode). Rendered in its own
            // widget, never concatenated into the status string, so the
            // untrusted plaintext cannot fabricate status lines (review F11).
            if (_isFileMode && _decryptedContent != null) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.description_outlined),
                          SizedBox(width: 8),
                          Text('Content Preview',
                              style: TextStyle(
                                  fontWeight: FontWeight.bold, fontSize: 16)),
                        ],
                      ),
                      const SizedBox(height: 12),
                      SelectableText(
                        _decryptedContent!.length > 500
                            ? '${_decryptedContent!.substring(0, 500)}...'
                            : _decryptedContent!,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                    ],
                  ),
                ),
              ),
            ],

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
                          Icon(Icons.check_circle_outline),
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
