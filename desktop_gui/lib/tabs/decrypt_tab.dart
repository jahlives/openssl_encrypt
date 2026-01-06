import 'package:flutter/material.dart';
import '../cli_service.dart';
import '../file_manager.dart';
import '../widgets/crypto_widgets.dart';

class DecryptTab extends StatefulWidget {
  final FileManager fileManager;

  const DecryptTab({super.key, required this.fileManager});

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

  @override
  void dispose() {
    _textController.dispose();
    _passwordController.dispose();
    super.dispose();
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
      );

      setState(() {
        result = 'Decrypted successfully!\n\n$decrypted';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        result = 'Decryption failed: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _decryptFile() async {
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
      );

      // Store decrypted content
      final preview = decrypted.length > 500 ? decrypted.substring(0, 500) + '...' : decrypted;
      setState(() {
        _decryptedContent = decrypted;
        result = 'File decrypted successfully!\n\n'
            'File: ${_selectedFile!.name}\n'
            'Size: ${_selectedFile!.sizeFormatted}\n\n'
            'Content Preview:\n$preview';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        result = 'File decryption failed: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _saveDecryptedFile() async {
    if (_decryptedContent == null) return;

    final outputPath = widget.fileManager.getDecryptedFileName(_selectedFile!.path);
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
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Advanced Options (Rarely needed - collapsed by default)
            ExpansionTile(
              title: const Text('Advanced Options'),
              subtitle: const Text('Integrity verification settings'),
              leading: const Icon(Icons.settings),
              children: [
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

            // Save to File Button (for file mode)
            if (_isFileMode && _decryptedContent != null) ...[
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _saveDecryptedFile,
                icon: const Icon(Icons.save),
                label: const Text('Save Decrypted Content to File'),
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
