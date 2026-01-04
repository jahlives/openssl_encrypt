import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../file_manager.dart';
import '../cli_service.dart';

/// Encryption modes for the application
enum EncryptionMode {
  symmetric,   // Traditional password-based encryption (V3-V6)
  asymmetric,  // Identity-based encryption with ML-KEM + ML-DSA (V7)
  cascade,     // Multi-layer encryption chaining (V8)
}

/// Encryption Mode Selector Widget
/// Allows user to choose between Symmetric, Asymmetric, and Cascade encryption
class EncryptionModeSelector extends StatelessWidget {
  final EncryptionMode selectedMode;
  final ValueChanged<EncryptionMode> onModeChanged;

  const EncryptionModeSelector({
    super.key,
    required this.selectedMode,
    required this.onModeChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.security),
                const SizedBox(width: 8),
                const Text('Encryption Mode', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Encryption Modes'),
                        content: const SingleChildScrollView(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text('Symmetric:', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('Traditional password-based encryption using AES, ChaCha20, or Fernet.\\n'),
                              Text('Asymmetric:', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('Identity-based encryption using post-quantum ML-KEM and ML-DSA. Requires identity management.\\n'),
                              Text('Cascade:', style: TextStyle(fontWeight: FontWeight.bold)),
                              Text('Multi-layer encryption chaining multiple algorithms for defense-in-depth security.'),
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
                selected: {selectedMode},
                onSelectionChanged: (Set<EncryptionMode> newSelection) {
                  onModeChanged(newSelection.first);
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Algorithm Selector with Categorized Dialog Picker
/// For symmetric mode algorithm selection
class AlgorithmSelector extends StatelessWidget {
  final String selectedAlgorithm;
  final ValueChanged<String> onAlgorithmChanged;
  final bool enabled;

  const AlgorithmSelector({
    super.key,
    required this.selectedAlgorithm,
    required this.onAlgorithmChanged,
    this.enabled = true,
  });

  /// Get detailed description for algorithm
  String _getAlgorithmDescription(String algorithm) {
    final descriptions = {
      // Classical Symmetric
      'fernet': 'AES-128-CBC with HMAC authentication - Python-compatible standard',
      'aes-gcm': 'AES-256-GCM authenticated encryption - High performance, military-grade (Recommended for general use)',
      'chacha20-poly1305': 'ChaCha20 stream cipher with Poly1305 MAC - Modern, fast, secure',
      'xchacha20-poly1305': 'Extended ChaCha20 with 192-bit nonce - Enhanced security for large files',
      'aes-siv': 'AES-SIV synthetic IV mode - Misuse-resistant encryption',
      'aes-gcm-siv': 'AES-GCM-SIV - Combines speed of GCM with misuse resistance',
      'aes-ocb3': 'AES-OCB3 high-performance authenticated encryption',
      'camellia': 'Camellia block cipher - International standard, alternative to AES',

      // Threefish (Large Block)
      'threefish-512': 'Threefish-512 - 512-bit block cipher, 256-bit PQ security, CTR mode with Poly1305 (Recommended)',
      'threefish-1024': 'Threefish-1024 - 1024-bit block cipher, 512-bit PQ security, CTR mode with Poly1305',

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
      'hqc-128-hybrid': 'HQC-128 hybrid - WARNING: Decryption issues in <1.3.0, theoretical flaws exist (https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-3rxw-4v8q-9gq5)',
      'hqc-192-hybrid': 'HQC-192 hybrid - WARNING: Decryption issues in <1.3.0, theoretical flaws exist (https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-3rxw-4v8q-9gq5)',
      'hqc-256-hybrid': 'HQC-256 hybrid - WARNING: Decryption issues in <1.3.0, theoretical flaws exist (https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-3rxw-4v8q-9gq5)',

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

  /// Build Classical Symmetric category with sub-group headers
  List<Widget> _buildClassicalSymmetricWithSubgroups(BuildContext context, List<String> algorithms) {
    final widgets = <Widget>[];

    // Group algorithms by family
    final fernet = algorithms.where((a) => a == 'fernet').toList();
    final aes = algorithms.where((a) => a.startsWith('aes-')).toList();
    final chacha = algorithms.where((a) => a.contains('chacha20') && !a.contains('ml-kem')).toList();
    final threefish = algorithms.where((a) => a.startsWith('threefish-')).toList();

    // Helper to build algorithm card
    Widget buildAlgoCard(String algorithm) {
      final isSelected = algorithm == selectedAlgorithm;
      return Card(
        color: isSelected ? Theme.of(context).colorScheme.primaryContainer : null,
        child: ListTile(
          leading: Icon(
            Icons.security,
            color: Theme.of(context).colorScheme.primary,
          ),
          title: Row(
            children: [
              Text(
                algorithm,
                style: TextStyle(
                  fontWeight: isSelected ? FontWeight.bold : null,
                ),
              ),
              if (algorithm == 'aes-gcm' || algorithm == 'threefish-512') ...[
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
    }

    // Fernet
    if (fernet.isNotEmpty) {
      widgets.add(
        Padding(
          padding: const EdgeInsets.only(left: 16, top: 8, bottom: 4),
          child: Text(
            'Fernet',
            style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12, color: Theme.of(context).colorScheme.secondary),
          ),
        ),
      );
      widgets.addAll(fernet.map(buildAlgoCard));
    }

    // AES Family
    if (aes.isNotEmpty) {
      widgets.add(
        Padding(
          padding: const EdgeInsets.only(left: 16, top: 8, bottom: 4),
          child: Text(
            'AES Family',
            style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12, color: Theme.of(context).colorScheme.secondary),
          ),
        ),
      );
      widgets.addAll(aes.map(buildAlgoCard));
    }

    // ChaCha Family
    if (chacha.isNotEmpty) {
      widgets.add(
        Padding(
          padding: const EdgeInsets.only(left: 16, top: 8, bottom: 4),
          child: Text(
            'ChaCha Family',
            style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12, color: Theme.of(context).colorScheme.secondary),
          ),
        ),
      );
      widgets.addAll(chacha.map(buildAlgoCard));
    }

    // Threefish (Large Block)
    if (threefish.isNotEmpty) {
      widgets.add(
        Padding(
          padding: const EdgeInsets.only(left: 16, top: 8, bottom: 4),
          child: Text(
            'Threefish (Large Block)',
            style: TextStyle(fontWeight: FontWeight.w600, fontSize: 12, color: Theme.of(context).colorScheme.secondary),
          ),
        ),
      );
      widgets.addAll(threefish.map(buildAlgoCard));
    }

    return widgets;
  }

  /// Show algorithm picker dialog
  void _showAlgorithmPicker(BuildContext context) async {
    final algorithmCategories = await CLIService.getSupportedAlgorithms();

    if (!context.mounted) return;

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

                  // Special handling for Classical Symmetric - add sub-group headers
                  if (category == 'Classical Symmetric') {
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
                        ..._buildClassicalSymmetricWithSubgroups(context, algorithms),
                        const SizedBox(height: 12),
                      ],
                    );
                  }

                  // Default rendering for other categories
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
                        final isSelected = algorithm == this.selectedAlgorithm;
                        final isPostQuantum = category.contains('Post-Quantum') || category.contains('ML-KEM') ||
                            category.contains('Kyber') || category.contains('HQC') ||
                            category.contains('MAYO') || category.contains('CROSS');

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
                                if (algorithm == 'aes-gcm' || algorithm == 'threefish-512' || algorithm == 'ml-kem-768-hybrid') ...[
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
                                if (algorithm.startsWith('hqc-')) ...[
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: Colors.orange,
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: const Text(
                                      'WARNING',
                                      style: TextStyle(color: Colors.white, fontSize: 10),
                                    ),
                                  ),
                                ],
                                if (algorithm.startsWith('kyber')) ...[
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: Colors.grey,
                                      borderRadius: BorderRadius.circular(4),
                                    ),
                                    child: const Text(
                                      'LEGACY',
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
      onAlgorithmChanged(selectedAlgorithm);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Card(
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
              ],
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: enabled ? () => _showAlgorithmPicker(context) : null,
              icon: const Icon(Icons.apps),
              label: Row(
                children: [
                  const Text('Selected: '),
                  Text(
                    selectedAlgorithm,
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ],
              ),
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.all(16),
                alignment: Alignment.centerLeft,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// HSM Configuration Section
/// For hardware security module settings
class HsmConfigSection extends StatelessWidget {
  final String hsmType;
  final int yubikeySlot;
  final ValueChanged<String> onHsmTypeChanged;
  final ValueChanged<int> onYubikeySlotChanged;

  const HsmConfigSection({
    super.key,
    required this.hsmType,
    required this.yubikeySlot,
    required this.onHsmTypeChanged,
    required this.onYubikeySlotChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.security),
                const SizedBox(width: 8),
                const Text('HSM Configuration', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Hardware Security Module (HSM)'),
                        content: const SingleChildScrollView(
                          child: Text(
                            'Use a hardware security module to securely generate and store encryption keys.\n\n'
                            'Supported devices:\n'
                            '• YubiKey - FIDO2/CTAP2 compatible USB keys\n\n'
                            'When enabled, cryptographic keys are generated on the HSM device and never exposed to the host system.',
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
                  tooltip: 'HSM Information',
                ),
              ],
            ),
            const SizedBox(height: 12),
            DropdownButtonFormField<String>(
              value: hsmType,
              decoration: const InputDecoration(
                labelText: 'HSM Type',
                border: OutlineInputBorder(),
                helperText: 'Select hardware security module type',
              ),
              items: const [
                DropdownMenuItem(value: 'none', child: Text('None (Software)')),
                DropdownMenuItem(value: 'yubikey', child: Text('YubiKey')),
              ],
              onChanged: (value) {
                if (value != null) onHsmTypeChanged(value);
              },
            ),
            if (hsmType == 'yubikey') ...[
              const SizedBox(height: 12),
              TextFormField(
                initialValue: yubikeySlot.toString(),
                decoration: const InputDecoration(
                  labelText: 'YubiKey Slot',
                  border: OutlineInputBorder(),
                  helperText: 'YubiKey slot number (1-8)',
                ),
                keyboardType: TextInputType.number,
                inputFormatters: [
                  FilteringTextInputFormatter.digitsOnly,
                ],
                onChanged: (value) {
                  final slot = int.tryParse(value);
                  if (slot != null && slot >= 1 && slot <= 8) {
                    onYubikeySlotChanged(slot);
                  }
                },
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Integrity Configuration Section
/// For integrity verification settings
class IntegrityConfigSection extends StatelessWidget {
  final bool enableIntegrity;
  final bool verifyIntegrity;
  final bool isEncryptMode;
  final ValueChanged<bool> onEnableIntegrityChanged;
  final ValueChanged<bool> onVerifyIntegrityChanged;

  const IntegrityConfigSection({
    super.key,
    required this.enableIntegrity,
    required this.verifyIntegrity,
    required this.isEncryptMode,
    required this.onEnableIntegrityChanged,
    required this.onVerifyIntegrityChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.verified_user),
                const SizedBox(width: 8),
                const Text('Integrity Verification', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ],
            ),
            const SizedBox(height: 12),
            if (isEncryptMode) ...[
              CheckboxListTile(
                value: enableIntegrity,
                onChanged: (value) => onEnableIntegrityChanged(value ?? false),
                title: const Text('Register hash with integrity server'),
                subtitle: const Text('Store cryptographic hash on remote server for later verification'),
                contentPadding: EdgeInsets.zero,
              ),
            ] else ...[
              CheckboxListTile(
                value: verifyIntegrity,
                onChanged: (value) => onVerifyIntegrityChanged(value ?? false),
                title: const Text('Verify integrity from server'),
                subtitle: const Text('Check if file hash matches registered hash on integrity server'),
                contentPadding: EdgeInsets.zero,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Input Type Toggle
/// Switch between text and file input modes
class InputTypeToggle extends StatelessWidget {
  final bool isFileMode;
  final ValueChanged<bool> onToggle;

  const InputTypeToggle({
    super.key,
    required this.isFileMode,
    required this.onToggle,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text('Input Type:', style: TextStyle(fontWeight: FontWeight.w500)),
            const SizedBox(width: 16),
            SegmentedButton<bool>(
              segments: const [
                ButtonSegment(
                  value: false,
                  label: Text('Text'),
                  icon: Icon(Icons.text_fields),
                ),
                ButtonSegment(
                  value: true,
                  label: Text('File'),
                  icon: Icon(Icons.insert_drive_file),
                ),
              ],
              selected: {isFileMode},
              onSelectionChanged: (Set<bool> newSelection) {
                onToggle(newSelection.first);
              },
            ),
          ],
        ),
      ),
    );
  }
}

/// File Picker Widget
/// Displays selected file info and pick button
class FilePickerWidget extends StatelessWidget {
  final FileInfo? selectedFile;
  final VoidCallback onPickFile;
  final VoidCallback? onClearFile;
  final bool enabled;

  const FilePickerWidget({
    super.key,
    required this.selectedFile,
    required this.onPickFile,
    this.onClearFile,
    this.enabled = true,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.folder_open),
                const SizedBox(width: 8),
                const Text('File Selection', style: TextStyle(fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 12),
            if (selectedFile != null) ...[
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
                    Row(
                      children: [
                        const Icon(Icons.insert_drive_file, size: 20),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            selectedFile!.name,
                            style: const TextStyle(fontWeight: FontWeight.w500),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (onClearFile != null)
                          IconButton(
                            icon: const Icon(Icons.close, size: 20),
                            onPressed: enabled ? onClearFile : null,
                            tooltip: 'Clear selection',
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Size: ${selectedFile!.sizeFormatted}',
                      style: TextStyle(fontSize: 12, color: Colors.grey.shade700),
                    ),
                    Text(
                      'Path: ${selectedFile!.path}',
                      style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
            ],
            ElevatedButton.icon(
              onPressed: enabled ? onPickFile : null,
              icon: const Icon(Icons.folder_open),
              label: Text(selectedFile == null ? 'Pick File' : 'Change File'),
            ),
          ],
        ),
      ),
    );
  }
}
