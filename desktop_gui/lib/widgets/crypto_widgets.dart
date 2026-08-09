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
              initialValue: hsmType,
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

/// Pepper Configuration Section
/// For remote pepper plugin settings
class PepperConfigSection extends StatelessWidget {
  final bool enablePepper;
  final String pepperMode;
  final TextEditingController pepperNameController;
  final ValueChanged<bool> onEnablePepperChanged;
  final ValueChanged<String> onPepperModeChanged;

  const PepperConfigSection({
    super.key,
    required this.enablePepper,
    required this.pepperMode,
    required this.pepperNameController,
    required this.onEnablePepperChanged,
    required this.onPepperModeChanged,
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
                const Icon(Icons.vpn_key),
                const SizedBox(width: 8),
                const Text('Remote Pepper', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.info_outline),
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Remote Pepper Plugin'),
                        content: const SingleChildScrollView(
                          child: Text(
                            'Remote pepper adds an additional cryptographic salt stored on a remote server.\n\n'
                            '• Auto Mode: Generates unique pepper per file\n'
                            '• Named Mode: Reuses existing pepper by name\n\n'
                            'The pepper is encrypted with your file password before storage.\n\n'
                            'Requires pepper plugin configuration with mTLS certificates.',
                          ),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: const Text('Close'),
                          ),
                        ],
                      ),
                    );
                  },
                  tooltip: 'Pepper Information',
                ),
              ],
            ),
            const SizedBox(height: 12),
            CheckboxListTile(
              value: enablePepper,
              onChanged: (value) => onEnablePepperChanged(value ?? false),
              title: const Text('Enable remote pepper'),
              subtitle: const Text('Store encrypted pepper on remote server'),
              contentPadding: EdgeInsets.zero,
            ),
            if (enablePepper) ...[
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                initialValue: pepperMode,
                decoration: const InputDecoration(
                  labelText: 'Pepper Mode',
                  border: OutlineInputBorder(),
                  helperText: 'Auto-generate or use existing pepper',
                ),
                items: const [
                  DropdownMenuItem(value: 'auto', child: Text('Auto-generate (unique per file)')),
                  DropdownMenuItem(value: 'named', child: Text('Use existing named pepper')),
                ],
                onChanged: (value) {
                  if (value != null) onPepperModeChanged(value);
                },
              ),
              if (pepperMode == 'named') ...[
                const SizedBox(height: 12),
                TextField(
                  controller: pepperNameController,
                  decoration: const InputDecoration(
                    labelText: 'Pepper Name',
                    border: OutlineInputBorder(),
                    helperText: 'Name of existing pepper to retrieve',
                    prefixIcon: Icon(Icons.label),
                  ),
                ),
              ],
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
                  color: Colors.grey.shade900,
                  border: Border.all(color: Colors.grey.shade700),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.insert_drive_file, size: 20, color: Colors.grey.shade300),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            selectedFile!.name,
                            style: const TextStyle(
                              fontWeight: FontWeight.w500,
                              color: Colors.white,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (onClearFile != null)
                          IconButton(
                            icon: Icon(Icons.close, size: 20, color: Colors.grey.shade300),
                            onPressed: enabled ? onClearFile : null,
                            tooltip: 'Clear selection',
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Size: ${selectedFile!.sizeFormatted}',
                      style: TextStyle(fontSize: 12, color: Colors.grey.shade300),
                    ),
                    Text(
                      'Path: ${selectedFile!.path}',
                      style: TextStyle(fontSize: 11, color: Colors.grey.shade400),
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

/// Shared hash-chain + KDF-chain configuration UI (gitlab#155).
///
/// Extracted verbatim from the Encrypt tab so the Batch Operations tab can
/// present the SAME controls instead of silently sending null config (which
/// made batching quietly use CLI defaults while the Encrypt tab used whatever
/// the user had set). The parent owns the config maps and this section mutates
/// them in place; the parent reads them back when building the CLI call.
class HashKdfConfigSection extends StatefulWidget {
  final Map<String, Map<String, dynamic>> hashConfig;
  final Map<String, List<String>> hashAlgorithms;
  final Map<String, Map<String, dynamic>> kdfConfig;

  const HashKdfConfigSection({
    super.key,
    required this.hashConfig,
    required this.hashAlgorithms,
    required this.kdfConfig,
  });

  @override
  State<HashKdfConfigSection> createState() => _HashKdfConfigSectionState();
}

class _HashKdfConfigSectionState extends State<HashKdfConfigSection> {
  bool _showHashConfig = false;
  bool _showKdfConfig = false;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _buildHashChainSection(),
        const SizedBox(height: 12),
        _buildKdfChainSection(),
      ],
    );
  }

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
    final config = widget.kdfConfig['argon2'] ?? {
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
                  widget.kdfConfig['argon2'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) =>
                setState(() => widget.kdfConfig['argon2']!['time_cost'] = v)),
              _buildKDFSlider('Memory (MB)', ((config['memory_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) =>
                setState(() => widget.kdfConfig['argon2']!['memory_cost'] = v * 1024)),
              _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) =>
                setState(() => widget.kdfConfig['argon2']!['parallelism'] = v)),
              _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 128, (v) =>
                setState(() => widget.kdfConfig['argon2']!['hash_len'] = v)),
              _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) =>
                setState(() => widget.kdfConfig['argon2']!['rounds'] = v)),
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
                          widget.kdfConfig['argon2']!['type'] = value ?? 2;
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
    final config = widget.kdfConfig['scrypt'] ?? {
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
                  widget.kdfConfig['scrypt'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('N (CPU/Memory)', ((config['n'] ?? 16384) / 1024).round(), 1, 1024, (v) =>
                setState(() => widget.kdfConfig['scrypt']!['n'] = v * 1024)),
              _buildKDFSlider('R (Block Size)', config['r'] ?? 8, 1, 32, (v) =>
                setState(() => widget.kdfConfig['scrypt']!['r'] = v)),
              _buildKDFSlider('P (Parallelism)', config['p'] ?? 1, 1, 16, (v) =>
                setState(() => widget.kdfConfig['scrypt']!['p'] = v)),
              _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) =>
                setState(() => widget.kdfConfig['scrypt']!['rounds'] = v)),
            ],
          ],
        ),
      ),
    );
  }

  /// Build HKDF configuration panel
  Widget _buildHKDFPanel() {
    final config = widget.kdfConfig['hkdf'] ?? {
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
                  widget.kdfConfig['hkdf'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 0, 1000000, (v) =>
                setState(() => widget.kdfConfig['hkdf']!['rounds'] = v)),
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
                          widget.kdfConfig['hkdf']!['algorithm'] = value ?? 'sha256';
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
                      widget.kdfConfig['hkdf']!['info'] = value;
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
    final config = widget.kdfConfig['balloon'] ?? {
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
                  widget.kdfConfig['balloon'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              contentPadding: EdgeInsets.zero,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) =>
                setState(() => widget.kdfConfig['balloon']!['time_cost'] = v)),
              _buildKDFSlider('Space Cost (KB)', ((config['space_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) =>
                setState(() => widget.kdfConfig['balloon']!['space_cost'] = v * 1024)),
              _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) =>
                setState(() => widget.kdfConfig['balloon']!['parallelism'] = v)),
              _buildKDFSlider('Rounds', config['rounds'] ?? 2, 0, 1000000, (v) =>
                setState(() => widget.kdfConfig['balloon']!['rounds'] = v)),
              _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 128, (v) =>
                setState(() => widget.kdfConfig['balloon']!['hash_len'] = v)),
            ],
          ],
        ),
      ),
    );
  }

  /// Build RandomX configuration panel
  Widget _buildRandomXPanel() {
    final config = widget.kdfConfig['randomx'] ?? {
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
                  widget.kdfConfig['randomx'] = Map.from(config)..['enabled'] = value ?? false;
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
                          widget.kdfConfig['randomx']!['mode'] = value ?? 'light';
                        });
                      },
                    ),
                  ],
                ),
              ),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 1, 10, (v) =>
                setState(() => widget.kdfConfig['randomx']!['rounds'] = v)),
              _buildKDFSlider('Block Height', config['height'] ?? 1, 1, 1000, (v) =>
                setState(() => widget.kdfConfig['randomx']!['height'] = v)),
              _buildKDFSlider('Hash Length', config['hash_len'] ?? 32, 16, 64, (v) =>
                setState(() => widget.kdfConfig['randomx']!['hash_len'] = v)),
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
    final isEnabled = widget.hashConfig[hashId]?['enabled'] ?? false;
    final rounds = (widget.hashConfig[hashId]?['rounds'] ?? 1000) as int;

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
                    if (widget.hashConfig[hashId] == null) {
                      widget.hashConfig[hashId] = {'rounds': 1000};
                    }
                    widget.hashConfig[hashId]!['enabled'] = value;
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
                            widget.hashConfig[hashId]!['rounds'] = value.toInt();
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
          ...widget.hashAlgorithms.entries.expand((entry) {
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
                    for (final group in widget.hashAlgorithms.values) {
                      for (String hash in group) {
                        widget.hashConfig[hash] = {
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
                    for (final group in widget.hashAlgorithms.values) {
                      for (String hash in group) {
                        if (widget.hashConfig[hash] != null) {
                          widget.hashConfig[hash]!['enabled'] = false;
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
                    for (final group in widget.hashAlgorithms.values) {
                      for (String hash in group) {
                        widget.hashConfig[hash] = {
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
                    widget.kdfConfig['argon2'] = {'enabled': true, 'time_cost': 3, 'memory_cost': 65536, 'parallelism': 4, 'hash_len': 32, 'type': 2, 'rounds': 10};
                    widget.kdfConfig['scrypt']!['enabled'] = false;
                    widget.kdfConfig['hkdf']!['enabled'] = false;
                    widget.kdfConfig['balloon']!['enabled'] = false;
                    widget.kdfConfig['randomx']!['enabled'] = false;
                  });
                },
                child: const Text('Argon2 Only', style: TextStyle(fontSize: 12)),
              ),
              TextButton(
                onPressed: () {
                  setState(() {
                    widget.kdfConfig['argon2']!['enabled'] = false;
                    widget.kdfConfig['scrypt']!['enabled'] = false;
                    widget.kdfConfig['hkdf']!['enabled'] = false;
                    widget.kdfConfig['balloon']!['enabled'] = false;
                    widget.kdfConfig['randomx']!['enabled'] = false;
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
}
