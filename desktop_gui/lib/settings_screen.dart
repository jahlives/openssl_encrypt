import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'settings_service.dart';
import 'cli_service.dart';
import 'input_validation.dart';

/// Security helper: Canonicalize file path to prevent symlink attacks
String _canonicalizePath(String filePath) {
  try {
    // Convert to absolute path and resolve symlinks
    return File(filePath).resolveSymbolicLinksSync();
  } catch (e) {
    // If canonicalization fails, fall back to absolute path
    try {
      return File(filePath).absolute.path;
    } catch (e2) {
      // Ultimate fallback - return original path
      return filePath;
    }
  }
}

/// Comprehensive settings and preferences screen
class SettingsScreen extends StatefulWidget {
  final Function(String key, dynamic value)? onSettingChanged;

  const SettingsScreen({super.key, this.onSettingChanged});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  String _searchQuery = '';
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings & Preferences'),
        backgroundColor: Colors.blue,
        foregroundColor: Theme.of(context).colorScheme.onPrimary,
        elevation: 2,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Reset to Defaults',
            onPressed: _showResetDialog,
          ),
          IconButton(
            icon: const Icon(Icons.import_export),
            tooltip: 'Import/Export Settings',
            onPressed: _showImportExportDialog,
          ),
        ],
      ),
      body: Column(
        children: [
          // Search bar
          Container(
            padding: const EdgeInsets.all(16.0),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primaryContainer,
              border: Border(bottom: BorderSide(color: Theme.of(context).colorScheme.outline)),
            ),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Search settings...',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchQuery.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _searchController.clear();
                          setState(() {
                            _searchQuery = '';
                          });
                        },
                      )
                    : null,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide.none,
                ),
                filled: true,
                fillColor: Theme.of(context).colorScheme.surface,
              ),
              onChanged: (value) {
                setState(() {
                  _searchQuery = value.toLowerCase();
                });
              },
            ),
          ),
          // Settings content
          Expanded(
            child: ListView(
              padding: const EdgeInsets.all(16.0),
              children: [
                // UI Mode Toggle - always visible
                if (_matchesSearch('mode simple pro'))
                  _buildCategoryCard(
                    'Interface Mode',
                    Icons.tune,
                    Colors.indigo,
                    [
                      _buildUiModeSelector(),
                    ],
                  ),
                const SizedBox(height: 16),
                if (_matchesSearch('theme appearance'))
                  _buildCategoryCard(
                    'Theme & Appearance',
                    Icons.palette,
                    Colors.purple,
                    [
                      _buildThemeSelector(),
                    ],
                  ),
                if (SettingsService.isProMode()) ...[
                const SizedBox(height: 16),
                if (_matchesSearch('cryptographic defaults security algorithm'))
                  _buildCategoryCard(
                    'Cryptographic Defaults',
                    Icons.security,
                    Colors.red,
                    [
                      _buildDefaultAlgorithmSelector(),
                      _buildDefaultSecurityLevelSelector(),
                      _buildDefaultOutputFormatSelector(),
                    ],
                  ),
                const SizedBox(height: 16),
                if (_matchesSearch('encryption mode defaults cascade asymmetric identity'))
                  _buildCategoryCard(
                    'Encryption Mode Defaults',
                    Icons.layers,
                    Colors.purple,
                    [
                      _buildDefaultEncryptionModeSelector(),
                      _buildDefaultCascadePresetSelector(),
                      _buildDefaultKemAlgorithmSelector(),
                      _buildDefaultSigAlgorithmSelector(),
                    ],
                  ),
                const SizedBox(height: 16),
                if (_matchesSearch('application behavior interface'))
                  _buildCategoryCard(
                    'Application Behavior',
                    Icons.settings,
                    Colors.blue,
                    [
                      _buildBooleanSetting(
                        'Auto-save Settings',
                        'Automatically save setting changes',
                        SettingsService.getAutoSaveSettings(),
                        SettingsService.setAutoSaveSettings,
                      ),
                      _buildBooleanSetting(
                        'Show Advanced Options',
                        'Display advanced cryptographic options',
                        SettingsService.getShowAdvancedOptions(),
                        SettingsService.setShowAdvancedOptions,
                      ),
                      _buildBooleanSetting(
                        'Confirm Dangerous Actions',
                        'Show confirmation for destructive operations',
                        SettingsService.getConfirmDangerousActions(),
                        SettingsService.setConfirmDangerousActions,
                      ),
                      _buildMaxRecentFilesSelector(),
                    ],
                  ),
                const SizedBox(height: 16),
                if (_matchesSearch('debug development logging'))
                  _buildCategoryCard(
                    'Debug & Development',
                    Icons.bug_report,
                    Colors.orange,
                    [
                      _buildBooleanSetting(
                        'Debug Mode',
                        'Enable debug logging and developer features',
                        SettingsService.getDebugMode(),
                        (value) async {
                          await SettingsService.setDebugMode(value);
                          // Sync with CLI service
                          if (value) {
                            await CLIService.enableDebugLogging();
                          } else {
                            CLIService.disableDebugLogging();
                          }
                          return true;
                        },
                      ),
                      _buildInfoTile(
                        'Debug Log Location',
                        CLIService.getDebugLogFile() ?? 'Not available',
                        Icons.folder_open,
                      ),
                    ],
                  ),
                const SizedBox(height: 16),
                if (_matchesSearch('window display'))
                  _buildCategoryCard(
                    'Window & Display',
                    Icons.desktop_windows,
                    Colors.green,
                    [
                      _buildInfoTile(
                        'Window Size',
                        '${SettingsService.getWindowWidth().toInt()} × ${SettingsService.getWindowHeight().toInt()}',
                        Icons.aspect_ratio,
                      ),
                      _buildBooleanSetting(
                        'Start Maximized',
                        'Open application in maximized window',
                        SettingsService.getWindowMaximized(),
                        SettingsService.setWindowMaximized,
                      ),
                    ],
                  ),
                const SizedBox(height: 16),
                if (_matchesSearch('network plugins keyserver pepper integrity'))
                  _buildCategoryCard(
                    'Network Plugins',
                    Icons.cloud,
                    Colors.teal,
                    [
                      _buildKeyserverSection(),
                      const Divider(height: 32),
                      _buildPepperSection(),
                      const Divider(height: 32),
                      _buildIntegritySection(),
                    ],
                  ),
                ], // end of Pro mode settings
                const SizedBox(height: 16),
                if (_matchesSearch('system information'))
                  _buildCategoryCard(
                    'System Information',
                    Icons.info_outline,
                    Colors.grey,
                    [
                      _buildInfoTile(
                        'Backend Type',
                        CLIService.isFlatpakVersion ? 'Flatpak' : 'Development',
                        Icons.computer,
                      ),
                      _buildInfoTile(
                        'CLI Version',
                        CLIService.cliVersion ?? 'Unknown',
                        Icons.terminal,
                      ),
                      _buildInfoTile(
                        'Python Version',
                        CLIService.pythonVersion ?? 'Unknown',
                        Icons.code,
                      ),
                    ],
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  bool _matchesSearch(String searchTerms) {
    if (_searchQuery.isEmpty) return true;
    return searchTerms.toLowerCase().contains(_searchQuery);
  }

  Widget _buildCategoryCard(
    String title,
    IconData icon,
    MaterialColor color,
    List<Widget> children,
  ) {
    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, color: color.shade700, size: 24),
                const SizedBox(width: 12),
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    color: color.shade700,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            ...children,
          ],
        ),
      ),
    );
  }

  Widget _buildBooleanSetting(
    String title,
    String description,
    bool currentValue,
    Future<bool> Function(bool) onChanged,
  ) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  description,
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          Switch(
            value: currentValue,
            onChanged: (value) async {
              await onChanged(value);
              setState(() {});
            },
          ),
        ],
      ),
    );
  }

  Widget _buildInfoTile(String title, String value, IconData icon) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Icon(icon, size: 20, color: Theme.of(context).colorScheme.onSurfaceVariant),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  value,
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildUiModeSelector() {
    final isProMode = SettingsService.isProMode();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SwitchListTile(
            title: const Text(
              'Pro Mode',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w500,
              ),
            ),
            subtitle: Text(
              isProMode
                  ? 'All encryption options, algorithms, and advanced features are visible'
                  : 'Using standard security template with simplified interface',
              style: TextStyle(
                fontSize: 14,
                color: Colors.grey.shade600,
              ),
            ),
            value: isProMode,
            onChanged: (value) async {
              await SettingsService.setUiMode(value ? 'pro' : 'simple');
              widget.onSettingChanged?.call('ui_mode', value ? 'pro' : 'simple');
              setState(() {});
            },
            secondary: Icon(
              isProMode ? Icons.science : Icons.shield,
              color: isProMode ? Colors.orange : Colors.green,
            ),
            contentPadding: EdgeInsets.zero,
          ),
          if (!isProMode)
            Padding(
              padding: const EdgeInsets.only(left: 56.0, top: 4.0),
              child: Text(
                'Simple mode uses the standard security template for encryption. '
                'Enable Pro mode to access algorithm selection, key stretching, '
                'cascade encryption, steganography, and other advanced features.',
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.grey.shade500,
                  fontStyle: FontStyle.italic,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildThemeSelector() {
    final currentTheme = SettingsService.getThemeMode();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Theme Mode',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Choose application theme',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentTheme,
            items: const [
              DropdownMenuItem(value: 'light', child: Text('Light')),
              DropdownMenuItem(value: 'dark', child: Text('Dark')),
              DropdownMenuItem(value: 'system', child: Text('System')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setThemeMode(value);
                widget.onSettingChanged?.call('theme_mode', value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultAlgorithmSelector() {
    final currentAlgorithm = SettingsService.getDefaultAlgorithm();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default Algorithm',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default encryption algorithm for new operations',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentAlgorithm,
            items: const [
              DropdownMenuItem(value: 'fernet', child: Text('Fernet')),
              DropdownMenuItem(value: 'aes-gcm', child: Text('AES-GCM')),
              DropdownMenuItem(value: 'chacha20-poly1305', child: Text('ChaCha20-Poly1305')),
              DropdownMenuItem(value: 'xchacha20-poly1305', child: Text('XChaCha20-Poly1305')),
              DropdownMenuItem(value: 'ml-kem-768-hybrid', child: Text('ML-KEM-768-Hybrid')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultAlgorithm(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultSecurityLevelSelector() {
    final currentLevel = SettingsService.getDefaultSecurityLevel();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default Security Level',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default cryptographic parameter strength',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentLevel,
            items: const [
              DropdownMenuItem(value: 'quick', child: Text('Quick')),
              DropdownMenuItem(value: 'standard', child: Text('Standard')),
              DropdownMenuItem(value: 'paranoid', child: Text('Paranoid')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultSecurityLevel(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultOutputFormatSelector() {
    final currentFormat = SettingsService.getDefaultOutputFormat();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default Output Format',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default format for encrypted output',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentFormat,
            items: const [
              DropdownMenuItem(value: 'base64', child: Text('Base64')),
              DropdownMenuItem(value: 'hex', child: Text('Hexadecimal')),
              DropdownMenuItem(value: 'binary', child: Text('Binary')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultOutputFormat(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultEncryptionModeSelector() {
    final currentMode = SettingsService.getDefaultEncryptionMode();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default Encryption Mode',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default mode when opening crypto tabs',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentMode,
            items: const [
              DropdownMenuItem(value: 'symmetric', child: Text('Symmetric')),
              DropdownMenuItem(value: 'asymmetric', child: Text('Asymmetric')),
              DropdownMenuItem(value: 'cascade', child: Text('Cascade')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultEncryptionMode(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultCascadePresetSelector() {
    final currentPreset = SettingsService.getDefaultCascadePreset();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default Cascade Preset',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default algorithm chain for cascade mode',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentPreset,
            items: const [
              DropdownMenuItem(value: 'standard', child: Text('Standard (AES+ChaCha)')),
              DropdownMenuItem(value: 'paranoia', child: Text('Paranoia (AES+ChaCha+Threefish)')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultCascadePreset(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultKemAlgorithmSelector() {
    final currentAlgorithm = SettingsService.getDefaultKemAlgorithm();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default KEM Algorithm',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default key encapsulation for new identities',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentAlgorithm,
            items: const [
              DropdownMenuItem(value: 'ML-KEM-512', child: Text('ML-KEM-512')),
              DropdownMenuItem(value: 'ML-KEM-768', child: Text('ML-KEM-768')),
              DropdownMenuItem(value: 'ML-KEM-1024', child: Text('ML-KEM-1024')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultKemAlgorithm(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildDefaultSigAlgorithmSelector() {
    final currentAlgorithm = SettingsService.getDefaultSigAlgorithm();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Default Signature Algorithm',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Default digital signature for new identities',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<String>(
            value: currentAlgorithm,
            items: const [
              DropdownMenuItem(value: 'ML-DSA-44', child: Text('ML-DSA-44')),
              DropdownMenuItem(value: 'ML-DSA-65', child: Text('ML-DSA-65')),
              DropdownMenuItem(value: 'ML-DSA-87', child: Text('ML-DSA-87')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setDefaultSigAlgorithm(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildMaxRecentFilesSelector() {
    final currentMax = SettingsService.getMaxRecentFiles();

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Max Recent Files',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  'Maximum number of recent files to remember',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.grey.shade600,
                  ),
                ),
              ],
            ),
          ),
          DropdownButton<int>(
            value: currentMax,
            items: const [
              DropdownMenuItem(value: 5, child: Text('5')),
              DropdownMenuItem(value: 10, child: Text('10')),
              DropdownMenuItem(value: 15, child: Text('15')),
              DropdownMenuItem(value: 20, child: Text('20')),
            ],
            onChanged: (value) async {
              if (value != null) {
                await SettingsService.setMaxRecentFiles(value);
                setState(() {});
              }
            },
          ),
        ],
      ),
    );
  }

  void _showResetDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset Settings'),
        content: const Text(
          'Are you sure you want to reset all settings to their default values? This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              await SettingsService.resetToDefaults();
              setState(() {});
              if (mounted) {
                // ignore: use_build_context_synchronously
                Navigator.of(context).pop();
                // ignore: use_build_context_synchronously
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Settings reset to defaults'),
                    backgroundColor: Colors.green,
                  ),
                );
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
              foregroundColor: Theme.of(context).colorScheme.onError,
            ),
            child: const Text('Reset'),
          ),
        ],
      ),
    );
  }

  void _showImportExportDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import/Export Settings'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.file_download),
              title: const Text('Export Settings'),
              subtitle: const Text('Save current settings to file'),
              onTap: () {
                Navigator.of(context).pop();
                _exportSettings();
              },
            ),
            ListTile(
              leading: const Icon(Icons.file_upload),
              title: const Text('Import Settings'),
              subtitle: const Text('Load settings from file'),
              onTap: () {
                Navigator.of(context).pop();
                _importSettings();
              },
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
  }

  Future<void> _exportSettings() async {
    try {
      // Get all current settings
      final settings = SettingsService.exportSettings();

      // Create export data with metadata
      final exportData = {
        'version': 1,
        'app_name': 'OpenSSL Encrypt Desktop',
        'exported_at': DateTime.now().toIso8601String(),
        'settings': settings,
      };

      // Convert to JSON
      final jsonString = const JsonEncoder.withIndent('  ').convert(exportData);

      // Show file save dialog
      final fileName = 'openssl_encrypt_settings_${DateTime.now().millisecondsSinceEpoch}.json';
      final filePath = await FilePicker.platform.saveFile(
        dialogTitle: 'Export Application Settings',
        fileName: fileName,
        type: FileType.custom,
        allowedExtensions: ['json'],
      );

      if (filePath != null) {
        // Security: Canonicalize path to prevent symlink attacks
        final canonicalPath = _canonicalizePath(filePath);
        // Write to file
        await File(canonicalPath).writeAsString(jsonString);

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Settings exported to: ${canonicalPath.split('/').last}'),
              backgroundColor: Colors.green,
              duration: const Duration(seconds: 4),
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Export failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _importSettings() async {
    try {
      // Show file picker dialog
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['json'],
        dialogTitle: 'Import Application Settings',
      );

      if (result != null && result.files.single.path != null) {
        // Security: Canonicalize path to prevent symlink attacks
        final canonicalPath = _canonicalizePath(result.files.single.path!);
        final file = File(canonicalPath);
        final jsonString = await file.readAsString();

        // Security: Validate JSON input before parsing
        final jsonValidation = InputValidator.validateJsonInput(jsonString);
        if (jsonValidation != null) {
          throw Exception('Invalid JSON: $jsonValidation');
        }

        final importData = jsonDecode(jsonString) as Map<String, dynamic>;

        // Validate import data
        if (importData['version'] != 1) {
          throw Exception('Unsupported settings format version');
        }

        if (importData['app_name'] != 'OpenSSL Encrypt Desktop') {
          // Show warning but allow import
          final confirmed = await _showImportWarningDialog(
            'These settings were not exported from OpenSSL Encrypt Desktop. Import anyway?',
          );
          if (!confirmed) return;
        }

        final settings = importData['settings'] as Map<String, dynamic>;

        if (mounted) {
          // Ask user about import mode
          final importMode = await _showImportModeDialog();
          if (importMode == null) return; // User cancelled

          if (importMode == 'replace') {
            // Clear existing settings first
            await SettingsService.resetToDefaults();
          }

          // Import the settings
          final success = await SettingsService.importSettings(settings);

          if (success) {
            // Notify about changes
            if (widget.onSettingChanged != null) {
              for (final entry in settings.entries) {
                widget.onSettingChanged!(entry.key, entry.value);
              }
            }

            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(
                    'Settings imported successfully (${importMode}d ${settings.length} settings)',
                  ),
                  backgroundColor: Colors.green,
                  duration: const Duration(seconds: 4),
                ),
              );

              // Refresh the UI
              setState(() {});
            }
          } else {
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Failed to import settings'),
                  backgroundColor: Colors.red,
                ),
              );
            }
          }
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Import failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<bool> _showImportWarningDialog(String message) async {
    return await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import Warning'),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.orange),
            child: const Text('Import Anyway', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    ) ?? false;
  }

  Future<String?> _showImportModeDialog() async {
    return await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import Mode'),
        content: const Text(
          'How would you like to import the settings?\n\n'
          '• Merge: Add imported settings, keep existing ones\n'
          '• Replace: Replace all settings with imported ones\n\n'
          'Note: Replace will reset all settings to defaults first.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(null),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop('merge'),
            child: const Text('Merge'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop('replace'),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.orange),
            child: const Text('Replace', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  Widget _buildKeyserverSection() {
    return StatefulBuilder(
      builder: (context, setState) {
        final keyserverEnabled = SettingsService.getKeyserverEnabled();
        final keyserverUrl = SettingsService.getKeyserverUrl();
        final cacheTtl = SettingsService.getKeyserverCacheTtl();
        final uploadEnabled = SettingsService.getKeyserverUploadEnabled();

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Keyserver header with enable toggle
            Row(
              children: [
                const Icon(Icons.vpn_key, size: 20),
                const SizedBox(width: 8),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Keyserver Plugin',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                      ),
                      Text(
                        'Distributed public key discovery and sharing',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),
                ),
                Switch(
                  value: keyserverEnabled,
                  onChanged: (value) async {
                    await SettingsService.setKeyserverEnabled(value);
                    setState(() {});
                    widget.onSettingChanged?.call('keyserver_enabled', value);
                  },
                ),
              ],
            ),

            if (keyserverEnabled) ...[
              const Divider(),
              const SizedBox(height: 8),

              // Server URL
              ListTile(
                leading: const Icon(Icons.link, size: 20),
                title: const Text('Server URL', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                subtitle: TextFormField(
                  initialValue: keyserverUrl,
                  style: const TextStyle(fontSize: 12),
                  decoration: InputDecoration(
                    hintText: 'https://keys.openssl-encrypt.org',
                    border: const OutlineInputBorder(),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                    suffixIcon: keyserverUrl != 'https://keys.openssl-encrypt.org'
                        ? IconButton(
                            icon: const Icon(Icons.restore, size: 16),
                            onPressed: () async {
                              await SettingsService.setKeyserverUrl('https://keys.openssl-encrypt.org');
                              setState(() {});
                              widget.onSettingChanged?.call('keyserver_url', 'https://keys.openssl-encrypt.org');
                            },
                            tooltip: 'Reset to default',
                          )
                        : null,
                  ),
                  onFieldSubmitted: (value) async {
                    if (value.isNotEmpty && value.startsWith('http')) {
                      await SettingsService.setKeyserverUrl(value);
                      widget.onSettingChanged?.call('keyserver_url', value);
                    }
                  },
                ),
              ),
              const SizedBox(height: 8),

              // Cache TTL
              ListTile(
                leading: const Icon(Icons.schedule, size: 20),
                title: const Text('Cache TTL', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                subtitle: DropdownButtonFormField<int>(
                  value: cacheTtl,
                  decoration: const InputDecoration(
                    border: OutlineInputBorder(),
                    contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                  ),
                  style: const TextStyle(fontSize: 12, color: Colors.black87),
                  items: const [
                    DropdownMenuItem(value: 1, child: Text('1 hour')),
                    DropdownMenuItem(value: 6, child: Text('6 hours')),
                    DropdownMenuItem(value: 24, child: Text('24 hours (default)')),
                    DropdownMenuItem(value: 48, child: Text('48 hours')),
                    DropdownMenuItem(value: 168, child: Text('7 days (168 hours)')),
                  ],
                  onChanged: (value) async {
                    if (value != null) {
                      await SettingsService.setKeyserverCacheTtl(value);
                      setState(() {});
                      widget.onSettingChanged?.call('keyserver_cache_ttl', value);
                    }
                  },
                ),
              ),
              const SizedBox(height: 8),

              // Upload enabled
              SwitchListTile(
                secondary: const Icon(Icons.upload, size: 20),
                title: const Text('Enable Key Upload', style: TextStyle(fontSize: 13)),
                subtitle: const Text('Allow uploading public keys to keyserver', style: TextStyle(fontSize: 11)),
                value: uploadEnabled,
                onChanged: (value) async {
                  await SettingsService.setKeyserverUploadEnabled(value);
                  setState(() {});
                  widget.onSettingChanged?.call('keyserver_upload_enabled', value);
                },
              ),
              const SizedBox(height: 8),

              // Action buttons
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: () async {
                        final success = await CLIService.testKeyserverConnection(keyserverUrl);
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text(success
                                ? 'Connection successful!'
                                : 'Connection failed. Check URL and network.'),
                              backgroundColor: success ? Colors.green : Colors.red,
                            ),
                          );
                        }
                      },
                      icon: const Icon(Icons.wifi_tethering, size: 16),
                      label: const Text('Test', style: TextStyle(fontSize: 12)),
                      style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: () async {
                        final success = await CLIService.clearKeyserverCache();
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text(success
                                ? 'Cache cleared successfully!'
                                : 'Failed to clear cache.'),
                              backgroundColor: success ? Colors.orange : Colors.red,
                            ),
                          );
                        }
                      },
                      icon: const Icon(Icons.clear_all, size: 16),
                      label: const Text('Clear Cache', style: TextStyle(fontSize: 12)),
                      style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ],
        );
      },
    );
  }

  Widget _buildPepperSection() {
    return StatefulBuilder(
      builder: (context, setState) {
        final pepperEnabled = SettingsService.getPepperEnabled();
        final pepperUrl = SettingsService.getPepperServerUrl();
        final certMode = SettingsService.getPepperCertMode();

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Pepper header with enable toggle
            Row(
              children: [
                const Icon(Icons.key, size: 20),
                const SizedBox(width: 8),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Remote Pepper Plugin',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                      ),
                      Text(
                        'Network-based pepper with mTLS and 2FA',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),
                ),
                Switch(
                  value: pepperEnabled,
                  onChanged: (value) async {
                    await SettingsService.setPepperEnabled(value);
                    setState(() {});
                    widget.onSettingChanged?.call('pepper_enabled', value);
                  },
                ),
              ],
            ),

            if (pepperEnabled) ...[
              const SizedBox(height: 8),
              // Security warning
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: Colors.orange.withValues(alpha: 0.3)),
                ),
                child: Row(
                  children: [
                    Icon(Icons.warning, size: 16, color: Colors.orange.shade700),
                    const SizedBox(width: 8),
                    const Expanded(
                      child: Text(
                        'Warning: Remote pepper requires secure mTLS authentication. Keep certificates safe.',
                        style: TextStyle(fontSize: 11),
                      ),
                    ),
                  ],
                ),
              ),
              const Divider(),
              const SizedBox(height: 8),

              // Server URL
              ListTile(
                leading: const Icon(Icons.link, size: 20),
                title: const Text('Server URL', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                subtitle: TextFormField(
                  initialValue: pepperUrl,
                  style: const TextStyle(fontSize: 12),
                  decoration: InputDecoration(
                    hintText: 'https://pepper.openssl-encrypt.org',
                    border: const OutlineInputBorder(),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                    suffixIcon: pepperUrl != 'https://pepper.openssl-encrypt.org'
                        ? IconButton(
                            icon: const Icon(Icons.restore, size: 16),
                            onPressed: () async {
                              await SettingsService.setPepperServerUrl('https://pepper.openssl-encrypt.org');
                              setState(() {});
                              widget.onSettingChanged?.call('pepper_server_url', 'https://pepper.openssl-encrypt.org');
                            },
                            tooltip: 'Reset to default',
                          )
                        : null,
                  ),
                  onFieldSubmitted: (value) async {
                    if (value.isNotEmpty && value.startsWith('http')) {
                      await SettingsService.setPepperServerUrl(value);
                      widget.onSettingChanged?.call('pepper_server_url', value);
                    }
                  },
                ),
              ),
              const SizedBox(height: 8),

              // Certificate mode selector
              ListTile(
                leading: const Icon(Icons.security, size: 20),
                title: const Text('Certificate Mode', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                subtitle: SegmentedButton<String>(
                  segments: const [
                    ButtonSegment(
                      value: 'file',
                      label: Text('File Paths', style: TextStyle(fontSize: 11)),
                      icon: Icon(Icons.folder, size: 16),
                    ),
                    ButtonSegment(
                      value: 'pem',
                      label: Text('Paste PEM', style: TextStyle(fontSize: 11)),
                      icon: Icon(Icons.content_paste, size: 16),
                    ),
                  ],
                  selected: {certMode},
                  onSelectionChanged: (Set<String> newSelection) async {
                    await SettingsService.setPepperCertMode(newSelection.first);
                    setState(() {});
                    widget.onSettingChanged?.call('pepper_cert_mode', newSelection.first);
                  },
                ),
              ),
              const SizedBox(height: 8),

              // Certificate configuration based on mode
              if (certMode == 'file')
                _buildCertificateFilePaths(setState)
              else
                _buildCertificatePemInputs(setState),

              const SizedBox(height: 8),

              // Action buttons
              _buildPepperActionButtons(pepperUrl, certMode, setState),
            ],
          ],
        );
      },
    );
  }

  Widget _buildCertificateFilePaths(StateSetter setState) {
    final clientCertPath = SettingsService.getPepperClientCertPath();
    final clientKeyPath = SettingsService.getPepperClientKeyPath();
    final caCertPath = SettingsService.getPepperCaCertPath();

    return Column(
      children: [
        // Client Certificate
        ListTile(
          leading: const Icon(Icons.badge, size: 20),
          title: const Text('Client Certificate', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: Text(
            clientCertPath ?? 'Not set',
            style: const TextStyle(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: () async {
                  final result = await FilePicker.platform.pickFiles(
                    type: FileType.custom,
                    allowedExtensions: ['pem', 'crt', 'cert'],
                  );
                  if (result != null && result.files.single.path != null) {
                    await SettingsService.setPepperClientCertPath(result.files.single.path);
                    setState(() {});
                  }
                },
                tooltip: 'Select file',
              ),
              if (clientCertPath != null)
                IconButton(
                  icon: const Icon(Icons.clear, size: 18),
                  onPressed: () async {
                    await SettingsService.setPepperClientCertPath(null);
                    setState(() {});
                  },
                  tooltip: 'Clear',
                ),
            ],
          ),
        ),

        // Client Key
        ListTile(
          leading: const Icon(Icons.vpn_key, size: 20),
          title: const Text('Client Key', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: Text(
            clientKeyPath ?? 'Not set',
            style: const TextStyle(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: () async {
                  final result = await FilePicker.platform.pickFiles(
                    type: FileType.custom,
                    allowedExtensions: ['pem', 'key'],
                  );
                  if (result != null && result.files.single.path != null) {
                    await SettingsService.setPepperClientKeyPath(result.files.single.path);
                    setState(() {});
                  }
                },
                tooltip: 'Select file',
              ),
              if (clientKeyPath != null)
                IconButton(
                  icon: const Icon(Icons.clear, size: 18),
                  onPressed: () async {
                    await SettingsService.setPepperClientKeyPath(null);
                    setState(() {});
                  },
                  tooltip: 'Clear',
                ),
            ],
          ),
        ),

        // CA Certificate
        ListTile(
          leading: const Icon(Icons.verified_user, size: 20),
          title: const Text('CA Certificate', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: Text(
            caCertPath ?? 'Not set',
            style: const TextStyle(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: () async {
                  final result = await FilePicker.platform.pickFiles(
                    type: FileType.custom,
                    allowedExtensions: ['pem', 'crt', 'cert'],
                  );
                  if (result != null && result.files.single.path != null) {
                    await SettingsService.setPepperCaCertPath(result.files.single.path);
                    setState(() {});
                  }
                },
                tooltip: 'Select file',
              ),
              if (caCertPath != null)
                IconButton(
                  icon: const Icon(Icons.clear, size: 18),
                  onPressed: () async {
                    await SettingsService.setPepperCaCertPath(null);
                    setState(() {});
                  },
                  tooltip: 'Clear',
                ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildCertificatePemInputs(StateSetter setState) {
    return Column(
      children: [
        // Client Cert + Key PEM
        ListTile(
          leading: const Icon(Icons.badge, size: 20),
          title: const Text('Client Certificate + Key (PEM)', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: const Text('Paste combined certificate and private key', style: TextStyle(fontSize: 10)),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: TextFormField(
            initialValue: SettingsService.getPepperClientCertPem(),
            maxLines: 4,
            style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              hintText: '-----BEGIN CERTIFICATE-----\n...\n-----END PRIVATE KEY-----',
              border: OutlineInputBorder(),
              contentPadding: EdgeInsets.all(8),
            ),
            onChanged: (value) async {
              await SettingsService.setPepperClientCertPem(value.isEmpty ? null : value);
            },
          ),
        ),
        const SizedBox(height: 8),

        // CA Certificate PEM
        ListTile(
          leading: const Icon(Icons.verified_user, size: 20),
          title: const Text('CA Certificate (PEM)', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: const Text('Paste CA certificate', style: TextStyle(fontSize: 10)),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: TextFormField(
            initialValue: SettingsService.getPepperCaCertPem(),
            maxLines: 4,
            style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              hintText: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
              border: OutlineInputBorder(),
              contentPadding: EdgeInsets.all(8),
            ),
            onChanged: (value) async {
              await SettingsService.setPepperCaCertPem(value.isEmpty ? null : value);
            },
          ),
        ),
      ],
    );
  }

  Widget _buildPepperActionButtons(String pepperUrl, String certMode, StateSetter setState) {
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: ElevatedButton.icon(
                onPressed: () async {
                  final result = await CLIService.testPepperConnection(
                    url: pepperUrl,
                    clientCertPath: certMode == 'file' ? SettingsService.getPepperClientCertPath() : null,
                    clientKeyPath: certMode == 'file' ? SettingsService.getPepperClientKeyPath() : null,
                    caCertPath: certMode == 'file' ? SettingsService.getPepperCaCertPath() : null,
                  );
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(result['success']
                          ? 'mTLS connection successful!'
                          : 'Connection failed: ${result['message']}'),
                        backgroundColor: result['success'] ? Colors.green : Colors.red,
                      ),
                    );
                  }
                },
                icon: const Icon(Icons.wifi_tethering, size: 16),
                label: const Text('Test mTLS', style: TextStyle(fontSize: 12)),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                ),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: ElevatedButton.icon(
                onPressed: () async {
                  final peppers = await CLIService.listPeppers();
                  if (context.mounted) {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Stored Peppers'),
                        content: peppers.isEmpty
                          ? const Text('No peppers stored yet.')
                          : SizedBox(
                              width: double.maxFinite,
                              child: ListView.builder(
                                shrinkWrap: true,
                                itemCount: peppers.length,
                                itemBuilder: (context, i) => ListTile(
                                  leading: const Icon(Icons.fiber_manual_record, size: 12),
                                  title: Text(peppers[i]['id'] ?? 'Unknown', style: const TextStyle(fontSize: 12)),
                                  subtitle: Text('Created: ${peppers[i]['created_at'] ?? 'N/A'}', style: const TextStyle(fontSize: 10)),
                                ),
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
                  }
                },
                icon: const Icon(Icons.list, size: 16),
                label: const Text('List Peppers', style: TextStyle(fontSize: 12)),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        ElevatedButton.icon(
          onPressed: () {
            // TODO: Implement TOTP setup dialog
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('TOTP setup coming soon')),
            );
          },
          icon: const Icon(Icons.qr_code, size: 16),
          label: const Text('Setup 2FA (TOTP)', style: TextStyle(fontSize: 12)),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(vertical: 8),
          ),
        ),
      ],
    );
  }

  Widget _buildIntegritySection() {
    return StatefulBuilder(
      builder: (context, setState) {
        final integrityEnabled = SettingsService.getIntegrityEnabled();
        final integrityUrl = SettingsService.getIntegrityServerUrl();
        final certMode = SettingsService.getIntegrityCertMode();

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Integrity header with enable toggle
            Row(
              children: [
                const Icon(Icons.verified, size: 20),
                const SizedBox(width: 8),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Integrity Verification Plugin',
                        style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                      ),
                      Text(
                        'Distributed hash verification and audit trail',
                        style: TextStyle(fontSize: 11, color: Colors.grey),
                      ),
                    ],
                  ),
                ),
                Switch(
                  value: integrityEnabled,
                  onChanged: (value) async {
                    await SettingsService.setIntegrityEnabled(value);
                    setState(() {});
                    widget.onSettingChanged?.call('integrity_enabled', value);
                  },
                ),
              ],
            ),

            if (integrityEnabled) ...[
              const Divider(),
              const SizedBox(height: 8),

              // Server URL
              ListTile(
                leading: const Icon(Icons.link, size: 20),
                title: const Text('Server URL', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                subtitle: TextFormField(
                  initialValue: integrityUrl,
                  style: const TextStyle(fontSize: 12),
                  decoration: InputDecoration(
                    hintText: 'https://integrity.openssl-encrypt.org',
                    border: const OutlineInputBorder(),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                    suffixIcon: integrityUrl != 'https://integrity.openssl-encrypt.org'
                        ? IconButton(
                            icon: const Icon(Icons.restore, size: 16),
                            onPressed: () async {
                              await SettingsService.setIntegrityServerUrl('https://integrity.openssl-encrypt.org');
                              setState(() {});
                              widget.onSettingChanged?.call('integrity_server_url', 'https://integrity.openssl-encrypt.org');
                            },
                            tooltip: 'Reset to default',
                          )
                        : null,
                  ),
                  onFieldSubmitted: (value) async {
                    if (value.isNotEmpty && value.startsWith('http')) {
                      await SettingsService.setIntegrityServerUrl(value);
                      widget.onSettingChanged?.call('integrity_server_url', value);
                    }
                  },
                ),
              ),
              const SizedBox(height: 8),

              // Certificate mode selector
              ListTile(
                leading: const Icon(Icons.security, size: 20),
                title: const Text('Certificate Mode', style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold)),
                subtitle: SegmentedButton<String>(
                  segments: const [
                    ButtonSegment(
                      value: 'file',
                      label: Text('File Paths', style: TextStyle(fontSize: 11)),
                      icon: Icon(Icons.folder, size: 16),
                    ),
                    ButtonSegment(
                      value: 'pem',
                      label: Text('Paste PEM', style: TextStyle(fontSize: 11)),
                      icon: Icon(Icons.content_paste, size: 16),
                    ),
                  ],
                  selected: {certMode},
                  onSelectionChanged: (Set<String> newSelection) async {
                    await SettingsService.setIntegrityCertMode(newSelection.first);
                    setState(() {});
                    widget.onSettingChanged?.call('integrity_cert_mode', newSelection.first);
                  },
                ),
              ),
              const SizedBox(height: 8),

              // Certificate configuration based on mode
              if (certMode == 'file')
                _buildIntegrityCertificateFilePaths(setState)
              else
                _buildIntegrityCertificatePemInputs(setState),

              const SizedBox(height: 8),

              // Action buttons
              _buildIntegrityActionButtons(integrityUrl, certMode, setState),
            ],
          ],
        );
      },
    );
  }

  Widget _buildIntegrityCertificateFilePaths(StateSetter setState) {
    final clientCertPath = SettingsService.getIntegrityClientCertPath();
    final clientKeyPath = SettingsService.getIntegrityClientKeyPath();
    final caCertPath = SettingsService.getIntegrityCaCertPath();

    return Column(
      children: [
        // Client Certificate
        ListTile(
          leading: const Icon(Icons.badge, size: 20),
          title: const Text('Client Certificate', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: Text(
            clientCertPath ?? 'Not set',
            style: const TextStyle(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: () async {
                  final result = await FilePicker.platform.pickFiles(
                    type: FileType.custom,
                    allowedExtensions: ['pem', 'crt', 'cert'],
                  );
                  if (result != null && result.files.single.path != null) {
                    await SettingsService.setIntegrityClientCertPath(result.files.single.path);
                    setState(() {});
                  }
                },
                tooltip: 'Select file',
              ),
              if (clientCertPath != null)
                IconButton(
                  icon: const Icon(Icons.clear, size: 18),
                  onPressed: () async {
                    await SettingsService.setIntegrityClientCertPath(null);
                    setState(() {});
                  },
                  tooltip: 'Clear',
                ),
            ],
          ),
        ),

        // Client Key
        ListTile(
          leading: const Icon(Icons.vpn_key, size: 20),
          title: const Text('Client Key', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: Text(
            clientKeyPath ?? 'Not set',
            style: const TextStyle(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: () async {
                  final result = await FilePicker.platform.pickFiles(
                    type: FileType.custom,
                    allowedExtensions: ['pem', 'key'],
                  );
                  if (result != null && result.files.single.path != null) {
                    await SettingsService.setIntegrityClientKeyPath(result.files.single.path);
                    setState(() {});
                  }
                },
                tooltip: 'Select file',
              ),
              if (clientKeyPath != null)
                IconButton(
                  icon: const Icon(Icons.clear, size: 18),
                  onPressed: () async {
                    await SettingsService.setIntegrityClientKeyPath(null);
                    setState(() {});
                  },
                  tooltip: 'Clear',
                ),
            ],
          ),
        ),

        // CA Certificate
        ListTile(
          leading: const Icon(Icons.verified_user, size: 20),
          title: const Text('CA Certificate', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: Text(
            caCertPath ?? 'Not set',
            style: const TextStyle(fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: () async {
                  final result = await FilePicker.platform.pickFiles(
                    type: FileType.custom,
                    allowedExtensions: ['pem', 'crt', 'cert'],
                  );
                  if (result != null && result.files.single.path != null) {
                    await SettingsService.setIntegrityCaCertPath(result.files.single.path);
                    setState(() {});
                  }
                },
                tooltip: 'Select file',
              ),
              if (caCertPath != null)
                IconButton(
                  icon: const Icon(Icons.clear, size: 18),
                  onPressed: () async {
                    await SettingsService.setIntegrityCaCertPath(null);
                    setState(() {});
                  },
                  tooltip: 'Clear',
                ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildIntegrityCertificatePemInputs(StateSetter setState) {
    return Column(
      children: [
        // Client Cert + Key PEM
        ListTile(
          leading: const Icon(Icons.badge, size: 20),
          title: const Text('Client Certificate + Key (PEM)', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: const Text('Paste combined certificate and private key', style: TextStyle(fontSize: 10)),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: TextFormField(
            initialValue: SettingsService.getIntegrityClientCertPem(),
            maxLines: 4,
            style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              hintText: '-----BEGIN CERTIFICATE-----\n...\n-----END PRIVATE KEY-----',
              border: OutlineInputBorder(),
              contentPadding: EdgeInsets.all(8),
            ),
            onChanged: (value) async {
              await SettingsService.setIntegrityClientCertPem(value.isEmpty ? null : value);
            },
          ),
        ),
        const SizedBox(height: 8),

        // CA Certificate PEM
        ListTile(
          leading: const Icon(Icons.verified_user, size: 20),
          title: const Text('CA Certificate (PEM)', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
          subtitle: const Text('Paste CA certificate', style: TextStyle(fontSize: 10)),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: TextFormField(
            initialValue: SettingsService.getIntegrityCaCertPem(),
            maxLines: 4,
            style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              hintText: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
              border: OutlineInputBorder(),
              contentPadding: EdgeInsets.all(8),
            ),
            onChanged: (value) async {
              await SettingsService.setIntegrityCaCertPem(value.isEmpty ? null : value);
            },
          ),
        ),
      ],
    );
  }

  Widget _buildIntegrityActionButtons(String integrityUrl, String certMode, StateSetter setState) {
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: ElevatedButton.icon(
                onPressed: () async {
                  final result = await CLIService.testIntegrityConnection(
                    url: integrityUrl,
                    clientCertPath: certMode == 'file' ? SettingsService.getIntegrityClientCertPath() : null,
                    clientKeyPath: certMode == 'file' ? SettingsService.getIntegrityClientKeyPath() : null,
                    caCertPath: certMode == 'file' ? SettingsService.getIntegrityCaCertPath() : null,
                  );
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(result['success']
                          ? 'mTLS connection successful!'
                          : 'Connection failed: ${result['message']}'),
                        backgroundColor: result['success'] ? Colors.green : Colors.red,
                      ),
                    );
                  }
                },
                icon: const Icon(Icons.wifi_tethering, size: 16),
                label: const Text('Test Connection', style: TextStyle(fontSize: 12)),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                ),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: ElevatedButton.icon(
                onPressed: () async {
                  final stats = await CLIService.getIntegrityStats();
                  if (context.mounted) {
                    showDialog(
                      context: context,
                      builder: (context) => AlertDialog(
                        title: const Text('Verification Statistics'),
                        content: stats['success']
                          ? Column(
                              mainAxisSize: MainAxisSize.min,
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text('Total Verifications: ${stats['total_verifications']}', style: const TextStyle(fontSize: 13)),
                                Text('Successful: ${stats['successful_verifications']}', style: const TextStyle(fontSize: 13, color: Colors.green)),
                                Text('Failed: ${stats['failed_verifications']}', style: const TextStyle(fontSize: 13, color: Colors.red)),
                                if (stats['last_verification'] != null)
                                  Text('Last: ${stats['last_verification']}', style: const TextStyle(fontSize: 11)),
                              ],
                            )
                          : Text('Failed to retrieve stats: ${stats['message']}'),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: const Text('Close'),
                          ),
                        ],
                      ),
                    );
                  }
                },
                icon: const Icon(Icons.bar_chart, size: 16),
                label: const Text('View Stats', style: TextStyle(fontSize: 12)),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }
}
