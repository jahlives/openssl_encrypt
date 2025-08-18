import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'settings_service.dart';
import 'cli_service.dart';

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
                if (_matchesSearch('theme appearance'))
                  _buildCategoryCard(
                    'Theme & Appearance',
                    Icons.palette,
                    Colors.purple,
                    [
                      _buildThemeSelector(),
                    ],
                  ),
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
        // Write to file
        await File(filePath).writeAsString(jsonString);

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Settings exported to: ${filePath.split('/').last}'),
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
        final file = File(result.files.single.path!);
        final jsonString = await file.readAsString();
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
}
