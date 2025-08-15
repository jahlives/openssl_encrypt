import 'package:flutter/material.dart';
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
        backgroundColor: Colors.blue.shade700,
        foregroundColor: Colors.white,
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
              color: Colors.blue.shade50,
              border: Border(bottom: BorderSide(color: Colors.blue.shade200)),
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
                fillColor: Colors.white,
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
          Icon(icon, size: 20, color: Colors.grey.shade600),
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
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
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
                    color: Colors.grey,
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
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
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
                    color: Colors.grey,
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
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
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
                    color: Colors.grey,
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
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
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
                    color: Colors.grey,
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
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
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
                    color: Colors.grey,
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
                Navigator.of(context).pop();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Settings reset to defaults'),
                    backgroundColor: Colors.green,
                  ),
                );
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
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

  void _exportSettings() {
    final settings = SettingsService.exportSettings();
    // TODO: Implement file export functionality
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Settings export feature coming soon'),
        backgroundColor: Colors.blue,
      ),
    );
  }

  void _importSettings() {
    // TODO: Implement file import functionality
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Settings import feature coming soon'),
        backgroundColor: Colors.blue,
      ),
    );
  }
}