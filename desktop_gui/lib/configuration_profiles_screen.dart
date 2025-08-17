import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import 'configuration_profiles_service.dart';

/// Screen for managing configuration profiles
class ConfigurationProfilesScreen extends StatefulWidget {
  final Function(ConfigurationProfile?)? onProfileSelected;
  final bool isSelectionMode;
  
  const ConfigurationProfilesScreen({
    super.key,
    this.onProfileSelected,
    this.isSelectionMode = false,
  });

  @override
  State<ConfigurationProfilesScreen> createState() => _ConfigurationProfilesScreenState();
}

class _ConfigurationProfilesScreenState extends State<ConfigurationProfilesScreen> {
  Map<String, ConfigurationProfile> _profiles = {};
  String? _activeProfileName;
  bool _isLoading = true;
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';

  @override
  void initState() {
    super.initState();
    _loadProfiles();
    _searchController.addListener(() {
      setState(() {
        _searchQuery = _searchController.text.toLowerCase();
      });
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadProfiles() async {
    setState(() {
      _isLoading = true;
    });

    try {
      final profiles = await ConfigurationProfilesService.getProfiles();
      final activeProfile = await ConfigurationProfilesService.getActiveProfileName();

      setState(() {
        _profiles = profiles;
        _activeProfileName = activeProfile;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _isLoading = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load profiles: $e')),
        );
      }
    }
  }

  List<MapEntry<String, ConfigurationProfile>> get _filteredProfiles {
    if (_searchQuery.isEmpty) {
      return _profiles.entries.toList();
    }
    
    return _profiles.entries.where((entry) {
      final name = entry.key.toLowerCase();
      final profile = entry.value;
      final description = profile.description.toLowerCase();
      final algorithm = profile.algorithm.toLowerCase();
      
      return name.contains(_searchQuery) ||
             description.contains(_searchQuery) ||
             algorithm.contains(_searchQuery);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.isSelectionMode ? 'Select Configuration Profile' : 'Configuration Profiles'),
        actions: [
          if (!widget.isSelectionMode) ...[
            IconButton(
              onPressed: _showCreateDefaultProfilesDialog,
              icon: const Icon(Icons.auto_fix_high),
              tooltip: 'Create Default Profiles',
            ),
            IconButton(
              onPressed: _showImportDialog,
              icon: const Icon(Icons.file_download),
              tooltip: 'Import Profiles',
            ),
            IconButton(
              onPressed: _exportProfiles,
              icon: const Icon(Icons.file_upload),
              tooltip: 'Export Profiles',
            ),
          ],
        ],
      ),
      body: Column(
        children: [
          // Search Bar
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Search profiles by name, algorithm, or description...',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchQuery.isNotEmpty
                    ? IconButton(
                        onPressed: () {
                          _searchController.clear();
                        },
                        icon: const Icon(Icons.clear),
                      )
                    : null,
                border: const OutlineInputBorder(),
              ),
            ),
          ),

          // Content
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _filteredProfiles.isEmpty
                    ? _buildEmptyState()
                    : _buildProfilesList(),
          ),
        ],
      ),
      floatingActionButton: widget.isSelectionMode
          ? null
          : FloatingActionButton(
              onPressed: () => _showCreateProfileDialog(),
              tooltip: 'Create New Profile',
              child: const Icon(Icons.add),
            ),
    );
  }

  Widget _buildEmptyState() {
    if (_searchQuery.isNotEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.search_off,
              size: 64,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(height: 16),
            Text(
              'No profiles found',
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Try adjusting your search terms',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      );
    }

    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.settings_applications,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            'No Configuration Profiles',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Create your first profile to save encryption settings',
            style: TextStyle(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            onPressed: () => _showCreateProfileDialog(),
            icon: const Icon(Icons.add),
            label: const Text('Create Profile'),
          ),
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed: _showCreateDefaultProfilesDialog,
            icon: const Icon(Icons.auto_fix_high),
            label: const Text('Create Default Profiles'),
          ),
        ],
      ),
    );
  }

  Widget _buildProfilesList() {
    final sortedProfiles = _filteredProfiles.toList()
      ..sort((a, b) {
        // Active profile first
        if (a.key == _activeProfileName) return -1;
        if (b.key == _activeProfileName) return 1;
        // Then alphabetically
        return a.key.compareTo(b.key);
      });

    return ListView.builder(
      padding: const EdgeInsets.all(16.0),
      itemCount: sortedProfiles.length,
      itemBuilder: (context, index) {
        final entry = sortedProfiles[index];
        final profileName = entry.key;
        final profile = entry.value;
        final isActive = profileName == _activeProfileName;

        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: CircleAvatar(
              backgroundColor: isActive 
                  ? Theme.of(context).colorScheme.primary
                  : Theme.of(context).colorScheme.surfaceContainer,
              child: Icon(
                isActive ? Icons.star : Icons.settings,
                color: isActive 
                    ? Theme.of(context).colorScheme.onPrimary
                    : Theme.of(context).colorScheme.onSurfaceVariant,
                size: 20,
              ),
            ),
            title: Row(
              children: [
                Expanded(
                  child: Text(
                    profileName,
                    style: TextStyle(
                      fontWeight: isActive ? FontWeight.bold : FontWeight.normal,
                    ),
                  ),
                ),
                if (isActive)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primary,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      'Active',
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.onPrimary,
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
              ],
            ),
            subtitle: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SizedBox(height: 4),
                Text(
                  profile.getSummary(),
                  style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
                ),
                if (profile.description.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(
                    profile.description,
                    style: const TextStyle(fontSize: 11),
                  ),
                ],
                const SizedBox(height: 4),
                Text(
                  'Created: ${_formatDate(profile.createdAt)}',
                  style: TextStyle(
                    fontSize: 10,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
            trailing: widget.isSelectionMode
                ? const Icon(Icons.chevron_right)
                : PopupMenuButton<String>(
                    onSelected: (action) => _handleProfileAction(action, profileName, profile),
                    itemBuilder: (context) => [
                      PopupMenuItem(
                        value: 'activate',
                        enabled: !isActive,
                        child: Row(
                          children: [
                            Icon(Icons.star, size: 16, color: isActive ? Colors.grey : null),
                            const SizedBox(width: 8),
                            const Text('Set as Active'),
                          ],
                        ),
                      ),
                      if (isActive)
                        const PopupMenuItem(
                          value: 'deactivate',
                          child: Row(
                            children: [
                              Icon(Icons.star_border, size: 16),
                              SizedBox(width: 8),
                              Text('Deactivate'),
                            ],
                          ),
                        ),
                      const PopupMenuItem(
                        value: 'edit',
                        child: Row(
                          children: [
                            Icon(Icons.edit, size: 16),
                            SizedBox(width: 8),
                            Text('Edit'),
                          ],
                        ),
                      ),
                      const PopupMenuItem(
                        value: 'duplicate',
                        child: Row(
                          children: [
                            Icon(Icons.copy, size: 16),
                            SizedBox(width: 8),
                            Text('Duplicate'),
                          ],
                        ),
                      ),
                      const PopupMenuItem(
                        value: 'rename',
                        child: Row(
                          children: [
                            Icon(Icons.drive_file_rename_outline, size: 16),
                            SizedBox(width: 8),
                            Text('Rename'),
                          ],
                        ),
                      ),
                      const PopupMenuItem(
                        value: 'delete',
                        child: Row(
                          children: [
                            Icon(Icons.delete, size: 16, color: Colors.red),
                            SizedBox(width: 8),
                            Text('Delete', style: TextStyle(color: Colors.red)),
                          ],
                        ),
                      ),
                    ],
                  ),
            onTap: widget.isSelectionMode
                ? () {
                    widget.onProfileSelected?.call(profile);
                    Navigator.of(context).pop();
                  }
                : null,
          ),
        );
      },
    );
  }

  String _formatDate(DateTime date) {
    return '${date.day}/${date.month}/${date.year}';
  }

  Future<void> _handleProfileAction(String action, String profileName, ConfigurationProfile profile) async {
    switch (action) {
      case 'activate':
        await _setActiveProfile(profileName);
        break;
      case 'deactivate':
        await _setActiveProfile(null);
        break;
      case 'edit':
        await _showEditProfileDialog(profileName, profile);
        break;
      case 'duplicate':
        await _duplicateProfile(profileName, profile);
        break;
      case 'rename':
        await _showRenameDialog(profileName);
        break;
      case 'delete':
        await _showDeleteDialog(profileName);
        break;
    }
  }

  Future<void> _setActiveProfile(String? profileName) async {
    final success = await ConfigurationProfilesService.setActiveProfile(profileName);
    if (success) {
      await _loadProfiles();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(profileName == null ? 'Profile deactivated' : 'Active profile: $profileName'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } else if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to update active profile')),
      );
    }
  }

  Future<void> _duplicateProfile(String originalName, ConfigurationProfile profile) async {
    String newName = '$originalName (Copy)';
    int counter = 1;
    
    while (_profiles.containsKey(newName)) {
      counter++;
      newName = '$originalName (Copy $counter)';
    }
    
    final success = await ConfigurationProfilesService.saveProfile(newName, profile);
    if (success) {
      await _loadProfiles();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Profile duplicated: $newName'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } else if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to duplicate profile')),
      );
    }
  }

  Future<void> _showCreateProfileDialog({String? initialName, ConfigurationProfile? initialProfile}) async {
    await showDialog(
      context: context,
      builder: (context) => CreateProfileDialog(
        initialName: initialName,
        initialProfile: initialProfile,
        onProfileCreated: (name, profile) async {
          final success = await ConfigurationProfilesService.saveProfile(name, profile);
          if (success) {
            await _loadProfiles();
            if (mounted) {
              // ignore: use_build_context_synchronously
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Profile created: $name'),
                  backgroundColor: Colors.green,
                ),
              );
            }
          } else if (mounted) {
            // ignore: use_build_context_synchronously
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Failed to create profile')),
            );
          }
        },
        existingNames: _profiles.keys.toSet(),
      ),
    );
  }

  Future<void> _showEditProfileDialog(String profileName, ConfigurationProfile profile) async {
    await _showCreateProfileDialog(initialName: profileName, initialProfile: profile);
  }

  Future<void> _showRenameDialog(String currentName) async {
    String? newName = await showDialog<String>(
      context: context,
      builder: (context) => _RenameDialog(
        currentName: currentName,
        existingNames: _profiles.keys.toSet(),
      ),
    );

    if (newName != null && newName != currentName) {
      final success = await ConfigurationProfilesService.renameProfile(currentName, newName);
      if (success) {
        await _loadProfiles();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Profile renamed: $currentName → $newName'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } else if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Failed to rename profile')),
        );
      }
    }
  }

  Future<void> _showDeleteDialog(String profileName) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Profile'),
        content: Text('Are you sure you want to delete "$profileName"?\n\nThis action cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Delete', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      final success = await ConfigurationProfilesService.deleteProfile(profileName);
      if (success) {
        await _loadProfiles();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Profile deleted: $profileName'),
              backgroundColor: Colors.orange,
            ),
          );
        }
      } else if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Failed to delete profile')),
        );
      }
    }
  }

  Future<void> _showCreateDefaultProfilesDialog() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create Default Profiles'),
        content: const Text(
          'This will create several pre-configured profiles:\n\n'
          '• Quick Encryption\n'
          '• High Security\n'
          '• Post-Quantum\n'
          '• Balanced Performance\n\n'
          'Existing profiles will not be affected.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Create'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      final success = await ConfigurationProfilesService.createDefaultProfiles();
      if (success) {
        await _loadProfiles();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Default profiles created successfully'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } else if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Failed to create default profiles')),
        );
      }
    }
  }

  Future<void> _exportProfiles() async {
    try {
      final jsonData = await ConfigurationProfilesService.exportProfiles();
      if (jsonData == null) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Failed to export profiles')),
          );
        }
        return;
      }

      final fileName = 'openssl_encrypt_profiles_${DateTime.now().millisecondsSinceEpoch}.json';
      final filePath = await FilePicker.platform.saveFile(
        dialogTitle: 'Export Configuration Profiles',
        fileName: fileName,
        type: FileType.custom,
        allowedExtensions: ['json'],
      );

      if (filePath != null) {
        await File(filePath).writeAsString(jsonData);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Profiles exported to: $filePath'),
              backgroundColor: Colors.green,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Export failed: $e')),
        );
      }
    }
  }

  Future<void> _showImportDialog() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['json'],
    );

    if (result != null && result.files.single.path != null) {
      try {
        final file = File(result.files.single.path!);
        final jsonData = await file.readAsString();

        if (mounted) {
          final overwrite = await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              title: const Text('Import Profiles'),
              content: const Text(
                'How would you like to import the profiles?\n\n'
                '• Merge: Add new profiles, keep existing ones\n'
                '• Replace: Replace all profiles with imported ones',
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(null),
                  child: const Text('Cancel'),
                ),
                TextButton(
                  onPressed: () => Navigator.of(context).pop(false),
                  child: const Text('Merge'),
                ),
                ElevatedButton(
                  onPressed: () => Navigator.of(context).pop(true),
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.orange),
                  child: const Text('Replace', style: TextStyle(color: Colors.white)),
                ),
              ],
            ),
          );

          if (overwrite != null) {
            final success = await ConfigurationProfilesService.importProfiles(
              jsonData,
              overwrite: overwrite,
            );

            if (success) {
              await _loadProfiles();
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('Profiles imported successfully (${overwrite ? 'replaced' : 'merged'})'),
                    backgroundColor: Colors.green,
                  ),
                );
              }
            } else if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Failed to import profiles')),
              );
            }
          }
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Import failed: $e')),
          );
        }
      }
    }
  }
}

/// Auto-repeat button that continues action when held down
class AutoRepeatButton extends StatefulWidget {
  final IconData icon;
  final MaterialColor color;
  final bool enabled;
  final VoidCallback onAction;
  final double size;
  final double iconSize;

  const AutoRepeatButton({
    super.key,
    required this.icon,
    required this.color,
    required this.enabled,
    required this.onAction,
    this.size = 32,
    this.iconSize = 16,
  });

  @override
  State<AutoRepeatButton> createState() => _AutoRepeatButtonState();
}

class _AutoRepeatButtonState extends State<AutoRepeatButton> {
  Timer? _repeatTimer;
  bool _isPressed = false;

  @override
  void dispose() {
    _repeatTimer?.cancel();
    super.dispose();
  }

  void _onPointerDown(PointerDownEvent event) {
    if (!widget.enabled) return;
    
    setState(() {
      _isPressed = true;
    });
    
    // Execute immediately
    widget.onAction();
    
    // Start repeating after a short delay
    _repeatTimer = Timer(const Duration(milliseconds: 300), () {
      if (_isPressed && mounted) {
        _startRepeating();
      }
    });
  }
  
  void _startRepeating() {
    _repeatTimer?.cancel();
    _repeatTimer = Timer.periodic(const Duration(milliseconds: 100), (timer) {
      if (!_isPressed || !mounted) {
        timer.cancel();
        return;
      }
      widget.onAction();
    });
  }

  void _onPointerUp(PointerUpEvent event) {
    _stopRepeating();
  }

  void _onPointerCancel(PointerCancelEvent event) {
    _stopRepeating();
  }

  void _stopRepeating() {
    if (!mounted) return;
    setState(() {
      _isPressed = false;
    });
    _repeatTimer?.cancel();
    _repeatTimer = null;
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      onPointerDown: _onPointerDown,
      onPointerUp: _onPointerUp,
      onPointerCancel: _onPointerCancel,
      child: Container(
        width: widget.size,
        height: widget.size,
        decoration: BoxDecoration(
          color: widget.enabled 
              ? (_isPressed ? widget.color.shade300 : widget.color.shade100)
              : Colors.grey.shade200,
          borderRadius: BorderRadius.circular(widget.size / 2),
          border: Border.all(
            color: widget.enabled ? widget.color : Colors.grey,
            width: 1,
          ),
        ),
        child: Icon(
          widget.icon,
          size: widget.iconSize,
          color: widget.enabled 
              ? (_isPressed ? widget.color.shade700 : widget.color)
              : Colors.grey,
        ),
      ),
    );
  }
}

/// Dialog for renaming a profile
class _RenameDialog extends StatefulWidget {
  final String currentName;
  final Set<String> existingNames;

  const _RenameDialog({
    required this.currentName,
    required this.existingNames,
  });

  @override
  State<_RenameDialog> createState() => _RenameDialogState();
}

class _RenameDialogState extends State<_RenameDialog> {
  late TextEditingController _controller;
  String? _errorText;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.currentName);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _validateName(String name) {
    setState(() {
      if (name.isEmpty) {
        _errorText = 'Name cannot be empty';
      } else if (name != widget.currentName && widget.existingNames.contains(name)) {
        _errorText = 'A profile with this name already exists';
      } else {
        _errorText = null;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Rename Profile'),
      content: TextField(
        controller: _controller,
        decoration: InputDecoration(
          labelText: 'Profile Name',
          errorText: _errorText,
          border: const OutlineInputBorder(),
        ),
        onChanged: _validateName,
        autofocus: true,
        textInputAction: TextInputAction.done,
        onSubmitted: (value) {
          if (_errorText == null && value.isNotEmpty) {
            Navigator.of(context).pop(value);
          }
        },
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(null),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _errorText == null && _controller.text.isNotEmpty
              ? () => Navigator.of(context).pop(_controller.text)
              : null,
          child: const Text('Rename'),
        ),
      ],
    );
  }
}

/// Dialog for creating/editing profiles
class CreateProfileDialog extends StatefulWidget {
  final String? initialName;
  final ConfigurationProfile? initialProfile;
  final Function(String name, ConfigurationProfile profile) onProfileCreated;
  final Set<String> existingNames;

  const CreateProfileDialog({
    super.key,
    this.initialName,
    this.initialProfile,
    required this.onProfileCreated,
    required this.existingNames,
  });

  @override
  State<CreateProfileDialog> createState() => _CreateProfileDialogState();
}

class _CreateProfileDialogState extends State<CreateProfileDialog> {
  late TextEditingController _nameController;
  late TextEditingController _descriptionController;
  String _algorithm = 'aes-gcm';
  String? _nameError;
  
  // Advanced configuration
  Map<String, Map<String, dynamic>> _hashConfig = {};
  Map<String, Map<String, dynamic>> _kdfConfig = {};
  bool _showAdvancedConfig = false;

  @override
  void initState() {
    super.initState();
    _nameController = TextEditingController(text: widget.initialName ?? '');
    _descriptionController = TextEditingController(text: widget.initialProfile?.description ?? '');
    _algorithm = widget.initialProfile?.algorithm ?? 'aes-gcm';
    
    // Initialize configuration from existing profile or defaults
    if (widget.initialProfile != null) {
      _hashConfig = Map<String, Map<String, dynamic>>.from(widget.initialProfile!.hashConfig);
      _kdfConfig = Map<String, Map<String, dynamic>>.from(widget.initialProfile!.kdfConfig);
    } else {
      _initializeDefaultConfiguration();
    }
  }

  @override
  void dispose() {
    _nameController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }

  void _validateName(String name) {
    setState(() {
      if (name.isEmpty) {
        _nameError = 'Name cannot be empty';
      } else if (name != widget.initialName && widget.existingNames.contains(name)) {
        _nameError = 'A profile with this name already exists';
      } else {
        _nameError = null;
      }
    });
  }
  
  void _initializeDefaultConfiguration() {
    // Initialize default hash configuration (from CLI help)
    _hashConfig = {
      'sha224': {'enabled': false, 'rounds': 1000},
      'sha256': {'enabled': true, 'rounds': 1000},
      'sha384': {'enabled': false, 'rounds': 1000}, 
      'sha512': {'enabled': false, 'rounds': 1000},
      'sha3-224': {'enabled': false, 'rounds': 1000},
      'sha3-256': {'enabled': false, 'rounds': 1000},
      'sha3-384': {'enabled': false, 'rounds': 1000},
      'sha3-512': {'enabled': false, 'rounds': 1000},
      'blake2b': {'enabled': false, 'rounds': 1000},
      'blake3': {'enabled': false, 'rounds': 1000},
      'shake128': {'enabled': false, 'rounds': 1000},
      'shake256': {'enabled': false, 'rounds': 1000},
      'whirlpool': {'enabled': false, 'rounds': 1000},
    };
    
    // Initialize default KDF configuration  
    _kdfConfig = {
      'pbkdf2': {'enabled': true, 'rounds': 100000},
      'scrypt': {'enabled': false, 'n': 16384, 'r': 8, 'p': 1, 'rounds': 1},
      'argon2': {'enabled': false, 'memory_cost': 65536, 'time_cost': 3, 'parallelism': 1, 'rounds': 1},
      'hkdf': {'enabled': false, 'info': 'openssl_encrypt_hkdf', 'rounds': 1},
      'balloon': {'enabled': false, 'space_cost': 65536, 'time_cost': 3, 'parallelism': 4, 'rounds': 2, 'hash_len': 32},
    };
  }

  bool get _canSave => _nameError == null && _nameController.text.isNotEmpty;

  void _save() {
    final profile = ConfigurationProfile(
      algorithm: _algorithm,
      hashConfig: _hashConfig,
      kdfConfig: _kdfConfig,
      description: _descriptionController.text,
    );

    widget.onProfileCreated(_nameController.text, profile);
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.initialName == null ? 'Create Profile' : 'Edit Profile'),
      content: SizedBox(
        width: 500,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
            TextField(
              controller: _nameController,
              decoration: InputDecoration(
                labelText: 'Profile Name',
                errorText: _nameError,
                border: const OutlineInputBorder(),
              ),
              onChanged: _validateName,
              autofocus: true,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _descriptionController,
              decoration: const InputDecoration(
                labelText: 'Description (optional)',
                border: OutlineInputBorder(),
              ),
              maxLines: 2,
            ),
            const SizedBox(height: 16),
            DropdownButtonFormField<String>(
              value: _algorithm,
              decoration: const InputDecoration(
                labelText: 'Algorithm',
                border: OutlineInputBorder(),
              ),
              items: [
                // Classical symmetric algorithms
                'fernet',
                'aes-gcm',
                'chacha20-poly1305',
                'xchacha20-poly1305',
                'aes-siv',
                'aes-gcm-siv',
                'aes-ocb3',
                'camellia',
                
                // ML-KEM (NIST Post-Quantum) algorithms
                'ml-kem-512-hybrid',
                'ml-kem-768-hybrid', 
                'ml-kem-1024-hybrid',
                'ml-kem-512-chacha20',
                'ml-kem-768-chacha20',
                'ml-kem-1024-chacha20',
                
                // Kyber (pre-NIST) algorithms  
                'kyber512-hybrid',
                'kyber768-hybrid',
                'kyber1024-hybrid',
                
                // HQC algorithms
                'hqc-128-hybrid',
                'hqc-192-hybrid', 
                'hqc-256-hybrid',
                
                // MAYO signature-based algorithms
                'mayo-1-hybrid',
                'mayo-3-hybrid',
                'mayo-5-hybrid',
                
                // CROSS signature-based algorithms
                'cross-128-hybrid',
                'cross-192-hybrid',
                'cross-256-hybrid',
              ].map((algorithm) => DropdownMenuItem<String>(
                value: algorithm,
                child: Text(algorithm),
              )).toList(),
              onChanged: (value) {
                setState(() {
                  _algorithm = value!;
                });
              },
            ),
            const SizedBox(height: 20),
            
            // Advanced Configuration Toggle
            Card(
              elevation: 1,
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Column(
                  children: [
                    Row(
                      children: [
                        Icon(Icons.tune, size: 20, color: Theme.of(context).colorScheme.primary),
                        const SizedBox(width: 8),
                        const Expanded(
                          child: Text(
                            'Advanced Configuration',
                            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
                          ),
                        ),
                        Switch(
                          value: _showAdvancedConfig,
                          onChanged: (value) {
                            setState(() {
                              _showAdvancedConfig = value;
                            });
                          },
                        ),
                      ],
                    ),
                    if (_showAdvancedConfig) ...[
                      const SizedBox(height: 16),
                      _buildHashConfigSection(),
                      const SizedBox(height: 16),
                      _buildKdfConfigSection(),
                    ],
                  ],
                ),
              ),
            ),
          ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _canSave ? _save : null,
          child: Text(widget.initialName == null ? 'Create' : 'Save'),
        ),
      ],
    );
  }
  
  Widget _buildHashConfigSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Row(
          children: [
            Icon(Icons.tag, size: 16),
            SizedBox(width: 8),
            Text('Hash Algorithms', style: TextStyle(fontWeight: FontWeight.w500, fontSize: 14)),
          ],
        ),
        const SizedBox(height: 8),
        Column(
          children: _hashConfig.entries.map((entry) {
            final hashName = entry.key;
            final config = entry.value;
            final isEnabled = config['enabled'] as bool;
            final rounds = config['rounds'] as int;
            
            return Padding(
              padding: const EdgeInsets.only(bottom: 8.0),
              child: _buildHashConfig(hashName, hashName.toUpperCase(), isEnabled, rounds),
            );
          }).toList(),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            TextButton(
              onPressed: () {
                setState(() {
                  for (final entry in _hashConfig.entries) {
                    entry.value['enabled'] = true;
                  }
                });
              },
              child: const Text('Enable All', style: TextStyle(fontSize: 12)),
            ),
            const SizedBox(width: 8),
            TextButton(
              onPressed: () {
                setState(() {
                  for (final entry in _hashConfig.entries) {
                    entry.value['enabled'] = false;
                  }
                });
              },
              child: const Text('Disable All', style: TextStyle(fontSize: 12)),
            ),
          ],
        ),
      ],
    );
  }
  
  Widget _buildHashConfig(String hashId, String hashName, bool isEnabled, int rounds) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        border: Border.all(color: isEnabled ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.outline),
        borderRadius: BorderRadius.circular(8),
        color: isEnabled ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      ),
      child: Column(
        children: [
          Row(
            children: [
              Switch(
                value: isEnabled,
                onChanged: (bool? value) {
                  setState(() {
                    _hashConfig[hashId]!['enabled'] = value ?? false;
                  });
                },
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  hashName,
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                    color: isEnabled ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ],
          ),
          if (isEnabled) ...[
            const SizedBox(height: 12),
            _buildHashRoundsSlider(hashId, rounds),
          ],
        ],
      ),
    );
  }
  
  Widget _buildHashRoundsSlider(String hashId, int currentRounds) {
    int minRounds = 0;
    int maxRounds = 1000000;
    int clampedRounds = currentRounds.clamp(minRounds, maxRounds);
    
    return Row(
      children: [
        const SizedBox(width: 60, child: Text('Rounds:', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w500))),
        // Decrement button
        _buildAutoRepeatButton(
          icon: Icons.remove,
          color: Colors.blue,
          enabled: clampedRounds > minRounds,
          onAction: () {
            setState(() {
              _hashConfig[hashId]!['rounds'] = (clampedRounds - 1).clamp(minRounds, maxRounds);
            });
          },
          size: 24,
          iconSize: 12,
        ),
        const SizedBox(width: 4),
        Expanded(
          child: Slider(
            value: clampedRounds.toDouble(),
            min: minRounds.toDouble(),
            max: maxRounds.toDouble(),
            divisions: maxRounds ~/ 1000,
            label: clampedRounds.toString(),
            activeColor: Theme.of(context).colorScheme.primary,
            inactiveColor: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
            onChanged: (double value) {
              setState(() {
                _hashConfig[hashId]!['rounds'] = value.toInt();
              });
            },
          ),
        ),
        const SizedBox(width: 4),
        // Increment button
        _buildAutoRepeatButton(
          icon: Icons.add,
          color: Colors.blue,
          enabled: clampedRounds < maxRounds,
          onAction: () {
            setState(() {
              _hashConfig[hashId]!['rounds'] = (clampedRounds + 1).clamp(minRounds, maxRounds);
            });
          },
          size: 24,
          iconSize: 12,
        ),
        const SizedBox(width: 8),
        SizedBox(width: 60, child: Text(clampedRounds.toString(), style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500))),
      ],
    );
  }
  
  Widget _buildKdfConfigSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Row(
          children: [
            Icon(Icons.key, size: 16),
            SizedBox(width: 8),
            Text('Key Derivation Functions', style: TextStyle(fontWeight: FontWeight.w500, fontSize: 14)),
          ],
        ),
        const SizedBox(height: 8),
        
        // PBKDF2 Panel
        _buildPBKDF2Panel(),
        const SizedBox(height: 8),
        
        // Argon2 Panel  
        _buildArgon2Panel(),
        const SizedBox(height: 8),
        
        // Scrypt Panel
        _buildScryptPanel(),
        const SizedBox(height: 8),
        
        // HKDF Panel
        _buildHKDFPanel(),
        const SizedBox(height: 8),
        
        // Balloon Panel
        _buildBalloonPanel(),
        const SizedBox(height: 8),
        
        // Quick presets
        Row(
          children: [
            TextButton(
              onPressed: () {
                setState(() {
                  _kdfConfig['pbkdf2']!['enabled'] = true;
                  _kdfConfig['scrypt']!['enabled'] = false;
                  _kdfConfig['argon2']!['enabled'] = false;
                  _kdfConfig['hkdf']!['enabled'] = false;
                  _kdfConfig['balloon']!['enabled'] = false;
                });
              },
              child: const Text('PBKDF2 Only', style: TextStyle(fontSize: 12)),
            ),
            const SizedBox(width: 8),
            TextButton(
              onPressed: () {
                setState(() {
                  _kdfConfig['pbkdf2']!['enabled'] = false;
                  _kdfConfig['scrypt']!['enabled'] = false;
                  _kdfConfig['argon2']!['enabled'] = true;
                  _kdfConfig['hkdf']!['enabled'] = false;
                  _kdfConfig['balloon']!['enabled'] = false;
                });
              },
              child: const Text('Argon2 Only', style: TextStyle(fontSize: 12)),
            ),
          ],
        ),
      ],
    );
  }
  
  /// Build PBKDF2 configuration panel
  Widget _buildPBKDF2Panel() {
    final config = _kdfConfig['pbkdf2'] ?? {'enabled': true, 'rounds': 100000};
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).colorScheme.surfaceContainer,
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            CheckboxListTile(
              title: Row(
                children: [
                  const Text('PBKDF2', style: TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.green,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Text('RECOMMENDED', style: TextStyle(color: Colors.white, fontSize: 10)),
                  ),
                ],
              ),
              subtitle: const Text('Password-Based Key Derivation Function 2 - Industry standard, widely supported'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['pbkdf2'] = {
                    'enabled': value ?? false,
                    'rounds': config['rounds'] ?? 100000,
                  };
                });
              },
              dense: true,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: Row(
                  children: [
                    const SizedBox(width: 80, child: Text('Rounds:', style: TextStyle(fontSize: 12))),
                    Expanded(
                      child: Slider(
                        value: (config['rounds'] ?? 100000).toDouble(),
                        min: 0,
                        max: 1000000,
                        divisions: 100,
                        label: (config['rounds'] ?? 100000).toString(),
                        onChanged: (double value) {
                          setState(() {
                            _kdfConfig['pbkdf2']!['rounds'] = value.toInt();
                          });
                        },
                      ),
                    ),
                    SizedBox(width: 60, child: Text('${config['rounds'] ?? 100000}', style: const TextStyle(fontSize: 12))),
                  ],
                ),
              ),
            ],
          ],
        ),
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
      'rounds': 10,
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.secondaryContainer : Theme.of(context).colorScheme.surfaceContainer,
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
              subtitle: const Text('Memory-hard function, winner of Password Hashing Competition - best against hardware attacks'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['argon2'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              dense: true,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ..._buildArgon2Parameters(config),
            ],
          ],
        ),
      ),
    );
  }

  List<Widget> _buildArgon2Parameters(Map<String, dynamic> config) {
    return [
      _buildKDFSlider('Time Cost', config['time_cost'] ?? 3, 1, 1000, (v) => 
        setState(() => _kdfConfig['argon2']!['time_cost'] = v)),
      _buildKDFSlider('Memory (MB)', ((config['memory_cost'] ?? 65536) / 1024).round(), 1, 1024, (v) => 
        setState(() => _kdfConfig['argon2']!['memory_cost'] = v * 1024)),
      _buildKDFSlider('Parallelism', config['parallelism'] ?? 4, 1, 16, (v) => 
        setState(() => _kdfConfig['argon2']!['parallelism'] = v)),
      _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) => 
        setState(() => _kdfConfig['argon2']!['rounds'] = v)),
    ];
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
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainer,
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
              subtitle: const Text('Memory-hard function used in cryptocurrencies - good balance of security and performance'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['scrypt'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              dense: true,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ..._buildScryptParameters(config),
            ],
          ],
        ),
      ),
    );
  }

  List<Widget> _buildScryptParameters(Map<String, dynamic> config) {
    return [
      _buildKDFSlider('N (CPU/Memory)', (config['n'] ?? 16384) ~/ 1024, 1, 1024, (v) => 
        setState(() => _kdfConfig['scrypt']!['n'] = v * 1024)),
      _buildKDFSlider('R (Block Size)', config['r'] ?? 8, 1, 32, (v) => 
        setState(() => _kdfConfig['scrypt']!['r'] = v)),
      _buildKDFSlider('P (Parallelism)', config['p'] ?? 1, 1, 16, (v) => 
        setState(() => _kdfConfig['scrypt']!['p'] = v)),
      _buildKDFSlider('Rounds', config['rounds'] ?? 10, 0, 1000000, (v) => 
        setState(() => _kdfConfig['scrypt']!['rounds'] = v)),
    ];
  }

  /// Build HKDF configuration panel
  Widget _buildHKDFPanel() {
    final config = _kdfConfig['hkdf'] ?? {
      'enabled': false,
      'rounds': 1,
      'info': 'openssl_encrypt_hkdf',
    };
    final enabled = config['enabled'] ?? false;
    
    return Card(
      color: enabled ? Theme.of(context).colorScheme.tertiaryContainer : Theme.of(context).colorScheme.surfaceContainer,
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
              subtitle: const Text('HMAC-based Key Derivation Function - efficient key expansion, suitable for low-latency applications'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['hkdf'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              dense: true,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              _buildKDFSlider('Rounds', config['rounds'] ?? 1, 0, 1000000, (v) => 
                setState(() => _kdfConfig['hkdf']!['rounds'] = v)),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0),
                child: TextFormField(
                  initialValue: config['info'] ?? 'openssl_encrypt_hkdf',
                  decoration: const InputDecoration(
                    labelText: 'Info String',
                    isDense: true,
                  ),
                  style: const TextStyle(fontSize: 12),
                  onChanged: (value) {
                    _kdfConfig['hkdf']!['info'] = value;
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
      color: enabled ? Theme.of(context).colorScheme.errorContainer : Theme.of(context).colorScheme.surfaceContainer,
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
              subtitle: const Text('Newer memory-hard function with configurable time/space tradeoffs - still under academic evaluation'),
              value: enabled,
              onChanged: (bool? value) {
                setState(() {
                  _kdfConfig['balloon'] = Map.from(config)..['enabled'] = value ?? false;
                });
              },
              dense: true,
            ),
            if (enabled) ...[
              const SizedBox(height: 8),
              ..._buildBalloonParameters(config),
            ],
          ],
        ),
      ),
    );
  }

  List<Widget> _buildBalloonParameters(Map<String, dynamic> config) {
    return [
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
    ];
  }

  /// Helper to build KDF slider
  Widget _buildKDFSlider(String label, int value, int min, int max, Function(int) onChanged) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
      child: Row(
        children: [
          SizedBox(width: 80, child: Text('$label:', style: const TextStyle(fontSize: 11))),
          // Decrement button with auto-repeat
          _buildAutoRepeatButton(
            icon: Icons.remove,
            color: Colors.orange,
            enabled: value > min,
            onAction: () => onChanged((value - 1).clamp(min, max)),
            size: 22,
            iconSize: 11,
          ),
          const SizedBox(width: 4),
          // Slider
          Expanded(
            child: Slider(
              value: value.toDouble(),
              min: min.toDouble(),
              max: max.toDouble(),
              divisions: (max - min) > 1000 ? max ~/ 100 : max - min,
              label: value.toString(),
              onChanged: (double v) => onChanged(v.toInt()),
            ),
          ),
          const SizedBox(width: 4),
          // Increment button with auto-repeat
          _buildAutoRepeatButton(
            icon: Icons.add,
            color: Colors.orange,
            enabled: value < max,
            onAction: () => onChanged((value + 1).clamp(min, max)),
            size: 22,
            iconSize: 11,
          ),
          const SizedBox(width: 6),
          SizedBox(width: 40, child: Text(value.toString(), style: const TextStyle(fontSize: 11))),
        ],
      ),
    );
  }

  /// Build an auto-repeat button that continues action when held down
  Widget _buildAutoRepeatButton({
    required IconData icon,
    required MaterialColor color,
    required bool enabled,
    required VoidCallback onAction,
    double size = 32,
    double iconSize = 16,
  }) {
    return AutoRepeatButton(
      icon: icon,
      color: color,
      enabled: enabled,
      onAction: onAction,
      size: size,
      iconSize: iconSize,
    );
  }
}