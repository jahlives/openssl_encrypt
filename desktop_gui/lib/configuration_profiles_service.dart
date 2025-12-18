import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'cli_service.dart';

/// Service for managing configuration profiles
class ConfigurationProfilesService {
  static const String _profilesKey = 'configuration_profiles';
  static const String _activeProfileKey = 'active_profile';

  /// Get all saved configuration profiles
  static Future<Map<String, ConfigurationProfile>> getProfiles() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final profilesJson = prefs.getString(_profilesKey);

      if (profilesJson == null) {
        return {};
      }

      final profilesData = jsonDecode(profilesJson) as Map<String, dynamic>;
      final profiles = <String, ConfigurationProfile>{};

      for (final entry in profilesData.entries) {
        try {
          profiles[entry.key] = ConfigurationProfile.fromJson(entry.value);
        } catch (e) {
          CLIService.outputDebugLog('Failed to parse profile ${entry.key}: $e');
        }
      }

      return profiles;
    } catch (e) {
      CLIService.outputDebugLog('Failed to load configuration profiles: $e');
      return {};
    }
  }

  /// Save a configuration profile
  static Future<bool> saveProfile(String name, ConfigurationProfile profile) async {
    try {
      final profiles = await getProfiles();
      profiles[name] = profile;

      final prefs = await SharedPreferences.getInstance();
      final profilesJson = jsonEncode(profiles.map((key, value) => MapEntry(key, value.toJson())));

      final success = await prefs.setString(_profilesKey, profilesJson);

      if (success) {
        CLIService.outputDebugLog('Saved configuration profile: $name');
      }

      return success;
    } catch (e) {
      CLIService.outputDebugLog('Failed to save configuration profile $name: $e');
      return false;
    }
  }

  /// Delete a configuration profile
  static Future<bool> deleteProfile(String name) async {
    try {
      final profiles = await getProfiles();
      profiles.remove(name);

      final prefs = await SharedPreferences.getInstance();
      final profilesJson = jsonEncode(profiles.map((key, value) => MapEntry(key, value.toJson())));

      final success = await prefs.setString(_profilesKey, profilesJson);

      // If the active profile was deleted, clear it
      if (success && await getActiveProfileName() == name) {
        await setActiveProfile(null);
      }

      if (success) {
        CLIService.outputDebugLog('Deleted configuration profile: $name');
      }

      return success;
    } catch (e) {
      CLIService.outputDebugLog('Failed to delete configuration profile $name: $e');
      return false;
    }
  }

  /// Rename a configuration profile
  static Future<bool> renameProfile(String oldName, String newName) async {
    try {
      final profiles = await getProfiles();
      if (!profiles.containsKey(oldName) || profiles.containsKey(newName)) {
        return false;
      }

      final profile = profiles[oldName]!;
      profiles.remove(oldName);
      profiles[newName] = profile;

      final prefs = await SharedPreferences.getInstance();
      final profilesJson = jsonEncode(profiles.map((key, value) => MapEntry(key, value.toJson())));

      final success = await prefs.setString(_profilesKey, profilesJson);

      // Update active profile name if necessary
      if (success && await getActiveProfileName() == oldName) {
        await setActiveProfile(newName);
      }

      if (success) {
        CLIService.outputDebugLog('Renamed configuration profile: $oldName -> $newName');
      }

      return success;
    } catch (e) {
      CLIService.outputDebugLog('Failed to rename configuration profile $oldName to $newName: $e');
      return false;
    }
  }

  /// Set the active profile
  static Future<bool> setActiveProfile(String? profileName) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final bool success;

      if (profileName == null) {
        success = await prefs.remove(_activeProfileKey);
      } else {
        success = await prefs.setString(_activeProfileKey, profileName);
      }

      if (success) {
        CLIService.outputDebugLog('Set active profile: ${profileName ?? 'none'}');
      }

      return success;
    } catch (e) {
      CLIService.outputDebugLog('Failed to set active profile: $e');
      return false;
    }
  }

  /// Get the name of the currently active profile
  static Future<String?> getActiveProfileName() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      return prefs.getString(_activeProfileKey);
    } catch (e) {
      CLIService.outputDebugLog('Failed to get active profile: $e');
      return null;
    }
  }

  /// Get the currently active profile
  static Future<ConfigurationProfile?> getActiveProfile() async {
    try {
      final profileName = await getActiveProfileName();
      if (profileName == null) return null;

      final profiles = await getProfiles();
      return profiles[profileName];
    } catch (e) {
      CLIService.outputDebugLog('Failed to get active profile: $e');
      return null;
    }
  }

  /// Export profiles to JSON string
  static Future<String?> exportProfiles() async {
    try {
      final profiles = await getProfiles();
      final exportData = {
        'version': 1,
        'exported_at': DateTime.now().toIso8601String(),
        'profiles': profiles.map((key, value) => MapEntry(key, value.toJson())),
      };

      return jsonEncode(exportData);
    } catch (e) {
      CLIService.outputDebugLog('Failed to export profiles: $e');
      return null;
    }
  }

  /// Import profiles from JSON string
  static Future<bool> importProfiles(String jsonData, {bool overwrite = false}) async {
    try {
      final importData = jsonDecode(jsonData) as Map<String, dynamic>;

      if (importData['version'] != 1) {
        throw Exception('Unsupported profile format version');
      }

      final importedProfiles = <String, ConfigurationProfile>{};
      final profilesData = importData['profiles'] as Map<String, dynamic>;

      for (final entry in profilesData.entries) {
        importedProfiles[entry.key] = ConfigurationProfile.fromJson(entry.value);
      }

      final existingProfiles = await getProfiles();

      if (overwrite) {
        // Replace all profiles
        final prefs = await SharedPreferences.getInstance();
        final profilesJson = jsonEncode(importedProfiles.map((key, value) => MapEntry(key, value.toJson())));
        final success = await prefs.setString(_profilesKey, profilesJson);

        if (success) {
          CLIService.outputDebugLog('Imported ${importedProfiles.length} profiles (overwrite)');
        }

        return success;
      } else {
        // Merge with existing profiles (skip duplicates)
        int importedCount = 0;
        for (final entry in importedProfiles.entries) {
          if (!existingProfiles.containsKey(entry.key)) {
            existingProfiles[entry.key] = entry.value;
            importedCount++;
          }
        }

        final prefs = await SharedPreferences.getInstance();
        final profilesJson = jsonEncode(existingProfiles.map((key, value) => MapEntry(key, value.toJson())));
        final success = await prefs.setString(_profilesKey, profilesJson);

        if (success) {
          CLIService.outputDebugLog('Imported $importedCount new profiles (merge)');
        }

        return success;
      }
    } catch (e) {
      CLIService.outputDebugLog('Failed to import profiles: $e');
      return false;
    }
  }

  /// Create default profiles
  static Future<bool> createDefaultProfiles() async {
    try {
      final profiles = <String, ConfigurationProfile>{
        'Quick Encryption': ConfigurationProfile(
          algorithm: 'fernet',
          hashConfig: {},
          kdfConfig: {},
          description: 'Fast encryption with minimal configuration',
        ),
        'High Security': ConfigurationProfile(
          algorithm: 'aes-gcm',
          hashConfig: {
            'sha512': {'enabled': true, 'rounds': 1000},
          },
          kdfConfig: {
            'argon2': {
              'enabled': true,
              'time_cost': 3,
              'memory_cost': 65536,
              'parallelism': 4,
              'hash_len': 32,
              'type': 2, // Argon2id
              'rounds': 1,
            },
            'randomx': {'enabled': false, 'rounds': 1, 'mode': 'light', 'height': 1, 'hash_len': 32},
          },
          description: 'Maximum security with Argon2id and SHA-512',
        ),
        'Post-Quantum': ConfigurationProfile(
          algorithm: 'ml-kem-768-hybrid',
          hashConfig: {
            'blake3': {'enabled': true, 'rounds': 1},
          },
          kdfConfig: {
            'hkdf': {
              'enabled': true,
              'rounds': 1,
              'algorithm': 'sha256',
              'info': 'pqc-encryption',
            },
            'randomx': {'enabled': false, 'rounds': 1, 'mode': 'light', 'height': 1, 'hash_len': 32},
          },
          description: 'Future-proof encryption with ML-KEM',
        ),
        'Balanced Performance': ConfigurationProfile(
          algorithm: 'chacha20-poly1305',
          hashConfig: {
            'blake2b': {'enabled': true, 'rounds': 1},
          },
          kdfConfig: {
            'scrypt': {
              'enabled': true,
              'n': 32768,
              'r': 8,
              'p': 1,
              'rounds': 1,
            },
            'randomx': {'enabled': false, 'rounds': 1, 'mode': 'light', 'height': 1, 'hash_len': 32},
          },
          description: 'Good balance of security and performance',
        ),
      };

      bool allSaved = true;
      for (final entry in profiles.entries) {
        final saved = await saveProfile(entry.key, entry.value);
        if (!saved) allSaved = false;
      }

      return allSaved;
    } catch (e) {
      CLIService.outputDebugLog('Failed to create default profiles: $e');
      return false;
    }
  }
}

/// Configuration profile data class
class ConfigurationProfile {
  final String algorithm;
  final Map<String, Map<String, dynamic>> hashConfig;
  final Map<String, Map<String, dynamic>> kdfConfig;
  final String description;
  final DateTime createdAt;
  final DateTime updatedAt;

  ConfigurationProfile({
    required this.algorithm,
    required this.hashConfig,
    required this.kdfConfig,
    required this.description,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) : createdAt = createdAt ?? DateTime.now(),
       updatedAt = updatedAt ?? DateTime.now();

  /// Create from JSON
  factory ConfigurationProfile.fromJson(Map<String, dynamic> json) {
    return ConfigurationProfile(
      algorithm: json['algorithm'] as String,
      hashConfig: Map<String, Map<String, dynamic>>.from(
        (json['hash_config'] as Map<String, dynamic>).map(
          (key, value) => MapEntry(key, Map<String, dynamic>.from(value)),
        ),
      ),
      kdfConfig: Map<String, Map<String, dynamic>>.from(
        (json['kdf_config'] as Map<String, dynamic>).map(
          (key, value) => MapEntry(key, Map<String, dynamic>.from(value)),
        ),
      ),
      description: json['description'] as String,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
    );
  }

  /// Convert to JSON
  Map<String, dynamic> toJson() {
    return {
      'algorithm': algorithm,
      'hash_config': hashConfig,
      'kdf_config': kdfConfig,
      'description': description,
      'created_at': createdAt.toIso8601String(),
      'updated_at': updatedAt.toIso8601String(),
    };
  }

  /// Create a copy with updated fields
  ConfigurationProfile copyWith({
    String? algorithm,
    Map<String, Map<String, dynamic>>? hashConfig,
    Map<String, Map<String, dynamic>>? kdfConfig,
    String? description,
  }) {
    return ConfigurationProfile(
      algorithm: algorithm ?? this.algorithm,
      hashConfig: hashConfig ?? this.hashConfig,
      kdfConfig: kdfConfig ?? this.kdfConfig,
      description: description ?? this.description,
      createdAt: createdAt,
      updatedAt: DateTime.now(),
    );
  }

  /// Get a summary of the configuration
  String getSummary() {
    final parts = <String>[algorithm.toUpperCase()];

    final enabledHash = hashConfig.entries.where((e) => e.value['enabled'] == true);
    if (enabledHash.isNotEmpty) {
      parts.add('Hash: ${enabledHash.map((e) => e.key.toUpperCase()).join(', ')}');
    }

    final enabledKdf = kdfConfig.entries.where((e) => e.value['enabled'] == true);
    if (enabledKdf.isNotEmpty) {
      parts.add('KDF: ${enabledKdf.map((e) => e.key.toUpperCase()).join(', ')}');
    }

    return parts.join(' • ');
  }
}
