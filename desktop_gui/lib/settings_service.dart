import 'package:shared_preferences/shared_preferences.dart';

/// Service for managing application settings and preferences
class SettingsService {
  static SharedPreferences? _prefs;

  // Settings keys
  static const String _themeKey = 'theme_mode';
  static const String _defaultAlgorithmKey = 'default_algorithm';
  static const String _defaultSecurityLevelKey = 'default_security_level';
  static const String _autoSaveSettingsKey = 'auto_save_settings';
  static const String _showAdvancedOptionsKey = 'show_advanced_options';
  static const String _confirmDangerousActionsKey = 'confirm_dangerous_actions';
  static const String _debugModeKey = 'debug_mode';
  static const String _maxRecentFilesKey = 'max_recent_files';
  static const String _defaultOutputFormatKey = 'default_output_format';
  static const String _windowMaximizedKey = 'window_maximized';
  static const String _windowWidthKey = 'window_width';
  static const String _windowHeightKey = 'window_height';

  /// Initialize the settings service
  static Future<void> initialize() async {
    _prefs = await SharedPreferences.getInstance();
  }

  /// Get SharedPreferences instance (ensure initialize() was called first)
  static SharedPreferences get prefs {
    if (_prefs == null) {
      throw StateError('SettingsService not initialized. Call SettingsService.initialize() first.');
    }
    return _prefs!;
  }

  // =============================================================================
  // Theme Settings
  // =============================================================================

  /// Get theme mode (light, dark, system)
  static String getThemeMode() {
    return prefs.getString(_themeKey) ?? 'system';
  }

  /// Set theme mode
  static Future<bool> setThemeMode(String themeMode) {
    return prefs.setString(_themeKey, themeMode);
  }

  // =============================================================================
  // Cryptographic Defaults
  // =============================================================================

  /// Get default encryption algorithm
  static String getDefaultAlgorithm() {
    return prefs.getString(_defaultAlgorithmKey) ?? 'fernet';
  }

  /// Set default encryption algorithm
  static Future<bool> setDefaultAlgorithm(String algorithm) {
    return prefs.setString(_defaultAlgorithmKey, algorithm);
  }

  /// Get default security level (quick, standard, paranoid)
  static String getDefaultSecurityLevel() {
    return prefs.getString(_defaultSecurityLevelKey) ?? 'standard';
  }

  /// Set default security level
  static Future<bool> setDefaultSecurityLevel(String level) {
    return prefs.setString(_defaultSecurityLevelKey, level);
  }

  // =============================================================================
  // Application Behavior
  // =============================================================================

  /// Get auto-save settings preference
  static bool getAutoSaveSettings() {
    return prefs.getBool(_autoSaveSettingsKey) ?? true;
  }

  /// Set auto-save settings preference
  static Future<bool> setAutoSaveSettings(bool enabled) {
    return prefs.setBool(_autoSaveSettingsKey, enabled);
  }

  /// Get show advanced options preference
  static bool getShowAdvancedOptions() {
    return prefs.getBool(_showAdvancedOptionsKey) ?? false;
  }

  /// Set show advanced options preference
  static Future<bool> setShowAdvancedOptions(bool enabled) {
    return prefs.setBool(_showAdvancedOptionsKey, enabled);
  }

  /// Get confirm dangerous actions preference
  static bool getConfirmDangerousActions() {
    return prefs.getBool(_confirmDangerousActionsKey) ?? true;
  }

  /// Set confirm dangerous actions preference
  static Future<bool> setConfirmDangerousActions(bool enabled) {
    return prefs.setBool(_confirmDangerousActionsKey, enabled);
  }

  /// Get debug mode preference
  static bool getDebugMode() {
    return prefs.getBool(_debugModeKey) ?? false;
  }

  /// Set debug mode preference
  static Future<bool> setDebugMode(bool enabled) {
    return prefs.setBool(_debugModeKey, enabled);
  }

  /// Get maximum recent files to keep
  static int getMaxRecentFiles() {
    return prefs.getInt(_maxRecentFilesKey) ?? 10;
  }

  /// Set maximum recent files to keep
  static Future<bool> setMaxRecentFiles(int count) {
    return prefs.setInt(_maxRecentFilesKey, count);
  }

  /// Get default output format (base64, hex, binary)
  static String getDefaultOutputFormat() {
    return prefs.getString(_defaultOutputFormatKey) ?? 'base64';
  }

  /// Set default output format
  static Future<bool> setDefaultOutputFormat(String format) {
    return prefs.setString(_defaultOutputFormatKey, format);
  }

  // =============================================================================
  // Window State
  // =============================================================================

  /// Get window maximized state
  static bool getWindowMaximized() {
    return prefs.getBool(_windowMaximizedKey) ?? false;
  }

  /// Set window maximized state
  static Future<bool> setWindowMaximized(bool maximized) {
    return prefs.setBool(_windowMaximizedKey, maximized);
  }

  /// Get window width
  static double getWindowWidth() {
    return prefs.getDouble(_windowWidthKey) ?? 1200.0;
  }

  /// Set window width
  static Future<bool> setWindowWidth(double width) {
    return prefs.setDouble(_windowWidthKey, width);
  }

  /// Get window height
  static double getWindowHeight() {
    return prefs.getDouble(_windowHeightKey) ?? 800.0;
  }

  /// Set window height
  static Future<bool> setWindowHeight(double height) {
    return prefs.setDouble(_windowHeightKey, height);
  }

  // =============================================================================
  // Utility Methods
  // =============================================================================

  /// Reset all settings to defaults
  static Future<bool> resetToDefaults() async {
    return await prefs.clear();
  }

  /// Export settings as JSON string
  static Map<String, dynamic> exportSettings() {
    final allKeys = prefs.getKeys();
    final settings = <String, dynamic>{};

    for (final key in allKeys) {
      final value = prefs.get(key);
      settings[key] = value;
    }

    return settings;
  }

  /// Import settings from JSON map with security validation
  static Future<bool> importSettings(Map<String, dynamic> settings) async {
    try {
      // Security: Define allowed settings keys to prevent configuration injection
      final allowedKeys = {
        _themeKey,
        _defaultAlgorithmKey,
        _defaultSecurityLevelKey,
        _autoSaveSettingsKey,
        _showAdvancedOptionsKey,
        _confirmDangerousActionsKey,
        _debugModeKey,
        _maxRecentFilesKey,
        _defaultOutputFormatKey,
        _windowMaximizedKey,
        _windowWidthKey,
        _windowHeightKey,
      };

      // Security: Validate settings schema and values
      for (final entry in settings.entries) {
        final key = entry.key;
        final value = entry.value;

        // Security: Only allow known configuration keys
        if (!allowedKeys.contains(key)) {
          throw ArgumentError('Invalid configuration key: $key');
        }

        // Security: Validate value types and constraints
        if (key == _themeKey) {
          if (value is! String || !['light', 'dark', 'system'].contains(value)) {
            throw ArgumentError('Invalid theme mode: $value');
          }
          await prefs.setString(key, value);
        } else if (key == _defaultAlgorithmKey) {
          if (value is! String || value.length > 50) {
            throw ArgumentError('Invalid algorithm name: $value');
          }
          await prefs.setString(key, value);
        } else if (key == _defaultSecurityLevelKey) {
          if (value is! String || !['quick', 'standard', 'paranoid'].contains(value)) {
            throw ArgumentError('Invalid security level: $value');
          }
          await prefs.setString(key, value);
        } else if (key == _defaultOutputFormatKey) {
          if (value is! String || value.length > 20) {
            throw ArgumentError('Invalid output format: $value');
          }
          await prefs.setString(key, value);
        } else if ([_autoSaveSettingsKey, _showAdvancedOptionsKey, _confirmDangerousActionsKey,
                   _debugModeKey, _windowMaximizedKey].contains(key)) {
          if (value is! bool) {
            throw ArgumentError('Invalid boolean value for $key: $value');
          }
          await prefs.setBool(key, value);
        } else if ([_maxRecentFilesKey, _windowWidthKey, _windowHeightKey].contains(key)) {
          if (value is! int || value < 0 || value > 10000) {
            throw ArgumentError('Invalid integer value for $key: $value');
          }
          await prefs.setInt(key, value);
        }
      }
      return true;
    } catch (e) {
      print('Settings import validation failed: $e');
      return false;
    }
  }

  /// Get setting value by key with fallback
  static T? getSetting<T>(String key, [T? defaultValue]) {
    final value = prefs.get(key);
    return value is T ? value : defaultValue;
  }

  /// Set setting value by key
  static Future<bool> setSetting<T>(String key, T value) {
    if (value is String) {
      return prefs.setString(key, value);
    } else if (value is bool) {
      return prefs.setBool(key, value);
    } else if (value is int) {
      return prefs.setInt(key, value);
    } else if (value is double) {
      return prefs.setDouble(key, value);
    } else if (value is List<String>) {
      return prefs.setStringList(key, value);
    } else {
      throw ArgumentError('Unsupported setting type: $T');
    }
  }
}
