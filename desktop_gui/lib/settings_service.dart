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

  // Keyserver network plugin settings
  static const String _keyserverEnabledKey = 'keyserver_enabled';
  static const String _keyserverUrlKey = 'keyserver_url';
  static const String _keyserverCacheTtlKey = 'keyserver_cache_ttl_hours';
  static const String _keyserverUploadEnabledKey = 'keyserver_upload_enabled';

  // Remote Pepper network plugin settings
  static const String _pepperEnabledKey = 'pepper_enabled';
  static const String _pepperServerUrlKey = 'pepper_server_url';
  static const String _pepperClientCertPathKey = 'pepper_client_cert_path';
  static const String _pepperClientKeyPathKey = 'pepper_client_key_path';
  static const String _pepperCaCertPathKey = 'pepper_ca_cert_path';
  static const String _pepperClientCertPemKey = 'pepper_client_cert_pem';
  static const String _pepperClientKeyPemKey = 'pepper_client_key_pem';
  static const String _pepperCaCertPemKey = 'pepper_ca_cert_pem';
  static const String _pepperCertModeKey = 'pepper_cert_mode'; // 'file' or 'pem'

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
  // Network Plugins - Keyserver
  // =============================================================================

  /// Get keyserver enabled state
  static bool getKeyserverEnabled() {
    return prefs.getBool(_keyserverEnabledKey) ?? false;
  }

  /// Set keyserver enabled state
  static Future<bool> setKeyserverEnabled(bool enabled) {
    return prefs.setBool(_keyserverEnabledKey, enabled);
  }

  /// Get keyserver URL
  static String getKeyserverUrl() {
    return prefs.getString(_keyserverUrlKey) ?? 'https://keys.openssl-encrypt.org';
  }

  /// Set keyserver URL
  static Future<bool> setKeyserverUrl(String url) {
    return prefs.setString(_keyserverUrlKey, url);
  }

  /// Get keyserver cache TTL in hours
  static int getKeyserverCacheTtl() {
    return prefs.getInt(_keyserverCacheTtlKey) ?? 24;
  }

  /// Set keyserver cache TTL in hours
  static Future<bool> setKeyserverCacheTtl(int hours) {
    return prefs.setInt(_keyserverCacheTtlKey, hours);
  }

  /// Get keyserver upload enabled state
  static bool getKeyserverUploadEnabled() {
    return prefs.getBool(_keyserverUploadEnabledKey) ?? true;
  }

  /// Set keyserver upload enabled state
  static Future<bool> setKeyserverUploadEnabled(bool enabled) {
    return prefs.setBool(_keyserverUploadEnabledKey, enabled);
  }

  // =============================================================================
  // Network Plugins - Remote Pepper
  // =============================================================================

  /// Get pepper enabled state
  static bool getPepperEnabled() {
    return prefs.getBool(_pepperEnabledKey) ?? false;
  }

  /// Set pepper enabled state
  static Future<bool> setPepperEnabled(bool enabled) {
    return prefs.setBool(_pepperEnabledKey, enabled);
  }

  /// Get pepper server URL
  static String getPepperServerUrl() {
    return prefs.getString(_pepperServerUrlKey) ?? 'https://pepper.openssl-encrypt.org';
  }

  /// Set pepper server URL
  static Future<bool> setPepperServerUrl(String url) {
    return prefs.setString(_pepperServerUrlKey, url);
  }

  /// Get pepper certificate mode ('file' or 'pem')
  static String getPepperCertMode() {
    return prefs.getString(_pepperCertModeKey) ?? 'file';
  }

  /// Set pepper certificate mode
  static Future<bool> setPepperCertMode(String mode) {
    return prefs.setString(_pepperCertModeKey, mode);
  }

  /// Get pepper client certificate file path
  static String? getPepperClientCertPath() {
    return prefs.getString(_pepperClientCertPathKey);
  }

  /// Set pepper client certificate file path
  static Future<bool> setPepperClientCertPath(String? path) {
    if (path == null) {
      return prefs.remove(_pepperClientCertPathKey);
    }
    return prefs.setString(_pepperClientCertPathKey, path);
  }

  /// Get pepper client key file path
  static String? getPepperClientKeyPath() {
    return prefs.getString(_pepperClientKeyPathKey);
  }

  /// Set pepper client key file path
  static Future<bool> setPepperClientKeyPath(String? path) {
    if (path == null) {
      return prefs.remove(_pepperClientKeyPathKey);
    }
    return prefs.setString(_pepperClientKeyPathKey, path);
  }

  /// Get pepper CA certificate file path
  static String? getPepperCaCertPath() {
    return prefs.getString(_pepperCaCertPathKey);
  }

  /// Set pepper CA certificate file path
  static Future<bool> setPepperCaCertPath(String? path) {
    if (path == null) {
      return prefs.remove(_pepperCaCertPathKey);
    }
    return prefs.setString(_pepperCaCertPathKey, path);
  }

  /// Get pepper client certificate PEM content
  static String? getPepperClientCertPem() {
    return prefs.getString(_pepperClientCertPemKey);
  }

  /// Set pepper client certificate PEM content
  static Future<bool> setPepperClientCertPem(String? pem) {
    if (pem == null) {
      return prefs.remove(_pepperClientCertPemKey);
    }
    return prefs.setString(_pepperClientCertPemKey, pem);
  }

  /// Get pepper client key PEM content
  static String? getPepperClientKeyPem() {
    return prefs.getString(_pepperClientKeyPemKey);
  }

  /// Set pepper client key PEM content
  static Future<bool> setPepperClientKeyPem(String? pem) {
    if (pem == null) {
      return prefs.remove(_pepperClientKeyPemKey);
    }
    return prefs.setString(_pepperClientKeyPemKey, pem);
  }

  /// Get pepper CA certificate PEM content
  static String? getPepperCaCertPem() {
    return prefs.getString(_pepperCaCertPemKey);
  }

  /// Set pepper CA certificate PEM content
  static Future<bool> setPepperCaCertPem(String? pem) {
    if (pem == null) {
      return prefs.remove(_pepperCaCertPemKey);
    }
    return prefs.setString(_pepperCaCertPemKey, pem);
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
        _keyserverEnabledKey,
        _keyserverUrlKey,
        _keyserverCacheTtlKey,
        _keyserverUploadEnabledKey,
        _pepperEnabledKey,
        _pepperServerUrlKey,
        _pepperClientCertPathKey,
        _pepperClientKeyPathKey,
        _pepperCaCertPathKey,
        _pepperClientCertPemKey,
        _pepperClientKeyPemKey,
        _pepperCaCertPemKey,
        _pepperCertModeKey,
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
        } else if (key == _keyserverUrlKey || key == _pepperServerUrlKey) {
          if (value is! String || value.length > 500 || !value.startsWith('http')) {
            throw ArgumentError('Invalid server URL for $key: $value');
          }
          await prefs.setString(key, value);
        } else if ([_pepperClientCertPathKey, _pepperClientKeyPathKey, _pepperCaCertPathKey].contains(key)) {
          if (value != null && (value is! String || value.length > 1000)) {
            throw ArgumentError('Invalid file path for $key: $value');
          }
          if (value == null) {
            await prefs.remove(key);
          } else {
            await prefs.setString(key, value);
          }
        } else if ([_pepperClientCertPemKey, _pepperClientKeyPemKey, _pepperCaCertPemKey].contains(key)) {
          if (value != null && (value is! String || value.length > 50000)) {
            throw ArgumentError('Invalid PEM content for $key: $value');
          }
          if (value == null) {
            await prefs.remove(key);
          } else {
            await prefs.setString(key, value);
          }
        } else if (key == _pepperCertModeKey) {
          if (value is! String || !['file', 'pem'].contains(value)) {
            throw ArgumentError('Invalid cert mode: $value');
          }
          await prefs.setString(key, value);
        } else if ([_autoSaveSettingsKey, _showAdvancedOptionsKey, _confirmDangerousActionsKey,
                   _debugModeKey, _windowMaximizedKey, _keyserverEnabledKey, _keyserverUploadEnabledKey, _pepperEnabledKey].contains(key)) {
          if (value is! bool) {
            throw ArgumentError('Invalid boolean value for $key: $value');
          }
          await prefs.setBool(key, value);
        } else if ([_maxRecentFilesKey, _windowWidthKey, _windowHeightKey, _keyserverCacheTtlKey].contains(key)) {
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
