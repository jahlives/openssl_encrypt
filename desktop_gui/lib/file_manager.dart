import 'dart:io';
import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path/path.dart' as path;
import 'cli_service.dart';

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

class FileInfo {
  final String name;
  final String path;
  final int size;
  final String extension;
  final DateTime lastModified;
  bool? _isEncrypted;

  FileInfo({
    required this.name,
    required this.path,
    required this.size,
    required this.extension,
    required this.lastModified,
  });

  String get sizeFormatted {
    if (size < 1024) return '$size B';
    if (size < 1024 * 1024) return '${(size / 1024).toStringAsFixed(1)} KB';
    if (size < 1024 * 1024 * 1024) return '${(size / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(size / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  /// Check if file contains valid OpenSSL Encrypt metadata
  Future<bool> get isEncrypted async {
    if (_isEncrypted != null) return _isEncrypted!;

    try {
      String? content;

      // Handle asset paths
      if (path.startsWith('assets/')) {
        try {
          content = await rootBundle.loadString(path);
        } catch (e) {
          CLIService.outputDebugLog('Failed to load asset $path: $e');
          _isEncrypted = false;
          return false;
        }
      } else {
        // Handle regular file paths
        // Security: Canonicalize path to prevent symlink attacks
        final canonicalPath = _canonicalizePath(path);
        final file = File(canonicalPath);
        if (!await file.exists()) {
          _isEncrypted = false;
          return false;
        }
        content = await file.readAsString();
      }

      // content is never null from readAsString(), so check removed

      // Check for CLI format: base64_metadata:base64_encrypted_data
      if (content.contains(':') && !content.contains('{')) {
        final parts = content.split(':');
        if (parts.length == 2) {
          try {
            // Try to decode the first part as base64 metadata
            final metadataBytes = base64Decode(parts[0]);
            final metadataJson = utf8.decode(metadataBytes);
            final metadata = jsonDecode(metadataJson);

            if (metadata is Map<String, dynamic>) {
              // Check for CLI format structures (V3, V4, V5)
              if (metadata.containsKey('format_version')) {
                final formatVersion = metadata['format_version'] as int?;
                if (formatVersion == 3) {
                  // V3 format: has format_version=3, salt, algorithm, hash_config at root level
                  if (metadata.containsKey('salt') &&
                      metadata.containsKey('algorithm') &&
                      metadata.containsKey('hash_config')) {
                    _isEncrypted = true;
                    return true;
                  }
                } else if (formatVersion == 4 || formatVersion == 5) {
                  // V4/V5 formats
                  _isEncrypted = true;
                  return true;
                }
              } else if (metadata.containsKey('derivation_config') ||
                         metadata.containsKey('encryption')) {
                // V5 specific structure without format_version
                _isEncrypted = true;
                return true;
              }
            }
          } catch (e) {
            // Not valid CLI format
          }
        }
      }

      // Check for JSON formats (mobile or test formats)
      try {
        final jsonData = jsonDecode(content);
        if (jsonData is Map<String, dynamic>) {
          // Check for mobile format
          if (jsonData.containsKey('format') &&
              jsonData['format'] == 'openssl_encrypt_mobile' &&
              jsonData.containsKey('encrypted_data') &&
              jsonData.containsKey('metadata')) {
            _isEncrypted = true;
            return true;
          }

          // Check for test JSON format (direct JSON with encrypted_data and metadata)
          if (jsonData.containsKey('encrypted_data') &&
              jsonData.containsKey('metadata')) {
            final metadata = jsonData['metadata'];
            if (metadata is Map<String, dynamic>) {
              if (metadata.containsKey('format_version') ||
                  metadata.containsKey('derivation_config')) {
                _isEncrypted = true;
                return true;
              }
            }
          }
        }
      } catch (e) {
        // Not JSON format
      }

    } catch (e) {
      CLIService.outputDebugLog('File encryption check failed: $e');
    }

    _isEncrypted = false;
    return false;
  }
}

class FileManager {
  /// Pick a single file for encryption/decryption
  Future<FileInfo?> pickFile({List<String>? allowedExtensions}) async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: allowedExtensions != null ? FileType.custom : FileType.any,
        allowedExtensions: allowedExtensions,
        allowMultiple: false,
        withData: false,
        withReadStream: false,
      );

      if (result != null && result.files.single.path != null) {
        final platformFile = result.files.first;
        // Security: Canonicalize path to prevent symlink attacks
        final canonicalPath = _canonicalizePath(platformFile.path!);
        final file = File(canonicalPath);
        final stat = await file.stat();

        return FileInfo(
          name: platformFile.name,
          path: canonicalPath,
          size: platformFile.size,
          extension: path.extension(platformFile.name).toLowerCase(),
          lastModified: stat.modified,
        );
      }
    } catch (e) {
      CLIService.outputDebugLog('Error picking file: $e');
    }
    return null;
  }

  /// Create FileInfo from a file path (for drag & drop support)
  Future<FileInfo?> createFileInfoFromPath(String filePath) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      final file = File(canonicalPath);
      if (!await file.exists()) {
        CLIService.outputDebugLog('File does not exist: $canonicalPath');
        return null;
      }

      final stat = await file.stat();
      final fileName = path.basename(canonicalPath);

      return FileInfo(
        name: fileName,
        path: canonicalPath,
        size: stat.size,
        extension: path.extension(fileName).toLowerCase(),
        lastModified: stat.modified,
      );
    } catch (e) {
      CLIService.outputDebugLog('Error creating FileInfo from path $filePath: $e');
      return null;
    }
  }

  /// Pick multiple files for batch operations
  Future<List<FileInfo>> pickMultipleFiles({List<String>? allowedExtensions}) async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: allowedExtensions != null ? FileType.custom : FileType.any,
        allowedExtensions: allowedExtensions,
        allowMultiple: true,
        withData: false,
      );

      if (result != null) {
        List<FileInfo> fileInfos = [];
        for (var platformFile in result.files) {
          if (platformFile.path != null) {
            // Security: Canonicalize path to prevent symlink attacks
            final canonicalPath = _canonicalizePath(platformFile.path!);
            final file = File(canonicalPath);
            final stat = await file.stat();

            fileInfos.add(FileInfo(
              name: platformFile.name,
              path: canonicalPath,
              size: platformFile.size,
              extension: path.extension(platformFile.name).toLowerCase(),
              lastModified: stat.modified,
            ));
          }
        }
        return fileInfos;
      }
    } catch (e) {
      CLIService.outputDebugLog('Error picking files: $e');
    }
    return [];
  }

  /// Read file contents as bytes
  Future<Uint8List?> readFileBytes(String filePath) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      final file = File(canonicalPath);
      if (await file.exists()) {
        return await file.readAsBytes();
      }
    } catch (e) {
      CLIService.outputDebugLog('Error reading file: $e');
    }
    return null;
  }

  /// Read file contents as string (for text files)
  Future<String?> readFileText(String filePath) async {
    try {
      // Check if it's an asset path
      if (filePath.startsWith('assets/')) {
        return await rootBundle.loadString(filePath);
      }

      // Regular file system path - Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      final file = File(canonicalPath);
      if (await file.exists()) {
        return await file.readAsString();
      }
    } catch (e) {
      CLIService.outputDebugLog('Error reading text file: $e');
    }
    return null;
  }

  /// Write bytes to file
  Future<bool> writeFileBytes(String filePath, Uint8List data) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      final file = File(canonicalPath);
      await file.writeAsBytes(data);
      return true;
    } catch (e) {
      CLIService.outputDebugLog('Error writing file: $e');
      return false;
    }
  }

  /// Write string to file
  Future<bool> writeFileText(String filePath, String content) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      final file = File(canonicalPath);
      await file.writeAsString(content);
      return true;
    } catch (e) {
      CLIService.outputDebugLog('Error writing text file: $e');
      return false;
    }
  }

  /// Get save location for encrypted/decrypted file
  Future<String?> getSaveLocation({
    String? suggestedName,
    String? fileExtension,
  }) async {
    try {
      String? outputFile = await FilePicker.platform.saveFile(
        dialogTitle: 'Save File',
        fileName: suggestedName,
        type: FileType.any,
        allowedExtensions: fileExtension != null ? [fileExtension] : null,
      );
      return outputFile;
    } catch (e) {
      CLIService.outputDebugLog('Error getting save location: $e');
    }
    return null;
  }

  /// Generate output file name for encryption
  String getEncryptedFileName(String originalPath) {
    final baseName = path.basenameWithoutExtension(originalPath);
    final dir = path.dirname(originalPath);
    return path.join(dir, '$baseName.enc');
  }

  /// Generate output file name for decryption
  String getDecryptedFileName(String encryptedPath) {
    String baseName = path.basenameWithoutExtension(encryptedPath);
    final dir = path.dirname(encryptedPath);

    // Remove .enc extension if present
    if (baseName.endsWith('.enc')) {
      baseName = baseName.substring(0, baseName.length - 4);
    }

    return path.join(dir, '$baseName.decrypted');
  }

  /// Check if file exists
  Future<bool> fileExists(String filePath) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      return await File(canonicalPath).exists();
    } catch (e) {
      return false;
    }
  }

  /// Delete file securely
  Future<bool> deleteFile(String filePath) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      final file = File(canonicalPath);
      if (await file.exists()) {
        await file.delete();
        return true;
      }
      return false;
    } catch (e) {
      CLIService.outputDebugLog('Error deleting file: $e');
      return false;
    }
  }

  /// Get file mime type based on extension
  String getMimeType(String fileName) {
    final ext = path.extension(fileName).toLowerCase();
    switch (ext) {
      case '.txt':
        return 'text/plain';
      case '.pdf':
        return 'application/pdf';
      case '.jpg':
      case '.jpeg':
        return 'image/jpeg';
      case '.png':
        return 'image/png';
      case '.doc':
        return 'application/msword';
      case '.docx':
        return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      case '.zip':
        return 'application/zip';
      case '.enc':
        return 'application/x-encrypted';
      default:
        return 'application/octet-stream';
    }
  }
}
