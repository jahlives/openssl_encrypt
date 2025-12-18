import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'package:file_picker/file_picker.dart';
import 'package:path/path.dart' as path;

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
      final file = File(path);
      if (!await file.exists()) {
        _isEncrypted = false;
        return false;
      }

      final content = await file.readAsString();

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
              // Check for CLI format version 5 structure
              if (metadata.containsKey('format_version') ||
                  metadata.containsKey('derivation_config') ||
                  metadata.containsKey('encryption')) {
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
      print('File encryption check failed: $e');
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
        final file = File(platformFile.path!);
        final stat = await file.stat();

        return FileInfo(
          name: platformFile.name,
          path: platformFile.path!,
          size: platformFile.size,
          extension: path.extension(platformFile.name).toLowerCase(),
          lastModified: stat.modified,
        );
      }
    } catch (e) {
      print('Error picking file: $e');
    }
    return null;
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
            final file = File(platformFile.path!);
            final stat = await file.stat();

            fileInfos.add(FileInfo(
              name: platformFile.name,
              path: platformFile.path!,
              size: platformFile.size,
              extension: path.extension(platformFile.name).toLowerCase(),
              lastModified: stat.modified,
            ));
          }
        }
        return fileInfos;
      }
    } catch (e) {
      print('Error picking files: $e');
    }
    return [];
  }

  /// Read file contents as bytes
  Future<Uint8List?> readFileBytes(String filePath) async {
    try {
      final file = File(filePath);
      if (await file.exists()) {
        return await file.readAsBytes();
      }
    } catch (e) {
      print('Error reading file: $e');
    }
    return null;
  }

  /// Read file contents as string (for text files)
  Future<String?> readFileText(String filePath) async {
    try {
      final file = File(filePath);
      if (await file.exists()) {
        return await file.readAsString();
      }
    } catch (e) {
      print('Error reading text file: $e');
    }
    return null;
  }

  /// Write bytes to file
  Future<bool> writeFileBytes(String filePath, Uint8List data) async {
    try {
      final file = File(filePath);
      await file.writeAsBytes(data);
      return true;
    } catch (e) {
      print('Error writing file: $e');
      return false;
    }
  }

  /// Write string to file
  Future<bool> writeFileText(String filePath, String content) async {
    try {
      final file = File(filePath);
      await file.writeAsString(content);
      return true;
    } catch (e) {
      print('Error writing text file: $e');
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
      print('Error getting save location: $e');
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
      return await File(filePath).exists();
    } catch (e) {
      return false;
    }
  }

  /// Delete file securely
  Future<bool> deleteFile(String filePath) async {
    try {
      final file = File(filePath);
      if (await file.exists()) {
        await file.delete();
        return true;
      }
      return false;
    } catch (e) {
      print('Error deleting file: $e');
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
