import 'dart:io';
import 'dart:convert';
import 'dart:math';
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
              // Check for CLI format structures (V3-V8)
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
                } else if (formatVersion != null && formatVersion >= 4 && formatVersion <= 8) {
                  // V4-V8 formats (current range: 4, 5, 6, 7, 8)
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
  /// Pick a directory (for identity store, etc.)
  Future<String?> pickDirectory() async {
    try {
      String? selectedDirectory = await FilePicker.platform.getDirectoryPath(
        dialogTitle: 'Select Directory',
      );
      if (selectedDirectory != null) {
        // Security: Canonicalize path to prevent symlink attacks
        return _canonicalizePath(selectedDirectory);
      }
    } catch (e) {
      CLIService.outputDebugLog('Error picking directory: $e');
    }
    return null;
  }

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

  /// True if [path] is owner-only on POSIX (no group/other permission bits).
  /// Windows uses per-user ACLs, so returns true there.
  bool _isOwnerOnly(String targetPath) {
    if (Platform.isWindows) return true;
    try {
      final m = File(targetPath).statSync().mode & 0x1FF;
      return (m & 0x3F) == 0; // no group (0o070) / other (0o007) bits
    } catch (_) {
      return false; // cannot verify -> fail closed
    }
  }

  /// Create [file] as a FRESH 0600 inode (POSIX), never reusing an existing one.
  /// `install -m 600 /dev/null` (same primitive as cli_service) sets the mode at
  /// creation, so there is no world-readable window and no pre-existing inode an
  /// attacker could hold an open fd to.
  Future<void> _create0600(File file) async {
    if (!Platform.isWindows) {
      try {
        final r = await Process.run('install', ['-m', '600', '/dev/null', file.path]);
        if (r.exitCode == 0) return;
      } catch (_) {}
    }
    // Fallback (Windows / no `install`): create then best-effort chmod.
    try {
      if (await file.exists()) await file.delete();
    } catch (_) {}
    await file.create(recursive: true);
    if (!Platform.isWindows) {
      try {
        await Process.run('chmod', ['600', file.path]);
      } catch (_) {}
    }
  }

  /// Write GUI output (notably decrypted plaintext) owner-only (0600), matching
  /// the CLI (F23, gitlab#260, CWE-276). The content is written to a fresh 0600
  /// temp in the destination directory, verified owner-only, and atomically
  /// renamed over the target (rename replaces a symlink at the destination
  /// rather than following it), so the plaintext never resides in a
  /// world-readable file and a failed permission set fails closed.
  Future<bool> _writeOwnerOnly(
    String canonicalPath,
    Future<void> Function(File tmp) writeBody,
  ) async {
    final target = File(canonicalPath);
    // Unpredictable temp name (secure-random suffix) so an attacker with write
    // access to the output dir cannot pre-plant a symlink at the temp path and
    // redirect the write (the install/create step would otherwise follow it).
    final rand = Random.secure();
    final suffix = List.generate(16, (_) => rand.nextInt(16).toRadixString(16)).join();
    final tmp = File(path.join(
      target.parent.path,
      '.${path.basename(canonicalPath)}.oe-$suffix.tmp',
    ));
    try {
      await _create0600(tmp);
      // Belt-and-suspenders against a symlink at the (already unpredictable)
      // temp path: dart:io cannot request O_EXCL/O_NOFOLLOW, so if the temp
      // resolved to a symlink, refuse rather than write plaintext through it.
      if (!Platform.isWindows && FileSystemEntity.isLinkSync(tmp.path)) {
        try {
          await tmp.delete();
        } catch (_) {}
        return false;
      }
      await writeBody(tmp);
      if (!_isOwnerOnly(tmp.path)) {
        // Fail closed: never leave decrypted output world-readable.
        try {
          await tmp.delete();
        } catch (_) {}
        return false;
      }
      await tmp.rename(canonicalPath);
      return true;
    } catch (e) {
      try {
        if (await tmp.exists()) await tmp.delete();
      } catch (_) {}
      rethrow;
    }
  }

  /// Write bytes to file (owner-only, 0600).
  Future<bool> writeFileBytes(String filePath, Uint8List data) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      return await _writeOwnerOnly(canonicalPath, (tmp) => tmp.writeAsBytes(data));
    } catch (e) {
      CLIService.outputDebugLog('Error writing file: $e');
      return false;
    }
  }

  /// Write string to file (owner-only, 0600).
  Future<bool> writeFileText(String filePath, String content) async {
    try {
      // Security: Canonicalize path to prevent symlink attacks
      final canonicalPath = _canonicalizePath(filePath);
      return await _writeOwnerOnly(canonicalPath, (tmp) => tmp.writeAsString(content));
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

  /// Get list of test file names from assets
  Future<List<String>> getTestFileNames() async {
    final List<String> testFiles = [];

    // List of test files in assets (must match assets in pubspec.yaml)
    const testFilePaths = [
      // V3 format test files
      'assets/test_files/v3/test1_aes-gcm.txt',
      'assets/test_files/v3/test1_chacha20-poly1305.txt',
      'assets/test_files/v3/test1_fernet.txt',
      'assets/test_files/v3/test1_fernet_balloon.txt',
      'assets/test_files/v3/test1_xchacha20-poly1305.txt',
      // V4 format test files
      'assets/test_files/v4/test1_aes-gcm.txt',
      'assets/test_files/v4/test1_chacha20-poly1305.txt',
      'assets/test_files/v4/test1_fernet.txt',
      'assets/test_files/v4/test1_fernet_balloon.txt',
      'assets/test_files/v4/test1_xchacha20-poly1305.txt',
      // V5 format test files
      'assets/test_files/v5/test1_aes-gcm.txt',
      'assets/test_files/v5/test1_chacha20-poly1305.txt',
      'assets/test_files/v5/test1_fernet.txt',
      'assets/test_files/v5/test1_fernet_balloon.txt',
      'assets/test_files/v5/test1_fernet_balloon_test.txt',
      'assets/test_files/v5/test1_xchacha20-poly1305.txt',
      'assets/test_files/v5/mobile_generated_test.txt',
    ];

    for (final filePath in testFilePaths) {
      try {
        // Try to load the asset to verify it exists
        await rootBundle.load(filePath);
        testFiles.add(filePath);
      } catch (e) {
        // Skip files that don't exist
        CLIService.outputDebugLog('Test file not found: $filePath');
      }
    }

    return testFiles;
  }

  /// Get FileInfo for a specific test file from assets
  Future<FileInfo?> getTestFileInfo(String assetPath) async {
    try {
      // Load the asset to get its size
      final data = await rootBundle.load(assetPath);
      final fileName = path.basename(assetPath);

      return FileInfo(
        name: fileName,
        path: assetPath,
        size: data.lengthInBytes,
        extension: path.extension(fileName).toLowerCase(),
        lastModified: DateTime.now(), // Assets don't have modification times
      );
    } catch (e) {
      CLIService.outputDebugLog('Error loading test file $assetPath: $e');
      return null;
    }
  }
}
