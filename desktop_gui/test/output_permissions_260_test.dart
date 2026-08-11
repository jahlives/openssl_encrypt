import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/file_manager.dart';

/// F23 (gitlab#260, CWE-276): GUI-written output (notably decrypted plaintext)
/// must be owner-only (0600), matching the CLI, not the world-readable 0644 that
/// writeAsString/writeAsBytes produce by default.
void main() {
  final fm = FileManager();
  late Directory tmp;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('out_perms_');
  });
  tearDown(() async {
    try {
      await tmp.delete(recursive: true);
    } catch (_) {}
  });

  int mode(String path) => File(path).statSync().mode & 0x1FF;

  test('writeFileText produces an owner-only file with the content', () async {
    final out = '${tmp.path}/secret.txt';
    final ok = await fm.writeFileText(out, 'recovered plaintext');
    expect(ok, isTrue);
    expect(await File(out).readAsString(), 'recovered plaintext');
    if (!Platform.isWindows) {
      expect(mode(out), 0x180); // 0600
    }
  });

  test('writeFileBytes produces an owner-only file with the content', () async {
    final out = '${tmp.path}/secret.bin';
    final data = Uint8List.fromList([1, 2, 3, 4, 5]);
    final ok = await fm.writeFileBytes(out, data);
    expect(ok, isTrue);
    expect(await File(out).readAsBytes(), data);
    if (!Platform.isWindows) {
      expect(mode(out), 0x180); // 0600
    }
  });

  test('a successful write leaves no temp file behind', () async {
    final out = '${tmp.path}/clean.txt';
    await fm.writeFileText(out, 'x');
    final leftovers = tmp
        .listSync()
        .whereType<File>()
        .where((f) => f.path.contains('.oe-'))
        .toList();
    expect(leftovers, isEmpty);
    expect(File(out).existsSync(), isTrue);
  });

  test('overwrite replaces the file atomically (fresh content, 0600)', () async {
    // Review F1: overwrite must not reuse an inode an attacker might hold open.
    // The temp+rename design replaces the target; assert the content is the new
    // one and the mode is 0600 (the old inode is gone).
    final out = '${tmp.path}/replaced.txt';
    await fm.writeFileText(out, 'first');
    await fm.writeFileText(out, 'second');
    expect(await File(out).readAsString(), 'second');
    if (!Platform.isWindows) {
      expect(mode(out), 0x180);
    }
  });

  test('overwriting an existing 0644 file tightens it to 0600', () async {
    final out = '${tmp.path}/existing.txt';
    final f = File(out);
    await f.writeAsString('old');
    if (!Platform.isWindows) {
      await Process.run('chmod', ['644', out]);
      expect(mode(out), 0x1A4); // 0644 precondition
    }
    await fm.writeFileText(out, 'new secret');
    expect(await File(out).readAsString(), 'new secret');
    if (!Platform.isWindows) {
      expect(mode(out), 0x180); // 0600
    }
  });
}
