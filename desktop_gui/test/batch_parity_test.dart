import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/main.dart';
import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';
import 'package:openssl_encrypt_desktop/widgets/crypto_widgets.dart';

// Batch Operations tab parity with the Encrypt tab (gitlab#155): the batch tab
// used to pass null hash/KDF config at every encrypt, so batching silently
// used CLI defaults while the same files through the Encrypt tab used whatever
// the user configured. It now shares the Encrypt tab's HashKdfConfigSection
// and the HsmConfigSection, and passes the built config.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    CLIService.commandRunnerOverride = _fakeCli;
  });

  tearDown(CLIService.resetForTesting);

  Future<void> useTallSurface(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1400, 3600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  }

  Widget wrap(Widget child) => MaterialApp(home: Scaffold(body: child));

  Widget batchTab() => BatchOperationsTab(
        fileManager: _StubFileManager(),
        onDebugChanged: (_) {},
      );

  Future<void> selectFiles(WidgetTester tester) async {
    final addButton = find.text('Select Files');
    await tester.ensureVisible(addButton.first);
    await tester.pump();
    await tester.tap(addButton.first);
    await tester.pump(const Duration(milliseconds: 300));
  }

  testWidgets('batch tab shares the hash/KDF and HSM config sections '
      '(symmetric encrypt)', (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await selectFiles(tester);

    // Default mode is symmetric encrypt, so both sections are present — the
    // same widgets the Encrypt tab uses, so the two cannot drift.
    expect(find.byType(HashKdfConfigSection), findsOneWidget);
    expect(find.byType(HsmConfigSection), findsOneWidget);
  });

  testWidgets('the batch tab holds real hash/KDF config, not null — the same '
      'maps its encrypt call passes', (WidgetTester tester) async {
    // The section is given the batch tab's own _hashConfig/_kdfConfig maps by
    // reference, and _processFile builds the encrypt config from those same
    // maps (_buildHashConfigMap/_buildKdfConfigMap). So proving the section
    // received real, populated config proves the encrypt no longer sends null.
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pumpAndSettle();
    await selectFiles(tester);

    final section =
        tester.widget<HashKdfConfigSection>(find.byType(HashKdfConfigSection));

    // KDF: argon2 is enabled by default, so _buildKdfConfigMap is non-null.
    expect(section.kdfConfig['argon2']?['enabled'], isTrue);
    // Hash: sha3-512 is enabled by default once algorithms load (fallback
    // family list), so _buildHashConfigMap is non-null.
    expect(section.hashConfig['sha3-512']?['enabled'], isTrue,
        reason: 'the batch hash config must seed sha3-512 like the Encrypt tab');
  });
}

Future<ProcessResult> _fakeCli(List<String> args, {String? stdinInput}) async {
  if (args.isNotEmpty && args.first == 'list-available-algorithms') {
    // Fail the availability probe so getHashAlgorithms uses its built-in
    // fallback family list, which includes sha3-512 — the algorithm the batch
    // hash config enables by default.
    return ProcessResult(0, 1, '', 'no availability');
  }
  if (args.length >= 2 && args[0] == 'identity' && args[1] == 'list') {
    return ProcessResult(
        0, 0, jsonEncode(const {'own': [], 'contacts': [], 'skipped': []}), '');
  }
  return ProcessResult(0, 0, 'BASE64CIPHERTEXT', '');
}

/// Returns a fixed selection and canned file IO instead of touching disk.
class _StubFileManager extends FileManager {
  @override
  Future<List<FileInfo>> pickMultipleFiles({List<String>? allowedExtensions}) async {
    return [
      FileInfo(
        name: 'a.txt',
        path: '/tmp/a.txt',
        size: 10,
        extension: '.txt',
        lastModified: DateTime.fromMillisecondsSinceEpoch(0),
      ),
    ];
  }

  @override
  Future<String?> readFileText(String path) async => 'plaintext';

  @override
  Future<bool> writeFileText(String filePath, String content) async => true;

  @override
  String getEncryptedFileName(String path) => '$path.enc';
}
