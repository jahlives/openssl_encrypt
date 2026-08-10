// gitlab#217: the Decrypt tab's steganography-extraction UI.
//
// The extract half of the steg surface (decryptFromSteganography) had no
// caller: the Encrypt tab could hide data in cover media, but round-tripping
// required the CLI. These tests pin the new extraction mode's UI wiring and
// the service's argv (no video formats are advertised -- dead CLI surface
// until gitlab#170).

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';
import 'package:openssl_encrypt_desktop/tabs/decrypt_tab.dart';

Future<ProcessResult> _fakeCli(List<String> args, {String? stdinInput}) async {
  if (args.length >= 2 && args[0] == 'identity' && args[1] == 'list') {
    return ProcessResult(0, 0,
        '{"own": [], "contacts": [], "skipped": []}', '');
  }
  if (args.isNotEmpty && args.first == 'list-available-algorithms') {
    return ProcessResult(0, 0,
        '{"ciphers": {}, "hashes": {}, "kdfs": {}, "kems": {}, '
        '"signatures": {}, "libraries": {}}', '');
  }
  return ProcessResult(0, 1, '', 'no canned response for: ${args.join(' ')}');
}

void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    CLIService.commandRunnerOverride = _fakeCli;
  });

  tearDown(CLIService.resetForTesting);

  Widget wrap(Widget child) => MaterialApp(home: Scaffold(body: child));

  group('extraction UI', () {
    testWidgets('the switch renders in Pro file mode and reveals the fields',
        (WidgetTester tester) async {
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      await tester.pumpWidget(wrap(DecryptTab(
        fileManager: FileManager(),
        isProMode: true,
      )));
      await tester.pump();

      expect(find.text('Extract from steganography'), findsOneWidget);
      // Off by default: no fields, the normal file picker is present.
      expect(find.text('Select cover media'), findsNothing);

      final switchFinder = find.descendant(
        of: find.ancestor(
          of: find.text('Extract from steganography'),
          matching: find.byType(Card),
        ),
        matching: find.byType(Switch),
      );
      tester.widget<Switch>(switchFinder).onChanged!(true);
      await tester.pump();

      expect(find.text('Select cover media'), findsOneWidget);
      expect(
          find.text('Steganography password (optional)'), findsOneWidget);
      expect(find.text('Bits per channel:'), findsOneWidget);
    });

    testWidgets('the switch is absent outside Pro mode',
        (WidgetTester tester) async {
      await tester.pumpWidget(wrap(DecryptTab(
        fileManager: FileManager(),
        isProMode: false,
      )));
      await tester.pump();
      expect(find.text('Extract from steganography'), findsNothing);
    });
  });

  group('decryptFromSteganography argv', () {
    test('emits --stego-extract with method/bits and optional stego password',
        () async {
      final captured = <List<String>>[];
      CLIService.commandRunnerOverride = (List<String> args, {String? stdinInput}) async {
        captured.add(List.of(args));
        final o = args.indexOf('-o');
        if (o >= 0) File(args[o + 1]).writeAsStringSync('plaintext');
        return ProcessResult(0, 0, '', '');
      };

      final tmp = Directory.systemTemp.createTempSync('steg_test_');
      addTearDown(() => tmp.deleteSync(recursive: true));
      final out = '${tmp.path}/out.txt';

      await CLIService.decryptFromSteganography(
        stegoImagePath: '/tmp/cover.png',
        outputPath: out,
        password: 'pw',
        stegoPassword: 'stego-pw',
        bitsPerChannel: 2,
      );

      expect(captured.length, 1);
      final argv = captured.single;
      expect(argv.first, 'decrypt');
      expect(argv, contains('--stego-extract'));
      expect(argv, containsAllInOrder(['--stego-method', 'lsb']));
      expect(argv, containsAllInOrder(['--stego-bits-per-channel', '2']));
      expect(argv, containsAllInOrder(['--stego-password', 'stego-pw']));
      // No verify flags without an identity, no video-related surface.
      expect(argv, isNot(contains('--verify-from')));
      expect(argv, isNot(contains('--no-verify')));
    });
  });
}
