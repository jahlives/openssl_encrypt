import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/main.dart';
import 'package:openssl_encrypt_desktop/file_manager.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';
import 'package:openssl_encrypt_desktop/widgets/crypto_widgets.dart';

// Widget tests for Batch Operations tab parity with the Encrypt tab
// (gitlab#155 / github#73), plan items P20-P24.
//
// The batch tab previously passed null hash/KDF config and omitted HSM, pepper
// and steganography, so batching silently used CLI defaults while the same
// files encrypted one at a time used whatever the user had configured. These
// tests pin that the controls exist; no CLI runs.
void main() {
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
  });

  // The batch tab's configuration form is taller than the default 800x600 test
  // viewport, so it overflows before the controls under test are laid out.
  Future<void> useTallSurface(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1400, 3000);
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

  // The batch tab only shows its configuration once files are selected, and a
  // widget test cannot drive a native file dialog. Supplying the selection
  // directly is the only way to reach the controls under test.
  Future<void> selectFiles(WidgetTester tester) async {
    final addButton = find.text('Select Files');
    await tester.ensureVisible(addButton.first);
    await tester.pump();
    await tester.tap(addButton.first);
    await tester.pump(const Duration(milliseconds: 300));
  }

  testWidgets('batch tab exposes the HSM/YubiKey configuration',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    expect(find.byType(HsmConfigSection), findsOneWidget);
  });

  testWidgets('batch tab exposes the pepper configuration',
      (WidgetTester tester) async {
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    expect(find.byType(PepperConfigSection), findsOneWidget);
  });

  testWidgets('batch tab exposes the shared hash/KDF chain configuration',
      (WidgetTester tester) async {
    // Extracted from the Encrypt tab rather than duplicated, so the two cannot
    // drift — the drift IS the defect: batching previously sent null for both
    // and silently used CLI defaults.
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    expect(find.byType(HashKdfConfigSection), findsOneWidget);
  });

  testWidgets('batch KDF config seeds every algorithm the shared panel indexes',
      (WidgetTester tester) async {
    // The shared panel's preset buttons write to every KDF key directly. A
    // partial map made them throw mid-mutation, and "Disable All" threw after
    // disabling argon2 — leaving every KDF off and silently falling back to
    // CLI defaults.
    //
    // Seeding does NOT preserve the CLI's STANDARD template: _buildKdfConfigMap
    // filters to enabled == true, so the four disabled entries emit nothing.
    // Sending any KDF config leaves that template behind, which is why the
    // config is sent for symmetric mode only — matching the Encrypt tab.
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    final section = tester.widget<HashKdfConfigSection>(
      find.byType(HashKdfConfigSection),
    );
    for (final kdf in ['argon2', 'scrypt', 'hkdf', 'balloon', 'randomx']) {
      expect(section.kdfConfig.containsKey(kdf), isTrue,
          reason: '$kdf missing: the shared panel indexes it directly');
    }
  });

  testWidgets('batch pepper mode defaults to a value the dropdown offers',
      (WidgetTester tester) async {
    // 'default' is not among the dropdown's items, which asserts in debug and
    // renders blank in release — making named peppers unreachable.
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    final pepper = tester.widget<PepperConfigSection>(
      find.byType(PepperConfigSection),
    );
    expect(['auto', 'named'], contains(pepper.pepperMode));
  });

  testWidgets('steganography is deliberately absent from the batch tab',
      (WidgetTester tester) async {
    // P24 (gitlab#155) declined, recorded here so the absence is a pinned
    // decision rather than an oversight: steganography embeds ONE payload
    // into ONE chosen cover file, so a batch run would need a distinct
    // cover per input plus per-pair capacity checks — a new design, not
    // parity wiring. Single-file steganography lives on the Encrypt tab.
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    expect(find.textContaining('Steganography'), findsNothing);
    expect(find.textContaining('steganography'), findsNothing);
    expect(find.textContaining('Cover media'), findsNothing);
  });

  testWidgets('the hash/KDF panel is hidden outside symmetric mode',
      (WidgetTester tester) async {
    // Sending hash/KDF config takes the CLI out of the branch that applies its
    // STANDARD template, which for asymmetric/cascade would drop blake3,
    // randomx, the v11 composition and the implicit cascade. The Encrypt tab
    // suppresses the config outside symmetric mode; the panel must follow, so
    // the UI never implies a setting applies where it is not sent.
    await useTallSurface(tester);
    await tester.pumpWidget(wrap(batchTab()));
    await tester.pump();
    await selectFiles(tester);

    // Default mode is symmetric, so it is present here.
    expect(find.byType(HashKdfConfigSection), findsOneWidget);

    final asymmetric = find.textContaining('Asymmetric');
    if (asymmetric.evaluate().isNotEmpty) {
      await tester.ensureVisible(asymmetric.first);
      await tester.pump();
      await tester.tap(asymmetric.first);
      await tester.pump(const Duration(milliseconds: 300));
      expect(find.byType(HashKdfConfigSection), findsNothing);
    }
  });
}

/// Returns a fixed selection instead of opening a native file dialog.
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
}
