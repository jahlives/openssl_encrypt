import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/settings_service.dart';

/// F20 (gitlab#259, CWE-312): the mTLS client cert+private-key PEM must never be
/// stored in SharedPreferences (a world-readable 0644 file). It is written to a
/// 0600 file; only the path is kept in prefs.
void main() {
  const pem =
      '-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n'
      '-----BEGIN PRIVATE KEY-----\nMIIsecret...\n-----END PRIVATE KEY-----\n';

  late Directory tmp;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('mtls_test_');
    SettingsService.securePemBaseDirOverride = tmp.path;
  });

  tearDown(() async {
    SettingsService.securePemBaseDirOverride = null;
    try {
      await tmp.delete(recursive: true);
    } catch (_) {}
  });

  test('the client cert+key PEM is stored in a 0600 file, not in prefs', () async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();

    await SettingsService.setPepperClientCertPem(pem);

    // The getter round-trips the content.
    expect(SettingsService.getPepperClientCertPem(), pem);

    // Prefs holds a PATH, never the PEM/private key.
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString('pepper_client_cert_pem');
    expect(stored, isNotNull);
    expect(stored!.contains('BEGIN PRIVATE KEY'), isFalse);
    expect(File(stored).existsSync(), isTrue);

    // The file carries the PEM and (on POSIX) mode 0600.
    final f = File(stored);
    expect(await f.readAsString(), pem);
    if (!Platform.isWindows) {
      final mode = f.statSync().mode & 0x1FF; // low 9 permission bits
      expect(mode, 0x180); // 0600
    }
  });

  test('null clears the file and the pref', () async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    await SettingsService.setPepperClientCertPem(pem);
    final path =
        (await SharedPreferences.getInstance()).getString('pepper_client_cert_pem')!;

    await SettingsService.setPepperClientCertPem(null);
    expect(SettingsService.getPepperClientCertPem(), isNull);
    expect(File(path).existsSync(), isFalse);
    expect(
        (await SharedPreferences.getInstance()).getString('pepper_client_cert_pem'),
        isNull);
  });

  test('migration relocates a legacy plaintext PEM out of prefs', () async {
    // An older version stored the PEM (with the private key) directly in prefs.
    SharedPreferences.setMockInitialValues({'pepper_client_cert_pem': pem});
    await SettingsService.initialize();

    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString('pepper_client_cert_pem');
    // No longer the PEM — now a path to the 0600 file.
    expect(stored, isNotNull);
    expect(stored!.contains('BEGIN PRIVATE KEY'), isFalse);
    expect(File(stored).existsSync(), isTrue);
    expect(await File(stored).readAsString(), pem);
    // The getter still returns the content.
    expect(SettingsService.getPepperClientCertPem(), pem);
  });

  test('migration scrubs the removed *_client_key_pem keys', () async {
    SharedPreferences.setMockInitialValues({
      'pepper_client_key_pem': '-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n',
      'integrity_client_key_pem': 'stale',
    });
    await SettingsService.initialize();
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('pepper_client_key_pem'), isNull);
    expect(prefs.getString('integrity_client_key_pem'), isNull);
  });

  test('an oversized client cert PEM error never echoes the value', () async {
    // Review F1: the error path must not interpolate the private-key value.
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    final huge = 'S' * 60000; // > 50000, triggers the length guard
    final logs = <String>[];
    await runZoned(
      () async {
        await SettingsService.importSettings({'pepper_client_cert_pem': huge});
      },
      zoneSpecification: ZoneSpecification(
        print: (self, parent, zone, line) => logs.add(line),
      ),
    );
    expect(logs.any((l) => l.contains(huge)), isFalse);
    expect(logs.any((l) => l.contains('SSSSSSS')), isFalse);
  });

  test('export carries only the path (no key) and re-import keeps the cert',
      () async {
    // Review F3: export dumps the path now; re-importing it must not corrupt the
    // cert by writing the path string as the file content.
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    await SettingsService.setPepperClientCertPem(pem);

    final exported = SettingsService.exportSettings();
    expect(
        exported['pepper_client_cert_pem'].toString().contains('BEGIN PRIVATE KEY'),
        isFalse);

    await SettingsService.importSettings(
        {'pepper_client_cert_pem': exported['pepper_client_cert_pem']});
    // Not corrupted: the getter still returns the PEM, not the path.
    expect(SettingsService.getPepperClientCertPem(), pem);
  });

  test('a legacy *_client_key_pem in an import blob is dropped, not stored',
      () async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    await SettingsService.importSettings({
      'pepper_client_key_pem': '-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n',
    });
    expect(
        (await SharedPreferences.getInstance()).getString('pepper_client_key_pem'),
        isNull);
  });

  test('integrity client cert PEM uses the same 0600-file backing', () async {
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
    await SettingsService.setIntegrityClientCertPem(pem);
    expect(SettingsService.getIntegrityClientCertPem(), pem);
    final stored = (await SharedPreferences.getInstance())
        .getString('integrity_client_cert_pem');
    expect(stored, isNotNull);
    expect(File(stored!).existsSync(), isTrue);
    expect(stored.contains('BEGIN PRIVATE KEY'), isFalse);
  });
}
