import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

import 'support/fake_cli.dart';

/// Regression tests for gitlab#211: CLIService must be injectable so tests
/// never spawn a real CLI subprocess, and getAvailabilityInfo must not rely
/// on timer polling to serialize concurrent fetches.
void main() {
  tearDown(CLIService.resetForTesting);

  test('override answers getAvailabilityInfo without a subprocess', () async {
    var calls = 0;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      calls++;
      expect(args, ['list-available-algorithms']);
      return ProcessResult(0, 0, jsonEncode(fakeAvailabilityJson), '');
    };

    final info = await CLIService.getAvailabilityInfo();

    expect(calls, 1);
    expect(info, isNotNull);
    expect(info!.hashes.keys, contains('sha256'));
    expect(info.ciphers['fernet']!.available, isTrue);
  });

  test('concurrent getAvailabilityInfo calls share one fetch', () async {
    var calls = 0;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      calls++;
      return ProcessResult(0, 0, jsonEncode(fakeAvailabilityJson), '');
    };

    final results = await Future.wait([
      CLIService.getAvailabilityInfo(),
      CLIService.getAvailabilityInfo(),
      CLIService.getAvailabilityInfo(),
    ]);

    expect(calls, 1);
    expect(results.every((r) => r != null), isTrue);
  });

  test('failed fetch returns null and a later call retries', () async {
    var calls = 0;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      calls++;
      if (calls == 1) {
        return ProcessResult(0, 1, '', 'availability probe failed');
      }
      return ProcessResult(0, 0, jsonEncode(fakeAvailabilityJson), '');
    };

    expect(await CLIService.getAvailabilityInfo(), isNull);
    expect(await CLIService.getAvailabilityInfo(), isNotNull);
    expect(calls, 2);
  });

  test('resetForTesting clears the availability cache and the override',
      () async {
    var calls = 0;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      calls++;
      return ProcessResult(0, 0, jsonEncode(fakeAvailabilityJson), '');
    };
    await CLIService.getAvailabilityInfo();
    expect(calls, 1);

    // Cached: no second runner call.
    await CLIService.getAvailabilityInfo();
    expect(calls, 1);

    CLIService.resetForTesting();
    expect(CLIService.commandRunnerOverride, isNull);

    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      calls++;
      return ProcessResult(0, 0, jsonEncode(fakeAvailabilityJson), '');
    };
    await CLIService.getAvailabilityInfo();
    expect(calls, 2);
  });

  test('override receives stdin-based commands too', () async {
    final seen = <String>[];
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      seen.add(stdinInput ?? '<none>');
      return ProcessResult(0, 0, jsonEncode(fakeIdentityListJson), '');
    };

    await CLIService.listIdentities();
    expect(seen, ['<none>']);
  });
}
