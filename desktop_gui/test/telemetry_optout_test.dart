import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

/// Service-layer tests for the telemetry opt-out action (gitlab#165 P34).
///
/// The GUI supplies its own confirmation, so the CLI is invoked with --force
/// (the CLI's interactive prompt cannot be answered by a subprocess). Opt-out
/// is destructive, so a nonzero exit must surface as an error — a caller must
/// never tell the user their data is gone when it is not.
void main() {
  tearDown(CLIService.resetForTesting);

  test('opt-out invokes `telemetry opt-out --force`', () async {
    late List<String> seen;
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      seen = args;
      return ProcessResult(0, 0, 'Telemetry disabled.', '');
    };

    await CLIService.telemetryOptOut();

    expect(seen, ['telemetry', 'opt-out', '--force']);
  });

  test('a nonzero exit throws (destructive action must fail loud)', () async {
    CLIService.commandRunnerOverride = (args, {stdinInput}) async {
      return ProcessResult(0, 1, '', 'plugin error: could not delete key');
    };

    expect(CLIService.telemetryOptOut(), throwsA(isA<Exception>()));
  });
}
