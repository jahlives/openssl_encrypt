import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:openssl_encrypt_desktop/cli_service.dart';

/// Regression tests for gitlab#175: the stdin helper must drain stdout/stderr
/// concurrently with writing stdin, and a broken pipe on write must fall
/// through to the child's real exit status/stderr rather than masking it.
///
/// These spawn real trivial `sh` processes (no openssl_encrypt CLI involved)
/// to exercise the actual pipe behaviour that the commandRunnerOverride seam
/// bypasses.
void main() {
  // Skip on any platform without a POSIX shell.
  final hasSh = File('/bin/sh').existsSync();

  test('a child that exits early without reading stdin does not throw, and '
      'its exit code and stderr survive', () async {
    final process = await Process.start('/bin/sh', [
      '-c',
      'echo real-error >&2; exit 3',
    ]);

    // A payload larger than a pipe buffer (~64 KiB): with the old
    // write-then-drain order this both risks a broken-pipe throw and could
    // wedge, because the child never reads stdin.
    final big = 'x' * 200000;
    final result = await CLIService.pumpStdinAndCollect(process, big);

    expect(result.exitCode, 3);
    expect(result.stderr.toString().trim(), 'real-error');
  }, skip: hasSh ? false : 'no /bin/sh');

  test('a child that writes more than a pipe buffer before reading stdin does '
      'not deadlock with a large payload', () async {
    // Emits ~128 KiB to stdout FIRST, then drains stdin. With write-then-read
    // ordering and a >pipe-buffer payload, both sides block forever.
    final process = await Process.start('/bin/sh', [
      '-c',
      'dd if=/dev/zero bs=1024 count=128 2>/dev/null; cat >/dev/null',
    ]);

    final big = 'y' * 200000;
    final result = await CLIService.pumpStdinAndCollect(process, big)
        .timeout(const Duration(seconds: 10), onTimeout: () {
      // If this ever regresses to a deadlock, kill the child rather than
      // leaking a running sh past teardown.
      process.kill();
      throw StateError('pumpStdinAndCollect deadlocked (gitlab#175 regression)');
    });

    expect(result.exitCode, 0);
    expect(result.stdout.toString().length, greaterThanOrEqualTo(128 * 1024));
  }, skip: hasSh ? false : 'no /bin/sh');

  test('the normal path still round-trips stdin to stdout', () async {
    final process = await Process.start('/bin/sh', ['-c', 'cat']);
    final result = await CLIService.pumpStdinAndCollect(process, 'hello');
    expect(result.exitCode, 0);
    expect(result.stdout.toString().trim(), 'hello');
  }, skip: hasSh ? false : 'no /bin/sh');
}
