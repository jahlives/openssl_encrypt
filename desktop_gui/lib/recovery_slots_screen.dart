import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'cli_service.dart';
import 'file_manager.dart';
import 'input_validation.dart';

/// Manage the recovery slots on an envelope file (gitlab#145 / github#63).
///
/// A recovery slot is an additional wrapping of the same data-encryption key,
/// so every credential here opens the whole file. Two consequences shape this
/// screen: a generated recovery code is shown exactly once and never persisted
/// in widget state beyond that, and removing a slot is gated behind an
/// explicit confirmation because it revokes a recovery path irreversibly.
///
/// Credentials reach the CLI through the environment, never on the command
/// line — see CLIService._recoveryEnv.
class RecoverySlotsScreen extends StatefulWidget {
  final FileManager fileManager;

  const RecoverySlotsScreen({super.key, required this.fileManager});

  @override
  State<RecoverySlotsScreen> createState() => _RecoverySlotsScreenState();
}

class _RecoverySlotsScreenState extends State<RecoverySlotsScreen> {
  final TextEditingController _password = TextEditingController();
  final TextEditingController _newPassphrase = TextEditingController();
  final TextEditingController _confirmPassphrase = TextEditingController();
  final TextEditingController _recoveryCode = TextEditingController();
  final TextEditingController _recoveryPassphrase = TextEditingController();
  final TextEditingController _outputController = TextEditingController();

  /// Which credential the recover action should use.
  bool _recoverWithPassphrase = false;
  FileInfo? _inputFile;
  List<RecoverySlot> _slots = const [];
  bool _loading = false;
  String _result = '';

  @override
  void dispose() {
    _password.dispose();
    _newPassphrase.dispose();
    _confirmPassphrase.dispose();
    _recoveryCode.dispose();
    _recoveryPassphrase.dispose();
    _outputController.dispose();
    super.dispose();
  }

  String? _requireInput() => _inputFile == null ? 'Select an input file.' : null;

  /// Guard for the actions that unlock the file.
  ///
  /// An empty password must be refused here: CLIService omits CRYPT_PASSWORD
  /// when blank, and the CLI then falls back to getpass() on a stdin nothing
  /// ever writes, hanging this screen with no timeout and no cancel.
  String? _requireInputAndPassword() {
    final err = _requireInput();
    if (err != null) return err;
    if (_password.text.isEmpty) return 'Enter the file password.';
    return null;
  }

  /// Whether two paths name the same file.
  ///
  /// canonicalize alone normalizes '..' and case but does not resolve symlinks
  /// or hardlinks, so an output linked to the input would pass and the recovered
  /// plaintext would overwrite the ciphertext it exists to rescue.
  Future<bool> _isSameFile(String a, String b) async {
    if (p.canonicalize(a) == p.canonicalize(b)) return true;
    try {
      if (!await File(a).exists()) return false;
      return await File(a).resolveSymbolicLinks() ==
          await File(b).resolveSymbolicLinks();
    } catch (_) {
      return false;
    }
  }

  /// Confirm overwriting an existing output file.
  Future<bool> _confirmOverwrite(String outPath) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Output file exists'),
        content: Text('$outPath already exists. Overwrite it?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Overwrite'),
          ),
        ],
      ),
    );
    return ok ?? false;
  }

  Future<void> _pickInput() async {
    final file = await widget.fileManager.pickFile();
    if (file == null) return;
    setState(() {
      _inputFile = file;
      _outputController.text = '${file.path}.recovered';
      _slots = const [];
      _result = '';
    });
    await _refreshSlots();
  }

  /// Run [action], funnelling failures into the result line.
  Future<void> _guard(Future<void> Function() action) async {
    setState(() {
      _loading = true;
      _result = '';
    });
    try {
      await action();
    } catch (e) {
      // The CLI error can interpolate untrusted slot/file metadata, and the
      // Python-side sanitizer deliberately excludes U+2028/U+2029/ZWSP/BOM;
      // escape here for the same reason as the slot fields (F19 review).
      if (mounted) {
        setState(() => _result = InputValidator.sanitizeForDisplay('$e'));
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  /// Refresh the slot list without clearing an existing result message.
  ///
  /// _guard resets _result, so a nested refresh would erase the confirmation
  /// of the operation that triggered it — including an irreversible removal.
  Future<void> _refreshSlotsQuietly() async {
    if (_inputFile == null) return;
    try {
      final slots = await CLIService.listRecoverySlots(_inputFile!.path);
      if (mounted) setState(() => _slots = slots);
    } catch (_) {
      // The operation's own message matters more than a listing failure.
    }
  }

  Future<void> _refreshSlots() async {
    final err = _requireInput();
    if (err != null) {
      setState(() => _result = err);
      return;
    }
    await _guard(() async {
      final slots = await CLIService.listRecoverySlots(_inputFile!.path);
      setState(() => _slots = slots);
    });
  }

  Future<void> _addCode() async {
    final err = _requireInputAndPassword();
    if (err != null) {
      setState(() => _result = err);
      return;
    }
    String? pending;
    try {
      await _guard(() async {
        await CLIService.addRecoveryCode(
          inputPath: _inputFile!.path,
          outputPath: _inputFile!.path,
          password: _password.text,
          // Delivery is a precondition of the temp file being shredded. If this
          // screen is gone, keep the code so the caller can still surface it —
          // a slot may exist that only this code opens.
          onCode: (code, afterFailure) async {
            if (mounted) {
              await _showCodeOnce(code, afterFailure: afterFailure);
            } else {
              pending = code;
            }
          },
        );
        _password.clear();
      });
    } finally {
      // Always refresh: after a failure the user was told to check this list to
      // see whether the code they were given is live.
      await _refreshSlotsQuietly();
      final warning = CLIService.takeShredWarning();
      if (mounted && (warning != null || pending != null)) {
        setState(() {
          _result = [
            if (pending != null)
              'A recovery code was generated but could not be shown: $pending',
            if (warning != null) warning,
            if (_result.isNotEmpty) _result,
          ].join('\n\n');
        });
      }
    }
  }

  Future<void> _addPassphrase() async {
    final err = _requireInputAndPassword();
    if (err != null) {
      setState(() => _result = err);
      return;
    }
    if (_newPassphrase.text.trim().isEmpty) {
      setState(() => _result = 'Enter the new recovery passphrase.');
      return;
    }
    // The CLI's interactive path asks twice; through the environment there is
    // no second channel, so the confirmation has to happen here. A typo would
    // otherwise wrap the key under a string nobody can reproduce.
    if (_newPassphrase.text != _confirmPassphrase.text) {
      setState(() => _result = 'Recovery passphrases do not match.');
      return;
    }
    await _guard(() async {
      await CLIService.addRecoveryPassphrase(
        inputPath: _inputFile!.path,
        outputPath: _inputFile!.path,
        newPassphrase: _newPassphrase.text,
        password: _password.text,
      );
      _newPassphrase.clear();
      _confirmPassphrase.clear();
      _password.clear();
      await _refreshSlotsQuietly();
      if (mounted) setState(() => _result = 'Recovery passphrase added.');
    });
  }

  Future<void> _removeSlot(RecoverySlot slot) async {
    final err = _requireInputAndPassword();
    if (err != null) {
      setState(() => _result = err);
      return;
    }
    final confirmed = await _confirmRemoval(slot);
    if (confirmed != true) return;
    await _guard(() async {
      await CLIService.removeRecoverySlot(
        inputPath: _inputFile!.path,
        outputPath: _inputFile!.path,
        // Raw id: the CLI must match the real slot id (F19, gitlab#254). Display
        // sites below use the sanitized slot.id.
        slotId: slot.rawId,
        password: _password.text,
      );
      _password.clear();
      await _refreshSlotsQuietly();
      if (mounted) setState(() => _result = 'Removed slot ${slot.id}.');
    });
  }

  Future<void> _recover() async {
    final err = _requireInput();
    if (err != null) {
      setState(() => _result = err);
      return;
    }
    if (_outputController.text.trim().isEmpty) {
      setState(() => _result = 'Set an output path.');
      return;
    }
    final out = _outputController.text.trim();
    // Writing the plaintext over the input would destroy the ciphertext, which
    // is the one file a recovery credential exists to rescue.
    if (await _isSameFile(out, _inputFile!.path)) {
      setState(() => _result = 'Output must be a different file than the input.');
      return;
    }
    if (_recoverWithPassphrase) {
      // NOT trimmed: the slot was wrapped under the exact string, and the CLI
      // deliberately does not normalize it either.
      if (_recoveryPassphrase.text.isEmpty) {
        setState(() => _result = 'Enter the recovery passphrase.');
        return;
      }
    } else if (_recoveryCode.text.trim().isEmpty) {
      setState(() => _result = 'Enter the recovery code.');
      return;
    }
    if (await File(out).exists()) {
      if (!mounted) return;
      if (!await _confirmOverwrite(out)) return;
    }
    await _guard(() async {
      await CLIService.recoverFile(
        inputPath: _inputFile!.path,
        outputPath: out,
        recoveryCode: _recoverWithPassphrase ? null : _recoveryCode.text.trim(),
        recoveryPassphrase: _recoverWithPassphrase ? _recoveryPassphrase.text : null,
      );
      _recoveryCode.clear();
      _recoveryPassphrase.clear();
      setState(() => _result = 'Recovered to $out');
    });
  }

  /// Show a freshly generated recovery code once.
  ///
  /// The code is not kept in State; it lives only for this dialog (reachable
  /// from the route's builder closure until the route is disposed). This is the
  /// only delivery channel, so displaying it is unavoidable — the mitigations
  /// are its lifetime and clearing the clipboard afterwards.
  ///
  /// [afterFailure] marks the case where the command failed but a code was
  /// nonetheless written: a slot may exist that only this code opens, so it
  /// must be shown rather than discarded.
  Future<void> _showCodeOnce(String code, {bool afterFailure = false}) {
    return showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Text(afterFailure
            ? 'Recovery code — the command failed'
            : 'Recovery code — shown once'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              afterFailure
                  ? 'The command reported an error, but this recovery code was '
                      'already generated. A recovery slot using it may exist on '
                      'the file. Store it, then check the slot list below. It '
                      'will not be shown again.'
                  : 'Store this somewhere safe now. It unlocks this file on its '
                      'own, so treat it like the password. It will not be shown '
                      'again.',
            ),
            const SizedBox(height: 16),
            SelectableText(
              code,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
            ),
            const SizedBox(height: 12),
            const Text(
              'Copying places it on the clipboard, which a clipboard manager '
              'may keep on disk. It is cleared automatically after 60 seconds.',
              style: TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
            ),
          ],
        ),
        actions: [
          TextButton.icon(
            icon: const Icon(Icons.copy),
            label: const Text('Copy'),
            onPressed: () => _copyCodeWithExpiry(context, code),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('I have stored it'),
          ),
        ],
      ),
    );
  }

  /// Copy the code, confirm visibly, and clear the clipboard afterwards.
  ///
  /// Without the confirmation a user can click Copy, get no feedback, dismiss
  /// the dialog and lose the only copy of the credential.
  void _copyCodeWithExpiry(BuildContext dialogContext, String code) {
    Clipboard.setData(ClipboardData(text: code));
    ScaffoldMessenger.of(dialogContext).showSnackBar(
      const SnackBar(
        content: Text('Recovery code copied — clipboard clears in 60 seconds'),
        duration: Duration(seconds: 4),
      ),
    );
    Timer(const Duration(seconds: 60), () async {
      // Only clear if it is still ours, so a later copy is not wiped.
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == code) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }

  /// Cap an already-escaped slot id for display in the confirmation dialog so a
  /// crafted, over-long id cannot dominate the layout (F19 review, gitlab#254).
  static String _capForDialog(String s) =>
      s.length <= 64 ? s : '${s.substring(0, 64)}…';

  Future<bool?> _confirmRemoval(RecoverySlot slot) {
    return showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        scrollable: true,
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: Colors.red.shade700),
            const SizedBox(width: 8),
            const Text('Remove recovery slot?'),
          ],
        ),
        // F19 review (gitlab#254): the untrusted slot id/type is kept OUT of the
        // load-bearing warning sentence. The warning is its own widget (always
        // fully visible); the already-escaped id/type is shown separately,
        // length-capped and forced LTR so a long or RTL slot value cannot push
        // "cannot be undone" off-screen or reorder the app's own text.
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'This revokes a recovery slot on the rewritten file. Anyone holding '
              'that credential loses access, and it cannot be undone. Copies of '
              'the file made earlier are unaffected.',
            ),
            const SizedBox(height: 12),
            Directionality(
              textDirection: TextDirection.ltr,
              child: Text(
                'Slot: ${slot.typeLabel} — ${_capForDialog(slot.id)}',
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Recovery Slots')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'A recovery slot is an extra way to unlock this file. Every slot '
              'opens the whole file, so treat each credential like the '
              'password. Removing a slot cannot be undone.',
            ),
            const SizedBox(height: 16),

            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(_inputFile == null
                  ? 'Select an envelope file'
                  : _inputFile!.path),
              subtitle: const Text('Envelope file whose recovery slots to manage'),
              trailing: OutlinedButton(
                onPressed: _loading ? null : _pickInput,
                child: const Text('Choose'),
              ),
            ),
            const Divider(),

            Text('Current slots', style: Theme.of(context).textTheme.titleMedium),
            if (_slots.isEmpty)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Text('No recovery slots on this file.'),
              )
            else
              ..._slots.map(
                (s) {
                  // A malformed slot (null/non-string id) has no matchable id;
                  // don't offer a Remove that can never succeed (F19 review F7).
                  final hasId = s.rawId.isNotEmpty;
                  return ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(Icons.vpn_key_outlined),
                    // Bound both untrusted fields to one line, LTR, so a long or
                    // RTL slot value can't dominate or reorder the row layout.
                    title: Text(
                      s.typeLabel,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    subtitle: Directionality(
                      textDirection: TextDirection.ltr,
                      child: Text(
                        hasId ? s.id : '(no id — malformed slot)',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    trailing: IconButton(
                      icon: const Icon(Icons.delete_outline),
                      tooltip: hasId
                          ? 'Remove this slot'
                          : 'Slot has no id and cannot be removed',
                      onPressed:
                          (_loading || !hasId) ? null : () => _removeSlot(s),
                    ),
                  );
                },
              ),
            const Divider(),

            TextField(
              controller: _password,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'File password',
                helperText: 'Needed to add or remove a slot',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),

            ElevatedButton.icon(
              onPressed: _loading ? null : _addCode,
              icon: const Icon(Icons.confirmation_number_outlined),
              label: const Text('ADD RECOVERY CODE'),
            ),
            const SizedBox(height: 12),

            TextField(
              controller: _newPassphrase,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'New recovery passphrase',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _confirmPassphrase,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Confirm recovery passphrase',
                helperText:
                    'A mistyped passphrase would create a slot nobody can open',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            ElevatedButton.icon(
              onPressed: _loading ? null : _addPassphrase,
              icon: const Icon(Icons.password_outlined),
              label: const Text('ADD PASSPHRASE'),
            ),
            const Divider(height: 32),

            Text('Recover without the password',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            SegmentedButton<bool>(
              segments: const [
                ButtonSegment(value: false, label: Text('Recovery code')),
                ButtonSegment(value: true, label: Text('Passphrase')),
              ],
              selected: {_recoverWithPassphrase},
              onSelectionChanged: _loading
                  ? null
                  : (sel) => setState(() => _recoverWithPassphrase = sel.first),
            ),
            const SizedBox(height: 8),
            if (_recoverWithPassphrase)
              TextField(
                controller: _recoveryPassphrase,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Recovery passphrase',
                  helperText: 'Entered exactly as it was set, including spaces',
                  border: OutlineInputBorder(),
                ),
              )
            else
              TextField(
                controller: _recoveryCode,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'Recovery code',
                  border: OutlineInputBorder(),
                ),
              ),
            const SizedBox(height: 8),
            TextField(
              controller: _outputController,
              decoration: const InputDecoration(
                labelText: 'Output file',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            ElevatedButton.icon(
              onPressed: _loading ? null : _recover,
              icon: _loading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.lock_open),
              label: const Text('RECOVER FILE'),
            ),

            if (_result.isNotEmpty) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(_result),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
