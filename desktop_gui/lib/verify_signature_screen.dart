import 'package:flutter/material.dart';

import 'cli_service.dart';
import 'input_validation.dart';
import 'file_manager.dart';

/// Verify a detached signature over a file (gitlab#158 / github#76).
///
/// Verification needs no credential — it uses public keys, and trust comes
/// from the local identity store, which refuses an unknown signer outright
/// rather than reporting the file as merely unverified.
///
/// The screen's one job beyond wiring is to make a failure unmistakable. The
/// dangerous outcome here is a user reading "could not verify" as "fine", so a
/// bad signature gets the same visual weight as a good one, and a verification
/// that could not be performed is shown as distinct from one that failed.
class VerifySignatureScreen extends StatefulWidget {
  final FileManager fileManager;

  const VerifySignatureScreen({super.key, required this.fileManager});

  @override
  State<VerifySignatureScreen> createState() => _VerifySignatureScreenState();
}

/// Cap on rendered components: the list comes from an untrusted signature file
/// and nothing bounds its length.
const int _maxComponentsShown = 32;

class _VerifySignatureScreenState extends State<VerifySignatureScreen> {
  final TextEditingController _signatureController = TextEditingController();
  final TextEditingController _signerController = TextEditingController();

  FileInfo? _inputFile;
  bool _loading = false;
  SignatureVerification? _result;
  /// A usage problem (nothing was attempted). Distinct from _error, which
  /// means the CLI was run and could not reach a verdict.
  String _validation = '';
  String _error = '';
  /// A failure that IS a verdict, not an inability to check.
  bool _errorIsHardFailure = false;
  bool _wasPinned = false;

  @override
  void dispose() {
    _signatureController.dispose();
    _signerController.dispose();
    super.dispose();
  }

  /// Drop any previous outcome when an input changes.
  ///
  /// Otherwise a green verdict stays on screen beside inputs that never
  /// produced it — the same "output misread" failure as showing the wrong
  /// verdict, reached by ordinary interaction.
  void _invalidateResult() {
    if (_result != null || _error.isNotEmpty || _validation.isNotEmpty) {
      setState(() {
        _result = null;
        _error = '';
        _validation = '';
      });
    }
  }

  Future<void> _pickInput() async {
    final file = await widget.fileManager.pickFile();
    if (file == null) return;
    setState(() {
      _inputFile = file;
      _result = null;
      _error = '';
      _validation = '';
    });
  }

  Future<void> _verify() async {
    if (_inputFile == null) {
      setState(() {
        _validation = 'Select the signed file.';
        _error = '';
        _result = null;
      });
      return;
    }
    final sigPath = _signatureController.text.trim();
    if (sigPath.startsWith('-')) {
      setState(() {
        _validation = 'The signature path cannot start with "-".';
        _result = null;
        _error = '';
      });
      return;
    }
    final pinned = _signerController.text.trim();
    setState(() {
      _loading = true;
      _validation = '';
      _error = '';
      _errorIsHardFailure = false;
      _result = null;
    });
    try {
      final verification = await CLIService.verifySignature(
        inputPath: _inputFile!.path,
        signaturePath: sigPath,
        signer: pinned.isEmpty ? null : pinned,
      );
      if (mounted) {
        setState(() {
          _result = verification;
          _wasPinned = pinned.isNotEmpty;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = InputValidator.sanitizeForDisplay('$e');
          // A pinned signer that could not be satisfied is a hard NO, not an
          // inability to check. The CLI reports "pinned signer does not match
          // the signature's fingerprint" on stderr with no JSON, which is
          // indistinguishable here from a genuine could-not-check — so when
          // the user pinned, fail loudly rather than reassuringly.
          _errorIsHardFailure = pinned.isNotEmpty;
          _wasPinned = pinned.isNotEmpty;
        });
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Widget _buildVerdict(SignatureVerification v) {
    final good = v.valid;
    final colour = good ? Colors.green.shade700 : Colors.red.shade700;
    return Card(
      color: (good ? Colors.green : Colors.red).withValues(alpha: 0.08),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(good ? Icons.verified : Icons.gpp_bad, color: colour, size: 32),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    good
                        ? (_wasPinned
                            ? 'Signature is valid'
                            : 'Signature is valid — signer not pinned')
                        : 'SIGNATURE IS NOT VALID',
                    style: TextStyle(
                      color: colour,
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            if (!good && v.reason.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text('Reason: ${v.reason}',
                    style: TextStyle(color: colour, fontWeight: FontWeight.w500)),
              ),
            Text(good
                ? 'Signer: ${InputValidator.sanitizeForDisplay(v.signer)}'
                : 'Claimed signer (unverified): '
                    '${InputValidator.sanitizeForDisplay(v.signer)}'),
            Text('Fingerprint: '
                '${InputValidator.sanitizeForDisplay(v.signerFingerprint)}'),
            if (v.signedAt.isNotEmpty)
              Text('Signed at (claimed): '
                  '${InputValidator.sanitizeForDisplay(v.signedAt)}'),
            const SizedBox(height: 8),
            Text(
              good
                  ? (_wasPinned
                      ? 'You pinned this signer by name, so the signature was '
                          'checked against that identity specifically.'
                      : 'The signer was resolved from the signature fingerprint '
                          'against your identity store. That confirms it was '
                          'signed by someone you have stored — not that it was '
                          'signed by a particular person. Pin a signer by name '
                          'to check that.')
                  : 'Nothing about this file’s origin was confirmed. The name '
                      'above is only what the signature file claims.',
              style: const TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
            ),
            if (v.components.isNotEmpty) ...[
              const Divider(height: 24),
              const Text('Algorithm components',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              // Each result is shown so a failing component is not hidden by a
              // passing one. The NAMES, though, are not covered by the
              // signature — the signed payload deliberately excludes the
              // sidecar's signatures field — so they must not be read as proof
              // of which algorithms were used. Capped: the list comes from an
              // untrusted file and nothing bounds its length.
              ...v.components.take(_maxComponentsShown).map(
                (c) => Row(
                  children: [
                    Icon(
                      c.valid ? Icons.check_circle_outline : Icons.cancel_outlined,
                      size: 16,
                      color: c.valid ? Colors.green.shade700 : Colors.red.shade700,
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(
                        '${InputValidator.sanitizeForDisplay(c.component)}: '
                        '${c.valid ? 'ok' : 'FAILED'}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
              if (v.components.length > _maxComponentsShown)
                Text('+ ${v.components.length - _maxComponentsShown} more'),
              const SizedBox(height: 6),
              const Text(
                'Component names are labels from the signature file and are '
                'not themselves signed. Treat them as a hint, not as proof of '
                'which algorithms were used.',
                style: TextStyle(fontSize: 11, fontStyle: FontStyle.italic),
              ),
            ],
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Verify Signature')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Check a detached signature against a file. This needs no '
              'password: it uses public keys from your identity store.',
            ),
            const SizedBox(height: 16),
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(_inputFile == null
                  ? 'Select the signed file'
                  : _inputFile!.path),
              subtitle: const Text('The file whose signature to check'),
              trailing: OutlinedButton(
                onPressed: _loading ? null : _pickInput,
                child: const Text('Choose'),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _signatureController,
              onChanged: (_) => _invalidateResult(),
              decoration: const InputDecoration(
                labelText: 'Signature file',
                helperText: 'Leave empty to use <file>.sig',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _signerController,
              onChanged: (_) => _invalidateResult(),
              decoration: const InputDecoration(
                labelText: 'Expected signer (optional)',
                helperText:
                    'Pin the identity you expect. Left empty, the signer is '
                    'resolved from the signature fingerprint, which only shows '
                    'it was signed by someone in your store.',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _loading ? null : _verify,
              icon: _loading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.fact_check_outlined),
              label: const Text('VERIFY'),
              style: ElevatedButton.styleFrom(padding: const EdgeInsets.all(18)),
            ),
            if (_validation.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(_validation,
                  style: TextStyle(color: Theme.of(context).colorScheme.error)),
            ],
            if (_error.isNotEmpty) ...[
              const SizedBox(height: 16),
              Card(
                color: (_errorIsHardFailure ? Colors.red : Colors.orange)
                    .withValues(alpha: 0.1),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(
                        _errorIsHardFailure ? Icons.gpp_bad : Icons.help_outline,
                        color: _errorIsHardFailure
                            ? Colors.red.shade700
                            : Colors.orange.shade800,
                        size: _errorIsHardFailure ? 32 : 24,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _errorIsHardFailure
                              ? 'THE PINNED SIGNER COULD NOT BE CONFIRMED.\n\n'
                                  'You named an expected signer and the check '
                                  'did not succeed against it. Do not treat '
                                  'this file as coming from that identity.'
                                  '\n\n$_error'
                              : 'Could not check the signature — this is not a '
                                  'verdict either way.\n\n$_error',
                          style: _errorIsHardFailure
                              ? TextStyle(
                                  color: Colors.red.shade700,
                                  fontWeight: FontWeight.w500)
                              : null,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
            if (_result != null) ...[
              const SizedBox(height: 16),
              _buildVerdict(_result!),
            ],
          ],
        ),
      ),
    );
  }
}
