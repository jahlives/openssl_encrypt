import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;

import 'cli_service.dart';
import 'file_manager.dart';

/// Rekey screen — re-encrypts an existing file with a new password (and
/// optionally a new algorithm) via the CLI `rekey` command. Passwords are
/// handled by CLIService.rekey() through environment variables, never argv.
class RekeyScreen extends StatefulWidget {
  final FileManager fileManager;

  const RekeyScreen({super.key, required this.fileManager});

  @override
  State<RekeyScreen> createState() => _RekeyScreenState();
}

class _RekeyScreenState extends State<RekeyScreen> {
  // null => keep the file's current algorithm.
  static const List<String> _algorithms = [
    'aes-gcm',
    'aes-gcm-siv',
    'chacha20-poly1305',
    'xchacha20-poly1305',
    'aes-siv',
  ];

  FileInfo? _inputFile;
  final TextEditingController _outputController = TextEditingController();
  final TextEditingController _oldPw = TextEditingController();
  final TextEditingController _newPw = TextEditingController();
  final TextEditingController _confirmPw = TextEditingController();
  String? _algorithm; // null = keep current
  bool _forcePassword = false;

  bool _loading = false;
  String _result = '';

  @override
  void dispose() {
    _outputController.dispose();
    _oldPw.dispose();
    _newPw.dispose();
    _confirmPw.dispose();
    super.dispose();
  }

  Future<void> _pickInput() async {
    final file = await widget.fileManager.pickFile();
    if (file == null) return;
    setState(() {
      _inputFile = file;
      _outputController.text = '${file.path}.rekeyed';
    });
  }

  String? _validate() {
    if (_inputFile == null) return 'Select an input file.';
    final out = _outputController.text.trim();
    if (out.isEmpty) return 'Set an output path.';
    // Refuse output == input: rekey writes the output unconditionally, so this
    // would destroy the original ciphertext (the screen promises otherwise).
    if (p.canonicalize(out) == p.canonicalize(_inputFile!.path)) {
      return 'Output must be a different file than the input.';
    }
    if (_oldPw.text.isEmpty) return 'Enter the current password.';
    if (_newPw.text.isEmpty) return 'Enter a new password.';
    if (_newPw.text != _confirmPw.text) return 'New passwords do not match.';
    return null;
  }

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

  Future<void> _rekey() async {
    final err = _validate();
    if (err != null) {
      setState(() => _result = err);
      return;
    }
    final outPath = _outputController.text.trim();
    if (File(outPath).existsSync()) {
      final ok = await _confirmOverwrite(outPath);
      if (!ok) {
        setState(() => _result = 'Cancelled — output file already exists.');
        return;
      }
    }
    setState(() {
      _loading = true;
      _result = 'Re-encrypting...';
    });
    try {
      await CLIService.rekey(
        inputPath: _inputFile!.path,
        outputPath: _outputController.text.trim(),
        oldPassword: _oldPw.text,
        newPassword: _newPw.text,
        algorithm: _algorithm,
        forcePassword: _forcePassword,
      );
      if (!mounted) return;
      setState(() {
        _result = 'Rekey successful.\nWrote: ${_outputController.text.trim()}';
        _loading = false;
        _oldPw.clear();
        _newPw.clear();
        _confirmPw.clear();
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _result = 'Rekey failed: $e';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Row(
              children: [
                Icon(Icons.autorenew),
                SizedBox(width: 8),
                Text('Rekey',
                    style:
                        TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'Change the password (and optionally the algorithm) of an '
              'existing encrypted file. The original is left untouched; the '
              're-encrypted copy is written to the output path.',
              style: TextStyle(fontSize: 13, color: Colors.grey),
            ),
            const SizedBox(height: 16),

            Card(
              child: ListTile(
                leading: const Icon(Icons.insert_drive_file),
                title: Text(_inputFile?.name ?? 'No file selected'),
                subtitle: _inputFile != null ? Text(_inputFile!.path) : null,
                trailing: OutlinedButton(
                  onPressed: _loading ? null : _pickInput,
                  child: const Text('Choose'),
                ),
              ),
            ),
            const SizedBox(height: 12),

            TextField(
              controller: _outputController,
              enabled: !_loading,
              decoration: const InputDecoration(
                labelText: 'Output path',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            const SizedBox(height: 16),

            TextField(
              controller: _oldPw,
              enabled: !_loading,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Current password',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.lock_open),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _newPw,
              enabled: !_loading,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'New password',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.lock),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _confirmPw,
              enabled: !_loading,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Confirm new password',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.lock),
              ),
            ),
            const SizedBox(height: 16),

            DropdownButtonFormField<String?>(
              initialValue: _algorithm,
              decoration: const InputDecoration(
                labelText: 'Algorithm',
                border: OutlineInputBorder(),
                isDense: true,
              ),
              items: [
                const DropdownMenuItem<String?>(
                  value: null,
                  child: Text('Keep current algorithm'),
                ),
                ..._algorithms.map((a) =>
                    DropdownMenuItem<String?>(value: a, child: Text(a))),
              ],
              onChanged:
                  _loading ? null : (v) => setState(() => _algorithm = v),
            ),
            const SizedBox(height: 8),
            CheckboxListTile(
              value: _forcePassword,
              onChanged: _loading
                  ? null
                  : (v) => setState(() => _forcePassword = v ?? false),
              title: const Text('Force password'),
              subtitle: const Text('Accept a weak new password (use with caution)'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
            ),
            const SizedBox(height: 16),

            ElevatedButton.icon(
              onPressed: _loading ? null : _rekey,
              icon: _loading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.autorenew),
              label: Text(_loading ? 'Re-encrypting...' : 'REKEY'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.all(18),
                textStyle:
                    const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
              ),
            ),

            if (_result.isNotEmpty) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: SelectableText(
                    _result,
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
