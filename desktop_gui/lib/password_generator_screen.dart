import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'cli_service.dart';

/// Password Generator screen — shells out to the CLI `generate-password`
/// command (via its --json mode) for both character-based and diceware
/// passphrase generation. Cryptographic generation stays in the CLI; this
/// screen only collects options and displays the result.
class PasswordGeneratorScreen extends StatefulWidget {
  const PasswordGeneratorScreen({super.key});

  @override
  State<PasswordGeneratorScreen> createState() =>
      _PasswordGeneratorScreenState();
}

class _PasswordGeneratorScreenState extends State<PasswordGeneratorScreen> {
  // Mode: false = character-based, true = diceware passphrase.
  bool _dice = false;

  // Character mode options.
  double _length = 32;
  bool _useLowercase = true;
  bool _useUppercase = true;
  bool _useDigits = true;
  bool _useSpecial = true;

  // Diceware options.
  double _diceCount = 10;
  final TextEditingController _diceSepController = TextEditingController();
  final TextEditingController _diceListController = TextEditingController();
  bool _forceWordlist = false;

  bool _loading = false;
  String? _error;
  GeneratedPassword? _result;

  @override
  void dispose() {
    _diceSepController.dispose();
    _diceListController.dispose();
    super.dispose();
  }

  bool get _noCharsetSelected =>
      !_useLowercase && !_useUppercase && !_useDigits && !_useSpecial;

  Future<void> _generate() async {
    setState(() {
      _loading = true;
      _error = null;
      _result = null;
    });

    try {
      final generated = await CLIService.generatePassword(
        length: _length.round(),
        useLowercase: _useLowercase,
        useUppercase: _useUppercase,
        useDigits: _useDigits,
        useSpecial: _useSpecial,
        dice: _dice,
        diceCount: _diceCount.round(),
        diceSep: _diceSepController.text,
        diceList: _diceListController.text.trim().isEmpty
            ? null
            : _diceListController.text.trim(),
        forceWordlist: _forceWordlist,
      );
      if (!mounted) return;
      setState(() {
        _result = generated;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _copyToClipboard() async {
    if (_result == null) return;
    await Clipboard.setData(ClipboardData(text: _result!.password));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Password copied to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: const [
                Icon(Icons.password),
                SizedBox(width: 8),
                Text('Password Generator',
                    style:
                        TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 16),

            // Mode toggle
            SegmentedButton<bool>(
              segments: const [
                ButtonSegment<bool>(
                  value: false,
                  label: Text('Character'),
                  icon: Icon(Icons.abc),
                ),
                ButtonSegment<bool>(
                  value: true,
                  label: Text('Diceware'),
                  icon: Icon(Icons.casino),
                ),
              ],
              selected: {_dice},
              onSelectionChanged: _loading
                  ? null
                  : (sel) => setState(() => _dice = sel.first),
            ),
            const SizedBox(height: 16),

            if (!_dice) _buildCharacterOptions() else _buildDiceOptions(),
            const SizedBox(height: 24),

            ElevatedButton.icon(
              onPressed: _loading ? null : _generate,
              icon: _loading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.refresh),
              label: Text(_loading ? 'Generating...' : 'GENERATE'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.all(18),
                textStyle:
                    const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
              ),
            ),

            if (_error != null) ...[
              const SizedBox(height: 16),
              Card(
                color: Colors.red.shade50,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      const Icon(Icons.error_outline, color: Colors.red),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(_error!,
                            style: const TextStyle(color: Colors.red)),
                      ),
                    ],
                  ),
                ),
              ),
            ],

            if (_result != null) ...[
              const SizedBox(height: 24),
              _buildResultCard(),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildCharacterOptions() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Length: ${_length.round()}',
                style: const TextStyle(fontWeight: FontWeight.bold)),
            Slider(
              value: _length,
              min: 8,
              max: 128,
              divisions: 120,
              label: _length.round().toString(),
              onChanged:
                  _loading ? null : (v) => setState(() => _length = v),
            ),
            const Divider(),
            CheckboxListTile(
              value: _useLowercase,
              onChanged: _loading
                  ? null
                  : (v) => setState(() => _useLowercase = v ?? false),
              title: const Text('Lowercase (a-z)'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
            ),
            CheckboxListTile(
              value: _useUppercase,
              onChanged: _loading
                  ? null
                  : (v) => setState(() => _useUppercase = v ?? false),
              title: const Text('Uppercase (A-Z)'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
            ),
            CheckboxListTile(
              value: _useDigits,
              onChanged: _loading
                  ? null
                  : (v) => setState(() => _useDigits = v ?? false),
              title: const Text('Digits (0-9)'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
            ),
            CheckboxListTile(
              value: _useSpecial,
              onChanged: _loading
                  ? null
                  : (v) => setState(() => _useSpecial = v ?? false),
              title: const Text('Special characters'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
            ),
            if (_noCharsetSelected)
              const Padding(
                padding: EdgeInsets.only(top: 4),
                child: Text(
                  'No character set selected — all four will be used by default.',
                  style: TextStyle(fontSize: 12, color: Colors.orange),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildDiceOptions() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Word count: ${_diceCount.round()}',
                style: const TextStyle(fontWeight: FontWeight.bold)),
            Slider(
              value: _diceCount,
              min: 4,
              max: 20,
              divisions: 16,
              label: _diceCount.round().toString(),
              onChanged:
                  _loading ? null : (v) => setState(() => _diceCount = v),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _diceSepController,
              enabled: !_loading,
              decoration: const InputDecoration(
                labelText: 'Word separator (optional)',
                helperText: 'Default: none (words joined directly)',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _diceListController,
              enabled: !_loading,
              decoration: const InputDecoration(
                labelText: 'Custom wordlist path (optional)',
                helperText: 'Default: bundled EFF Large Wordlist',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            CheckboxListTile(
              value: _forceWordlist,
              onChanged: _loading
                  ? null
                  : (v) => setState(() => _forceWordlist = v ?? false),
              title: const Text('Force small custom wordlist'),
              subtitle: const Text(
                  'Override the 1024-word minimum (weakens entropy per word)'),
              dense: true,
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResultCard() {
    final r = _result!;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.vpn_key, color: Colors.green),
                SizedBox(width: 8),
                Text('Generated Password',
                    style:
                        TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
              ],
            ),
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                r.password,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 16,
              runSpacing: 4,
              children: [
                Text('Entropy: ${r.entropyBits.toStringAsFixed(1)} bits'),
                if (r.strength != null) Text('Strength: ${r.strength}'),
                if (r.mode == 'diceware' && r.wordCount != null)
                  Text('Words: ${r.wordCount}'),
                if (r.mode == 'character' && r.length != null)
                  Text('Length: ${r.length}'),
              ],
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _copyToClipboard,
              icon: const Icon(Icons.copy),
              label: const Text('Copy to clipboard'),
            ),
          ],
        ),
      ),
    );
  }
}
