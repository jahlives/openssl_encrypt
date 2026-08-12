import 'dart:io';

import 'package:flutter/material.dart';

import 'cli_service.dart';
import 'file_manager.dart';

/// Secure Shred screen — securely deletes files/directories via the CLI
/// `shred` command. Deletion is irreversible, so a mandatory confirmation
/// dialog gates every run.
class ShredScreen extends StatefulWidget {
  final FileManager fileManager;

  const ShredScreen({super.key, required this.fileManager});

  @override
  State<ShredScreen> createState() => _ShredScreenState();
}

class _ShredScreenState extends State<ShredScreen> {
  final List<String> _paths = [];
  int _passes = 3;
  bool _recursive = false;
  bool _loading = false;
  final List<String> _log = [];

  bool get _hasDirectory => _paths.any((p) => Directory(p).existsSync());

  // The CLI prompts interactively for a directory without --recursive, which
  // has no stdin under Process.run; block that combination in the UI.
  bool get _needsRecursive => _hasDirectory && !_recursive;

  Future<void> _addFiles() async {
    final files = await widget.fileManager.pickMultipleFiles();
    if (files.isEmpty) return;
    setState(() {
      for (final f in files) {
        if (!_paths.contains(f.path)) _paths.add(f.path);
      }
    });
  }

  Future<void> _addDirectory() async {
    final dir = await widget.fileManager.pickDirectory();
    if (dir == null) return;
    setState(() {
      if (!_paths.contains(dir)) _paths.add(dir);
    });
  }

  Future<void> _confirmAndShred() async {
    if (_paths.isEmpty) return;

    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: Colors.red.shade700),
            const SizedBox(width: 8),
            const Text('Permanently destroy files?'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'This will securely overwrite and delete ${_paths.length} '
              'item(s) with $_passes pass(es). This CANNOT be undone.',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            ConstrainedBox(
              constraints: const BoxConstraints(maxHeight: 160),
              child: SingleChildScrollView(
                child: Text(
                  _paths.join('\n'),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
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
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Shred permanently',
                style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    setState(() {
      _loading = true;
      _log.clear();
    });

    final remaining = List<String>.from(_paths);
    for (final path in List<String>.from(_paths)) {
      try {
        await CLIService.shred(path, passes: _passes, recursive: _recursive);
        remaining.remove(path);
        setState(() => _log.add('OK   $path'));
      } catch (e) {
        setState(() => _log.add('FAIL $path — $e'));
      }
    }

    if (!mounted) return;
    setState(() {
      _paths
        ..clear()
        ..addAll(remaining); // keep only the paths that failed to shred
      _loading = false;
    });
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
              children: [
                Icon(Icons.delete_forever, color: Colors.red.shade700),
                const SizedBox(width: 8),
                const Text('Secure Shred',
                    style:
                        TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'Securely overwrite and delete files so they cannot be recovered. '
              'This is irreversible.',
              style: TextStyle(fontSize: 13, color: Colors.grey),
            ),
            const SizedBox(height: 16),

            Wrap(
              spacing: 12,
              children: [
                OutlinedButton.icon(
                  onPressed: _loading ? null : _addFiles,
                  icon: const Icon(Icons.add),
                  label: const Text('Add files'),
                ),
                OutlinedButton.icon(
                  onPressed: _loading ? null : _addDirectory,
                  icon: const Icon(Icons.folder_open),
                  label: const Text('Add directory'),
                ),
              ],
            ),
            const SizedBox(height: 12),

            if (_paths.isNotEmpty)
              Card(
                child: Column(
                  children: [
                    for (final p in _paths)
                      ListTile(
                        dense: true,
                        leading: Icon(Directory(p).existsSync()
                            ? Icons.folder
                            : Icons.insert_drive_file),
                        title: Text(p,
                            style: const TextStyle(
                                fontFamily: 'monospace', fontSize: 12)),
                        trailing: IconButton(
                          icon: const Icon(Icons.close),
                          onPressed: _loading
                              ? null
                              : () => setState(() => _paths.remove(p)),
                        ),
                      ),
                  ],
                ),
              ),
            const SizedBox(height: 12),

            Card(
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Text('Overwrite passes:'),
                        const SizedBox(width: 12),
                        DropdownButton<int>(
                          value: _passes,
                          items: [1, 3, 5, 7]
                              .map((n) => DropdownMenuItem<int>(
                                  value: n, child: Text('$n')))
                              .toList(),
                          onChanged: _loading
                              ? null
                              : (v) => setState(() => _passes = v ?? 3),
                        ),
                      ],
                    ),
                    CheckboxListTile(
                      value: _recursive,
                      onChanged: _loading
                          ? null
                          : (v) => setState(() => _recursive = v ?? false),
                      title: const Text('Recursive (required for directories)'),
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      controlAffinity: ListTileControlAffinity.leading,
                    ),
                    if (_needsRecursive)
                      const Text(
                        'A directory is selected — enable "Recursive" to shred it.',
                        style: TextStyle(fontSize: 12, color: Colors.orange),
                      ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            ElevatedButton.icon(
              onPressed: (_loading || _paths.isEmpty || _needsRecursive)
                  ? null
                  : _confirmAndShred,
              icon: _loading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.delete_forever),
              label: Text(_loading ? 'Shredding...' : 'SHRED'),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.red,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.all(18),
                textStyle:
                    const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
              ),
            ),

            if (_log.isNotEmpty) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Result',
                          style: TextStyle(fontWeight: FontWeight.bold)),
                      const SizedBox(height: 8),
                      SelectableText(
                        _log.join('\n'),
                        style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 12),
                      ),
                    ],
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
