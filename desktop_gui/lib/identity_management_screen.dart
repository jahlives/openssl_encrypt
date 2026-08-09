import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'cli_service.dart';
import 'input_validation.dart';

/// Identity Management Screen
/// Allows users to create, view, and manage identities and contacts for asymmetric encryption
class IdentityManagementScreen extends StatefulWidget {
  const IdentityManagementScreen({super.key});

  @override
  State<IdentityManagementScreen> createState() => _IdentityManagementScreenState();
}

class _IdentityManagementScreenState extends State<IdentityManagementScreen>
    with SingleTickerProviderStateMixin {
  List<Map<String, dynamic>> _ownIdentities = [];
  List<Map<String, dynamic>> _contacts = [];
  List<Map<String, dynamic>> _skipped = [];
  bool _isLoading = false;
  String? _errorMessage;
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadIdentities();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadIdentities() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final identities = await CLIService.listIdentities();
      setState(() {
        _ownIdentities = (identities['own'] as List<Map<String, dynamic>>?) ?? [];
        _contacts = (identities['contacts'] as List<Map<String, dynamic>>?) ?? [];
        _skipped = (identities['skipped'] as List<Map<String, dynamic>>?) ?? [];
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        // The exception text can embed CLI output (a FormatException quotes
        // the stdout excerpt), so it is untrusted display input.
        _errorMessage =
            InputValidator.sanitizeForDisplay('Failed to load identities: $e');
        _isLoading = false;
      });
    }
  }

  Future<void> _createIdentity() async {
    final nameController = TextEditingController();
    final emailController = TextEditingController();
    final passphraseController = TextEditingController();
    final confirmPassphraseController = TextEditingController();
    String kemAlgorithm = 'ML-KEM-768';
    String sigAlgorithm = 'ML-DSA-65';
    String hsmType = 'none';
    int? hsmSlot;
    // Touch-reminder preference. Maps to --no-touch when turned off. Defaults
    // ON to match the CLI. NB (gitlab#218): on identity create this flag only
    // controls whether the tool prints a "touch your key" reminder — it does
    // NOT configure whether the key itself demands a button press (that is a
    // hardware slot setting, e.g. `ykman`). The copy stays honest about that.
    bool requireTouch = true;

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Create New Identity'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Create a new identity for asymmetric encryption. This generates a key pair for encrypting and signing data.',
                  style: TextStyle(fontSize: 14),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: nameController,
                  decoration: const InputDecoration(
                    labelText: 'Name *',
                    hintText: 'e.g., Alice',
                    border: OutlineInputBorder(),
                  ),
                  maxLength: 100,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: emailController,
                  decoration: const InputDecoration(
                    labelText: 'Email (optional)',
                    hintText: 'alice@example.com',
                    border: OutlineInputBorder(),
                  ),
                  keyboardType: TextInputType.emailAddress,
                  maxLength: 200,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: passphraseController,
                  decoration: const InputDecoration(
                    labelText: 'Passphrase *',
                    hintText: 'Strong passphrase to protect private keys',
                    border: OutlineInputBorder(),
                  ),
                  obscureText: true,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: confirmPassphraseController,
                  decoration: const InputDecoration(
                    labelText: 'Confirm Passphrase *',
                    border: OutlineInputBorder(),
                  ),
                  obscureText: true,
                ),
                const SizedBox(height: 16),
                const Text('Key Encapsulation Algorithm:', style: TextStyle(fontWeight: FontWeight.w500)),
                const SizedBox(height: 8),
                DropdownButtonFormField<String>(
                  initialValue: kemAlgorithm,
                  decoration: const InputDecoration(border: OutlineInputBorder()),
                  items: const [
                    DropdownMenuItem(value: 'ML-KEM-512', child: Text('ML-KEM-512 (NIST Level 1)')),
                    DropdownMenuItem(value: 'ML-KEM-768', child: Text('ML-KEM-768 (NIST Level 3) - Recommended')),
                    DropdownMenuItem(value: 'ML-KEM-1024', child: Text('ML-KEM-1024 (NIST Level 5)')),
                  ],
                  onChanged: (value) {
                    setDialogState(() => kemAlgorithm = value!);
                  },
                ),
                const SizedBox(height: 16),
                const Text('Signature Algorithm:', style: TextStyle(fontWeight: FontWeight.w500)),
                const SizedBox(height: 8),
                DropdownButtonFormField<String>(
                  initialValue: sigAlgorithm,
                  decoration: const InputDecoration(border: OutlineInputBorder()),
                  items: const [
                    DropdownMenuItem(value: 'ML-DSA-44', child: Text('ML-DSA-44 (NIST Level 2)')),
                    DropdownMenuItem(value: 'ML-DSA-65', child: Text('ML-DSA-65 (NIST Level 3) - Recommended')),
                    DropdownMenuItem(value: 'ML-DSA-87', child: Text('ML-DSA-87 (NIST Level 5)')),
                  ],
                  onChanged: (value) {
                    setDialogState(() => sigAlgorithm = value!);
                  },
                ),
                const SizedBox(height: 16),
                CheckboxListTile(
                  title: const Text('Use HSM (Hardware Security Module)'),
                  subtitle: const Text('Protect keys with YubiKey'),
                  value: hsmType != 'none',
                  onChanged: (value) {
                    setDialogState(() {
                      hsmType = (value ?? false) ? 'yubikey' : 'none';
                    });
                  },
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
                if (hsmType != 'none') ...[
                  const SizedBox(height: 8),
                  DropdownButtonFormField<int?>(
                    initialValue: hsmSlot,
                    decoration: const InputDecoration(
                      labelText: 'YubiKey Slot',
                      border: OutlineInputBorder(),
                    ),
                    items: const [
                      DropdownMenuItem(value: null, child: Text('Auto-detect')),
                      DropdownMenuItem(value: 1, child: Text('Slot 1')),
                      DropdownMenuItem(value: 2, child: Text('Slot 2')),
                    ],
                    onChanged: (value) {
                      setDialogState(() => hsmSlot = value);
                    },
                  ),
                  const SizedBox(height: 8),
                  SwitchListTile(
                    title: const Text(
                        'Show a touch reminder when this identity is used'),
                    subtitle: const Text(
                      'Records a preference on the identity so the tool prints '
                      'a "touch your key" reminder. It does NOT change whether '
                      'the key itself requires a physical button press — that '
                      'is configured on the key (e.g. with ykman). Set once, '
                      'at creation.',
                      style: TextStyle(fontSize: 12),
                    ),
                    value: requireTouch,
                    onChanged: (value) {
                      setDialogState(() => requireTouch = value);
                    },
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                  ),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () async {
                if (nameController.text.isEmpty) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Name is required')),
                  );
                  return;
                }
                if (passphraseController.text.isEmpty) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Passphrase is required')),
                  );
                  return;
                }
                if (passphraseController.text != confirmPassphraseController.text) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Passphrases do not match')),
                  );
                  return;
                }

                try {
                  await CLIService.createIdentity(
                    name: nameController.text,
                    email: emailController.text.isEmpty ? null : emailController.text,
                    passphrase: passphraseController.text,
                    kemAlgorithm: kemAlgorithm,
                    sigAlgorithm: sigAlgorithm,
                    hsmType: hsmType != 'none' ? hsmType : null,
                    hsmSlot: hsmSlot,
                    // --no-touch only when the user turned off the reminder
                    // AND an HSM is selected (the flag suppresses the touch
                    // reminder, not any hardware press requirement; gitlab#218).
                    noTouch: hsmType != 'none' && !requireTouch,
                  );
                  if (context.mounted) {
                    Navigator.of(context).pop(true);
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Identity created successfully!'),
                        backgroundColor: Colors.green,
                      ),
                    );
                  }
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed to create identity: $e')),
                    );
                  }
                }
              },
              child: const Text('Create'),
            ),
          ],
        ),
      ),
    );

    if (result == true) {
      _loadIdentities();
    }
  }

  Future<void> _exportIdentity(String name) async {
    try {
      final publicKey = await CLIService.exportIdentity(name);

      if (!mounted) return;

      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: Text('Export Identity: $name'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Share this public key with others so they can encrypt messages for you:',
                  style: TextStyle(fontSize: 14),
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade200,
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: SelectableText(
                    publicKey,
                    style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: publicKey));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Public key copied to clipboard')),
                );
              },
              child: const Text('Copy to Clipboard'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Close'),
            ),
          ],
        ),
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to export identity: $e')),
        );
      }
    }
  }

  /// The pinned key for a contact differs from the imported one. This is the
  /// exact move in a key-substitution / MITM attack, so the confirmation shows
  /// both fingerprints and states plainly what accepting means; it never reads
  /// as a routine "retry?" (gitlab#161).
  Future<bool?> _confirmKeyChange(
    BuildContext context,
    IdentityKeyChangedError keyChange,
  ) {
    Widget fingerprintRow(String label, String value, Color color) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 2),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 130,
                child: Text(label, style: const TextStyle(fontSize: 12)),
              ),
              Expanded(
                child: SelectableText(
                  value,
                  style: TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                    color: color,
                  ),
                ),
              ),
            ],
          ),
        );

    return showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning_amber, color: Colors.red.shade700),
            const SizedBox(width: 8),
            // Sanitize even here: this is the most trust-sensitive widget in
            // the app, and it must not be the one that skips the display
            // chokepoint.
            Expanded(
              child: Text(
                'The key for "${InputValidator.sanitizeForDisplay(keyChange.name)}" '
                'has changed',
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'A changed key can mean the contact re-keyed — or that this '
              'bundle is forged / a man-in-the-middle. Replacing the pinned '
              'key removes the protection that detects impersonation.',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            fingerprintRow(
                'Stored (pinned):',
                InputValidator.sanitizeForDisplay(keyChange.oldFingerprint),
                Colors.green.shade800),
            fingerprintRow(
                'Imported:',
                InputValidator.sanitizeForDisplay(keyChange.newFingerprint),
                Colors.red.shade800),
            const SizedBox(height: 12),
            const Text(
              'Only replace it if you have verified the new fingerprint with '
              'the contact through a separate, trusted channel.',
              style: TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Keep the pinned key'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Replace the pinned key'),
          ),
        ],
      ),
    );
  }

  Future<void> _importContact() async {
    final publicKeyController = TextEditingController();

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import Contact'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Import a contact\'s public identity to encrypt messages for '
                'them.',
                style: TextStyle(fontSize: 14),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: publicKeyController,
                decoration: const InputDecoration(
                  labelText: 'Public Identity Document *',
                  // The wire format is the JSON object written by
                  // `identity export`, not a bare base64 key: cmd_import
                  // json.loads the file and rejects anything else.
                  hintText: 'Paste the JSON document from "identity export"',
                  border: OutlineInputBorder(),
                ),
                maxLines: 8,
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              if (publicKeyController.text.isEmpty) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('A public identity document is required')),
                );
                return;
              }

              final document = publicKeyController.text;
              try {
                await CLIService.importContact(document);
                if (context.mounted) {
                  Navigator.of(context).pop(true);
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Contact imported successfully!'),
                      backgroundColor: Colors.green,
                    ),
                  );
                }
              } on IdentityKeyChangedError catch (keyChange) {
                // TOFU key change: never retry silently. Show the old and new
                // fingerprints and the MITM framing, and only replace the
                // pinned key on an explicit, out-of-band-verified confirmation
                // (gitlab#161).
                if (!context.mounted) return;
                final confirmed =
                    await _confirmKeyChange(context, keyChange) ?? false;
                if (!confirmed) return;
                try {
                  await CLIService.importContact(document,
                      allowKeyChange: true);
                  if (context.mounted) {
                    Navigator.of(context).pop(true);
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Contact key replaced.'),
                        backgroundColor: Colors.orange,
                      ),
                    );
                  }
                } catch (e) {
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(InputValidator.sanitizeForDisplay(
                            'Failed to replace key: $e')),
                      ),
                    );
                  }
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(InputValidator.sanitizeForDisplay(
                          'Failed to import contact: $e')),
                    ),
                  );
                }
              }
            },
            child: const Text('Import'),
          ),
        ],
      ),
    );

    if (result == true) {
      _loadIdentities();
    }
  }

  Future<void> _deleteIdentity(String name, {bool isContact = false}) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Delete ${isContact ? 'Contact' : 'Identity'}'),
        content: Text(
          isContact
              ? 'Are you sure you want to delete contact "$name"?\n\nYou won\'t be able to encrypt messages for this contact anymore.'
              : 'Are you sure you want to delete identity "$name"?\n\nWARNING: You will NOT be able to decrypt any data encrypted for this identity!',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        await CLIService.deleteIdentity(name, isContact: isContact);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('${isContact ? 'Contact' : 'Identity'} deleted successfully'),
              backgroundColor: Colors.green,
            ),
          );
          _loadIdentities();
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to delete: $e')),
          );
        }
      }
    }
  }

  Widget _buildIdentityCard(Map<String, dynamic> identity, {bool isContact = false}) {
    final name = identity['name'] as String? ?? 'Unknown';
    final email = identity['email'] as String?;
    final fingerprint = identity['fingerprint'] as String? ?? 'N/A';
    final kemAlgorithm = identity['kem_algorithm'] as String?;
    final sigAlgorithm = identity['sig_algorithm'] as String?;
    final createdAt = identity['created_at'] as String?;

    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4, horizontal: 8),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: isContact ? Colors.blue : Colors.teal,
          child: Icon(
            isContact ? Icons.person : Icons.badge,
            color: Colors.white,
          ),
        ),
        title: Text(
          name,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (email != null) Text(email, style: const TextStyle(fontSize: 12)),
            Text(
                'Fingerprint: ${fingerprint.length > 16 ? '${fingerprint.substring(0, 16)}...' : fingerprint}',
                style: const TextStyle(fontSize: 11)),
            if (!isContact && kemAlgorithm != null)
              Text('KEM: $kemAlgorithm  |  Sig: $sigAlgorithm', style: const TextStyle(fontSize: 11)),
            if (createdAt != null) Text('Created: $createdAt', style: const TextStyle(fontSize: 11)),
          ],
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (value) {
            if (value == 'export' && !isContact) {
              _exportIdentity(name);
            } else if (value == 'delete') {
              _deleteIdentity(name, isContact: isContact);
            }
          },
          itemBuilder: (context) => [
            if (!isContact)
              const PopupMenuItem(
                value: 'export',
                child: Row(
                  children: [
                    Icon(Icons.upload, size: 18),
                    SizedBox(width: 8),
                    Text('Export Public Key'),
                  ],
                ),
              ),
            const PopupMenuItem(
              value: 'delete',
              child: Row(
                children: [
                  Icon(Icons.delete, size: 18, color: Colors.red),
                  SizedBox(width: 8),
                  Text('Delete', style: TextStyle(color: Colors.red)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          // Header Card
          Card(
            margin: const EdgeInsets.all(16),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.badge, size: 32, color: Theme.of(context).colorScheme.primary),
                      const SizedBox(width: 12),
                      const Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Identity Management',
                              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                            ),
                            SizedBox(height: 4),
                            Text(
                              'Manage identities for asymmetric encryption with post-quantum ML-KEM and ML-DSA',
                              style: TextStyle(fontSize: 14),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),

          // Tab Bar
          TabBar(
            controller: _tabController,
            tabs: const [
              Tab(text: 'My Identities', icon: Icon(Icons.badge)),
              Tab(text: 'Contacts', icon: Icon(Icons.contacts)),
            ],
          ),

          // Tab View
          if (_skipped.isNotEmpty)
            Container(
              width: double.infinity,
              color: Colors.orange.shade100,
              padding: const EdgeInsets.all(8),
              child: Text(
                '${_skipped.length} store entr${_skipped.length == 1 ? 'y' : 'ies'} '
                'could not be read and ${_skipped.length == 1 ? 'is' : 'are'} not '
                'listed: ${_skipped.map((s) => s['entry']).join(', ')}',
                style: TextStyle(color: Colors.orange.shade900, fontSize: 12),
              ),
            ),
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _errorMessage != null
                    ? Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(Icons.error, size: 64, color: Colors.red.shade300),
                            const SizedBox(height: 16),
                            Text(_errorMessage!, style: const TextStyle(color: Colors.red)),
                            const SizedBox(height: 16),
                            ElevatedButton(
                              onPressed: _loadIdentities,
                              child: const Text('Retry'),
                            ),
                          ],
                        ),
                      )
                    : TabBarView(
                        controller: _tabController,
                        children: [
                          // My Identities Tab
                          _ownIdentities.isEmpty
                              ? Center(
                                  child: Column(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(Icons.badge_outlined, size: 64, color: Colors.grey.shade400),
                                      const SizedBox(height: 16),
                                      const Text('No identities yet', style: TextStyle(fontSize: 18)),
                                      const SizedBox(height: 8),
                                      const Text('Create your first identity to start using asymmetric encryption'),
                                      const SizedBox(height: 16),
                                      ElevatedButton.icon(
                                        onPressed: _createIdentity,
                                        icon: const Icon(Icons.add),
                                        label: const Text('Create Identity'),
                                      ),
                                    ],
                                  ),
                                )
                              : ListView.builder(
                                  itemCount: _ownIdentities.length,
                                  itemBuilder: (context, index) => _buildIdentityCard(_ownIdentities[index]),
                                ),

                          // Contacts Tab
                          _contacts.isEmpty
                              ? Center(
                                  child: Column(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(Icons.contacts_outlined, size: 64, color: Colors.grey.shade400),
                                      const SizedBox(height: 16),
                                      const Text('No contacts yet', style: TextStyle(fontSize: 18)),
                                      const SizedBox(height: 8),
                                      const Text('Import public keys from others to encrypt messages for them'),
                                      const SizedBox(height: 16),
                                      ElevatedButton.icon(
                                        onPressed: _importContact,
                                        icon: const Icon(Icons.add),
                                        label: const Text('Import Contact'),
                                      ),
                                    ],
                                  ),
                                )
                              : ListView.builder(
                                  itemCount: _contacts.length,
                                  itemBuilder: (context, index) => _buildIdentityCard(_contacts[index], isContact: true),
                                ),
                        ],
                      ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          if (_tabController.index == 0) {
            _createIdentity();
          } else {
            _importContact();
          }
        },
        tooltip: _tabController.index == 0 ? 'Create Identity' : 'Import Contact',
        child: const Icon(Icons.add),
      ),
    );
  }
}
