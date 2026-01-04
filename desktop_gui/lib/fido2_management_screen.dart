import 'package:flutter/material.dart';
import 'cli_service.dart';

/// FIDO2 Credential Management Screen
/// Allows users to register, view, and manage FIDO2 authenticator credentials
class Fido2ManagementScreen extends StatefulWidget {
  const Fido2ManagementScreen({super.key});

  @override
  State<Fido2ManagementScreen> createState() => _Fido2ManagementScreenState();
}

class _Fido2ManagementScreenState extends State<Fido2ManagementScreen> {
  List<Map<String, dynamic>> _credentials = [];
  bool _isLoading = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _loadCredentials();
  }

  Future<void> _loadCredentials() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final credentials = await CLIService.listFido2Credentials();
      setState(() {
        _credentials = credentials;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Failed to load credentials: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _registerCredential() async {
    final descriptionController = TextEditingController();
    bool isBackup = false;

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Register FIDO2 Credential'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Register a new FIDO2 authenticator for hardware-based key derivation.',
                  style: TextStyle(fontSize: 14),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: descriptionController,
                  decoration: const InputDecoration(
                    labelText: 'Description',
                    hintText: 'e.g., YubiKey 5 NFC',
                    border: OutlineInputBorder(),
                  ),
                  maxLength: 100,
                ),
                const SizedBox(height: 8),
                CheckboxListTile(
                  title: const Text('Backup credential'),
                  subtitle: const Text('Allow this credential as a backup option'),
                  value: isBackup,
                  onChanged: (value) {
                    setDialogState(() {
                      isBackup = value ?? false;
                    });
                  },
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.blue.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.blue.withValues(alpha: 0.3)),
                  ),
                  child: const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.info, size: 20, color: Colors.blue),
                          SizedBox(width: 8),
                          Text(
                            'Instructions',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                      SizedBox(height: 8),
                      Text(
                        '1. Ensure your FIDO2 authenticator is connected\n'
                        '2. Click "Register" below\n'
                        '3. Follow prompts to touch your device\n'
                        '4. You may need to enter your PIN',
                        style: TextStyle(fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () {
                Navigator.pop(context, true);
              },
              child: const Text('Register'),
            ),
          ],
        ),
      ),
    );

    if (result == true) {
      setState(() {
        _isLoading = true;
        _errorMessage = null;
      });

      try {
        await CLIService.registerFido2Credential(
          descriptionController.text.trim().isEmpty
              ? 'FIDO2 Credential'
              : descriptionController.text.trim(),
          isBackup,
        );

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('FIDO2 credential registered successfully!'),
              backgroundColor: Colors.green,
            ),
          );
        }

        await _loadCredentials();
      } catch (e) {
        setState(() {
          _errorMessage = 'Registration failed: $e';
          _isLoading = false;
        });

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Registration failed: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }

    descriptionController.dispose();
  }

  Future<void> _deleteCredential(String credentialId, String description) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Credential'),
        content: Text(
          'Are you sure you want to delete the credential "$description"?\n\n'
          'You will no longer be able to decrypt data encrypted with this credential.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      setState(() {
        _isLoading = true;
        _errorMessage = null;
      });

      try {
        await CLIService.deleteFido2Credential(credentialId);

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Credential deleted successfully'),
              backgroundColor: Colors.orange,
            ),
          );
        }

        await _loadCredentials();
      } catch (e) {
        setState(() {
          _errorMessage = 'Deletion failed: $e';
          _isLoading = false;
        });

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Deletion failed: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('FIDO2 Credentials'),
        backgroundColor: Colors.blue,
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Header Card
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16.0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Row(
                            children: [
                              Icon(Icons.fingerprint, size: 32, color: Colors.blue),
                              SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'FIDO2 Hardware Authenticators',
                                      style: TextStyle(
                                        fontSize: 18,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                    SizedBox(height: 4),
                                    Text(
                                      'Manage credentials for FIDO2 authenticators (YubiKey, Nitrokey, etc.)',
                                      style: TextStyle(fontSize: 12),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          ElevatedButton.icon(
                            onPressed: _registerCredential,
                            icon: const Icon(Icons.add),
                            label: const Text('Register New Credential'),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.green,
                              foregroundColor: Colors.white,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Error message
                  if (_errorMessage != null) ...[
                    Card(
                      color: Colors.red.withValues(alpha: 0.1),
                      child: Padding(
                        padding: const EdgeInsets.all(12.0),
                        child: Row(
                          children: [
                            const Icon(Icons.error, color: Colors.red),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Text(
                                _errorMessage!,
                                style: const TextStyle(color: Colors.red),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],

                  // Credentials list
                  Expanded(
                    child: _credentials.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(
                                  Icons.security,
                                  size: 64,
                                  color: Colors.grey.shade400,
                                ),
                                const SizedBox(height: 16),
                                Text(
                                  'No FIDO2 credentials registered',
                                  style: TextStyle(
                                    fontSize: 16,
                                    color: Colors.grey.shade600,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  'Register a credential to use FIDO2 authentication',
                                  style: TextStyle(
                                    fontSize: 12,
                                    color: Colors.grey.shade500,
                                  ),
                                ),
                              ],
                            ),
                          )
                        : ListView.builder(
                            itemCount: _credentials.length,
                            itemBuilder: (context, index) {
                              final credential = _credentials[index];
                              final description = credential['description'] ?? 'Unknown';
                              final createdAt = credential['created_at'] ?? '';
                              final lastUsed = credential['last_used'] ?? '';
                              final credentialId = credential['credential_id'] ?? '';
                              final isBackup = credential['is_backup'] ?? false;

                              return Card(
                                margin: const EdgeInsets.only(bottom: 8),
                                child: ListTile(
                                  leading: CircleAvatar(
                                    backgroundColor: Colors.blue,
                                    child: Icon(
                                      isBackup ? Icons.backup : Icons.fingerprint,
                                      color: Colors.white,
                                    ),
                                  ),
                                  title: Text(
                                    description,
                                    style: const TextStyle(fontWeight: FontWeight.bold),
                                  ),
                                  subtitle: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      if (createdAt.isNotEmpty)
                                        Text('Created: $createdAt', style: const TextStyle(fontSize: 11)),
                                      if (lastUsed.isNotEmpty)
                                        Text('Last used: $lastUsed', style: const TextStyle(fontSize: 11)),
                                      if (isBackup)
                                        Container(
                                          margin: const EdgeInsets.only(top: 4),
                                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                          decoration: BoxDecoration(
                                            color: Colors.orange.withValues(alpha: 0.2),
                                            borderRadius: BorderRadius.circular(4),
                                          ),
                                          child: const Text(
                                            'BACKUP',
                                            style: TextStyle(
                                              fontSize: 10,
                                              fontWeight: FontWeight.bold,
                                              color: Colors.orange,
                                            ),
                                          ),
                                        ),
                                    ],
                                  ),
                                  trailing: IconButton(
                                    icon: const Icon(Icons.delete, color: Colors.red),
                                    onPressed: () => _deleteCredential(credentialId, description),
                                    tooltip: 'Delete credential',
                                  ),
                                ),
                              );
                            },
                          ),
                  ),
                ],
              ),
            ),
    );
  }
}
