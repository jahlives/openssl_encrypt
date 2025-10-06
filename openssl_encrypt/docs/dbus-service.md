# D-Bus Service for openssl_encrypt

## Overview

The openssl_encrypt D-Bus service provides IPC-based access to cryptographic operations without requiring network access. This enables cross-language integration while maintaining security within Flatpak sandboxes and other isolated environments.

**Service Name:** `ch.rm-rf.openssl_encrypt`
**Object Path:** `/ch/rm_rf/openssl_encrypt/CryptoService`
**Interface:** `ch.rm-rf.openssl_encrypt.Crypto`

## Key Benefits

- **No network access required**: Uses local IPC only
- **Flatpak compatible**: Works within sandbox constraints
- **Language agnostic**: Any language with D-Bus support can use it
- **Secure by design**: Polkit integration, audit logging, secure memory handling
- **Auto-activation**: Service starts on-demand
- **Standard Linux pattern**: Similar to GNOME Keyring, Secret Service

## Installation

### Prerequisites

Install D-Bus Python bindings:

```bash
# Debian/Ubuntu
sudo apt install python3-dbus python3-gi

# Fedora
sudo dnf install python3-dbus python3-gobject

# Arch
sudo pacman -S python-dbus python-gobject

# Or via pip
pip install dbus-python PyGObject
```

### User Installation (Session Bus)

For per-user service (recommended for Flatpak):

```bash
# Install D-Bus service file
mkdir -p ~/.local/share/dbus-1/services/
cp openssl_encrypt/dbus/ch.rm-rf.openssl_encrypt.service \
   ~/.local/share/dbus-1/services/

# Install systemd user service (optional)
mkdir -p ~/.config/systemd/user/
cp systemd/openssl-encrypt-dbus.service \
   ~/.config/systemd/user/

# Reload systemd
systemctl --user daemon-reload
```

### System Installation (System Bus)

For system-wide service:

```bash
# Install D-Bus service file
sudo cp openssl_encrypt/dbus/ch.rm-rf.openssl_encrypt.service \
        /usr/share/dbus-1/services/

# Install D-Bus configuration
sudo cp openssl_encrypt/dbus/ch.rm-rf.openssl_encrypt.conf \
        /etc/dbus-1/system.d/

# Install Polkit policy
sudo cp openssl_encrypt/dbus/ch.rm-rf.openssl_encrypt.policy \
        /usr/share/polkit-1/actions/

# Install systemd service
sudo cp systemd/openssl-encrypt-dbus.service \
        /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

## Usage

### Python Client

```python
from openssl_encrypt.modules.dbus_client import CryptoClient

# Create client
client = CryptoClient()

# Define progress callback
def on_progress(operation_id, percent, message):
    print(f"Progress: {percent:.1f}% - {message}")

# Encrypt a file
success, error, op_id = client.encrypt_file(
    input_path="/path/to/input.txt",
    output_path="/path/to/output.enc",
    password="secure_password_123",
    algorithm="ml-kem-768-hybrid",
    options={
        "balloon_rounds": 5,
        "sha512_rounds": 50000,
        "enable_hkdf": True
    },
    progress_callback=on_progress
)

if success:
    print(f"Encryption started: {op_id}")
else:
    print(f"Encryption failed: {error}")

# Decrypt a file
success, error, op_id = client.decrypt_file(
    input_path="/path/to/output.enc",
    output_path="/path/to/decrypted.txt",
    password="secure_password_123"
)

# Generate PQC key
success, key_id, error = client.generate_pqc_key(
    algorithm="ml-kem-768",
    keystore_path="/path/to/keystore.pqc",
    keystore_password="keystore_password",
    key_name="My Key"
)

# List supported algorithms
algorithms = client.get_supported_algorithms()
print(f"Supported: {algorithms}")

# Get service version
version = client.get_version()
print(f"Version: {version}")
```

### Shell Script (using busctl)

```bash
# Get version
busctl --user call ch.rm-rf.openssl_encrypt \
    /ch/rm_rf/openssl_encrypt/CryptoService \
    ch.rm-rf.openssl_encrypt.Crypto \
    GetVersion

# Get supported algorithms
busctl --user call ch.rm-rf.openssl_encrypt \
    /ch/rm_rf/openssl_encrypt/CryptoService \
    ch.rm-rf.openssl_encrypt.Crypto \
    GetSupportedAlgorithms

# Validate password
busctl --user call ch.rm-rf.openssl_encrypt \
    /ch/rm_rf/openssl_encrypt/CryptoService \
    ch.rm-rf.openssl_encrypt.Crypto \
    ValidatePassword s "test_password"

# Get active operations count
busctl --user get-property ch.rm-rf.openssl_encrypt \
    /ch/rm_rf/openssl_encrypt/CryptoService \
    ch.rm-rf.openssl_encrypt.Crypto \
    ActiveOperations
```

### C/C++ Client (GDBus)

```c
#include <gio/gio.h>
#include <stdio.h>

int main() {
    GError *error = NULL;
    GDBusConnection *connection;
    GVariant *result;

    // Connect to session bus
    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (error) {
        fprintf(stderr, "Error connecting to D-Bus: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    // Call GetVersion method
    result = g_dbus_connection_call_sync(
        connection,
        "ch.rm-rf.openssl_encrypt",
        "/ch/rm_rf/openssl_encrypt/CryptoService",
        "ch.rm-rf.openssl_encrypt.Crypto",
        "GetVersion",
        NULL,
        G_VARIANT_TYPE("(s)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error
    );

    if (error) {
        fprintf(stderr, "Error calling GetVersion: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    // Extract version string
    const char *version;
    g_variant_get(result, "(&s)", &version);
    printf("Version: %s\n", version);

    g_variant_unref(result);
    g_object_unref(connection);
    return 0;
}
```

Compile with:
```bash
gcc example.c -o example $(pkg-config --cflags --libs gio-2.0)
```

### Rust Client (zbus)

Add to `Cargo.toml`:
```toml
[dependencies]
zbus = "3.0"
tokio = { version = "1", features = ["full"] }
```

```rust
use zbus::{Connection, Result, dbus_proxy};

#[dbus_proxy(
    interface = "ch.rm-rf.openssl_encrypt.Crypto",
    default_service = "ch.rm-rf.openssl_encrypt",
    default_path = "/ch/rm_rf/openssl_encrypt/CryptoService"
)]
trait Crypto {
    fn get_version(&self) -> Result<String>;
    fn get_supported_algorithms(&self) -> Result<Vec<String>>;
    fn encrypt_file(
        &self,
        input_path: &str,
        output_path: &str,
        password: &str,
        algorithm: &str,
        options: std::collections::HashMap<String, zbus::zvariant::Value>,
    ) -> Result<(bool, String, String)>;
}

#[tokio::main]
async fn main() -> Result<()> {
    let connection = Connection::session().await?;
    let proxy = CryptoProxy::new(&connection).await?;

    // Get version
    let version = proxy.get_version().await?;
    println!("Version: {}", version);

    // Get algorithms
    let algorithms = proxy.get_supported_algorithms().await?;
    println!("Algorithms: {:?}", algorithms);

    Ok(())
}
```

### Go Client (godbus)

```go
package main

import (
    "fmt"
    "github.com/godbus/dbus/v5"
)

func main() {
    // Connect to session bus
    conn, err := dbus.SessionBus()
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    // Get proxy object
    obj := conn.Object(
        "ch.rm-rf.openssl_encrypt",
        "/ch/rm_rf/openssl_encrypt/CryptoService",
    )

    // Call GetVersion method
    var version string
    err = obj.Call(
        "ch.rm-rf.openssl_encrypt.Crypto.GetVersion",
        0,
    ).Store(&version)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Version: %s\n", version)

    // Call GetSupportedAlgorithms
    var algorithms []string
    err = obj.Call(
        "ch.rm-rf.openssl_encrypt.Crypto.GetSupportedAlgorithms",
        0,
    ).Store(&algorithms)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Algorithms: %v\n", algorithms)
}
```

### JavaScript/Node.js Client (dbus-next)

```javascript
const dbus = require('dbus-next');

async function main() {
    const bus = dbus.sessionBus();

    const obj = await bus.getProxyObject(
        'ch.rm-rf.openssl_encrypt',
        '/ch/rm_rf/openssl_encrypt/CryptoService'
    );

    const iface = obj.getInterface('ch.rm-rf.openssl_encrypt.Crypto');

    // Get version
    const version = await iface.GetVersion();
    console.log(`Version: ${version}`);

    // Get algorithms
    const algorithms = await iface.GetSupportedAlgorithms();
    console.log(`Algorithms: ${algorithms}`);

    // Encrypt file
    const [success, error, opId] = await iface.EncryptFile(
        '/path/to/input.txt',
        '/path/to/output.enc',
        'password',
        'ml-kem-768-hybrid',
        {}
    );

    console.log(`Encryption success: ${success}, op_id: ${opId}`);
}

main().catch(console.error);
```

## Flatpak Integration

### Manifest Configuration

Add to your Flatpak manifest:

```yaml
finish-args:
  # Allow talking to openssl_encrypt D-Bus service
  - --talk-name=ch.rm-rf.openssl_encrypt

  # Optional: Allow Polkit authentication
  - --system-talk-name=org.freedesktop.PolicyKit1

  # Allow file access for encryption/decryption
  - --filesystem=home
```

### Runtime Installation

The D-Bus service can be included in your Flatpak:

```yaml
modules:
  - name: openssl_encrypt
    buildsystem: simple
    build-commands:
      - pip3 install --prefix=/app .
      - install -Dm644 openssl_encrypt/dbus/ch.rm-rf.openssl_encrypt.service \
          /app/share/dbus-1/services/ch.rm-rf.openssl_encrypt.service
      - install -Dm644 openssl_encrypt/dbus/interface.xml \
          /app/share/dbus-1/interfaces/ch.rm-rf.openssl_encrypt.Crypto.xml
```

## API Reference

### Methods

#### EncryptFile
```
EncryptFile(s input_path, s output_path, s password, s algorithm, a{sv} options)
→ (b success, s error_msg, s operation_id)
```

Encrypts a file with the specified algorithm and password.

**Options:**
- `sha256_rounds` (i): Number of SHA-256 rounds
- `sha512_rounds` (i): Number of SHA-512 rounds
- `blake3_rounds` (i): Number of BLAKE3 rounds
- `balloon_rounds` (i): Number of Balloon hash rounds
- `enable_hkdf` (b): Enable HKDF key derivation
- `argon2_mode` (s): Argon2 mode ("argon2i", "argon2d", "argon2id")
- `template` (s): Preset template ("quick", "standard", "paranoid")

#### DecryptFile
```
DecryptFile(s input_path, s output_path, s password)
→ (b success, s error_msg, s operation_id)
```

Decrypts a file encrypted by openssl_encrypt.

#### GeneratePQCKey
```
GeneratePQCKey(s algorithm, s keystore_path, s keystore_password, s key_name)
→ (b success, s key_id, s error_msg)
```

Generates a post-quantum cryptographic key pair.

#### GetSupportedAlgorithms
```
GetSupportedAlgorithms() → (as algorithms)
```

Returns list of supported encryption algorithms.

#### GetVersion
```
GetVersion() → (s version)
```

Returns openssl_encrypt version string.

### Signals

#### Progress
```
Progress(s operation_id, d percent, s message)
```

Emitted during long-running operations to report progress.

#### OperationComplete
```
OperationComplete(s operation_id, b success, s error_msg)
```

Emitted when an operation finishes.

### Properties

#### ActiveOperations (read-only)
```
u ActiveOperations
```

Number of currently running operations.

#### MaxConcurrentOperations (read/write)
```
u MaxConcurrentOperations
```

Maximum number of concurrent operations allowed.

#### DefaultTimeout (read/write)
```
u DefaultTimeout
```

Default operation timeout in seconds.

## Security Considerations

### Password Handling
- Passwords are never stored permanently
- Passwords are securely zeroed from memory after use
- Use SecureBytes internally for password storage

### File Path Validation
- All file paths are validated to prevent directory traversal
- Paths must be absolute
- Paths cannot contain ".." components

### Resource Limits
- Configurable maximum concurrent operations
- Per-operation timeouts prevent DoS
- Memory and CPU limits via systemd

### Audit Logging
- All operations are logged to systemd journal
- Logs include: operation type, user, timestamp, success/failure
- View logs: `journalctl -u openssl-encrypt-dbus.service`

### Polkit Authorization
- Optional Polkit integration for fine-grained access control
- Different policies for encrypt, decrypt, shred, keystore operations
- Can require authentication for sensitive operations

## Troubleshooting

### Service Not Starting

Check if service is running:
```bash
systemctl --user status openssl-encrypt-dbus.service
```

View logs:
```bash
journalctl --user -u openssl-encrypt-dbus.service -f
```

Manually start service:
```bash
python3 -m openssl_encrypt.modules.dbus_service
```

### Connection Errors

Verify D-Bus service file is installed:
```bash
ls ~/.local/share/dbus-1/services/ch.rm-rf.openssl_encrypt.service
```

Test connection:
```bash
busctl --user list | grep openssl_encrypt
```

### Permission Denied

Check Polkit policy:
```bash
pkaction --action-id ch.rm-rf.openssl_encrypt.encrypt --verbose
```

Check D-Bus configuration:
```bash
cat /etc/dbus-1/system.d/ch.rm-rf.openssl_encrypt.conf
```

## Performance

### Benchmarks

Typical operation times (Intel i7, SSD):
- File encryption (1 MB, standard template): ~2 seconds
- File encryption (1 MB, paranoid template): ~40 seconds
- File decryption (1 MB): ~1 second
- PQC key generation (ML-KEM-768): ~0.5 seconds

### Optimization Tips

1. **Reduce hash rounds** for faster encryption (less security)
2. **Use quick template** for testing/development
3. **Process multiple files concurrently** (up to MaxConcurrentOperations)
4. **Use data encryption methods** for small data to avoid file I/O overhead

## Development

### Running Tests

```bash
python3 -m pytest tests/test_dbus_service.py -v
```

### Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Monitor D-Bus traffic:
```bash
dbus-monitor --session "sender='ch.rm-rf.openssl_encrypt'"
```

### Contributing

See main project README for contribution guidelines.

## License

Same as openssl_encrypt project.

## Support

Create issues at: https://gitlab.rm-rf.ch/world/openssl_encrypt/-/issues

Or email: issue+world-openssl-encrypt-2-issue-+gitlab@rm-rf.ch
