# D-Bus Client Examples

This directory contains example code demonstrating how to use the openssl_encrypt D-Bus service from various programming languages.

## Prerequisites

1. **Install openssl_encrypt**:
   ```bash
   pip install -e .
   ```

2. **Install D-Bus dependencies**:
   ```bash
   # Debian/Ubuntu
   sudo apt install python3-dbus python3-gi

   # Fedora
   sudo dnf install python3-dbus python3-gobject

   # Arch
   sudo pacman -S python-dbus python-gobject
   ```

3. **Start the D-Bus service**:
   ```bash
   python3 -m openssl_encrypt.modules.dbus_service
   ```

   Or in a separate terminal for testing.

## Examples

### Python Example

**File**: `python_example.py`

**Run**:
```bash
python3 examples/dbus_clients/python_example.py
```

**Features**:
- Connects to D-Bus service
- Gets service version and supported algorithms
- Validates passwords
- Encrypts and decrypts a test file
- Demonstrates progress callbacks
- Generates post-quantum keys

### Shell Script Example

**File**: `shell_example.sh`

**Run**:
```bash
./examples/dbus_clients/shell_example.sh
```

**Features**:
- Uses `busctl` command-line tool
- Demonstrates basic method calls
- Shows property access
- Monitors D-Bus signals

### Rust Example

**File**: `rust_example.rs`

**Setup**:
```bash
# Create new Rust project
cargo new --bin openssl_encrypt_client
cd openssl_encrypt_client

# Copy the example
cp ../openssl_encrypt/examples/dbus_clients/rust_example.rs src/main.rs

# Add dependencies to Cargo.toml:
[dependencies]
zbus = "3.15"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
```

**Run**:
```bash
cargo run
```

**Features**:
- Async/await with Tokio
- Type-safe D-Bus proxy
- Full encryption/decryption workflow
- Error handling with anyhow

### C/C++ Example

See the [D-Bus Service documentation](../../openssl_encrypt/docs/dbus-service.md#cc-client-gdbus) for C/C++ examples using GDBus.

### Go Example

See the [D-Bus Service documentation](../../openssl_encrypt/docs/dbus-service.md#go-client-godbus) for Go examples using godbus.

### JavaScript/Node.js Example

See the [D-Bus Service documentation](../../openssl_encrypt/docs/dbus-service.md#javascriptnodejs-client-dbus-next) for JavaScript examples using dbus-next.

## Common Operations

### Encrypt a File

```python
from openssl_encrypt.modules.dbus_client import CryptoClient

client = CryptoClient()
success, error, op_id = client.encrypt_file(
    "/path/to/input.txt",
    "/path/to/output.enc",
    "password",
    "ml-kem-768-hybrid"
)
```

### Decrypt a File

```python
success, error, op_id = client.decrypt_file(
    "/path/to/output.enc",
    "/path/to/decrypted.txt",
    "password"
)
```

### Generate PQC Key

```python
success, key_id, error = client.generate_pqc_key(
    "ml-kem-768",
    "/path/to/keystore.pqc",
    "keystore_password",
    "My Key"
)
```

### List Supported Algorithms

```python
algorithms = client.get_supported_algorithms()
print(algorithms)
```

## Progress Monitoring

All encryption/decryption operations can have progress callbacks:

```python
def on_progress(op_id, percent, message):
    print(f"{percent:.1f}% - {message}")

def on_complete(op_id, success, error):
    if success:
        print("Operation completed!")
    else:
        print(f"Operation failed: {error}")

client.encrypt_file(
    input_path,
    output_path,
    password,
    algorithm,
    progress_callback=on_progress,
    completion_callback=on_complete
)
```

## Troubleshooting

### Service Not Found

If you get "Service not found" errors:

1. Check if service is running:
   ```bash
   busctl --user list | grep openssl_encrypt
   ```

2. Start the service manually:
   ```bash
   python3 -m openssl_encrypt.modules.dbus_service
   ```

3. Check D-Bus service file is installed:
   ```bash
   ls ~/.local/share/dbus-1/services/ch.rm-rf.openssl_encrypt.service
   ```

### Connection Timeout

If operations timeout:

1. Increase client timeout:
   ```python
   client = CryptoClient(timeout=600)  # 10 minutes
   ```

2. Check service timeout property:
   ```python
   timeout = client.get_default_timeout()
   client.set_default_timeout(600)
   ```

### Permission Denied

If you get permission errors:

1. Check if running on correct bus (session vs system)
2. Verify Polkit policies are installed
3. Check D-Bus configuration file

## More Information

See the [D-Bus Service documentation](../../openssl_encrypt/docs/dbus-service.md) for:
- Complete API reference
- Security considerations
- Flatpak integration
- Performance tuning
- Advanced usage
