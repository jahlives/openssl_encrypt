## Installation

### Requirements

- Python 3.6 or higher
- Dependencies: cryptography (required), pywhirlpool (optional), tkinter (for GUI)

### Installation Methods

#### From PyPI (Recommended)

The easiest way to install is via pip from PyPI:

```bash
pip install openssl_encrypt
```

#### From GitLab Package Registry

The package is also available from the custom GitLab package registry:

```bash
# Configure pip to use the custom package registry
pip config set global.extra-index-url https://gitlab.rm-rf.ch/api/v4/projects/world%2Fopenssl_encrypt/packages/pypi/simple

# Install the package
pip install openssl_encrypt
```

#### From Source

1. Clone or download this repository
2. Install required packages:

```bash
pip install -r requirements.txt
```

### Optional Dependencies

#### For GUI Support
The GUI interface requires tkinter:

```bash
# On Debian/Ubuntu
sudo apt-get install python3-tk

# On Fedora
sudo dnf install python3-tkinter

# On macOS (with Homebrew)
brew install python-tk
```

#### For Enhanced Security Features

For Argon2 support:
```bash
pip install argon2-cffi
```

For Whirlpool support:
```bash
pip install pywhirlpool
```

### Development Installation

For development purposes, install additional testing dependencies:

```bash
pip install -e ".[dev]"
# or
pip install pytest pylint coverage
```

### Testing

After installation I highly recommend running the unit tests first.  
Although they're also run when I commit, it's always preferable to verify that  
locally before encrypting important files. Better safe than sorry ;-)

```bash
pip install pytest
pytest unittests/unittests.pytest
```

They all must pass or [else open an issue here](mailto:tobster+world-openssl-encrypt-2-issue-+gitlab@brain-force.ch) :-)  
Another recommendation is to avoid the `--overwrite` parameter first when encrypting  
and verify first that the file can be decrypted.

### Verifying Installation

You can verify the installation by running:

```bash
python -m openssl_encrypt.crypt version
```

### Troubleshooting

If you encounter any installation issues:

1. Ensure you have the latest pip version:
   ```bash
   pip install --upgrade pip
   ```

2. If you're behind a proxy, make sure your pip configuration includes the proper proxy settings

3. For system-level installations, you might need to use `sudo` (Linux/macOS) or run as administrator (Windows)

4. If you encounter SSL/TLS errors when installing from the custom registry, ensure your system's CA certificates are up to date

### Package Signatures

The packages on both PyPI and the GitLab registry are signed. You can verify the signature using:

```bash
pip install openssl_encrypt --require-hashes
```

### Offline Installation

For air-gapped systems, you can download the wheel file from either:
- PyPI: https://pypi.org/project/openssl_encrypt/
- GitLab: https://gitlab.rm-rf.ch/world/openssl_encrypt/-/packages

Then install using:

```bash
pip install openssl_encrypt-x.x.x-py3-none-any.whl
```
