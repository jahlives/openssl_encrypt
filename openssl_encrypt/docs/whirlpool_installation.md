# Whirlpool Hash Module Installation Guide

The Whirlpool hash algorithm is an optional but recommended component for enhancing security in openssl_encrypt. This guide will help you install and configure the Whirlpool module correctly, especially for newer Python versions.

## Automatic Installation

When you install `openssl_encrypt`, it will automatically attempt to install and configure the appropriate Whirlpool module for your Python version. The package includes two different implementations:

- `Whirlpool` - For Python versions below 3.11
- `whirlpool-py311` - For Python 3.11 and above

## Manual Installation Steps

If you encounter issues with the automatic installation, you can manually install and configure Whirlpool:

### For Python 3.11 and above:

```bash
# Install the Python 3.11+ compatible version
pip install whirlpool-py311

# Create a symbolic link for the module (Linux/Mac):
# 1. Find the installed module
SITE_PACKAGES=$(python -c "import site; print(site.getsitepackages()[0])")
WHIRLPOOL_MODULE=$(find $SITE_PACKAGES -name "whirlpool-py311*.so")
PYTHON_VERSION=$(python -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")
MACHINE_TYPE=$(python -c "import platform; print(platform.machine())")

# 2. Create the symbolic link
ln -sf $WHIRLPOOL_MODULE $SITE_PACKAGES/whirlpool.cpython-${PYTHON_VERSION}-${MACHINE_TYPE}-linux-gnu.so
```

### For Windows:

```powershell
# Install the appropriate version based on your Python version
pip install whirlpool-py311  # For Python 3.11+
# OR
pip install Whirlpool  # For Python 3.10 and below

# Copy the module (need to run as administrator)
$pythonPath = python -c "import sys; print(sys.executable)"
$sitePackages = python -c "import site; print(site.getsitepackages()[1])"
$pythonVersion = python -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')"

# Find the module
$whirlpoolModule = Get-ChildItem -Path $sitePackages -Recurse -Filter "whirlpool*.pyd" | Select-Object -First 1
$targetPath = Join-Path $sitePackages "whirlpool.pyd"

# Create a copy
Copy-Item $whirlpoolModule.FullName $targetPath
```

## Verifying Installation

You can verify the Whirlpool module is working correctly by running:

```python
python -c "import whirlpool; print('Whirlpool module successfully installed!')"
```

## Troubleshooting

If you encounter issues with the Whirlpool module:

1. **ImportError: No module named 'whirlpool'**
   - Make sure you've installed the correct version for your Python version
   - Check if the symbolic link or file copy was created correctly

2. **Module works but openssl_encrypt doesn't recognize it**
   - The module may be installed in a different Python environment than openssl_encrypt
   - Make sure you're using the same Python interpreter for both

3. **Permission issues creating symbolic links**
   - On Linux/Mac, you may need to use `sudo` to create the symbolic link in system directories
   - On Windows, you need administrative privileges to copy files to system directories

4. **Other Issues**
   - Run `python -m openssl_encrypt.modules.setup_whirlpool` to manually trigger the setup process
   - Check the logs for any specific errors by adding the `-v` flag to your pip install command