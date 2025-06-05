#!/usr/bin/env python3
"""
Common Password List Generator

This script generates a compressed and encoded version of common passwords
for embedding in the password_policy.py module. This ensures baseline protection
against common passwords even when external files are not available.
"""

import base64
import os
import sys
import urllib.request
import zlib
from pathlib import Path

# URLs for common password lists
COMMON_PASSWORD_URLS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "https://github.com/OWASP/passfault/raw/master/wordlists/wordlists/common-passwords-win.txt",
]

# Local paths to consider
LOCAL_PATHS = [
    "/usr/share/dict/words",
    "/usr/share/common-passwords/common-passwords.txt",
]


def download_password_lists(target_dir, max_passwords=10000):
    """Download common password lists and combine them into a single file."""
    os.makedirs(target_dir, exist_ok=True)
    output_path = os.path.join(target_dir, "common_passwords.txt")

    passwords = set()

    # Try to download from each URL
    for url in COMMON_PASSWORD_URLS:
        try:
            print(f"Downloading from {url}...")
            with urllib.request.urlopen(url) as response:
                content = response.read().decode("utf-8", errors="ignore")
                for line in content.splitlines():
                    password = line.strip()
                    if password and len(password) >= 6:  # Only include reasonably sized passwords
                        passwords.add(password)
                        if len(passwords) >= max_passwords:
                            break
        except Exception as e:
            print(f"Error downloading from {url}: {e}")

    # Try to include passwords from local files
    for path in LOCAL_PATHS:
        if os.path.exists(path):
            try:
                print(f"Reading from {path}...")
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        password = line.strip()
                        if password and len(password) >= 6:
                            passwords.add(password)
                            if len(passwords) >= max_passwords:
                                break
            except Exception as e:
                print(f"Error reading from {path}: {e}")

    # Write combined list to output file
    passwords = sorted(list(passwords))[:max_passwords]
    with open(output_path, "w", encoding="utf-8") as f:
        for password in passwords:
            f.write(f"{password}\n")

    print(f"Wrote {len(passwords)} passwords to {output_path}")
    return output_path


def compress_and_encode(input_path):
    """Compress and base64 encode the password list for embedding."""
    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Compress with zlib
    compressed = zlib.compress(content.encode("utf-8"), level=9)

    # Encode with base64
    encoded = base64.b64encode(compressed).decode("ascii")

    # Format for embedding in Python code
    formatted = "\n    ".join([encoded[i : i + 80] for i in range(0, len(encoded), 80)])

    print(f"Original size: {len(content)} bytes")
    print(f"Compressed size: {len(compressed)} bytes")
    print(f"Encoded size: {len(encoded)} bytes")
    print(f"Compression ratio: {len(compressed) / len(content):.2f}")

    return f'"""\n    {formatted}\n    """'


def main():
    """Main function."""
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    else:
        # Default to a data directory in the current directory
        target_dir = os.path.join(os.path.dirname(__file__), "data")

    password_file = download_password_lists(target_dir)
    encoded_data = compress_and_encode(password_file)

    print("\nEmbedded data for password_policy.py:")
    print("EMBEDDED_PASSWORDS_B64Z =", encoded_data)


if __name__ == "__main__":
    main()
