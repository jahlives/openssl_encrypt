#!/usr/bin/env python3
"""
The portable-USB workspace must be genuinely encrypted at rest (gitlab#263, F27).

Before the fix, `_create_encrypted_workspace` received the derived key but never
used it: it wrote a `.workspace` marker declaring `encrypted: true`, a README
titled "Encrypted USB Workspace" claiming "AES-256-GCM encryption", and returned
`{"encryption": "AES-256-GCM"}` -- while the `data/` directory was ordinary
cleartext. A user who trusted the branding and dropped a file into the workspace
left it unencrypted on the removable media (CWE-311, a false security assurance).

The fix adds a real AES-256-GCM workspace vault:
  * `_seal_workspace_vault` archives the workspace's regular files into an
    authenticated `workspace.vault` (nonce + ciphertext under the derived key),
  * `_unlock_workspace_vault` decrypts + extracts it, rejecting tamper and any
    archive member that would escape the destination directory,
  * `_create_encrypted_workspace` seals a real (initially empty) vault using the
    key and writes an HONEST marker/README (content is protected only when
    sealed; loose files are NOT encrypted until sealed).
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator


class TestWorkspaceVaultRoundTrip(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.key = os.urandom(32)

    def test_seal_then_unlock_round_trips_files(self):
        src = self.tmp / "work"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_bytes(b"hello alpha")
        (src / "sub" / "b.bin").write_bytes(os.urandom(2048))
        vault = self.tmp / "workspace.vault"

        n = self.creator._seal_workspace_vault(src, vault, self.key)
        self.assertEqual(n, 2)
        self.assertTrue(vault.exists())

        # The vault must NOT be cleartext: the plaintext bytes must be absent.
        blob = vault.read_bytes()
        self.assertNotIn(b"hello alpha", blob)

        dest = self.tmp / "restored"
        m = self.creator._unlock_workspace_vault(vault, dest, self.key)
        self.assertEqual(m, 2)
        self.assertEqual((dest / "a.txt").read_bytes(), b"hello alpha")
        self.assertEqual(
            (dest / "sub" / "b.bin").read_bytes(),
            (src / "sub" / "b.bin").read_bytes(),
        )

    def test_wrong_key_is_rejected(self):
        src = self.tmp / "work"
        src.mkdir()
        (src / "secret.txt").write_bytes(b"top secret")
        vault = self.tmp / "workspace.vault"
        self.creator._seal_workspace_vault(src, vault, self.key)

        with self.assertRaises((InvalidTag, Exception)):
            self.creator._unlock_workspace_vault(vault, self.tmp / "out", os.urandom(32))

    def test_tampered_vault_is_rejected(self):
        src = self.tmp / "work"
        src.mkdir()
        (src / "secret.txt").write_bytes(b"top secret")
        vault = self.tmp / "workspace.vault"
        self.creator._seal_workspace_vault(src, vault, self.key)

        blob = bytearray(vault.read_bytes())
        blob[-1] ^= 0x01  # flip a ciphertext bit
        vault.write_bytes(bytes(blob))

        with self.assertRaises((InvalidTag, Exception)):
            self.creator._unlock_workspace_vault(vault, self.tmp / "out", self.key)

    def test_vault_uses_owner_only_permissions(self):
        src = self.tmp / "work"
        src.mkdir()
        (src / "a.txt").write_bytes(b"x")
        vault = self.tmp / "workspace.vault"
        self.creator._seal_workspace_vault(src, vault, self.key)
        # owner-only (0600): no group/other bits
        self.assertEqual(vault.stat().st_mode & 0o077, 0)


class TestVaultRejectsPathTraversal(unittest.TestCase):
    """A forged member name must never write outside the destination dir."""

    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.key = os.urandom(32)

    def _make_malicious_vault(self, member_name: str) -> Path:
        import io
        import tarfile

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            data = b"pwned"
            ti = tarfile.TarInfo(name=member_name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        nonce = os.urandom(self.creator.NONCE_LENGTH)
        ct = AESGCM(self.key).encrypt(nonce, buf.getvalue(), None)
        vault = self.tmp / "evil.vault"
        vault.write_bytes(nonce + ct)
        return vault

    def test_parent_traversal_member_is_rejected(self):
        vault = self._make_malicious_vault("../escape.txt")
        dest = self.tmp / "dest"
        with self.assertRaises(Exception):
            self.creator._unlock_workspace_vault(vault, dest, self.key)
        self.assertFalse((self.tmp / "escape.txt").exists())

    def test_absolute_member_is_rejected(self):
        marker = self.tmp / "abs_escape.txt"
        vault = self._make_malicious_vault("/" + str(marker.relative_to("/")))
        dest = self.tmp / "dest"
        with self.assertRaises(Exception):
            self.creator._unlock_workspace_vault(vault, dest, self.key)
        self.assertFalse(marker.exists())


class TestCreateEncryptedWorkspaceIsHonest(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.workspace = self.tmp / "data"
        self.workspace.mkdir()
        self.key = os.urandom(32)

    def test_creates_a_real_encrypted_vault_using_the_key(self):
        info = self.creator._create_encrypted_workspace(self.workspace, self.key)
        vault = self.workspace / "workspace.vault"
        self.assertTrue(vault.exists(), "a real encrypted vault must be created")
        self.assertTrue(info.get("created"))
        # The vault must be decryptable with the SAME key -> it genuinely used it.
        m = self.creator._unlock_workspace_vault(vault, self.tmp / "out", self.key)
        self.assertEqual(m, 0)  # initially empty workspace

    def test_marker_is_honest_not_a_blanket_encrypted_true(self):
        self.creator._create_encrypted_workspace(self.workspace, self.key)
        marker = json.loads((self.workspace / ".workspace").read_text())
        # Must reference the real vault + warn that loose files are unprotected.
        self.assertEqual(marker.get("vault"), "workspace.vault")
        self.assertIn("note", marker)
        self.assertIn("not", marker["note"].lower())

    def test_readme_does_not_claim_transparent_directory_encryption(self):
        self.creator._create_encrypted_workspace(self.workspace, self.key)
        readme = (self.workspace / "README.txt").read_text().lower()
        # It must document the seal/unlock workflow ...
        self.assertIn("seal", readme)
        self.assertIn("unlock", readme)
        # ... and must NOT imply that loose files in the dir are auto-encrypted.
        self.assertNotIn("encrypted files are stored safely in this workspace", readme)


class TestGeneratedHelperExposesSealUnlock(unittest.TestCase):
    """The portable crypt.py must offer seal/unlock and re-derive the key
    without a package-relative import (which fails on a standalone script)."""

    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.portable_root = self.tmp / "portable"
        self.portable_root.mkdir()
        self.creator._create_transparent_encryption_helpers(self.portable_root)
        self.source = (self.portable_root / "crypt.py").read_text(encoding="utf-8")

    def test_generated_script_is_valid_python(self):
        import ast

        ast.parse(self.source)

    def test_seal_and_unlock_are_wired(self):
        self.assertIn("def run_seal", self.source)
        self.assertIn("def run_unlock", self.source)
        self.assertIn("_seal_workspace_vault", self.source)
        self.assertIn("_unlock_workspace_vault", self.source)

    def test_no_package_relative_imports(self):
        offenders = [
            line
            for line in self.source.splitlines()
            if line.strip().startswith("from ..") or line.strip().startswith("from .")
        ]
        self.assertEqual(offenders, [], offenders)

    def test_password_never_from_argv(self):
        # The key derivation reads CRYPT_PASSWORD or prompts; never argv.
        self.assertIn("CRYPT_PASSWORD", self.source)
        self.assertIn("getpass", self.source)

    def test_stored_hash_config_is_bounded_and_validated(self):
        # The drive is untrusted: the on-target key derivation must not read an
        # unbounded hash_config.json nor feed it to the KDF unvalidated.
        self.assertIn("_MAX_HASH_CONFIG_BYTES", self.source)
        self.assertIn("_validated_drive_hash_config", self.source)

    def test_rederived_key_is_zeroized(self):
        self.assertIn("secure_memzero", self.source)


if __name__ == "__main__":
    unittest.main()
