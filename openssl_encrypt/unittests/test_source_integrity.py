#!/usr/bin/env python3
"""
Unit tests for the source-code integrity protection subsystem.

This suite is developed test-first (TDD) alongside the openssl_encrypt.integrity
package. It is organised by implementation step:

- Step 1: allowlist loading and validation (this commit)

Security-relevant cases (adversarial allowlist entries, path traversal, symlinks,
tamper detection, signature failures, fail-closed behaviour) are covered as the
corresponding implementation lands.
"""

import os
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.integrity.allowlist import (
    AllowlistError,
    default_allowlist_path,
    load_allowlist,
)


class TestAllowlistLoading(unittest.TestCase):
    """Parsing and validation of the protected-files allowlist."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, content: str) -> Path:
        path = Path(self.tmpdir) / "protected_files.txt"
        path.write_text(content, encoding="utf-8")
        return path

    def test_parses_simple_list(self) -> None:
        """Plain entries are returned verbatim."""
        path = self._write("a/b.py\nc/d.py\n")
        self.assertEqual(load_allowlist(path), ["a/b.py", "c/d.py"])

    def test_skips_comments_and_blank_lines(self) -> None:
        """Lines that are blank or start with '#' are ignored."""
        path = self._write("# header comment\n\na/b.py\n   \n# trailing\nc/d.py\n")
        self.assertEqual(load_allowlist(path), ["a/b.py", "c/d.py"])

    def test_strips_surrounding_whitespace(self) -> None:
        """Leading/trailing whitespace on an entry is stripped."""
        path = self._write("  a/b.py  \n\tc/d.py\t\n")
        self.assertEqual(load_allowlist(path), ["a/b.py", "c/d.py"])

    def test_result_is_sorted_and_deduplicated(self) -> None:
        """Output is deterministically sorted with duplicates removed."""
        path = self._write("z/last.py\na/first.py\nz/last.py\nm/mid.py\n")
        self.assertEqual(
            load_allowlist(path),
            ["a/first.py", "m/mid.py", "z/last.py"],
        )

    def test_rejects_absolute_path(self) -> None:
        """Absolute paths are rejected (manifest is repo-relative only)."""
        path = self._write("/etc/passwd\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_rejects_parent_traversal(self) -> None:
        """Entries containing a '..' component are rejected."""
        path = self._write("a/../../secrets.py\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_rejects_bare_parent_traversal(self) -> None:
        """A leading '..' is rejected."""
        path = self._write("../outside.py\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_rejects_backslash_separators(self) -> None:
        """Backslash path separators are rejected (repo uses forward slashes)."""
        path = self._write("a\\b.py\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_missing_file_raises(self) -> None:
        """A nonexistent allowlist path raises AllowlistError, not bare OSError."""
        with self.assertRaises(AllowlistError):
            load_allowlist(Path(self.tmpdir) / "does-not-exist.txt")

    def test_empty_allowlist_raises(self) -> None:
        """An allowlist with no real entries is an error (fail closed)."""
        path = self._write("# only comments\n\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)


class TestShippedAllowlist(unittest.TestCase):
    """The real protected_files.txt shipped in the package."""

    def test_default_allowlist_path_exists(self) -> None:
        """default_allowlist_path() points at a file that exists."""
        self.assertTrue(default_allowlist_path().is_file())

    def test_shipped_allowlist_loads(self) -> None:
        """The shipped allowlist parses and is non-trivial."""
        entries = load_allowlist(default_allowlist_path())
        self.assertGreater(len(entries), 30)

    def test_shipped_entries_all_exist_on_disk(self) -> None:
        """Every protected path resolves to a real file in the repo tree."""
        # Repo root = three levels up from this test file:
        #   <root>/openssl_encrypt/unittests/test_source_integrity.py
        repo_root = Path(__file__).resolve().parents[2]
        entries = load_allowlist(default_allowlist_path())
        missing = [e for e in entries if not (repo_root / e).is_file()]
        self.assertEqual(missing, [], f"Allowlist references missing files: {missing}")

    def test_shipped_allowlist_excludes_generated_version(self) -> None:
        """The auto-generated version.py must never be protected."""
        entries = load_allowlist(default_allowlist_path())
        self.assertNotIn("openssl_encrypt/version.py", entries)


class TestInstallableSubset(unittest.TestCase):
    """The subset of protected files that survive installation into site-packages."""

    def test_filter_keeps_only_package_paths(self) -> None:
        """Only openssl_encrypt/-prefixed entries are installable."""
        from openssl_encrypt.integrity.allowlist import filter_installable

        entries = [
            "openssl_encrypt/cli.py",
            "openssl_encrypt/modules/crypt_core.py",
            "requirements.txt",
            "requirements-dev.in",
            "threefish_native/src/lib.rs",
            "threefish_native/Cargo.toml",
        ]
        self.assertEqual(
            filter_installable(entries),
            ["openssl_encrypt/cli.py", "openssl_encrypt/modules/crypt_core.py"],
        )

    def test_shipped_allowlist_installable_subset(self) -> None:
        """The shipped allowlist yields the installable .py files only (37 on 1.5.x)."""
        from openssl_encrypt.integrity.allowlist import (
            default_allowlist_path,
            filter_installable,
            load_allowlist,
        )

        inst = filter_installable(load_allowlist(default_allowlist_path()))
        self.assertEqual(len(inst), 37)
        self.assertTrue(all(e.startswith("openssl_encrypt/") for e in inst))
        self.assertNotIn("requirements.txt", inst)
        self.assertFalse(any(e.startswith("threefish_native/") for e in inst))


class TestHashFile(unittest.TestCase):
    """SHA-512 file hashing."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _file(self, name: str, data: bytes) -> Path:
        path = Path(self.tmpdir) / name
        path.write_bytes(data)
        return path

    def test_empty_file_known_digest(self) -> None:
        """SHA-512 of the empty input matches the published KAT."""
        from openssl_encrypt.integrity.manifest_core import hash_file

        expected = (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        self.assertEqual(hash_file(self._file("empty", b"")), expected)

    def test_abc_known_digest(self) -> None:
        """SHA-512 of b'abc' matches the published KAT."""
        from openssl_encrypt.integrity.manifest_core import hash_file

        expected = (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        self.assertEqual(hash_file(self._file("abc", b"abc")), expected)

    def test_handles_large_nonutf8_content(self) -> None:
        """Binary / non-UTF-8 content hashes without error (chunked read)."""
        from openssl_encrypt.integrity.manifest_core import hash_file

        data = bytes(range(256)) * 8192  # 2 MiB, all byte values
        digest = hash_file(self._file("blob", data))
        self.assertEqual(len(digest), 128)  # SHA-512 hex length


class TestBuildManifest(unittest.TestCase):
    """Canonical, reproducible manifest construction."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir)
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.py").write_text("alpha\n", encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("beta\n", encoding="utf-8")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_manifest_structure(self) -> None:
        """Manifest carries schema/algorithm/fingerprint and per-file entries."""
        from openssl_encrypt.integrity.manifest_core import (
            HASH_ALGORITHM,
            SCHEMA_VERSION,
            build_manifest,
        )

        m = build_manifest(self.root, ["pkg/a.py", "pkg/b.py"], key_fingerprint="DEADBEEF")
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)
        self.assertEqual(m["hash_algorithm"], HASH_ALGORITHM)
        self.assertEqual(m["key_fingerprint"], "DEADBEEF")
        self.assertEqual(set(m["files"]), {"pkg/a.py", "pkg/b.py"})
        self.assertTrue(m["files"]["pkg/a.py"].startswith("sha512:"))

    def test_no_timestamp_or_commit_fields(self) -> None:
        """Reproducibility (Q5): no volatile provenance fields in the payload."""
        from openssl_encrypt.integrity.manifest_core import build_manifest

        m = build_manifest(self.root, ["pkg/a.py"])
        self.assertNotIn("generated_at_utc", m)
        self.assertNotIn("git_commit", m)

    def test_excludes_self_check_omitted(self) -> None:
        """Missing protected file is a hard error (fail closed)."""
        from openssl_encrypt.integrity.manifest_core import ManifestError, build_manifest

        with self.assertRaises(ManifestError):
            build_manifest(self.root, ["pkg/a.py", "pkg/missing.py"])

    def test_rejects_symlink_entry(self) -> None:
        """A symlinked protected path is rejected (no following links)."""
        from openssl_encrypt.integrity.manifest_core import ManifestError, build_manifest

        link = self.root / "pkg" / "link.py"
        try:
            os.symlink(self.root / "pkg" / "a.py", link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform")
        with self.assertRaises(ManifestError):
            build_manifest(self.root, ["pkg/link.py"])

    def test_rejects_symlink_escape(self) -> None:
        """A path resolving outside the repo root (via symlinked dir) is rejected."""
        from openssl_encrypt.integrity.manifest_core import ManifestError, build_manifest

        outside = Path(self.tmpdir).parent / "outside_secret.py"
        outside.write_text("secret\n", encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        linkdir = self.root / "escape"
        try:
            os.symlink(Path(self.tmpdir).parent, linkdir)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform")
        with self.assertRaises(ManifestError):
            build_manifest(self.root, ["escape/outside_secret.py"])


class TestSerializeManifest(unittest.TestCase):
    """Deterministic canonical serialization."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir)
        for name in ("z.py", "a.py", "m.py"):
            (self.root / name).write_text(name, encoding="utf-8")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_deterministic_regardless_of_entry_order(self) -> None:
        """Same tree + same files in any order -> byte-identical manifest."""
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        m1 = build_manifest(self.root, ["z.py", "a.py", "m.py"], key_fingerprint="K")
        m2 = build_manifest(self.root, ["m.py", "z.py", "a.py"], key_fingerprint="K")
        self.assertEqual(serialize_manifest(m1), serialize_manifest(m2))

    def test_ends_with_newline_and_is_bytes(self) -> None:
        """Serialized form is UTF-8 bytes ending in a single newline."""
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        blob = serialize_manifest(build_manifest(self.root, ["a.py"]))
        self.assertIsInstance(blob, bytes)
        self.assertTrue(blob.endswith(b"\n"))
        self.assertFalse(blob.endswith(b"\n\n"))

    def test_round_trips_as_json(self) -> None:
        """Serialized manifest parses back to an equal mapping."""
        import json

        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        m = build_manifest(self.root, ["a.py", "m.py"], key_fingerprint="K")
        self.assertEqual(json.loads(serialize_manifest(m).decode("utf-8")), m)


def _gpg_or_skip(test: unittest.TestCase) -> str:
    """Return the gpg binary path, or skip the test if gpg is unavailable."""
    import shutil

    gpg = shutil.which("gpg")
    if not gpg:
        test.skipTest("gpg binary not available")
    return gpg


def _make_ephemeral_key(gpg: str, home: Path) -> tuple:
    """Create an Ed25519 signing key in an isolated GNUPGHOME.

    Returns:
        tuple: (fingerprint, armored_public_key_bytes).
    """
    import subprocess

    home.mkdir(mode=0o700, exist_ok=True)
    env = {"GNUPGHOME": str(home), "PATH": os.environ.get("PATH", "")}
    subprocess.run(
        [
            gpg, "--homedir", str(home), "--batch", "--pinentry-mode", "loopback",
            "--passphrase", "", "--quick-generate-key",
            "Integrity Test <test@example.invalid>", "ed25519", "sign", "0",
        ],
        check=True, capture_output=True, env=env,
    )
    listing = subprocess.run(
        [gpg, "--homedir", str(home), "--batch", "--with-colons", "--list-keys"],
        check=True, capture_output=True, env=env, text=True,
    ).stdout
    fpr = ""
    for line in listing.splitlines():
        if line.startswith("fpr:"):
            fpr = line.split(":")[9]
            break
    pub = subprocess.run(
        [gpg, "--homedir", str(home), "--batch", "--armor", "--export", fpr],
        check=True, capture_output=True, env=env,
    ).stdout
    return fpr, pub


class TestGpgRunner(unittest.TestCase):
    """Detached signing and verification via the system gpg binary."""

    def setUp(self) -> None:
        self.gpg = _gpg_or_skip(self)
        self.tmpdir = tempfile.mkdtemp()
        self.home = Path(self.tmpdir) / "gnupg"
        self.fpr, self.pub = _make_ephemeral_key(self.gpg, self.home)
        self.data = b"manifest-bytes\n"

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_sign_then_verify_roundtrip(self) -> None:
        """A detached signature verifies and reports the signing fingerprint."""
        from openssl_encrypt.integrity.gpg_runner import detached_sign, verify_detached

        sig = detached_sign(self.data, self.fpr, home=self.home)
        self.assertIn(b"BEGIN PGP SIGNATURE", sig)
        result = verify_detached(self.data, sig, public_key=self.pub)
        self.assertTrue(result.good)
        self.assertTrue(self.fpr.endswith(result.fingerprint) or result.fingerprint == self.fpr)

    def test_corrupted_signature_fails(self) -> None:
        """A tampered signature does not verify."""
        from openssl_encrypt.integrity.gpg_runner import detached_sign, verify_detached

        sig = bytearray(detached_sign(self.data, self.fpr, home=self.home))
        # Flip a byte inside the armored body (avoid the header line).
        sig[len(sig) // 2] ^= 0x01
        result = verify_detached(self.data, bytes(sig), public_key=self.pub)
        self.assertFalse(result.good)

    def test_modified_data_fails(self) -> None:
        """A signature over different data does not verify."""
        from openssl_encrypt.integrity.gpg_runner import detached_sign, verify_detached

        sig = detached_sign(self.data, self.fpr, home=self.home)
        result = verify_detached(self.data + b"tampered", sig, public_key=self.pub)
        self.assertFalse(result.good)

    def test_fingerprint_mismatch_fails(self) -> None:
        """A valid signature by an unexpected key is reported as not good."""
        from openssl_encrypt.integrity.gpg_runner import detached_sign, verify_detached

        sig = detached_sign(self.data, self.fpr, home=self.home)
        result = verify_detached(
            self.data, sig, public_key=self.pub, expected_fingerprint="0" * 40
        )
        self.assertFalse(result.good)

    def test_missing_gpg_binary_raises_unavailable(self) -> None:
        """A nonexistent gpg binary triggers the fail-closed error (Q8)."""
        from openssl_encrypt.integrity.gpg_runner import (
            GpgUnavailableError,
            verify_detached,
        )

        with self.assertRaises(GpgUnavailableError):
            verify_detached(
                self.data, b"sig", public_key=self.pub, gpg_binary="/nonexistent/gpg-xyz"
            )


class TestVerifyFiles(unittest.TestCase):
    """Hash comparison against a manifest (tamper detection, no signature)."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir)
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.py").write_text("alpha\n", encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("beta\n", encoding="utf-8")
        from openssl_encrypt.integrity.manifest_core import build_manifest

        self.entries = ["pkg/a.py", "pkg/b.py"]
        self.manifest = build_manifest(self.root, self.entries, key_fingerprint="K")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_unmodified_tree_all_ok(self) -> None:
        """An untouched tree verifies clean."""
        from openssl_encrypt.integrity.verify import OK, verify_files

        result = verify_files(self.root, self.manifest)
        self.assertTrue(result.all_ok)
        self.assertTrue(all(s.status == OK for s in result.statuses))
        self.assertEqual(result.problems, [])

    def test_modified_file_detected(self) -> None:
        """A one-byte change flips the file to MODIFIED and fails overall."""
        from openssl_encrypt.integrity.verify import MODIFIED, verify_files

        (self.root / "pkg" / "a.py").write_text("alpha!\n", encoding="utf-8")
        result = verify_files(self.root, self.manifest)
        self.assertFalse(result.all_ok)
        statuses = {s.path: s.status for s in result.statuses}
        self.assertEqual(statuses["pkg/a.py"], MODIFIED)
        self.assertEqual(statuses["pkg/b.py"], "OK")

    def test_missing_file_detected(self) -> None:
        """A deleted protected file is reported MISSING."""
        from openssl_encrypt.integrity.verify import MISSING, verify_files

        (self.root / "pkg" / "a.py").unlink()
        result = verify_files(self.root, self.manifest)
        self.assertFalse(result.all_ok)
        statuses = {s.path: s.status for s in result.statuses}
        self.assertEqual(statuses["pkg/a.py"], MISSING)

    def test_symlink_swap_detected(self) -> None:
        """Replacing a protected file with a symlink is treated as MISSING."""
        from openssl_encrypt.integrity.verify import MISSING, verify_files

        target = self.root / "pkg" / "a.py"
        target.unlink()
        try:
            os.symlink(self.root / "pkg" / "b.py", target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform")
        result = verify_files(self.root, self.manifest)
        statuses = {s.path: s.status for s in result.statuses}
        self.assertEqual(statuses["pkg/a.py"], MISSING)

    def test_unsupported_algorithm_fails_closed(self) -> None:
        """A manifest declaring an unknown hash algorithm is rejected."""
        from openssl_encrypt.integrity.verify import VerifyError, verify_files

        bad = dict(self.manifest)
        bad["hash_algorithm"] = "md5"
        with self.assertRaises(VerifyError):
            verify_files(self.root, bad)


class TestSyncAllManifests(unittest.TestCase):
    """sync_all_manifests maintains both the source and installed manifests."""

    def setUp(self) -> None:
        self.gpg = _gpg_or_skip(self)
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir) / "repo"
        (self.root / "openssl_encrypt" / "modules").mkdir(parents=True)
        (self.root / "openssl_encrypt" / "cli.py").write_text("cli\n", encoding="utf-8")
        (self.root / "openssl_encrypt" / "modules" / "m.py").write_text("m\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("dep\n", encoding="utf-8")
        self.allowlist = self.root / "protected_files.txt"
        self.allowlist.write_text(
            "openssl_encrypt/cli.py\nopenssl_encrypt/modules/m.py\nrequirements.txt\n",
            encoding="utf-8",
        )
        self.src_m = self.root / "manifest.json"
        self.src_s = self.root / "manifest.json.asc"
        self.inst_m = self.root / "manifest-installed.json"
        self.inst_s = self.root / "manifest-installed.json.asc"
        self.home = Path(self.tmpdir) / "gnupg"
        self.fpr, self.pub = _make_ephemeral_key(self.gpg, self.home)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _sync(self):
        from openssl_encrypt.integrity.update_manifest import sync_all_manifests

        return sync_all_manifests(
            self.root,
            key_fingerprint=self.fpr,
            sign=True,
            home=self.home,
            allowlist_path=self.allowlist,
            manifest_path=self.src_m,
            signature_path=self.src_s,
            installed_manifest_path=self.inst_m,
            installed_signature_path=self.inst_s,
        )

    def test_writes_both_manifests(self) -> None:
        """Both manifests and signatures are produced."""
        import json

        self.assertTrue(self._sync())
        for p in (self.src_m, self.src_s, self.inst_m, self.inst_s):
            self.assertTrue(p.is_file(), f"missing {p}")
        src_files = set(json.loads(self.src_m.read_text())["files"])
        inst_files = set(json.loads(self.inst_m.read_text())["files"])
        self.assertEqual(
            src_files,
            {"openssl_encrypt/cli.py", "openssl_encrypt/modules/m.py", "requirements.txt"},
        )
        self.assertEqual(
            inst_files, {"openssl_encrypt/cli.py", "openssl_encrypt/modules/m.py"}
        )

    def test_idempotent(self) -> None:
        """A second run with no changes rewrites nothing."""
        self.assertTrue(self._sync())
        self.assertFalse(self._sync())


class TestVerifyIntegrityCli(unittest.TestCase):
    """The verify-integrity command core: warning, signature + hash, exit codes."""

    def setUp(self) -> None:
        self.gpg = _gpg_or_skip(self)
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir) / "repo"
        (self.root / "pkg").mkdir(parents=True)
        (self.root / "pkg" / "a.py").write_text("alpha\n", encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("beta\n", encoding="utf-8")

        self.home = Path(self.tmpdir) / "gnupg"
        self.fpr, self.pub = _make_ephemeral_key(self.gpg, self.home)

        from openssl_encrypt.integrity.gpg_runner import detached_sign
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        manifest = build_manifest(self.root, ["pkg/a.py", "pkg/b.py"], key_fingerprint=self.fpr)
        self.manifest_bytes = serialize_manifest(manifest)
        self.manifest_path = self.root / "manifest.json"
        self.sig_path = self.root / "manifest.json.asc"
        self.pub_path = self.root / "pub.asc"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.sig_path.write_bytes(detached_sign(self.manifest_bytes, self.fpr, home=self.home))
        self.pub_path.write_bytes(self.pub)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, **overrides):
        import contextlib
        import io

        from openssl_encrypt.integrity import verify_cli

        out, err = io.StringIO(), io.StringIO()
        kwargs = dict(
            repo_root=self.root,
            manifest_path=self.manifest_path,
            signature_path=self.sig_path,
            pubkey_path=self.pub_path,
            expected_fingerprint=self.fpr,
        )
        kwargs.update(overrides)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = verify_cli.verify_integrity(**kwargs)
        return code, out.getvalue(), err.getvalue()

    def test_happy_path_returns_ok(self) -> None:
        """Valid signature + unmodified files -> exit 0."""
        from openssl_encrypt.integrity.verify_cli import EXIT_OK

        code, _out, _err = self._run()
        self.assertEqual(code, EXIT_OK)

    def test_full_warning_printed_by_default(self) -> None:
        """The full trust warning is printed to stderr unless --quiet."""
        _code, _out, err = self._run()
        self.assertIn("tripwire", err.lower())
        self.assertIn("out-of-band", err.lower())

    def test_quiet_shortens_warning(self) -> None:
        """--quiet collapses the warning to a one-line pointer (Q6b)."""
        _code, _out, err = self._run(quiet=True)
        self.assertIn("SOURCE_INTEGRITY", err)
        self.assertLessEqual(len(err.strip().splitlines()), 2)

    def test_json_reports_installed_scope(self) -> None:
        """Installed-context verification labels its reduced scope."""
        import json

        _code, out, _err = self._run(as_json=True, quiet=True, installed=True)
        payload = json.loads(out)
        self.assertEqual(payload["scope"], "installed")

    def test_json_reports_source_scope(self) -> None:
        """Source-checkout verification labels full scope."""
        import json

        _code, out, _err = self._run(as_json=True, quiet=True, installed=False)
        payload = json.loads(out)
        self.assertEqual(payload["scope"], "source")

    def test_json_always_includes_trust_warning(self) -> None:
        """--json output retains the full trust caveat in a field (Q6b)."""
        import json

        code, out, _err = self._run(as_json=True, quiet=True)
        payload = json.loads(out)
        self.assertIn("trust_warning", payload)
        self.assertIn("tripwire", payload["trust_warning"].lower())
        self.assertEqual(payload["exit_code"], code)

    def test_modified_file_returns_hash_mismatch(self) -> None:
        """A tampered protected file -> exit 1."""
        from openssl_encrypt.integrity.verify_cli import EXIT_HASH_MISMATCH

        (self.root / "pkg" / "a.py").write_text("alpha-TAMPERED\n", encoding="utf-8")
        code, _out, _err = self._run()
        self.assertEqual(code, EXIT_HASH_MISMATCH)

    def test_bad_signature_returns_two(self) -> None:
        """A corrupted signature -> exit 2 (outranks a hash mismatch)."""
        from openssl_encrypt.integrity.verify_cli import EXIT_BAD_SIGNATURE

        blob = bytearray(self.sig_path.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        self.sig_path.write_bytes(bytes(blob))
        code, _out, _err = self._run()
        self.assertEqual(code, EXIT_BAD_SIGNATURE)

    def test_missing_manifest_returns_not_found(self) -> None:
        """A missing manifest -> exit 4 (fail closed, never silent pass)."""
        from openssl_encrypt.integrity.verify_cli import EXIT_NOT_FOUND

        self.manifest_path.unlink()
        code, _out, _err = self._run()
        self.assertEqual(code, EXIT_NOT_FOUND)

    def test_missing_gpg_returns_unavailable(self) -> None:
        """No gpg binary -> exit 3, fail closed (Q8)."""
        from openssl_encrypt.integrity.verify_cli import EXIT_GPG_UNAVAILABLE

        code, _out, _err = self._run(gpg_binary="/nonexistent/gpg-xyz")
        self.assertEqual(code, EXIT_GPG_UNAVAILABLE)


class TestUpdateManifest(unittest.TestCase):
    """Manifest generation, signing and drift checking (pre-commit hook core)."""

    def setUp(self) -> None:
        self.gpg = _gpg_or_skip(self)
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir) / "repo"
        (self.root / "pkg").mkdir(parents=True)
        (self.root / "pkg" / "a.py").write_text("alpha\n", encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("beta\n", encoding="utf-8")
        self.allowlist = self.root / "protected_files.txt"
        self.allowlist.write_text("pkg/a.py\npkg/b.py\n", encoding="utf-8")
        self.manifest_path = self.root / "manifest.json"
        self.sig_path = self.root / "manifest.json.asc"

        self.home = Path(self.tmpdir) / "gnupg"
        self.fpr, self.pub = _make_ephemeral_key(self.gpg, self.home)
        self.pub_path = self.root / "pubkey.asc"
        self.pub_path.write_bytes(self.pub)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generate_matches_build_manifest(self) -> None:
        """Generated bytes equal the canonical manifest and are written to disk."""
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest
        from openssl_encrypt.integrity.update_manifest import generate_manifest

        blob = generate_manifest(
            self.root,
            allowlist_path=self.allowlist,
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
        )
        expected = serialize_manifest(
            build_manifest(self.root, ["pkg/a.py", "pkg/b.py"], key_fingerprint=self.fpr)
        )
        self.assertEqual(blob, expected)
        self.assertEqual(self.manifest_path.read_bytes(), expected)

    def test_generate_with_entries_override(self) -> None:
        """An explicit entries list overrides the allowlist (used for the subset)."""
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest
        from openssl_encrypt.integrity.update_manifest import generate_manifest

        blob = generate_manifest(
            self.root,
            entries=["pkg/a.py"],
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
        )
        expected = serialize_manifest(
            build_manifest(self.root, ["pkg/a.py"], key_fingerprint=self.fpr)
        )
        self.assertEqual(blob, expected)

    def test_generate_is_idempotent(self) -> None:
        """Two generations of an unchanged tree produce identical bytes."""
        from openssl_encrypt.integrity.update_manifest import generate_manifest

        b1 = generate_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
        )
        b2 = generate_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
        )
        self.assertEqual(b1, b2)

    def test_sign_produces_verifiable_signature(self) -> None:
        """With sign=True the detached signature verifies against the manifest."""
        from openssl_encrypt.integrity.gpg_runner import verify_detached
        from openssl_encrypt.integrity.update_manifest import generate_manifest

        blob = generate_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path, signature_path=self.sig_path,
            sign=True, home=self.home,
        )
        result = verify_detached(blob, self.sig_path.read_bytes(), public_key=self.pub)
        self.assertTrue(result.good)

    def test_check_passes_when_current(self) -> None:
        """check_manifest is True immediately after generation."""
        from openssl_encrypt.integrity.update_manifest import check_manifest, generate_manifest

        generate_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
        )
        self.assertTrue(
            check_manifest(
                self.root,
                allowlist_path=self.allowlist,
                manifest_path=self.manifest_path,
                verify_signature=False,
            )
        )

    def test_check_detects_drift(self) -> None:
        """check_manifest is False after a protected file changes."""
        from openssl_encrypt.integrity.update_manifest import check_manifest, generate_manifest

        generate_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
        )
        (self.root / "pkg" / "a.py").write_text("alpha-changed\n", encoding="utf-8")
        self.assertFalse(
            check_manifest(self.root, allowlist_path=self.allowlist,
                           manifest_path=self.manifest_path)
        )

    def test_sync_is_idempotent_no_resign(self) -> None:
        """sync_manifest does not rewrite/re-sign when nothing changed."""
        from openssl_encrypt.integrity.update_manifest import sync_manifest

        changed1 = sync_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path, signature_path=self.sig_path,
            sign=True, home=self.home,
        )
        self.assertTrue(changed1)
        sig_before = self.sig_path.read_bytes()
        changed2 = sync_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path, signature_path=self.sig_path,
            sign=True, home=self.home,
        )
        self.assertFalse(changed2)
        self.assertEqual(self.sig_path.read_bytes(), sig_before)

    def test_sync_rewrites_on_change(self) -> None:
        """sync_manifest rewrites and re-signs after a protected file changes."""
        from openssl_encrypt.integrity.update_manifest import sync_manifest

        sync_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path, signature_path=self.sig_path,
            sign=True, home=self.home,
        )
        (self.root / "pkg" / "a.py").write_text("alpha-v2\n", encoding="utf-8")
        changed = sync_manifest(
            self.root, allowlist_path=self.allowlist, key_fingerprint=self.fpr,
            manifest_path=self.manifest_path, signature_path=self.sig_path,
            sign=True, home=self.home,
        )
        self.assertTrue(changed)

    def test_check_false_when_manifest_absent(self) -> None:
        """A missing manifest is treated as not-current (fail closed)."""
        from openssl_encrypt.integrity.update_manifest import check_manifest

        self.assertFalse(
            check_manifest(self.root, allowlist_path=self.allowlist,
                           manifest_path=self.manifest_path)
        )

    def test_check_passes_with_valid_signature(self) -> None:
        """Signature-aware check passes when content matches and the .asc verifies."""
        from openssl_encrypt.integrity.update_manifest import check_manifest, sync_manifest

        sync_manifest(
            self.root,
            allowlist_path=self.allowlist,
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
            signature_path=self.sig_path,
            sign=True,
            home=self.home,
        )
        self.assertTrue(
            check_manifest(
                self.root,
                allowlist_path=self.allowlist,
                manifest_path=self.manifest_path,
                signature_path=self.sig_path,
                pubkey_path=self.pub_path,
                expected_fingerprint=self.fpr,
            )
        )

    def test_check_detects_invalid_signature(self) -> None:
        """A content-current manifest with a stale signature is drift (regression).

        Reproduces the incident: the manifest matches the tree, but its detached
        signature covers different bytes, so ``--check`` must report drift.
        """
        from openssl_encrypt.integrity.gpg_runner import detached_sign
        from openssl_encrypt.integrity.update_manifest import check_manifest, sync_manifest

        sync_manifest(
            self.root,
            allowlist_path=self.allowlist,
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
            signature_path=self.sig_path,
            sign=True,
            home=self.home,
        )
        # Valid armor, valid key, but signs the wrong content -> a stale signature.
        self.sig_path.write_bytes(detached_sign(b"a different manifest", self.fpr, home=self.home))
        self.assertFalse(
            check_manifest(
                self.root,
                allowlist_path=self.allowlist,
                manifest_path=self.manifest_path,
                signature_path=self.sig_path,
                pubkey_path=self.pub_path,
                expected_fingerprint=self.fpr,
            )
        )

    def test_sync_resigns_when_signature_stale(self) -> None:
        """sync re-signs when content matches but the .asc no longer verifies (regression).

        Previously sync short-circuited on a *present* signature, so a stale .asc
        left by an earlier failed signing run was reported as "already up to date".
        """
        from openssl_encrypt.integrity.gpg_runner import detached_sign, verify_detached
        from openssl_encrypt.integrity.update_manifest import sync_manifest

        sync_manifest(
            self.root,
            allowlist_path=self.allowlist,
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
            signature_path=self.sig_path,
            sign=True,
            home=self.home,
        )
        # Content stays current; replace the signature with one over other bytes.
        self.sig_path.write_bytes(detached_sign(b"stale content", self.fpr, home=self.home))
        changed = sync_manifest(
            self.root,
            allowlist_path=self.allowlist,
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
            signature_path=self.sig_path,
            sign=True,
            home=self.home,
        )
        self.assertTrue(changed)
        result = verify_detached(
            self.manifest_path.read_bytes(), self.sig_path.read_bytes(), public_key=self.pub
        )
        self.assertTrue(result.good)

    def test_sign_failure_leaves_manifest_untouched(self) -> None:
        """A signing failure must not rewrite the manifest (atomicity regression).

        Guards against the rewritten-but-unsigned state: writing the new manifest
        and only then failing to sign is what stranded a stale .asc.
        """
        from openssl_encrypt.integrity.gpg_runner import GpgError
        from openssl_encrypt.integrity.update_manifest import generate_manifest

        generate_manifest(
            self.root,
            allowlist_path=self.allowlist,
            key_fingerprint=self.fpr,
            manifest_path=self.manifest_path,
            signature_path=self.sig_path,
            sign=True,
            home=self.home,
        )
        manifest_before = self.manifest_path.read_bytes()
        sig_before = self.sig_path.read_bytes()
        (self.root / "pkg" / "a.py").write_text("changed-before-sign-fails\n", encoding="utf-8")
        with self.assertRaises(GpgError):
            generate_manifest(
                self.root,
                allowlist_path=self.allowlist,
                key_fingerprint="0" * 40,  # not in the keyring -> signing fails
                manifest_path=self.manifest_path,
                signature_path=self.sig_path,
                sign=True,
                home=self.home,
            )
        self.assertEqual(self.manifest_path.read_bytes(), manifest_before)
        self.assertEqual(self.sig_path.read_bytes(), sig_before)


class TestInstalledLayoutDetection(unittest.TestCase):
    """Detecting whether we run from a source checkout or an installed package."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_source_checkout_detected(self) -> None:
        """A tree with requirements.txt / threefish_native/ is a source checkout."""
        from openssl_encrypt.integrity.verify_cli import is_installed_layout

        root = Path(self.tmpdir)
        (root / "requirements.txt").write_text("x\n", encoding="utf-8")
        self.assertFalse(is_installed_layout(root))

    def test_installed_layout_detected(self) -> None:
        """A tree without those repo-root markers is an installed layout."""
        from openssl_encrypt.integrity.verify_cli import is_installed_layout

        self.assertTrue(is_installed_layout(Path(self.tmpdir)))

    def test_real_repo_is_source(self) -> None:
        """This repository checkout is detected as a source tree."""
        from openssl_encrypt.integrity.verify_cli import default_repo_root, is_installed_layout

        self.assertFalse(is_installed_layout(default_repo_root()))


class TestPackagingShipsIntegrity(unittest.TestCase):
    """The integrity artifacts must be packaged so installed verification works."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]

    def test_manifest_in_includes_integrity_artifacts(self) -> None:
        """MANIFEST.in ships the integrity manifests and keys (sdist)."""
        text = (self.repo_root / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("openssl_encrypt/integrity", text)

    def test_setup_package_data_includes_integrity(self) -> None:
        """setup.py package_data ships the integrity artifacts into the wheel."""
        text = (self.repo_root / "setup.py").read_text(encoding="utf-8")
        self.assertIn("openssl_encrypt.integrity", text)


class TestVerifyIntegrityCliWiring(unittest.TestCase):
    """End-to-end wiring: the verify-integrity subcommand is reachable."""

    def test_subcommand_dispatches_and_warns(self) -> None:
        """`python -m openssl_encrypt verify-integrity --json` routes to our handler."""
        import json
        import subprocess
        import sys

        repo_root = Path(__file__).resolve().parents[2]
        proc = subprocess.run(
            [sys.executable, "-m", "openssl_encrypt", "verify-integrity", "--json", "--quiet"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
        )
        # Exit code is environment-dependent (manifest may or may not be present),
        # but the command must be recognised (not an argparse error code 2 with usage)
        # and must always emit the trust warning in its JSON payload.
        self.assertNotIn("invalid choice: 'verify-integrity'", proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn("trust_warning", payload)
        self.assertEqual(payload["exit_code"], proc.returncode)


if __name__ == "__main__":
    unittest.main()
