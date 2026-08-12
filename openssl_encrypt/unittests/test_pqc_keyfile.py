#!/usr/bin/env python3
"""
`--pqc-keyfile` must not write a post-quantum private key in the clear
(gitlab#157).

`crypt_cli.py` grew two independent implementations of the keyfile
save/load logic. Commit 320305ee added password-wrapping to the one that
existed then; c41a3a1cb ("fix for claude code massive deletions")
reconstructed the file and reintroduced the pre-fix plaintext pattern as a
second copy; aef4ab42 (gitlab#131/F16) later upgraded the wrapping to
Argon2id and its own message says it touched "the one write site" — the
duplicate was never noticed.

The duplicate writes `private_key` as bare base64 with no `key_encrypted`
marker, and its loader reads `private_key` unconditionally, so handed a
properly wrapped keyfile it would base64-decode the AES-GCM ciphertext and
use it as if it were the key.

These tests pin the two properties that matter and are cheap to check
statically, because the write path itself is not reachable from the shipped
CLI (`--pqc-gen-key` is declared only on a vestigial monolithic parser that
`main()` never routes to — see `test_pqc_gen_key_is_reachable`):

  * no code path writes an unwrapped private key to a keyfile;
  * every loader understands the wrapped format.
"""

import ast
import os
import unittest

_PW = "Tr0ub4dor&3-Correct-Horse!"

CLI = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "crypt_cli.py"
)


def _source():
    with open(CLI, "r", encoding="utf-8") as handle:
        return handle.read()


def _keyfile_dict_literals(tree):
    """Every dict literal that looks like a keyfile document.

    Identified by carrying both `public_key` and `private_key` keys, so it
    finds the shape regardless of which branch builds it.
    """
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        if {"public_key", "private_key"} <= keys:
            found.append((node, keys))
    return found


class TestNoCleartextPrivateKeyIsWritten(unittest.TestCase):
    def test_every_keyfile_document_marks_the_key_as_encrypted(self):
        """A keyfile dict without `key_encrypted` is a cleartext writer.

        The wrapped writer sets `key_encrypted`, `key_salt` and `key_kdf`
        alongside the key; the cleartext duplicate set none of them. Keying
        the check on the document shape rather than on a line number means a
        third copy would be caught the same way.
        """
        tree = ast.parse(_source(), filename=CLI)
        documents = _keyfile_dict_literals(tree)
        self.assertTrue(
            documents,
            "no keyfile document literal found at all; this test would pass "
            "vacuously forever if the writer were refactored into another shape",
        )
        offenders = []
        for node, keys in documents:
            if "key_encrypted" not in keys:
                offenders.append(f"  line {node.lineno}: keys={sorted(keys)}")

        self.assertFalse(
            offenders,
            "A post-quantum keyfile document is built without the wrapping "
            "markers, i.e. it stores the private key in the clear:\n"
            + "\n".join(offenders)
            + "\n\nThe private key is long-lived: anyone who obtains the file "
            "gets the key outright, with no password to brute-force first.",
        )

    def test_every_loader_checks_the_wrapping_marker(self):
        """A loader that ignores `key_encrypted` misreads a wrapped file.

        It would base64-decode the AES-GCM ciphertext and hand it over as the
        private key -- no error, no warning, just the wrong bytes.
        """
        source = _source()
        tree = ast.parse(source, filename=CLI)

        loaders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Subscript):
                continue
            if not isinstance(node.slice, ast.Constant) or node.slice.value != "private_key":
                continue
            if not isinstance(node.value, ast.Name) or node.value.id != "key_data":
                continue
            loaders.append(node.lineno)

        self.assertTrue(loaders, "no key_data['private_key'] read found; test is stale")

        # Comments do not count. A comment of mine mentioning key_encrypted
        # sits at the coordinates of the deleted duplicate, so a
        # reintroduction at its old location would otherwise be pre-blessed by
        # it -- and re-inserting the block at its old location is precisely how
        # this bug got here.
        marker_lines = [
            index + 1
            for index, line in enumerate(source.splitlines())
            if "key_encrypted" in line and not line.lstrip().startswith("#")
        ]
        for lineno in loaders:
            nearby = [m for m in marker_lines if abs(m - lineno) <= 60]
            self.assertTrue(
                nearby,
                f"the key_data['private_key'] read at line {lineno} has no "
                f"key_encrypted check within 60 lines, so it cannot tell a "
                f"wrapped keyfile from an unwrapped one",
            )


class TestKeyfileIsCreatedPrivately(unittest.TestCase):
    def test_the_keyfile_is_not_written_through_a_bare_open(self):
        """`open(path, "w")` uses the umask, so typically 0644.

        The file holds the long-lived post-quantum private key, wrapped but
        still worth keeping to yourself; `file_permissions.create_secure_file`
        already exists and creates 0600.
        """
        source = _source()
        offenders = [
            index + 1
            for index, line in enumerate(source.splitlines())
            if "open(args.pqc_keyfile" in line and '"w"' in line
        ]
        self.assertFalse(
            offenders,
            f"the PQC keyfile is written through a bare open() at line(s) "
            f"{offenders}, so it lands at the umask (typically 0644). Use "
            f"create_secure_file(..., exclusive=True).",
        )


class TestPqcGenKeyIsReachable(unittest.TestCase):
    def test_pqc_gen_key_is_declared_on_the_encrypt_subparser(self):
        """The flag has to exist where the CLI actually parses.

        `--pqc-gen-key` was declared only on the monolithic parser inside
        `main_with_args`, which `main()` never routes to for `encrypt`, and a
        compatibility shim back-filled `pqc_gen_key = False` for every real
        invocation. So the save branch could not run at all, and
        `--pqc-keyfile` naming a non-existent path was silently ignored.
        """
        import argparse

        from openssl_encrypt.modules.crypt_cli_subparser import setup_encrypt_parser

        parser = argparse.ArgumentParser()
        setup_encrypt_parser(parser)
        options = {opt for action in parser._actions for opt in action.option_strings}
        self.assertIn("--pqc-gen-key", options)
        self.assertIn("--pqc-keyfile", options)


class TestKeyfileEndToEnd(unittest.TestCase):
    """The behaviour, not just the source shape.

    --pqc-keyfile could not save by ANY invocation before this: the save
    branch was gated on --pqc-gen-key, which was declared only on a parser
    the CLI never routes to, so naming a non-existent path silently produced
    an ephemeral key and no file.
    """

    def _run(self, *extra):
        return self._run_raw("encrypt", *extra)

    def _run_raw(self, *argv):
        """argv verbatim, so the legacy ordering can be exercised too."""
        import subprocess
        import sys

        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return subprocess.run(
            [sys.executable, "-m", "openssl_encrypt.crypt", *argv],
            capture_output=True,
            text=True,
            cwd=repo,
        )

    def setUp(self):
        import shutil
        import tempfile

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.source = os.path.join(self.tmp, "in.txt")
        with open(self.source, "w", encoding="utf-8") as handle:
            handle.write("hello pqc")

    def test_gen_key_writes_a_wrapped_keyfile_at_0600(self):
        import json
        import stat

        keyfile = os.path.join(self.tmp, "key.json")
        result = self._run(
            "-i",
            self.source,
            "-o",
            os.path.join(self.tmp, "out.enc"),
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-keyfile",
            keyfile,
            "--pqc-gen-key",
            "--password",
            "hunter2hunter2",
        )
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertTrue(os.path.exists(keyfile), "no keyfile was written")
        self.assertEqual(stat.S_IMODE(os.stat(keyfile).st_mode), 0o600)

        with open(keyfile, encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertTrue(document.get("key_encrypted"), "private key stored unwrapped")
        self.assertIn("key_kdf", document)
        self.assertIn("key_salt", document)

    def test_the_saved_key_actually_opens_the_file_it_encrypted(self):
        """The property the shape checks cannot reach.

        This save path had never executed in a released version, so asserting
        the JSON's shape proves nothing about whether the key inside it opens
        the ciphertext produced alongside it.
        """
        keyfile = os.path.join(self.tmp, "roundtrip.json")
        encrypted = os.path.join(self.tmp, "roundtrip.enc")
        recovered = os.path.join(self.tmp, "roundtrip.out")

        result = self._run(
            "-i",
            self.source,
            "-o",
            encrypted,
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-keyfile",
            keyfile,
            "--pqc-gen-key",
            "--password",
            _PW,
            "--force-password",
        )
        self.assertEqual(result.returncode, 0, result.stderr[-800:])

        back = self._run_raw(
            "decrypt",
            "-i",
            encrypted,
            "-o",
            recovered,
            "--pqc-keyfile",
            keyfile,
            "--password",
            _PW,
        )
        self.assertEqual(back.returncode, 0, back.stderr[-800:])
        with open(recovered, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "hello pqc")

    def test_overwrite_refuses_before_touching_the_input(self):
        """The ordering the review caught.

        Deleting the duplicate left --overwrite with no keyfile handling at
        all: it encrypted with an ephemeral key and only reached the keyfile
        code afterwards, so an unusable keyfile was reported after the input
        had already been replaced. The keyfile is resolved once, before the
        overwrite branch, so a bad one aborts while the input is intact.

        Uses the legacy argument ordering (option before the subcommand),
        which is the route that reaches the monolithic parser.
        """
        victim = os.path.join(self.tmp, "victim.txt")
        with open(victim, "w", encoding="utf-8") as handle:
            handle.write("VICTIM-CANARY")

        result = self._run_raw(
            "-i",
            victim,
            "encrypt",
            "--overwrite",
            "--pqc-keyfile",
            os.path.join(self.tmp, "absent.json"),
            "--algorithm",
            "ml-kem-768-hybrid",
            "--password",
            _PW,
            "--force-password",
        )
        self.assertNotEqual(result.returncode, 0)
        with open(victim, encoding="utf-8") as handle:
            self.assertEqual(
                handle.read(), "VICTIM-CANARY", "the input was overwritten before the refusal"
            )

    def test_gen_key_without_a_keyfile_is_refused(self):
        """The mirror image, newly reachable now that the flag exists."""
        result = self._run(
            "-i",
            self.source,
            "-o",
            os.path.join(self.tmp, "x.enc"),
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-gen-key",
            "--password",
            _PW,
            "--force-password",
        )
        self.assertNotEqual(result.returncode, 0, "--pqc-gen-key was silently ignored")
        self.assertIn("--pqc-keyfile", result.stderr)

    def test_an_existing_keyfile_is_never_clobbered(self):
        """Overwriting one destroys the key it holds, and with it anything
        encrypted to that key."""
        keyfile = os.path.join(self.tmp, "existing.json")
        first = self._run(
            "-i",
            self.source,
            "-o",
            os.path.join(self.tmp, "one.enc"),
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-keyfile",
            keyfile,
            "--pqc-gen-key",
            "--password",
            _PW,
            "--force-password",
        )
        self.assertEqual(first.returncode, 0, first.stderr[-400:])
        with open(keyfile, "rb") as handle:
            before = handle.read()

        second = self._run(
            "-i",
            self.source,
            "-o",
            os.path.join(self.tmp, "two.enc"),
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-keyfile",
            keyfile,
            "--pqc-gen-key",
            "--password",
            _PW,
            "--force-password",
            "--quiet",
        )
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("already exists", second.stderr, "no reason given under --quiet")
        with open(keyfile, "rb") as handle:
            self.assertEqual(handle.read(), before, "the existing key file was modified")

    def test_a_missing_keyfile_without_gen_key_is_refused(self):
        """Previously ignored in silence: the user got an ephemeral key and
        no file, so nothing could ever open the ciphertext again with the
        keyfile they believed they had created.
        """
        result = self._run(
            "-i",
            self.source,
            "-o",
            os.path.join(self.tmp, "out.enc"),
            "--algorithm",
            "ml-kem-768-hybrid",
            "--pqc-keyfile",
            os.path.join(self.tmp, "absent.json"),
            "--password",
            "hunter2hunter2",
        )
        self.assertNotEqual(result.returncode, 0, "the flag was ignored again")
        self.assertIn("does not exist", result.stderr)
        self.assertIn("--pqc-gen-key", result.stderr)


if __name__ == "__main__":
    unittest.main()
