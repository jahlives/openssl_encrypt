#!/usr/bin/env python3
"""
`--keyring-store` must store the password whatever source it came from
(gitlab#156).

Both keyring flags were gated on `args.password`, which is set only by
`-p/--password`. `CRYPT_PASSWORD` is consumed straight into the secure
buffer and never assigned to `args.password`, so for any caller supplying
the password through the environment -- the recommended way, and the only
way the desktop GUI uses -- `--keyring-store` silently stored nothing.

Reproduced before the fix:

    -p + --keyring-store              -> "Password stored in keyring as 'lbl-p'"
    CRYPT_PASSWORD + --keyring-store  -> (no output at all)
    stored labels                     -> ['openssl_encrypt/lbl-p']

The silence is what makes it dangerous rather than merely broken: the
confirmation lives inside the same `if`, so the user gets no error and no
confirmation. Someone who believes the password is now recoverable from the
keyring may discard their only copy of it, and the data is then
unrecoverable.

Driven through a real subprocess with a keyring shim on PYTHONPATH, because
the defect is in how the CLI resolves its password across sources -- an
in-process test that hands the function a namespace would not exercise the
environment path at all, which is the one that was broken.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PASSWORD = "Tr0ub4dor&3-Correct-Horse!"

_SHIM = """
import json, os
STORE = os.environ["FAKE_KEYRING_FILE"]


def _load():
    return json.load(open(STORE)) if os.path.exists(STORE) else {}


def set_password(service, label, pw):
    d = _load()
    d[f"{service}/{label}"] = pw
    json.dump(d, open(STORE, "w"))


def get_password(service, label):
    return _load().get(f"{service}/{label}")


def delete_password(service, label):
    d = _load()
    k = f"{service}/{label}"
    if k not in d:
        raise errors.PasswordDeleteError("not found")
    del d[k]
    json.dump(d, open(STORE, "w"))


class errors:
    class PasswordDeleteError(Exception):
        pass
"""


class TestKeyringStoreAcrossSources(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.shim = self.tmp / "shim"
        self.shim.mkdir()
        (self.shim / "keyring.py").write_text(_SHIM)
        self.store = self.tmp / "store.json"
        self.plain = self.tmp / "plain.txt"
        self.plain.write_text("canary")

    def _run(self, *argv, env=None):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(self.shim)
        environment["FAKE_KEYRING_FILE"] = str(self.store)
        environment.pop("CRYPT_PASSWORD", None)
        environment.pop("OPENSSL_ENCRYPT_PASSWORD", None)
        environment.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "openssl_encrypt.crypt", *argv],
            capture_output=True,
            text=True,
            cwd=REPO,
            env=environment,
            timeout=180,
        )

    def _stored(self):
        if not self.store.exists():
            return {}
        return json.load(open(self.store))

    def test_a_password_from_the_command_line_is_stored(self):
        """The one case that already worked; it must keep working."""
        result = self._run(
            "encrypt",
            "-i",
            str(self.plain),
            "-o",
            str(self.tmp / "a.enc"),
            "-p",
            PASSWORD,
            "--keyring-store",
            "lbl-p",
        )
        self.assertEqual(
            self._stored().get("openssl_encrypt/lbl-p"), PASSWORD, result.stderr[-400:]
        )

    def test_a_password_from_the_environment_is_stored(self):
        """The defect: this stored nothing and said nothing."""
        result = self._run(
            "encrypt",
            "-i",
            str(self.plain),
            "-o",
            str(self.tmp / "b.enc"),
            "--keyring-store",
            "lbl-env",
            env={"CRYPT_PASSWORD": PASSWORD},
        )
        self.assertEqual(
            self._stored().get("openssl_encrypt/lbl-env"),
            PASSWORD,
            "the password came from the environment and was silently not "
            f"stored: {result.stderr[-400:]}",
        )

    def test_the_confirmation_is_printed_for_the_environment_path_too(self):
        """Silence is what turns this from broken into dangerous."""
        result = self._run(
            "encrypt",
            "-i",
            str(self.plain),
            "-o",
            str(self.tmp / "c.enc"),
            "--keyring-store",
            "lbl-env2",
            env={"CRYPT_PASSWORD": PASSWORD},
        )
        self.assertIn("lbl-env2", result.stderr, result.stderr[-400:])

    def test_the_other_environment_variable_works_too(self):
        result = self._run(
            "encrypt",
            "-i",
            str(self.plain),
            "-o",
            str(self.tmp / "d.enc"),
            "--keyring-store",
            "lbl-oe",
            env={"OPENSSL_ENCRYPT_PASSWORD": PASSWORD},
        )
        self.assertEqual(
            self._stored().get("openssl_encrypt/lbl-oe"), PASSWORD, result.stderr[-400:]
        )


class TestTheRoundTrip(TestKeyringStoreAcrossSources):
    """Storing is only useful if the stored value opens the file."""

    def test_store_from_the_environment_then_load_from_the_keyring(self):
        encrypted = self.tmp / "rt.enc"
        store = self._run(
            "encrypt",
            "-i",
            str(self.plain),
            "-o",
            str(encrypted),
            "--keyring-store",
            "round-trip",
            env={"CRYPT_PASSWORD": PASSWORD},
        )
        self.assertEqual(
            self._stored().get("openssl_encrypt/round-trip"),
            PASSWORD,
            store.stderr[-400:],
        )

        recovered = self.tmp / "rt.out"
        load = self._run(
            "decrypt", "-i", str(encrypted), "-o", str(recovered), "--keyring-load", "round-trip"
        )
        self.assertTrue(recovered.exists(), load.stderr[-500:])
        self.assertEqual(recovered.read_text(), "canary")


class TestItNeverSilentlyDoesNothing(TestKeyringStoreAcrossSources):
    """Whatever happens, the user must be told."""

    def test_a_missing_keyring_package_is_reported(self):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(self.tmp / "empty")
        environment.pop("CRYPT_PASSWORD", None)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt.crypt",
                "encrypt",
                "-i",
                str(self.plain),
                "-o",
                str(self.tmp / "e.enc"),
                "-p",
                PASSWORD,
                "--keyring-store",
                "lbl",
            ],
            capture_output=True,
            text=True,
            cwd=REPO,
            env=environment,
            timeout=180,
        )
        combined = result.stdout + result.stderr
        self.assertRegex(
            combined,
            r"(?i)keyring",
            "--keyring-store produced no mention of the keyring at all",
        )


if __name__ == "__main__":
    unittest.main()
