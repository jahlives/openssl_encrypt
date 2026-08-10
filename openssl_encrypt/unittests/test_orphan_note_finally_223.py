#!/usr/bin/env python3
"""The orphan-password NOTE must fire on EVERY incomplete encrypt exit (gitlab#223).

The #182/#222 wiring called `_warn_orphan_random_password` from individually
chosen early-exit sites, and the #222 review found the set incomplete: the
encrypt dispatch has many more `sys.exit(1)` / `return 1` sites that fire
after the 0600 password file is written (XOR mutual-exclusivity aborts,
keystore-branch failures, validation aborts), and the top-level handler is
`except Exception`, which cannot catch SystemExit by language rule.

The fix wraps the dispatch in try/finally with a ciphertext-completion flag:
every incomplete exit announces the orphan exactly once, and a completed
encrypt (the password file is then the live credential, already announced at
write time) stays silent.
"""

import os
import subprocess
import sys
import tempfile
import unittest

TIMEOUT = 300


def _run_encrypt(tmp, *extra, pw=None):
    plain = os.path.join(tmp, "p.txt")
    with open(plain, "w") as f:
        f.write("payload")
    out = os.path.join(tmp, "o.enc")
    pw = pw or os.path.join(tmp, "pw.txt")
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "openssl_encrypt.crypt",
            "encrypt",
            "-i",
            plain,
            "-o",
            out,
            "--random",
            "24",
            "--random-password-out",
            pw,
            *extra,
        ],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=TIMEOUT,
    )
    return r, pw, out


class TestIncompleteExitsFireTheNote(unittest.TestCase):
    def test_xor_mutex_abort_fires_the_note_exactly_once(self):
        # --use-xor-composition + --independent-xor is refused by a
        # sys.exit(1) deep in the dispatch -- one of the sites the #222
        # review found uncovered (SystemExit bypasses `except Exception`).
        with tempfile.TemporaryDirectory() as tmp:
            r, pw, out = _run_encrypt(tmp, "--use-xor-composition", "--independent-xor")
            self.assertNotEqual(r.returncode, 0)
            self.assertTrue(os.path.exists(pw), "password file should have been written")
            self.assertFalse(os.path.exists(out), "no ciphertext should exist")
            self.assertEqual(r.stderr.count("NOTE:"), 1, f"expected exactly one NOTE\n{r.stderr}")
            self.assertIn("no usable encrypted file", r.stderr)
            # The password value itself is never echoed.
            with open(pw) as f:
                secret = f.read().strip()
            self.assertNotIn(secret, r.stderr)


class TestCompleteRunStaysSilent(unittest.TestCase):
    def test_successful_encrypt_prints_no_orphan_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            r, pw, out = _run_encrypt(tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(out))
            self.assertNotIn("NOTE:", r.stderr)
            self.assertNotIn("password file may remain", r.stderr)

    def test_successful_overwrite_encrypt_prints_no_orphan_note(self):
        # The --overwrite branch completes through the same common tail; a
        # missed completion-flag site would print a false orphan NOTE after
        # a successful in-place encrypt (gitlab#223 review f8).
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "p.txt")
            with open(plain, "w") as f:
                f.write("payload")
            pw = os.path.join(tmp, "pw.txt")
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "openssl_encrypt.crypt",
                    "encrypt",
                    "-i",
                    plain,
                    "--overwrite",
                    "--random",
                    "24",
                    "--random-password-out",
                    pw,
                ],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=TIMEOUT,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("NOTE:", r.stderr)

    def test_successful_stdout_encrypt_prints_no_orphan_note(self):
        # stdin -> stdout delivery is a separate terminal (return, no file);
        # its completion flag site is the only thing between a successful
        # pipe run and a false orphan NOTE (gitlab#223 review f8).
        with tempfile.TemporaryDirectory() as tmp:
            pw = os.path.join(tmp, "pw.txt")
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "openssl_encrypt.crypt",
                    "encrypt",
                    "-i",
                    "/dev/stdin",
                    "--random",
                    "24",
                    "--random-password-out",
                    pw,
                ],
                capture_output=True,
                input=b"payload",
                stdin=None,
                timeout=TIMEOUT,
            )
            stderr = r.stderr.decode()
            self.assertEqual(r.returncode, 0, stderr)
            self.assertTrue(r.stdout, "ciphertext expected on stdout")
            self.assertNotIn("NOTE:", stderr)


class TestPostWriteFailureGetsVerifyFirstWording(unittest.TestCase):
    def test_armor_failure_after_ciphertext_says_verify_not_remove(self):
        # The exact f1/f2 regression shape: the ciphertext is fully written,
        # then post-processing (the in-place armor rewrite) fails. The NOTE
        # must use the verify-first wording -- "you can remove it" would
        # delete the only credential of a live encrypted file. The driver
        # mirrors the real -m entry but patches armor_file to fail before
        # dispatch (the CLI imports it lazily at the call site).
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "p.txt")
            with open(plain, "w") as f:
                f.write("payload")
            out = os.path.join(tmp, "o.enc")
            pw = os.path.join(tmp, "pw.txt")
            driver = (
                "import sys, runpy\n"
                f"sys.argv = ['openssl_encrypt', 'encrypt', '-i', {plain!r}, '-o', {out!r}, "
                f"'--random', '24', '--random-password-out', {pw!r}, '--armor']\n"
                "import openssl_encrypt.modules.armor as armor\n"
                "def boom(p):\n"
                "    raise OSError(28, 'No space left on device (simulated)')\n"
                "armor.armor_file = boom\n"
                "runpy.run_module('openssl_encrypt.crypt', run_name='__main__')\n"
            )
            r = subprocess.run(
                [sys.executable, "-c", driver],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=TIMEOUT,
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stderr.count("NOTE:"), 1, r.stderr)
            self.assertIn("decryptable", r.stderr)
            self.assertNotIn("You can remove it", r.stderr)
            self.assertTrue(os.path.exists(out), "ciphertext should exist on disk")


class TestPreexistingDestination(unittest.TestCase):
    def test_existing_destination_is_refused_without_the_removable_note(self):
        # A pre-existing --random-password-out may hold the password of an
        # EARLIER successful run; the removable-orphan NOTE would tell the
        # user to delete a live credential (gitlab#223 review f3).
        with tempfile.TemporaryDirectory() as tmp:
            pw = os.path.join(tmp, "pw.txt")
            with open(pw, "w") as f:
                f.write("earlier-run-password\n")
            r, _, out = _run_encrypt(tmp, pw=pw)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("already exists", r.stderr)
            self.assertIn("verify before removing", r.stderr)
            self.assertNotIn("You can remove it", r.stderr)
            self.assertFalse(os.path.exists(out))
            with open(pw) as f:
                self.assertEqual(f.read(), "earlier-run-password\n")


if __name__ == "__main__":
    unittest.main()
