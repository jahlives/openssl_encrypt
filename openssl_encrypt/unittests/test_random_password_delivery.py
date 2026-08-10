#!/usr/bin/env python3
"""
Tests for a safe delivery channel for `encrypt --random` (gitlab#152 / github#70).

`--random` generated the password, encrypted the file, then printed the
password to **stderr** inside a banner, waited out a 10-second countdown, and
"cleared" it with ANSI escapes.

Every part of that is unsound as a delivery channel:

* stderr is collapsed into stdout by `2>&1`, lands in terminal scrollback, in
  `script(1)` transcripts, in CI job logs, and in the desktop GUI's persistent
  debug log. The password is the *only* thing standing between an attacker and
  the file's plaintext.
* The ANSI clear is theatre. It repaints the visible screen; it removes
  nothing from scrollback, from a pipe, or from a log file.
* The 10-second countdown makes the command unusable from a script and does
  not protect anything -- the value is already written.
* A non-interactive caller had no way to receive the password at all.

The fix mirrors the recovery-code channel built for gitlab#146: name a
destination, and the tool writes it there itself with 0600 permissions,
refusing to overwrite. The precedent that `--add-code --json` is *refused*
without a destination rather than silently withholding the credential applies
here too.
"""

import argparse
import os
import stat
import tempfile
import unittest
from unittest import mock


class TestParserAcceptsADestination(unittest.TestCase):
    def _parse(self, *argv):
        from openssl_encrypt.modules.crypt_cli_subparser import setup_encrypt_parser

        parser = argparse.ArgumentParser()
        setup_encrypt_parser(parser)
        return parser.parse_args(["-i", "a", "-o", "b", *argv])

    def test_random_password_out_is_accepted(self):
        args = self._parse("--random", "20", "--random-password-out", "/tmp/pw")
        self.assertEqual(args.random_password_out, "/tmp/pw")

    def test_it_defaults_to_none(self):
        self.assertIsNone(self._parse("--random", "20").random_password_out)


class TestWritingTheGeneratedPassword(unittest.TestCase):
    """The tool writes the file itself, so it controls the permissions."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "pw.txt")

    def _write(self, path, password="s3cret-generated"):
        from openssl_encrypt.modules.crypt_cli import _write_generated_password_file

        _write_generated_password_file(path, password)

    def test_the_password_is_written(self):
        self._write(self.path)
        with open(self.path) as f:
            self.assertEqual(f.read().rstrip("\n"), "s3cret-generated")

    def test_the_file_is_owner_only(self):
        self._write(self.path)
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600, f"expected 0600, got {oct(mode)}")

    def test_an_existing_file_is_refused(self):
        """Never clobber: the existing file may be another file's password."""
        with open(self.path, "w") as f:
            f.write("do not lose me")
        with self.assertRaises((ValueError, OSError, FileExistsError)):
            self._write(self.path)
        with open(self.path) as f:
            self.assertEqual(f.read(), "do not lose me")

    def test_a_symlink_destination_is_refused(self):
        """A pre-planted symlink must not redirect the password."""
        target = os.path.join(self.tmp.name, "elsewhere")
        link = os.path.join(self.tmp.name, "link")
        os.symlink(target, link)
        with self.assertRaises((ValueError, OSError, FileExistsError)):
            self._write(link)
        self.assertFalse(os.path.exists(target), "the password followed a symlink")


class TestNonInteractiveDeliveryIsNotSilentlyLost(unittest.TestCase):
    """Without a terminal there is nowhere safe to display it.

    Mirrors `add-recovery --add-code --json`, which is refused rather than
    silently withholding the credential.
    """

    def _requires(self, isatty, out, quiet=False):
        from openssl_encrypt.modules.crypt_cli import _random_password_destination_ok

        return _random_password_destination_ok(isatty=isatty, out_path=out, quiet=quiet)

    def test_a_destination_is_required_without_a_tty(self):
        self.assertFalse(self._requires(isatty=False, out=None))

    def test_a_destination_satisfies_it(self):
        self.assertTrue(self._requires(isatty=False, out="/tmp/pw"))

    def test_a_tty_alone_is_enough(self):
        """The existing interactive display stays available."""
        self.assertTrue(self._requires(isatty=True, out=None))

    def test_quiet_on_a_tty_still_requires_a_destination(self):
        """--quiet suppresses the banner, so the tty proves nothing.

        Without this the command encrypts the file, prints nothing, exits 0,
        and leaves nobody holding the password.
        """
        self.assertFalse(self._requires(isatty=True, out=None, quiet=True))

    def test_quiet_with_a_destination_is_fine(self):
        self.assertTrue(self._requires(isatty=True, out="/tmp/pw", quiet=True))


class TestTheDisplayIsSkippedWhenWrittenToAFile(unittest.TestCase):
    """Naming a destination must replace the banner, not add to it.

    Printing it as well would put the password back on the stream the
    destination exists to avoid. Asserted end to end rather than through a
    predicate helper: the helper it used to call became dead code when the
    post-encryption banner was removed, and a test of a dead helper proves
    nothing about the product.
    """

    def test_the_banner_is_not_printed_when_a_destination_is_used(self):
        import subprocess
        import sys as _sys

        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "p.txt")
            with open(plain, "w") as f:
                f.write("payload")
            out = os.path.join(tmp, "o.enc")
            pw = os.path.join(tmp, "pw.txt")
            r = subprocess.run(
                [
                    _sys.executable,
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
                ],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=300,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("Generated Password:", r.stderr)
            self.assertNotIn("SAVE THIS PASSWORD NOW", r.stderr)


class TestTheHonestBannerMakesNoEraseClaim(unittest.TestCase):
    """The tty-display path replaced the false 'cleared from screen' banner.

    The old post-encryption display ran a countdown, emitted \\033[2J and
    announced the password had been cleared from the screen -- which was false.
    _display_generated_password is the honest replacement (gitlab#152/#222).
    """

    def test_display_shows_the_password_without_claiming_to_erase_it(self):
        import io
        from contextlib import redirect_stderr

        from openssl_encrypt.modules.crypt_cli import _display_generated_password

        err = io.StringIO()
        with redirect_stderr(err):
            _display_generated_password("s3cret-generated")
        out = err.getvalue()
        self.assertIn("s3cret-generated", out)  # it IS the delivery channel
        self.assertNotIn("cleared from screen", out.lower())
        self.assertNotIn("\033[2J", out)  # no fake screen-clear escape


class TestTheSecretIsNotEchoedOnFailure(unittest.TestCase):
    """An error path must not put the password back on a stream."""

    def test_a_write_failure_message_excludes_the_password(self):
        from openssl_encrypt.modules.crypt_cli import _write_generated_password_file

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "missing", "pw")
            try:
                _write_generated_password_file(path, "s3cret-generated")
            except Exception as e:  # noqa: BLE001 - asserting the message
                self.assertNotIn("s3cret-generated", str(e))
            else:
                self.fail("expected a failure for an unwritable destination")


class TestTheWiringEndToEnd(unittest.TestCase):
    """Drive the real CLI.

    The helpers above are each correct in isolation, which is precisely why
    they did not catch either blocking defect: `--quiet` bypassed the delivery
    guarantee, and a destination equal to `--output` was truncated by the
    ciphertext write. Both are only visible through the wiring.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.plain = os.path.join(self.tmp.name, "plain.txt")
        with open(self.plain, "w") as f:
            f.write("payload")

    def _run(self, *argv):
        import subprocess
        import sys as _sys

        return subprocess.run(
            [_sys.executable, "-m", "openssl_encrypt.crypt", *argv],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=300,
        )

    def test_random_no_longer_crashes_and_delivers(self):
        """gitlab#181: this raised AttributeError before reaching anything."""
        out = os.path.join(self.tmp.name, "out.enc")
        pw = os.path.join(self.tmp.name, "pw.txt")
        r = self._run(
            "encrypt", "-i", self.plain, "-o", out, "--random", "24", "--random-password-out", pw
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("AttributeError", r.stderr)
        self.assertTrue(os.path.exists(pw))

    def test_the_written_password_actually_opens_the_file(self):
        """The delivered value must be the one the file was encrypted with."""
        out = os.path.join(self.tmp.name, "out.enc")
        pw = os.path.join(self.tmp.name, "pw.txt")
        back = os.path.join(self.tmp.name, "back.txt")
        self.assertEqual(
            self._run(
                "encrypt",
                "-i",
                self.plain,
                "-o",
                out,
                "--random",
                "24",
                "--random-password-out",
                pw,
            ).returncode,
            0,
        )
        with open(pw) as f:
            password = f.read().rstrip("\n")
        # --password=<value>, not --password <value>: a generated password can
        # start with '-', which argparse would otherwise read as a flag (this
        # is a test-harness quirk, not a product limitation -- the file channel
        # is the recommended path anyway).
        r = self._run("decrypt", "-i", out, "-o", back, f"--password={password}")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(back) as f:
            self.assertEqual(f.read(), "payload")

    def test_the_password_never_appears_on_a_stream(self):
        out = os.path.join(self.tmp.name, "out.enc")
        pw = os.path.join(self.tmp.name, "pw.txt")
        r = self._run(
            "encrypt", "-i", self.plain, "-o", out, "--random", "24", "--random-password-out", pw
        )
        with open(pw) as f:
            password = f.read().rstrip("\n")
        self.assertNotIn(password, r.stdout)
        self.assertNotIn(password, r.stderr)

    def test_a_destination_equal_to_the_output_is_refused(self):
        """Otherwise the ciphertext write truncates the password file.

        O_EXCL does not catch it: the destination does not exist yet when it
        is created. The result was exit 0, "encrypted successfully", and a
        file sealed under a password that no longer existed anywhere.
        """
        out = os.path.join(self.tmp.name, "collide.enc")
        r = self._run(
            "encrypt", "-i", self.plain, "-o", out, "--random", "24", "--random-password-out", out
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must differ from", r.stderr)

    def test_a_destination_equal_to_the_DEFAULT_output_is_refused(self):
        """`--output` is not normalized, so reading it alone was not enough.

        With `-o` omitted the ciphertext goes to `<input>.encrypted`. The
        first version of the collision check compared only `args.output`,
        which is None here, so it passed -- and the ciphertext then truncated
        the password file. Exit 0, "encrypted successfully", password gone.
        """
        r = self._run(
            "encrypt",
            "-i",
            self.plain,
            "--random",
            "24",
            "--random-password-out",
            self.plain + ".encrypted",
        )
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("must differ from", r.stderr)

    def test_a_destination_equal_to_the_overwrite_target_is_refused(self):
        """--overwrite writes back over the input."""
        r = self._run(
            "encrypt",
            "-i",
            self.plain,
            "--overwrite",
            "--random",
            "24",
            "--random-password-out",
            self.plain,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must differ from", r.stderr)

    def test_the_flag_is_refused_for_asymmetric_encryption(self):
        """--for-identity skips the whole password-resolution block.

        A guard placed inside it was silently bypassed, which is exactly the
        stale-file hazard the guard exists to prevent.
        """
        pw = os.path.join(self.tmp.name, "pw.txt")
        r = self._run(
            "encrypt",
            "-i",
            self.plain,
            "-o",
            os.path.join(self.tmp.name, "a.enc"),
            "--for-identity",
            "nobody",
            "--random",
            "24",
            "--random-password-out",
            pw,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(pw), "a stale password file was left")

    def test_a_destination_equal_to_the_input_is_refused(self):
        out = os.path.join(self.tmp.name, "out.enc")
        r = self._run(
            "encrypt",
            "-i",
            self.plain,
            "-o",
            out,
            "--random",
            "24",
            "--random-password-out",
            self.plain,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must differ from", r.stderr)
        with open(self.plain) as f:
            self.assertEqual(f.read(), "payload", "the input was clobbered")

    def test_quiet_on_a_real_tty_without_a_destination_is_refused(self):
        """It would encrypt, print nothing, exit 0, and lose the password.

        stderr must be a REAL tty here. With a pipe the command is refused for
        the non-tty reason instead, and the test passes with the --quiet gate
        removed -- which is exactly what happened the first time.
        """
        import pty
        import subprocess
        import sys as _sys

        out = os.path.join(self.tmp.name, "quiet.enc")
        controller, worker = pty.openpty()
        try:
            proc = subprocess.run(
                [
                    _sys.executable,
                    "-m",
                    "openssl_encrypt.crypt",
                    "encrypt",
                    "-i",
                    self.plain,
                    "-o",
                    out,
                    "--random",
                    "24",
                    "--quiet",
                ],
                stdin=subprocess.DEVNULL,
                stdout=worker,
                stderr=worker,
                timeout=300,
            )
        finally:
            os.close(worker)
            os.close(controller)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(
            os.path.exists(out),
            "a file was encrypted under a password nobody holds",
        )

    def test_no_destination_without_a_tty_is_refused(self):
        out = os.path.join(self.tmp.name, "notty.enc")
        r = self._run("encrypt", "-i", self.plain, "-o", out, "--random", "24")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(out))

    def test_the_destination_flag_without_random_is_refused(self):
        """A stale file must not be read back as this run's password."""
        out = os.path.join(self.tmp.name, "nr.enc")
        pw = os.path.join(self.tmp.name, "pw.txt")
        r = self._run(
            "encrypt",
            "-i",
            self.plain,
            "-o",
            out,
            "--password",
            "pw12345678",
            "--random-password-out",
            pw,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no effect without --random", r.stderr)


if __name__ == "__main__":
    unittest.main()
