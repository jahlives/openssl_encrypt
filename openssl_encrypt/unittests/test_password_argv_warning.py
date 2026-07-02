"""Regression test: the -p/--password argv-exposure warning is not silenceable (#67).

Passing a password with -p places it in the process command line (visible via ps
/ /proc/<pid>/cmdline). The tool warns about this, but the warning was gated by
`if not args.quiet`, so --quiet -- an output-verbosity flag -- silenced a security
warning. It now fires regardless of --quiet.
"""

import os
import subprocess
import sys
import tempfile
import unittest


class TestPasswordArgvWarning(unittest.TestCase):
    def test_argv_password_warning_shown_even_with_quiet(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "in.txt")
            dst = os.path.join(d, "in.enc")
            with open(src, "w") as f:
                f.write("data")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "openssl_encrypt.crypt",
                    "encrypt",
                    "-i",
                    src,
                    "-o",
                    dst,
                    "-p",
                    "secretpass",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                cwd=os.getcwd(),
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(
                "visible in process list",
                proc.stderr,
                f"argv-exposure warning must appear even with --quiet; stderr={proc.stderr!r}",
            )


if __name__ == "__main__":
    unittest.main()
