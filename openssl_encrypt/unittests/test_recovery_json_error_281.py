#!/usr/bin/env python3
"""list-recovery --json failures answer with a JSON error document (gitlab#281).

The recovery dispatch handler printed `Error: ...` to stderr and exited 1
without emitting any JSON document — under --json a failed invocation
produced empty stdout plus a bare exit code, exactly on the crafted-file
inputs the gitlab#278/#279/#280 hardening turned into clean
ValidationErrors. Mirrors the 1.5.x behavior (gitlab#277): the caller gets
one error envelope on stdout.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest


def _run_list_recovery(path):
    return subprocess.run(
        [sys.executable, "-m", "openssl_encrypt.crypt", "list-recovery", "-i", path, "--json"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=300,
    )


class TestJsonErrorEnvelope(unittest.TestCase):
    def test_missing_file_emits_error_envelope_on_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run_list_recovery(os.path.join(tmp, "missing.enc"))
        self.assertNotEqual(r.returncode, 0)
        envelope = json.loads(r.stdout)
        self.assertEqual(envelope["status"], "error")
        self.assertIn("message", envelope["error"])

    def test_malformed_file_emits_error_envelope_on_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "crafted.enc")
            with open(path, "wb") as f:
                f.write(b"not-base64!:payload")
            r = _run_list_recovery(path)
        self.assertNotEqual(r.returncode, 0)
        envelope = json.loads(r.stdout)
        self.assertEqual(envelope["status"], "error")

    def test_without_json_stdout_stays_empty_on_failure(self):
        """The human contract is unchanged: errors go to stderr only."""
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "openssl_encrypt.crypt",
                    "list-recovery",
                    "-i",
                    os.path.join(tmp, "missing.enc"),
                ],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=300,
            )
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")
        self.assertIn("Error:", r.stderr)


if __name__ == "__main__":
    unittest.main()
