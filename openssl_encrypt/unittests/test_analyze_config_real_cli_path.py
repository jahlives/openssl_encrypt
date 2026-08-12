#!/usr/bin/env python3
"""`analyze-config` must run through the REAL CLI path without crashing
(gitlab#219).

The crash only reproduces through `main_with_args`'s subparser-args
compatibility layer, which back-fills `args.algorithm = None`
(crypt_cli.py:5813) for any command whose parser does not define `--algorithm`.
`setup_analyze_config_parser` defines only `--encryption-data-algorithm`, so
`args.algorithm` was None for every analyze-config run; the old cipher
extraction did `config.get("algorithm", "aes-gcm")` — key PRESENT with value
None, so the fallback never fired — and the scorer's `"gcm" in algorithm` on
None raised `TypeError: argument of type 'NoneType' is not iterable`, caught
and turned into exit 1 with empty stdout.

Every prior analyze-config test built args from a bare `ArgumentParser`, which
bypasses the compatibility layer and never saw the crash. These drive
`build_subparser()` -> `main_with_args()`, the same objects the CLI uses, so
the back-fill is exercised. The gitlab#168 fix (reading
`encryption_data_algorithm` via an explicit whitelist, never the back-filled
`algorithm`) is what makes this pass; this is its real-path regression guard.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout


class TestAnalyzeConfigRealCliPath(unittest.TestCase):
    def _run(self, *extra):
        from openssl_encrypt.modules.crypt_cli import main_with_args
        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        parser = build_subparser()
        args = parser.parse_args(["analyze-config", *extra, "--output-format", "json"])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                main_with_args(args)
        code = ctx.exception.code
        return (0 if code is None else code), out.getvalue(), err.getvalue()

    def test_bare_invocation_does_not_crash(self):
        # The exact repro from gitlab#219: this crashed with a NoneType
        # TypeError and exited 1 with empty stdout.
        code, out, err = self._run()
        self.assertEqual(code, 0, f"analyze-config exited {code}; stderr: {err}")
        doc = json.loads(out)  # must be a real JSON document, not empty
        self.assertIn("configuration_summary", doc)

    def test_flags_are_scored_through_the_real_path(self):
        # gitlab#168 must also hold through the real compatibility-layer path,
        # not only the hand-built parser: a passed KDF flag reaches the report.
        code, out, _ = self._run("--pbkdf2-rounds", "600000")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertIn("PBKDF2", doc["configuration_summary"]["active_kdfs"])


if __name__ == "__main__":
    unittest.main()
