"""Regression test for follow-up finding H1 [HSM-1]: pepper printed in cleartext.

The `hsm fido2-test` command printed the full derived hardware pepper
(`click.echo(f"Pepper (hex): {pepper.hex()}")`) to stdout unconditionally —
no --debug, no --unsafe-show-secrets, and not through the debug_secret()
redaction chokepoint. Hardware peppers are key material / KDF intermediates
and must never be emitted in cleartext. This test guards that no secret
(pepper / key / response / secret) is hex-dumped to output in hsm_cli.py.
"""

import re
import unittest
from pathlib import Path

HSM_CLI = Path(__file__).resolve().parent.parent / "modules" / "hsm_cli.py"

# Match a print/echo of a secret-named value's raw hex, e.g.
#   click.echo(f"Pepper (hex): {pepper.hex()}")
#   print(key.hex())
SECRET_HEX_ECHO = re.compile(
    r"(?:click\.echo|print)\(.*\b(pepper|secret|key|response)\w*\.hex\(\)",
    re.IGNORECASE,
)


class TestNoPepperHexLeak(unittest.TestCase):
    def test_no_secret_hex_dump_in_hsm_cli(self) -> None:
        source = HSM_CLI.read_text(encoding="utf-8")
        offenders = [
            f"line {n}: {line.strip()}"
            for n, line in enumerate(source.splitlines(), start=1)
            if SECRET_HEX_ECHO.search(line)
        ]
        self.assertEqual(
            offenders,
            [],
            "hsm_cli.py must not print secret material (pepper/key/response) in "
            "cleartext hex; route through debug_secret() or print only the length:\n"
            + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
