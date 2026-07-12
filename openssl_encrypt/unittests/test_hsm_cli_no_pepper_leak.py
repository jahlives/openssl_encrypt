"""Regression tests for finding H1 [HSM-1] and its residual (gitlab#121).

The `hsm fido2-test` command printed the full derived hardware pepper
(`click.echo(f"Pepper (hex): {pepper.hex()}")`) to stdout unconditionally —
no --debug, no --unsafe-show-secrets, and not through the debug_secret()
redaction chokepoint. Hardware peppers are key material / KDF intermediates
and must never be emitted in cleartext.

The original H1 fix covered only modules/hsm_cli.py, which is not wired into
the `openssl-encrypt` entry point (cli.py dispatches `hsm` to
crypt_cli.handle_hsm_command), so the live `fido2-test`/`onlykey-test`
handlers in crypt_cli.py kept hex-dumping the pepper (gitlab#121). These
tests guard every known secret-print site:

- hsm_cli.py and crypt_cli.py: no print/echo of pepper/secret/response hex
  (the `derive-key` command's `print(derived.hex())` is intentional output —
  emitting the derived key is that command's documented purpose — and is
  deliberately not matched here);
- asymmetric_core.py: the __main__ self-test must not hex-dump the roundtrip
  password (random test data, but a never-print-keys policy violation);
- plugins/hsm/fido2_pepper: the raw prf/hmac-secret extension output (the
  pepper's source material) must not be interpolated into log lines.
"""

import re
import unittest
from pathlib import Path

MODULES = Path(__file__).resolve().parent.parent / "modules"
PLUGINS = Path(__file__).resolve().parent.parent / "plugins"

HSM_CLI = MODULES / "hsm_cli.py"
CRYPT_CLI = MODULES / "crypt_cli.py"
ASYMMETRIC_CORE = MODULES / "asymmetric_core.py"
FIDO2_PEPPER_PLUGIN = PLUGINS / "hsm" / "fido2_pepper" / "__init__.py"
ONLYKEY_PLUGIN = PLUGINS / "hsm" / "onlykey_challenge_response" / "__init__.py"
YUBIKEY_PLUGIN = PLUGINS / "hsm" / "yubikey_challenge_response" / "__init__.py"

# Match a print/echo of a secret-named value's raw hex, e.g.
#   click.echo(f"Pepper (hex): {pepper.hex()}")
#   eprint(f"Pepper (hex): {pepper.hex()}")
#   print(key.hex())
SECRET_HEX_ECHO = re.compile(
    r"(?:click\.echo|eprint|print)\(.*\b(pepper|secret|key|response)\w*\.hex\(\)",
    re.IGNORECASE,
)

# Match any hex dump in a print in asymmetric_core.py — the module prints
# lengths for its public values, so a `.hex()` inside a print there is always
# secret material (e.g. the self-test's password/recovered pair).
ANY_HEX_ECHO = re.compile(r"(?:eprint|print)\(.*\.hex\(\)")

# Match raw prf_data interpolated into ANY sink — logger calls, prints, or
# PluginResult messages (error messages propagate to eprint in the CLI), e.g.
#   logger.debug(f"prf_data value: {prf_data}")
#   PluginResult.error_result(f"Unexpected format: {prf_data}")
# Structure-only renderings (type(prf_data), len(prf_data), prf_data.keys())
# are allowed; the bare value (incl. !r/format-spec variants) is not.
PRF_DATA_LOG = re.compile(r"\{\s*prf_data\s*[!:}]")


def _offenders(path: Path, pattern: re.Pattern) -> list:
    source = path.read_text(encoding="utf-8")
    return [
        f"{path.name} line {n}: {line.strip()}"
        for n, line in enumerate(source.splitlines(), start=1)
        if pattern.search(line)
    ]


class TestNoPepperHexLeak(unittest.TestCase):
    def test_no_secret_hex_dump_in_hsm_cli(self) -> None:
        offenders = _offenders(HSM_CLI, SECRET_HEX_ECHO)
        self.assertEqual(
            offenders,
            [],
            "hsm_cli.py must not print secret material (pepper/key/response) in "
            "cleartext hex; route through debug_secret() or print only the length:\n"
            + "\n".join(offenders),
        )

    def test_no_secret_hex_dump_in_crypt_cli(self) -> None:
        """gitlab#121: the LIVE hsm handlers are in crypt_cli.handle_hsm_command."""
        offenders = _offenders(CRYPT_CLI, SECRET_HEX_ECHO)
        self.assertEqual(
            offenders,
            [],
            "crypt_cli.py must not print secret material (pepper/key/response) in "
            "cleartext hex; route through debug_secret() or print only the length:\n"
            + "\n".join(offenders),
        )

    def test_no_hex_dump_in_asymmetric_core(self) -> None:
        """gitlab#121 rider: __main__ self-test hex-dumped the roundtrip password."""
        offenders = _offenders(ASYMMETRIC_CORE, ANY_HEX_ECHO)
        self.assertEqual(
            offenders,
            [],
            "asymmetric_core.py must not hex-dump values in prints (the self-test "
            "password/recovered pair is secret-shaped); print lengths instead:\n"
            + "\n".join(offenders),
        )

    def test_no_raw_prf_data_in_fido2_plugin_logs(self) -> None:
        """gitlab#121 rider: raw prf/hmac-secret output is pepper source material.

        Covers every sink, not just logger calls — PluginResult error messages
        propagate to the user via eprint(result.message) in the CLI handlers.
        """
        offenders = _offenders(FIDO2_PEPPER_PLUGIN, PRF_DATA_LOG)
        self.assertEqual(
            offenders,
            [],
            "fido2_pepper plugin must not interpolate raw prf_data into any output "
            "(logs, prints, PluginResult messages); render its type/keys/lengths "
            "or use debug_secret():\n" + "\n".join(offenders),
        )

    def test_no_secret_hex_dump_in_challenge_response_plugins(self) -> None:
        """The HMAC challenge-response output IS the pepper on these plugins."""
        offenders = _offenders(ONLYKEY_PLUGIN, SECRET_HEX_ECHO) + _offenders(
            YUBIKEY_PLUGIN, SECRET_HEX_ECHO
        )
        self.assertEqual(
            offenders,
            [],
            "challenge-response plugins must not print secret material "
            "(pepper/response/key) in cleartext hex; log only lengths:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
