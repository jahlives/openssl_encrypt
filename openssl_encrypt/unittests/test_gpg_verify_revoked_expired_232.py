#!/usr/bin/env python3
"""verify_detached must reject signatures from revoked or expired GPG keys
(gitlab#232, scan F36, CWE-347).

verify_detached is the single primitive behind plugin signatures (ENFORCE by
default), the per-package PLUGIN.manifest, and the source-integrity manifest.
It used to set its "good" verdict from a VALIDSIG/GOODSIG status line alone,
never inspecting the gpg exit status or the REVKEYSIG / EXPKEYSIG / EXPSIG
lines -- and GnuPG emits VALIDSIG *alongside* REVKEYSIG for a cryptographically
valid signature made by a revoked key. So a compromised-then-revoked key (or the
project key after expiry) still got plugins accepted and executed.

Two layers of coverage:
1. Mock-based unit tests over the exact status lines GnuPG documents, so every
   failure marker (REVKEYSIG/EXPKEYSIG/EXPSIG/ERRSIG/BADSIG, non-zero exit) and
   the primary-key-fingerprint selection are pinned without depending on live
   key state.
2. Real gpg integration tests: a genuinely good signature is accepted (and its
   primary fingerprint reported/matched), while tampered data and the wrong key
   are rejected -- proving the parser path works against real gpg output. (gpg
   2.2 will not re-import its own saved revocation certificate, so the
   revoked/expired markers are pinned at the unit level in layer 1.)
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.integrity import gpg_runner
from openssl_encrypt.integrity.gpg_runner import SignatureResult, verify_detached

_GPG = shutil.which("gpg")

# A 40-hex primary-key fingerprint and a distinct 40-hex subkey fingerprint.
_PRIMARY_FPR = "1111111111111111111111111111111111111111"
_SUBKEY_FPR = "2222222222222222222222222222222222222222"


def _completed(returncode=0, stdout=b""):
    return subprocess.CompletedProcess(
        args=["gpg"], returncode=returncode, stdout=stdout, stderr=b""
    )


def _validsig_line(sig_fpr=_SUBKEY_FPR, primary_fpr=_PRIMARY_FPR):
    # GnuPG VALIDSIG args: <sig-fpr> <date> <ts> <expire-ts> <version> <reserved>
    # <pubkey-algo> <hash-algo> <sig-class> <primary-key-fpr>
    return f"[GNUPG:] VALIDSIG {sig_fpr} 2026-01-01 1767225600 0 4 0 22 8 00 " f"{primary_fpr}"


class TestStatusParsing(unittest.TestCase):
    """Unit-level: drive verify_detached's decision purely from crafted status
    output by mocking the gpg subprocess (import success, then the verify run)."""

    def _verify_with_status(self, status_lines, returncode=0, **kw):
        status = ("\n".join(status_lines) + "\n").encode()

        def fake_run(args, home, stdin):
            # first call: --import (success); second call: --verify (status)
            if "--import" in args:
                return _completed(0, b"")
            return _completed(returncode, status)

        with mock.patch.object(gpg_runner, "_run", side_effect=fake_run):
            return verify_detached(b"data", b"sig", public_key=b"pub", **kw)

    def test_good_goodsig_validsig_accepted(self):
        res = self._verify_with_status(
            ["[GNUPG:] GOODSIG DEADBEEF signer", _validsig_line()], returncode=0
        )
        self.assertTrue(res.good, res.summary)

    def test_revoked_key_rejected(self):
        # VALIDSIG still present (crypto valid), but the key is revoked.
        # NB: real gpg emits REVKEYSIG *instead of* GOODSIG (they are mutually
        # exclusive). Co-emitting both here is deliberately adversarial -- it
        # pins that the failure marker alone forces rejection even if a GOODSIG
        # somehow appeared; do not "fix" this to match real gpg output.
        res = self._verify_with_status(
            [
                "[GNUPG:] GOODSIG DEADBEEF signer",
                _validsig_line(),
                f"[GNUPG:] REVKEYSIG {_SUBKEY_FPR} signer",
            ],
            returncode=1,
        )
        self.assertFalse(res.good, "a signature from a revoked key must be rejected")

    def test_expired_key_rejected(self):
        res = self._verify_with_status(
            [
                "[GNUPG:] EXPKEYSIG DEADBEEF signer",
                _validsig_line(),
            ],
            returncode=1,
        )
        self.assertFalse(res.good, "a signature from an expired key must be rejected")

    def test_expired_signature_rejected(self):
        res = self._verify_with_status(
            [
                "[GNUPG:] EXPSIG DEADBEEF signer",
                _validsig_line(),
            ],
            returncode=1,
        )
        self.assertFalse(res.good, "an expired signature must be rejected")

    def test_bad_signature_rejected(self):
        res = self._verify_with_status(["[GNUPG:] BADSIG DEADBEEF signer"], returncode=1)
        self.assertFalse(res.good)

    def test_errsig_rejected(self):
        res = self._verify_with_status(
            ["[GNUPG:] ERRSIG DEADBEEF 22 8 00 1767225600 9"], returncode=2
        )
        self.assertFalse(res.good)

    def test_nonzero_exit_without_marker_rejected(self):
        # Even a lone VALIDSIG must not pass if gpg exited non-zero.
        res = self._verify_with_status([_validsig_line()], returncode=1)
        self.assertFalse(res.good)

    def test_expected_fingerprint_matches_primary_not_subkey(self):
        # The expected-fingerprint check must compare the PRIMARY key fpr, not
        # the (possibly subkey) signing fpr from VALIDSIG's first field.
        res = self._verify_with_status(
            ["[GNUPG:] GOODSIG DEADBEEF signer", _validsig_line()],
            returncode=0,
            expected_fingerprint=_PRIMARY_FPR,
        )
        self.assertTrue(res.good, "primary-key fingerprint should match")

    def test_expected_fingerprint_subkey_value_is_not_accepted_as_match(self):
        # Passing the subkey fpr as "expected" must NOT match when we compare the
        # primary; this pins that we bind to the primary key identity.
        res = self._verify_with_status(
            ["[GNUPG:] GOODSIG DEADBEEF signer", _validsig_line()],
            returncode=0,
            expected_fingerprint=_SUBKEY_FPR,
        )
        self.assertFalse(res.good, "must not accept a subkey fpr as the pinned identity")


@unittest.skipUnless(_GPG, "gpg not available")
class TestRealGpgIntegration(unittest.TestCase):
    """End-to-end against a live gpg, proving the status parser both accepts a
    genuinely good signature and fails closed on a bad one. (The revoked/expired
    markers are pinned precisely by TestStatusParsing against gpg's documented
    REVKEYSIG/EXPKEYSIG/EXPSIG output; gpg 2.2 will not re-import its own saved
    revocation certificate, so that path is covered at the unit level.)"""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.home.chmod(0o700)
        self.data = b"integrity manifest payload\n"
        r = self._gpg(
            "--passphrase",
            "",
            "--quick-generate-key",
            "Test Signer <signer@fixture.test>",
            "ed25519",
            "sign",
            "0",
        )
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.fpr = self._first_fpr()
        self.pub = self._gpg("--armor", "--export", self.fpr).stdout
        self.sig = self._gpg(
            "--detach-sign", "--armor", "--local-user", self.fpr, stdin=self.data
        ).stdout
        self.assertTrue(self.sig)

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def _gpg(self, *args, stdin=None):
        return subprocess.run(
            [
                _GPG,
                "--batch",
                "--yes",
                "--homedir",
                str(self.home),
                "--pinentry-mode",
                "loopback",
                *args,
            ],
            input=stdin,
            capture_output=True,
        )

    def _first_fpr(self):
        out = self._gpg("--list-keys", "--with-colons").stdout.decode()
        for line in out.splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
        self.fail("no fingerprint found")

    def test_good_signature_accepted(self):
        res = verify_detached(self.data, self.sig, public_key=self.pub)
        self.assertTrue(res.good, res.summary)
        # And the reported fingerprint is the (primary) signing key.
        self.assertTrue((res.fingerprint or "").upper().endswith(self.fpr[-16:].upper()))

    def test_good_signature_matches_expected_primary_fingerprint(self):
        res = verify_detached(
            self.data, self.sig, public_key=self.pub, expected_fingerprint=self.fpr
        )
        self.assertTrue(res.good, res.summary)

    def test_tampered_data_rejected(self):
        res = verify_detached(self.data + b"x", self.sig, public_key=self.pub)
        self.assertFalse(res.good, "a signature over different data must be rejected")

    def test_wrong_key_rejected(self):
        # A different key that never signed this data must not verify it.
        other = self._gpg(
            "--passphrase",
            "",
            "--quick-generate-key",
            "Other <other@fixture.test>",
            "ed25519",
            "sign",
            "0",
        )
        self.assertEqual(other.returncode, 0, other.stderr.decode())
        other_fpr = [
            l.split(":")[9]
            for l in self._gpg("--list-keys", "--with-colons").stdout.decode().splitlines()
            if l.startswith("fpr:")
        ][-1]
        other_pub = self._gpg("--armor", "--export", other_fpr).stdout
        res = verify_detached(self.data, self.sig, public_key=other_pub)
        self.assertFalse(res.good, "verification against the wrong key must fail")


if __name__ == "__main__":
    unittest.main()
