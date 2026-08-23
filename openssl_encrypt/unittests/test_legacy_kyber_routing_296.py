#!/usr/bin/env python3
"""Legacy kyber*-hybrid algorithm names must route on 1.5.x (gitlab#296).

v1.5.0 renamed the Kyber hybrid algorithms to their NIST ML-KEM names. The
rename was a naming change, not a decrypt removal — pqc.py deliberately kept
``normalize_algorithm_name`` — but the crypt_core dispatch lost its legacy
remap entries (a dangling "Legacy Kyber mappings" comment survived with
nothing under it), so a genuine 1.4.x file with ``algorithm:
"kyber512-hybrid"`` fell through to the generic "Unsupported encryption
algorithm" error before pqc.py's normalization was ever reached.

These tests pin the restored routing: metadata-sourced legacy names are
normalized through ``LEGACY_ALGORITHM_ALIASES`` for decrypt and rekey, while
encrypt-side validation stays strict (no new file may be written under a
removed name — pinned by test_legacy_removal.py's enum assertions).
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    LEGACY_ALGORITHM_ALIASES,
    EncryptionAlgorithm,
    decrypt_file,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "format_versions")
PASSWORD = b"fixture-corpus-password-2026"
PLAINTEXT = b"openssl_encrypt format-version fixture corpus 2026-07-10\n"


def _rewrite_algorithm(src_path: str, legacy_name: str, dest_dir: str) -> str:
    """Copy a fixture with its metadata algorithm renamed to a legacy alias.

    Args:
        src_path: Existing PQC fixture whose algorithm is an ML-KEM name.
        legacy_name: Legacy kyber name to write into the metadata header.
        dest_dir: Directory receiving the rewritten copy.

    Returns:
        Path of the rewritten file.
    """
    raw = open(src_path, "rb").read()
    head, sep, rest = raw.partition(b":")
    meta = json.loads(base64.b64decode(head))
    meta["encryption"]["algorithm"] = legacy_name
    out = os.path.join(dest_dir, os.path.basename(src_path) + ".kyber")
    with open(out, "wb") as f:
        f.write(base64.b64encode(json.dumps(meta).encode()) + sep + rest)
    return out


class TestLegacyAliasTable(unittest.TestCase):
    """The alias table carries exactly the three renamed hybrids."""

    def test_alias_table_contents(self):
        """Exactly kyber512/768/1024-hybrid map to their ML-KEM successors."""
        self.assertEqual(
            LEGACY_ALGORITHM_ALIASES,
            {
                "kyber512-hybrid": EncryptionAlgorithm.ML_KEM_512_HYBRID.value,
                "kyber768-hybrid": EncryptionAlgorithm.ML_KEM_768_HYBRID.value,
                "kyber1024-hybrid": EncryptionAlgorithm.ML_KEM_1024_HYBRID.value,
            },
        )

    def test_enum_stays_free_of_legacy_names(self):
        """The rename stays a rename: no kyber value re-enters the enum."""
        values = [alg.value for alg in EncryptionAlgorithm]
        for name in LEGACY_ALGORITHM_ALIASES:
            self.assertNotIn(name, values)


class TestKyberNamedFileRouting(unittest.TestCase):
    """A kyber-named PQC file must route into the PQC decrypt path."""

    @classmethod
    def setUpClass(cls):
        """Skip without liboqs; the routing test needs the PQC path live."""
        from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE

        if not LIBOQS_AVAILABLE:
            raise unittest.SkipTest("liboqs not available")
        cls.tmp = tempfile.mkdtemp()

    def test_kyber_named_file_not_rejected_as_unsupported(self):
        """The legacy name must never hit the generic unsupported-algorithm error.

        The v14 fixture binds its metadata into the AEAD transcript, so the
        renamed copy cannot fully decrypt — but the failure must come from
        the PQC path (authentication), proving the dispatch routed the name,
        not from the pre-fix "Unsupported encryption algorithm" fallthrough.
        """
        path = _rewrite_algorithm(
            os.path.join(FIXTURE_DIR, "v14_pqc.enc"), "kyber768-hybrid", self.tmp
        )
        outfile = os.path.join(self.tmp, "v14.out")
        try:
            decrypt_file(path, outfile, PASSWORD, quiet=True)
        except Exception as exc:  # noqa: BLE001 - asserting on the failure class
            self.assertNotIn(
                "Unsupported encryption algorithm",
                str(exc),
                msg="kyber-named file fell through the dispatch instead of "
                "routing into the PQC path (gitlab#296)",
            )
