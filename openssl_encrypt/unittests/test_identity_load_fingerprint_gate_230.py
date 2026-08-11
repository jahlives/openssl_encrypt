#!/usr/bin/env python3
"""Identity.load must fail closed when the stored fingerprint does not match the
public keys, and TOFU must compare RECOMPUTED fingerprints (gitlab#230, scan
F6/F7, CWE-345).

The gap: `Identity.load` copied `fingerprint` verbatim from an untrusted
`identity.json` and never called `check_fingerprint_consistency()` (only the
`import_public` path did). Public keys, meanwhile, are read from sibling `.pem`
files. So a supplied store whose `identity.json` claims a genuine
out-of-band-verified fingerprint but whose `.pem` files hold attacker keys was
indistinguishable from a real pinned contact:

- `identity show` printed the good fingerprint while `encrypt --for-identity`
  encapsulated to the attacker's key (F6);
- signature verification printed "verified from: <legitimate fingerprint>"
  against the substituted signing key (F7);
- re-importing the real bundle raised no TOFU warning because `add_identity`
  compared the JSON-claimed fingerprint, not one recomputed from the keys.

These tests pin: (1) load() refuses an entry whose stored fingerprint does not
match its own public keys; (2) list_identities skips and reports it rather than
using it; (3) the TOFU key-change gate is driven by the recomputed fingerprint,
so forging the JSON `fingerprint` to match a pinned contact cannot smuggle a
key substitution past it.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.identity import (
    Identity,
    IdentityError,
    IdentityKeyChangedError,
    IdentityStore,
)


class TestLoadFingerprintGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = IdentityStore(base_path=Path(self.tmp))
        self.alice = Identity.generate("alice", None, "pass")
        self.store.add_identity(self.alice, "pass")
        self.alice_dir = self.store.base_path / "alice"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _substitute_public_keys_from_attacker(self):
        """Overwrite alice's public .pem files with a different identity's keys,
        leaving identity.json (and its claimed fingerprint) untouched — the F6/F7
        supplied-store attack."""
        attacker_tmp = tempfile.mkdtemp()
        try:
            attacker = Identity.generate("alice", None, "pass")
            self.assertNotEqual(attacker.fingerprint, self.alice.fingerprint)
            attacker_dir = Path(attacker_tmp) / "attacker"
            attacker.save(attacker_dir, "pass")
            for pem in ("encryption_public.pem", "signing_public.pem"):
                shutil.copyfile(attacker_dir / pem, self.alice_dir / pem)
            return attacker
        finally:
            shutil.rmtree(attacker_tmp, ignore_errors=True)

    def test_consistent_identity_loads(self):
        # Sanity: an untampered identity loads fine.
        loaded = Identity.load(self.alice_dir, load_private_keys=False)
        self.assertEqual(loaded.fingerprint, self.alice.fingerprint)

    def test_load_refuses_substituted_public_keys(self):
        self._substitute_public_keys_from_attacker()
        with self.assertRaises(IdentityError) as ctx:
            Identity.load(self.alice_dir, load_private_keys=False)
        self.assertIn("fingerprint", str(ctx.exception).lower())

    def test_list_identities_skips_inconsistent_entry(self):
        self._substitute_public_keys_from_attacker()
        skipped = []
        identities = self.store.list_identities(skipped=skipped)
        self.assertNotIn("alice", [i.name for i in identities])
        self.assertIn("alice", [s["entry"] for s in skipped])

    def test_tofu_uses_recomputed_fingerprint_not_json_claim(self):
        """F7 TOFU bypass: an impostor with different keys forges its JSON
        `fingerprint` to equal the pinned contact's, so a stored-value comparison
        would see 'no change'. The recomputed comparison must still refuse."""
        impostor = Identity.generate("alice", None, "pass")  # different keys
        self.assertNotEqual(impostor.calculate_fingerprint(), self.alice.calculate_fingerprint())
        # Forge the claimed fingerprint to match the pinned one.
        impostor.fingerprint = self.alice.fingerprint
        with self.assertRaises(IdentityKeyChangedError):
            self.store.add_identity(impostor, "pass", overwrite=True)
        # The pinned key is unchanged.
        self.assertEqual(self.store.get_by_name("alice").fingerprint, self.alice.fingerprint)


if __name__ == "__main__":
    unittest.main()
