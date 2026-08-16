#!/usr/bin/env python3
"""list-recovery --json stdout payload is pinned to a frozen key allowlist (gitlab#280).

The gitlab#278 port moved the list-recovery JSON payload out of the print()
call into a `_slot_doc` builder, which broke the stdout-leak lint's
pinned-payload property: the whitelist in test_no_stdout_leaks.py authorizes
the exact source text of the call, so with the payload built elsewhere, a
field added inside the builder (e.g. a slot's wrap or params.salt) would no
longer trip the lint. The compensating control is SLOT_DOC_KEYS: a
module-level frozen allowlist that _slot_doc filters through, so nothing
beyond the pinned keys can reach stdout regardless of how the builder
changes. These tests pin the allowlist itself and prove the filter holds for
every slot type, including hostile extra fields on attacker-authored slots.
"""

import unittest

from openssl_encrypt.modules import recovery_slots

# Every slot type the format knows: the three creatable on this line
# (SLOT_TYPES) plus shamir (1.5.x-created, listable here, gitlab#278).
ALL_SLOT_TYPES = tuple(sorted(recovery_slots.SLOT_TYPES)) + ("shamir",)

# Fields that must never reach the credential-free --json listing: real
# header fields (wrap, params, salt) and credential-shaped names a buggy
# future builder might copy through.
HOSTILE_EXTRAS = {
    "wrap": "AAAA",
    "params": {"salt": "AAAA", "shamir": {"threshold": 2, "num_shares": 3}},
    "salt": "AAAA",
    "code": "RRRR-RRRR-RRRR-RRRR",
    "passphrase": "hunter2",
    "recovery_code": "RRRR-RRRR-RRRR-RRRR",
}


class TestSlotDocKeyPinning(unittest.TestCase):
    def test_allowlist_is_pinned(self):
        """Extending the stdout payload must require editing this pin.

        SLOT_DOC_KEYS is the authorized stdout payload of the credential-free
        listing (the whitelist entry in test_no_stdout_leaks.py names the
        call; this constant names the fields). Growing it is a security
        decision — this test makes that decision explicit in the diff.
        """
        self.assertEqual(
            recovery_slots.SLOT_DOC_KEYS,
            ("id", "type", "key_id", "threshold", "num_shares"),
        )

    def test_slot_doc_is_filtered_through_the_allowlist_per_type(self):
        """No slot type can push a field past SLOT_DOC_KEYS into --json."""
        for slot_type in ALL_SLOT_TYPES:
            slot = {
                "id": f"{slot_type}-0",
                "type": slot_type,
                "key_id": "k" * 20,
                **HOSTILE_EXTRAS,
            }
            if slot_type == "shamir":
                # As list_recovery_slots surfaces them post-validation.
                slot["threshold"] = 2
                slot["num_shares"] = 3
            doc = recovery_slots._slot_doc(slot)
            self.assertLessEqual(set(doc), set(recovery_slots.SLOT_DOC_KEYS), (slot_type, doc))
            for forbidden in HOSTILE_EXTRAS:
                self.assertNotIn(forbidden, doc, slot_type)

    def test_hostile_values_never_appear_in_the_document(self):
        """Value-level check: the filter drops contents, not just key names."""
        slot = {"id": "s-0", "type": "recovery_code", **HOSTILE_EXTRAS}
        import json

        rendered = json.dumps(recovery_slots._slot_doc(slot))
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("RRRR-RRRR", rendered)

    def test_threshold_pair_requires_both_keys(self):
        """One key alone (attacker-authored partial pair) emits neither."""
        for partial in ({"threshold": 2}, {"num_shares": 3}):
            doc = recovery_slots._slot_doc({"id": "x", "type": "shamir", **partial})
            self.assertNotIn("threshold", doc)
            self.assertNotIn("num_shares", doc)


class TestRenderBoundaryValidation(unittest.TestCase):
    """The rendering layer re-validates K-of-N instead of trusting core.

    list_recovery_slots guarantees threshold/num_shares are validated
    in-range ints, but the module's own convention is that the rendering
    boundary de-fangs untrusted header data itself — a future producer, a
    second caller, or a partial revert of the core validation must not put
    an unsanitized header string straight into --json or a terminal line
    (gitlab#280 finding 2).
    """

    NON_INTS = ("2", b"2", 2.0, True, False, None, [2], {"n": 2})

    def test_slot_doc_drops_non_int_kofn_values(self):
        for bad in self.NON_INTS:
            doc = recovery_slots._slot_doc(
                {"id": "x", "type": "shamir", "threshold": bad, "num_shares": 3}
            )
            self.assertNotIn("threshold", doc, repr(bad))
            self.assertNotIn("num_shares", doc, repr(bad))

    def test_human_view_drops_non_int_kofn_values(self):
        """A hostile string never reaches the terminal K-of-N suffix."""
        import argparse
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        import openssl_encrypt.modules.crypt_core as cc

        hostile = [
            {
                "id": "s-1",
                "type": "shamir",
                "threshold": "\x1b[31mEVIL",
                "num_shares": "of everything",
            }
        ]
        args = argparse.Namespace(input="ignored", json=False, quiet=True)
        err = io.StringIO()
        with mock.patch.object(cc, "list_recovery_slots", return_value=hostile):
            with redirect_stderr(err):
                recovery_slots.list_recovery_cli(args)
        out = err.getvalue()
        self.assertNotIn("EVIL", out)
        self.assertNotIn(" of ", out.split("unauthenticated")[-1].split("id=")[-1])

    def test_human_view_keeps_valid_kofn(self):
        """The re-validation must not eat the legitimate case."""
        import argparse
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        import openssl_encrypt.modules.crypt_core as cc

        good = [{"id": "s-1", "type": "shamir", "threshold": 2, "num_shares": 3}]
        args = argparse.Namespace(input="ignored", json=False, quiet=True)
        err = io.StringIO()
        with mock.patch.object(cc, "list_recovery_slots", return_value=good):
            with redirect_stderr(err):
                recovery_slots.list_recovery_cli(args)
        self.assertIn('type="shamir" (2 of 3)', err.getvalue())


if __name__ == "__main__":
    unittest.main()
