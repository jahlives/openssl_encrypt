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
    def test_top_level_allowlist_is_pinned(self):
        """The document's top level is fail-closed like the per-slot level:
        a conditional key added under a branch the tests don't exercise must
        be filtered out unless it is pinned here (review F5)."""
        self.assertEqual(
            recovery_slots.LISTING_DOC_KEYS,
            ("metadata_authenticated", "slots", "truncated"),
        )

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
    # Out-of-range or mis-ordered pairs a reverted core could pass through:
    # the boundary defends the full 2 <= K <= N <= 255 invariant, not just
    # the type (review F6).
    BAD_PAIRS = (
        {"threshold": 0, "num_shares": 3},
        {"threshold": 1, "num_shares": 3},
        {"threshold": 2, "num_shares": 256},
        {"threshold": 256, "num_shares": 256},
        # Below CPython's 4300-digit int->str limit so the test's own
        # diagnostics can render it; the boundary must drop it either way.
        {"threshold": 10**4000, "num_shares": 10**4000},
        {"threshold": 5, "num_shares": 2},
        {"threshold": -3, "num_shares": 3},
    )

    def test_slot_doc_drops_non_int_kofn_values(self):
        for bad in self.NON_INTS:
            doc = recovery_slots._slot_doc(
                {"id": "x", "type": "shamir", "threshold": bad, "num_shares": 3}
            )
            self.assertNotIn("threshold", doc, repr(bad))
            self.assertNotIn("num_shares", doc, repr(bad))

    def test_slot_doc_drops_out_of_range_or_misordered_pairs(self):
        for pair in self.BAD_PAIRS:
            doc = recovery_slots._slot_doc({"id": "x", "type": "shamir", **pair})
            self.assertNotIn("threshold", doc, repr(pair)[:60])
            self.assertNotIn("num_shares", doc, repr(pair)[:60])

    def test_human_view_drops_out_of_range_pairs(self):
        import argparse
        import io
        from contextlib import redirect_stderr
        from unittest import mock

        import openssl_encrypt.modules.crypt_core as cc

        hostile = [{"id": "s-1", "type": "shamir", "threshold": 255, "num_shares": 2}]
        args = argparse.Namespace(input="ignored", json=False, quiet=True)
        err = io.StringIO()
        with mock.patch.object(cc, "list_recovery_slots", return_value=hostile):
            with redirect_stderr(err):
                recovery_slots.list_recovery_cli(args)
        self.assertNotIn("(255 of 2)", err.getvalue())

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


class TestBareDocumentMarksEmitted(unittest.TestCase):
    """Bare-document endpoints must record that a document went out.

    The recovery dispatch's error path is guarded by document_emitted() so a
    failure after the success document cannot emit a second one — but the
    recovery success documents are printed bare (the payload stays inside
    the whitelisted call text), so unless they mark the flag themselves the
    guard is inert by construction (confirmation review of the gitlab#280
    batch, finding F2).
    """

    def setUp(self):
        from openssl_encrypt.modules import json_output

        json_output.reset_emitted()
        self.json_output = json_output

    def tearDown(self):
        self.json_output.reset_emitted()

    def _run_list(self, json_mode):
        import argparse
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock

        import openssl_encrypt.modules.crypt_core as cc

        args = argparse.Namespace(input="ignored", json=json_mode, quiet=True)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
            cc, "list_recovery_slots", return_value=[{"id": "s", "type": "recovery_code"}]
        ):
            with redirect_stdout(out), redirect_stderr(err):
                recovery_slots.list_recovery_cli(args)

    def test_json_success_marks_the_document_as_emitted(self):
        self._run_list(json_mode=True)
        self.assertTrue(self.json_output.document_emitted())

    def test_human_mode_does_not_mark(self):
        self._run_list(json_mode=False)
        self.assertFalse(self.json_output.document_emitted())

    def test_mark_emitted_primitive(self):
        self.assertFalse(self.json_output.document_emitted())
        self.json_output.mark_emitted()
        self.assertTrue(self.json_output.document_emitted())


class TestUnauthenticatedMarker(unittest.TestCase):
    """--json carries an in-band unauthenticated-metadata marker (gitlab#280).

    The human view warns that the listing is unverified until decrypt, but
    the GUI — the stated consumer — reads --json. Without an in-band signal,
    a tampered header that under-reports N ("2 of 3" for a real 3-of-5 set)
    could lead a user to destroy shares they still need. The document-level
    marker lets a consumer gate destructive advice on it, and the top-level
    key set is pinned here for the same reason SLOT_DOC_KEYS pins the
    per-slot keys.
    """

    def _doc(self, slots):
        import argparse
        import io
        import json
        from contextlib import redirect_stdout
        from unittest import mock

        import openssl_encrypt.modules.crypt_core as cc

        args = argparse.Namespace(input="ignored", json=True, quiet=True)
        out = io.StringIO()
        with mock.patch.object(cc, "list_recovery_slots", return_value=slots):
            with redirect_stdout(out):
                recovery_slots.list_recovery_cli(args)
        # 1.5.x emits through the total-json envelope (gitlab#268); the
        # pinned top level here is the envelope's data payload.
        envelope = json.loads(out.getvalue())
        self.assertEqual(envelope["status"], "ok")
        return envelope["data"]

    def test_marker_is_present_and_false(self):
        doc = self._doc([{"id": "s-1", "type": "recovery_code"}])
        self.assertIs(doc["metadata_authenticated"], False)

    def test_top_level_keys_are_pinned(self):
        doc = self._doc([])
        self.assertEqual(set(doc), {"metadata_authenticated", "slots"})

    def test_top_level_keys_are_pinned_when_truncated(self):
        """The only conditional top-level key is the gitlab#279 cap marker."""
        from openssl_encrypt.modules.recovery_slots import MAX_DEK_SLOTS

        doc = self._doc(
            [{"id": f"s-{i}", "type": "recovery_code"} for i in range(MAX_DEK_SLOTS + 1)]
        )
        self.assertEqual(set(doc), {"metadata_authenticated", "slots", "truncated"})

    def test_marker_is_declared_in_the_capabilities_manifest(self):
        """A GUI must be able to discover the field before relying on it
        (gitlab#281 finding: list-recovery had no json_fields entry at all).
        Asserted on the curated _JSON_FIELDS map — the manifest builder
        passes it through filtered by json_endpoints, and
        test_capabilities_manifest.py pins that wiring."""
        from openssl_encrypt.modules.capabilities import _JSON_FIELDS

        self.assertEqual(
            _JSON_FIELDS["list-recovery"], ["metadata_authenticated", "slots", "truncated"]
        )
        for endpoint in ("recover", "add-recovery", "remove-recovery"):
            self.assertIn(endpoint, _JSON_FIELDS)


if __name__ == "__main__":
    unittest.main()
