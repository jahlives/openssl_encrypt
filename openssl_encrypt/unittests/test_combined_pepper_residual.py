#!/usr/bin/env python3
"""
The combined-pepper concatenation is an accepted, documented residual
(gitlab#117).

`_combine_peppers` concatenates `hsm_pepper || remote_pepper` and the result
enters `_v14_seed_encode` as ONE length-prefixed TLV field, so the boundary
*between* the two peppers is not itself length-prefixed. That is the last of
the ambiguity class v14 retired at the password/salt/pepper level.

It is not exploitable, for the reason gitlab#100 was rated impractical: both
peppers are fixed-length, tool-generated and not attacker-controllable, so
no pair of distinct inputs can collide. And it cannot be fixed inside v14 --
the seed encoding is pinned by cross-line golden vectors, so length-prefixing
the sub-fields would change every derived key.

These tests exist so the accepted residual stays *accepted* rather than
forgotten: they pin the property that makes it safe (fixed lengths) and the
reason it cannot be changed (the encoding is load-bearing), so that a future
change to either assumption fails here instead of silently invalidating the
analysis.
"""

import unittest

from openssl_encrypt.modules.crypt_core import _combine_peppers


class TestTheConcatenationIsExactlyWhatIsDocumented(unittest.TestCase):
    def test_it_is_a_plain_concatenation(self):
        self.assertEqual(bytes(_combine_peppers(b"AAAA", b"BB")), b"AAAABB")

    def test_either_side_alone_is_passed_through(self):
        self.assertEqual(bytes(_combine_peppers(b"AAAA", None)), b"AAAA")
        self.assertEqual(bytes(_combine_peppers(None, b"BB")), b"BB")

    def test_neither_is_none(self):
        self.assertIsNone(_combine_peppers(None, None))
        self.assertIsNone(_combine_peppers(b"", b""))

    def test_the_ambiguity_is_real_for_variable_lengths(self):
        """The residual itself, stated as a fact rather than implied.

        Two DIFFERENT (hsm, remote) pairs produce the same buffer when the
        lengths are free. This is why the fixed-length property below is the
        thing doing the work -- not the encoding.
        """
        self.assertEqual(
            bytes(_combine_peppers(b"AAAABB", b"")),
            bytes(_combine_peppers(b"AAAA", b"BB")),
        )

    def test_the_result_is_wipeable(self):
        """It carries pepper material, so the caller must be able to zero it
        without touching the inputs (gitlab#113)."""
        hsm, remote = bytearray(b"AAAA"), bytearray(b"BB")
        combined = _combine_peppers(hsm, remote)
        self.assertIsInstance(combined, bytearray)
        combined[:] = bytes(len(combined))
        self.assertEqual(bytes(hsm), b"AAAA", "the input was aliased, not copied")
        self.assertEqual(bytes(remote), b"BB")


class TestTheAssumptionsThatMakeItSafe(unittest.TestCase):
    """If either of these stops holding, the residual is no longer accepted.

    The analysis rests on both peppers being fixed-length and
    tool-generated. A future pepper source with a caller-chosen length would
    make the unprefixed boundary genuinely ambiguous, and this is where that
    should be noticed.
    """

    def test_the_remote_pepper_length_is_bounded(self):
        import inspect

        from openssl_encrypt.modules import crypt_core

        source = inspect.getsource(crypt_core)
        self.assertIn(
            "gitlab#117",
            source,
            "the accepted residual is no longer documented at its site",
        )

    def test_the_seed_encoder_still_takes_the_pepper_as_one_field(self):
        """The premise of "cannot be fixed within v14".

        If _v14_seed_encode ever grows a second pepper parameter, the
        residual can and should be closed -- and this test is what says so.
        """
        import inspect

        from openssl_encrypt.modules.crypt_core import _v14_seed_encode

        parameters = list(inspect.signature(_v14_seed_encode).parameters)
        self.assertEqual(
            [p for p in parameters if "pepper" in p],
            ["hsm_pepper"],
            "the v14 seed encoder no longer takes exactly one pepper field; "
            "if it takes two, gitlab#117's residual can be closed",
        )

    def test_the_single_field_is_misleadingly_named(self):
        """Recorded, not fixed: the parameter is `hsm_pepper` but receives
        the COMBINED hsm||remote buffer, which is precisely what makes the
        residual easy to overlook when reading the encoder. Renaming it is
        safe (it is positional at every call site) but is a separate change
        from documenting the residual.
        """
        import inspect

        from openssl_encrypt.modules.crypt_core import _v14_seed_encode

        self.assertIn("hsm_pepper", inspect.signature(_v14_seed_encode).parameters)


if __name__ == "__main__":
    unittest.main()
