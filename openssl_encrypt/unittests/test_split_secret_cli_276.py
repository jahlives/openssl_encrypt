#!/usr/bin/env python3
"""split-secret/combine-secrets must be usable end-to-end (gitlab#276).

The two actions dispatch through the monolithic parser, but their specific
flags (--shares, --threshold, --output-dir) were only ever defined on dead
subparsers that nothing routed to (removed in gitlab#208). The live parser
never accepted them, so both commands have always failed with "unrecognized
arguments" while their handlers (secret_sharing.split_secret_cli /
combine_secrets_cli) sat unreachable behind the parse error.

These tests pin the repaired surface: the flags parse, split writes 0600
share files, split->combine round-trips through a real encrypted file, and
bad inputs fail cleanly (no tracebacks, no partial share sets).
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest

TIMEOUT = 300
PASSWORD = "Correct-Horse-Battery-Staple-276!"


def _run(argv, env_extra=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "openssl_encrypt.crypt", *argv],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=TIMEOUT,
        env=env,
    )


def _split(out_dir, *extra):
    return _run(
        ["split-secret", "--shares", "3", "--threshold", "2", "--output-dir", out_dir, *extra],
        env_extra={"CRYPT_PASSWORD": PASSWORD},
    )


class TestSplitSecretParsesAndWritesShares(unittest.TestCase):
    def test_split_secret_flags_are_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _split(tmp)
            self.assertNotIn("unrecognized arguments", r.stderr)
            self.assertEqual(r.returncode, 0, f"split-secret failed: {r.stderr[:300]}")

    def test_split_secret_writes_n_share_files_with_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _split(tmp)
            self.assertEqual(r.returncode, 0, f"split-secret failed: {r.stderr[:300]}")
            shares = sorted(f for f in os.listdir(tmp) if f.endswith(".json"))
            self.assertEqual(len(shares), 3, f"expected 3 share files, got {shares}")
            for name in shares:
                mode = stat.S_IMODE(os.stat(os.path.join(tmp, name)).st_mode)
                self.assertEqual(mode, 0o600, f"{name} has mode {oct(mode)}")

    def test_split_secret_help_documents_the_flags(self):
        r = _run(["split-secret", "--help"])
        self.assertEqual(r.returncode, 0)
        for flag in ("--shares", "--threshold", "--output-dir"):
            self.assertIn(flag, r.stdout)


class TestSplitCombineRoundTrip(unittest.TestCase):
    def test_two_of_three_shares_decrypt_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "plain.txt")
            enc = os.path.join(tmp, "cipher.enc")
            dec = os.path.join(tmp, "roundtrip.txt")
            share_dir = os.path.join(tmp, "shares")
            payload = "secret payload gitlab#276\n"
            with open(plain, "w") as f:
                f.write(payload)

            r = _run(
                ["encrypt", "-i", plain, "-o", enc, "--force-password", "--quiet"],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertEqual(r.returncode, 0, f"encrypt failed: {r.stderr[:300]}")

            r = _split(share_dir)
            self.assertEqual(r.returncode, 0, f"split-secret failed: {r.stderr[:300]}")
            shares = sorted(
                os.path.join(share_dir, f) for f in os.listdir(share_dir) if f.endswith(".json")
            )
            self.assertEqual(len(shares), 3)

            # Any 2 of the 3 shares must reconstruct the password and decrypt.
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    enc,
                    "--shares",
                    shares[0],
                    shares[2],
                    "--output",
                    dec,
                    "--quiet",
                ]
            )
            self.assertNotIn("unrecognized arguments", r.stderr)
            self.assertEqual(r.returncode, 0, f"combine-secrets failed: {r.stderr[:300]}")
            with open(dec) as f:
                self.assertEqual(f.read(), payload)

    def test_fewer_than_threshold_shares_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            enc = os.path.join(tmp, "cipher.enc")
            plain = os.path.join(tmp, "plain.txt")
            share_dir = os.path.join(tmp, "shares")
            with open(plain, "w") as f:
                f.write("x")
            r = _run(
                ["encrypt", "-i", plain, "-o", enc, "--force-password", "--quiet"],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertEqual(r.returncode, 0, f"encrypt failed: {r.stderr[:300]}")
            r = _split(share_dir)
            self.assertEqual(r.returncode, 0, f"split-secret failed: {r.stderr[:300]}")
            one_share = sorted(
                os.path.join(share_dir, f) for f in os.listdir(share_dir) if f.endswith(".json")
            )[0]

            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    enc,
                    "--shares",
                    one_share,
                    "--output",
                    os.path.join(tmp, "out.txt"),
                    "--quiet",
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("insufficient", r.stderr.lower())
            self.assertNotIn("Traceback", r.stderr)


class TestBadInputsFailCleanly(unittest.TestCase):
    def test_split_shares_must_be_a_single_integer(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                ["split-secret", "--shares", "abc", "--threshold", "2", "--output-dir", tmp],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--shares", r.stderr)
            self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(os.listdir(tmp), [])

    def test_split_without_shares_flag_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                ["split-secret", "--threshold", "2", "--output-dir", tmp],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--shares", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_split_without_threshold_flag_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                ["split-secret", "--shares", "3", "--output-dir", tmp],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--threshold", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_threshold_larger_than_share_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                ["split-secret", "--shares", "2", "--threshold", "3", "--output-dir", tmp],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(os.listdir(tmp), [])

    def test_threshold_below_two_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                ["split-secret", "--shares", "3", "--threshold", "1", "--output-dir", tmp],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("Traceback", r.stderr)
            self.assertEqual(os.listdir(tmp), [])

    def test_combine_without_shares_flag_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    os.path.join(tmp, "missing.enc"),
                    "--output",
                    os.path.join(tmp, "out.txt"),
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--shares", r.stderr)
            self.assertNotIn("Traceback", r.stderr)


class TestShareFileWriteSafety(unittest.TestCase):
    """Security-review hardening: share writes must be exclusive + symlink-safe."""

    def test_existing_share_file_is_not_clobbered(self):
        with tempfile.TemporaryDirectory() as tmp:
            canary = os.path.join(tmp, "share_1.json")
            with open(canary, "w") as f:
                f.write("canary")
            r = _split(tmp)
            self.assertNotEqual(r.returncode, 0)
            with open(canary) as f:
                self.assertEqual(f.read(), "canary")
            self.assertNotIn("Traceback", r.stderr)

    def test_symlinked_share_filename_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            share_dir = os.path.join(tmp, "shares")
            os.makedirs(share_dir)
            target = os.path.join(tmp, "victim.txt")
            with open(target, "w") as f:
                f.write("victim")
            os.symlink(target, os.path.join(share_dir, "share_1.json"))
            r = _split(share_dir)
            self.assertNotEqual(r.returncode, 0)
            with open(target) as f:
                self.assertEqual(f.read(), "victim")

    def test_new_output_dir_is_created_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            share_dir = os.path.join(tmp, "brand", "new")
            r = _split(share_dir)
            self.assertEqual(r.returncode, 0, f"split-secret failed: {r.stderr[:300]}")
            mode = stat.S_IMODE(os.stat(share_dir).st_mode)
            self.assertEqual(mode, 0o700, f"share dir has mode {oct(mode)}")


class TestPasswordHygieneInProcess(unittest.TestCase):
    """Security-review hardening: env cleanup and interactive confirmation."""

    def _args(self, tmp):
        import argparse

        return argparse.Namespace(
            shares=["3"], threshold=2, output_dir=tmp, password=None, quiet=True
        )

    def test_env_password_is_cleared_from_environment(self):
        from unittest import mock

        from openssl_encrypt.modules.secret_sharing import split_secret_cli

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"CRYPT_PASSWORD": PASSWORD}):
                split_secret_cli(self._args(tmp))
                self.assertNotIn("CRYPT_PASSWORD", os.environ)
            self.assertEqual(len([f for f in os.listdir(tmp) if f.endswith(".json")]), 3)

    def test_interactive_prompt_requires_matching_confirmation(self):
        from unittest import mock

        from openssl_encrypt.modules.secret_sharing import split_secret_cli

        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "CRYPT_PASSWORD"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch("getpass.getpass", side_effect=[PASSWORD, PASSWORD]) as gp:
                    split_secret_cli(self._args(tmp))
                    self.assertEqual(gp.call_count, 2)
            self.assertEqual(len([f for f in os.listdir(tmp) if f.endswith(".json")]), 3)

    def test_mismatched_confirmation_is_rejected(self):
        from unittest import mock

        from openssl_encrypt.modules.secret_sharing import split_secret_cli

        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "CRYPT_PASSWORD"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch("getpass.getpass", side_effect=[PASSWORD, "different"]):
                    with self.assertRaises(ValueError):
                        split_secret_cli(self._args(tmp))
            self.assertEqual(os.listdir(tmp), [])


class TestRangeValidationBeforePassword(unittest.TestCase):
    """2 <= K <= N <= 255 must be enforced before any password handling."""

    def _run_no_password(self, *argv):
        env = os.environ.copy()
        env.pop("CRYPT_PASSWORD", None)
        return subprocess.run(
            [sys.executable, "-m", "openssl_encrypt.crypt", *argv],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=TIMEOUT,
            env=env,
        )

    def test_threshold_above_share_count_fails_without_prompting(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run_no_password(
                "split-secret", "--shares", "2", "--threshold", "3", "--output-dir", tmp
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("EOF", r.stderr)
            self.assertNotIn("Password", r.stdout)
            self.assertIn("threshold", r.stderr.lower())
            self.assertEqual(os.listdir(tmp), [])

    def test_share_count_above_255_fails_without_prompting(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run_no_password(
                "split-secret", "--shares", "300", "--threshold", "2", "--output-dir", tmp
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("EOF", r.stderr)
            self.assertEqual(os.listdir(tmp), [])


class TestUntrustedShareFiles(unittest.TestCase):
    """Share files come back from other people: from_json is a trust boundary."""

    def _combine(self, tmp, share_payloads):
        import json as _json

        paths = []
        for i, payload in enumerate(share_payloads):
            p = os.path.join(tmp, f"crafted_{i}.json")
            with open(p, "w") as f:
                f.write(_json.dumps(payload))
            paths.append(p)
        return _run(
            [
                "combine-secrets",
                "--input",
                os.path.join(tmp, "missing.enc"),
                "--shares",
                *paths,
                "--output",
                os.path.join(tmp, "out.txt"),
                "--quiet",
            ]
        )

    def _meta(self, index):
        return {
            "threshold": 2,
            "total_shares": 2,
            "share_index": index,
            "key_id": "k",
            "algorithm": "shamir-gf256",
            "created_at": "",
        }

    def test_integer_data_field_is_refused_not_allocated(self):
        with tempfile.TemporaryDirectory() as tmp:
            crafted = {
                "header": "ossl_encrypt_share",
                "metadata": self._meta(1),
                "data": 100_000_000,
            }
            r = self._combine(tmp, [crafted, crafted | {"metadata": self._meta(2)}])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("share", r.stderr.lower())
            self.assertNotIn("Traceback", r.stderr)

    def test_string_threshold_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta = self._meta(1)
            meta["threshold"] = "2"
            crafted = {
                "header": "ossl_encrypt_share",
                "metadata": meta,
                "data": [1, 2, 3],
            }
            r = self._combine(tmp, [crafted])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("share", r.stderr.lower())
            self.assertNotIn("Traceback", r.stderr)

    def test_oversized_data_list_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            crafted = {
                "header": "ossl_encrypt_share",
                "metadata": self._meta(1),
                "data": [0] * 5000,
            }
            r = self._combine(tmp, [crafted])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("share", r.stderr.lower())
            self.assertNotIn("Traceback", r.stderr)


class TestFlagScoping(unittest.TestCase):
    """Sharing flags must be refused outside their actions (fail-closed)."""

    def test_shares_flag_rejected_on_encrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "p.txt")
            with open(plain, "w") as f:
                f.write("x")
            r = _run(
                [
                    "encrypt",
                    "-i",
                    plain,
                    "-o",
                    os.path.join(tmp, "o.enc"),
                    "--shares",
                    "3",
                ],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            # encrypt is subparser-routed (flag unknown there); monolithic
            # actions hit the explicit split-secret/combine-secrets guard.
            self.assertTrue(
                "split-secret" in r.stderr or "unrecognized arguments" in r.stderr,
                r.stderr[-300:],
            )
            self.assertFalse(os.path.exists(os.path.join(tmp, "o.enc")))

    def test_threshold_flag_rejected_on_decrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "decrypt",
                    "-i",
                    os.path.join(tmp, "missing.enc"),
                    "-o",
                    os.path.join(tmp, "out.txt"),
                    "--threshold",
                    "2",
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertTrue(
                "split-secret" in r.stderr or "unrecognized arguments" in r.stderr,
                r.stderr[-300:],
            )

    def test_shares_flag_rejected_on_monolithic_action(self):
        # verify parses via the monolithic parser (same surface that defines
        # the sharing flags), so this exercises the explicit action guard.
        with tempfile.TemporaryDirectory() as tmp:
            probe = os.path.join(tmp, "probe.enc")
            with open(probe, "w") as f:
                f.write("x")
            r = _run(["verify", "-i", probe, "--shares", "3"])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("split-secret", r.stderr)

    def test_output_dir_rejected_on_combine_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    os.path.join(tmp, "missing.enc"),
                    "--shares",
                    os.path.join(tmp, "s.json"),
                    "--output",
                    os.path.join(tmp, "out.txt"),
                    "--output-dir",
                    tmp,
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--output-dir", r.stderr)

    def test_input_rejected_on_split_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "split-secret",
                    "--input",
                    os.path.join(tmp, "some.enc"),
                    "--shares",
                    "3",
                    "--threshold",
                    "2",
                    "--output-dir",
                    tmp,
                ],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--input", r.stderr)
            self.assertEqual(os.listdir(tmp), [])

    def test_combine_secrets_refuses_hsm(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    os.path.join(tmp, "missing.enc"),
                    "--shares",
                    os.path.join(tmp, "s.json"),
                    "--output",
                    os.path.join(tmp, "out.txt"),
                    "--hsm",
                    "yubikey",
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("not supported", r.stderr)


class TestSecondReviewHardening(unittest.TestCase):
    """Round-2 review fixes: token echo, early-exit guard, read bounds."""

    def test_threshold_error_does_not_echo_the_token(self):
        # A mis-ordered argv can put a password where K belongs; neither
        # argparse nor the handler may echo it (the flag is deliberately
        # not type=int on the parser).
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                ["split-secret", "--shares", "3", "--threshold", "hunter2", "--output-dir", tmp],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("hunter2", r.stderr)
            self.assertNotIn("hunter2", r.stdout)
            self.assertIn("--threshold", r.stderr)

    def test_shares_flag_rejected_on_early_exit_monolithic_action(self):
        # create-usb exits inside the action chain long before the old guard
        # location; the guard must fire before ANY action runs or prompts.
        r = _run(["create-usb", "--shares", "3"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("split-secret", r.stderr)

    def test_keyring_load_rejected_on_split_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "split-secret",
                    "--shares",
                    "3",
                    "--threshold",
                    "2",
                    "--output-dir",
                    tmp,
                    "--keyring-load",
                    "label",
                ],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--keyring-load", r.stderr)
            self.assertEqual(os.listdir(tmp), [])

    def test_password_flag_rejected_on_combine_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    os.path.join(tmp, "missing.enc"),
                    "--shares",
                    os.path.join(tmp, "s.json"),
                    "--output",
                    os.path.join(tmp, "out.txt"),
                    "-p",
                    "irrelevant",
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("--password", r.stderr)

    def test_oversized_share_file_is_refused_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = os.path.join(tmp, "big.json")
            with open(big, "w") as f:
                f.write("[" + "0," * 200_000 + "0]")
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    os.path.join(tmp, "missing.enc"),
                    "--shares",
                    big,
                    "--output",
                    os.path.join(tmp, "out.txt"),
                    "--quiet",
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("too large", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_non_object_share_json_is_refused_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            crafted = os.path.join(tmp, "list.json")
            with open(crafted, "w") as f:
                f.write("[1, 2, 3]")
            r = _run(
                [
                    "combine-secrets",
                    "--input",
                    os.path.join(tmp, "missing.enc"),
                    "--shares",
                    crafted,
                    "--output",
                    os.path.join(tmp, "out.txt"),
                    "--quiet",
                ]
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("share", r.stderr.lower())
            self.assertNotIn("Traceback", r.stderr)

    def test_partial_collision_refused_before_writing_anything(self):
        # share_2.json exists; the pre-flight must refuse BEFORE share_1 is
        # written, so no mixed/partial share set can appear.
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "share_2.json"), "w") as f:
                f.write("old")
            r = _split(tmp)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("already exist", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(tmp, "share_1.json")))
            with open(os.path.join(tmp, "share_2.json")) as f:
                self.assertEqual(f.read(), "old")

    def test_output_dir_naming_a_regular_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            not_a_dir = os.path.join(tmp, "file.txt")
            with open(not_a_dir, "w") as f:
                f.write("x")
            r = _run(
                [
                    "split-secret",
                    "--shares",
                    "3",
                    "--threshold",
                    "2",
                    "--output-dir",
                    not_a_dir,
                ],
                env_extra={"CRYPT_PASSWORD": PASSWORD},
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("not a directory", r.stderr)
            mode = stat.S_IMODE(os.stat(not_a_dir).st_mode)
            self.assertNotEqual(mode, 0o700, "pre-existing file must not be chmod'd")

    def test_secret_longer_than_share_cap_is_refused_at_split_time(self):
        from openssl_encrypt.modules.crypt_errors import SecretSharingError
        from openssl_encrypt.modules.secret_sharing import MAX_SHARE_DATA_LEN, split_secret

        with self.assertRaises(SecretSharingError):
            split_secret(b"x" * (MAX_SHARE_DATA_LEN + 1), 2, 3)


if __name__ == "__main__":
    unittest.main()
