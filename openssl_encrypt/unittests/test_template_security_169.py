#!/usr/bin/env python3
"""Template security (gitlab#169): a template file must not be able to claim a
security rating it did not earn, silently downgrade key derivation, or be
planted by another local user.

Part 1 (HIGH): `_load_template_file` took `security_score`/`security_level`
verbatim from the (untrusted) file, and `list_templates()` sorts by that value
-- so a planted template claiming a top score ranked first. The rating is now
recomputed from the actual config on load.

Part 2 (HIGH): a template's `hash_config` was applied with no KDF floor, so a
dropped-in file could downgrade key derivation (e.g. pbkdf2_iterations: 1).
Applying a weak template now warns loudly; and the template directory is no
longer group/other-writable, so another local process cannot plant a template.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from openssl_encrypt.modules.crypt_cli import _warn_if_weak_template_kdf
from openssl_encrypt.modules.file_permissions import harden_directory_permissions
from openssl_encrypt.modules.template_manager import TemplateManager


class TestSelfAssertedScoreIsRecomputed(unittest.TestCase):
    def _drop(self, directory, name, doc):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_a_planted_top_score_is_recomputed_low(self):
        with tempfile.TemporaryDirectory() as d:
            self._drop(
                d,
                "evil.json",
                {
                    "metadata": {
                        "name": "evil",
                        "security_score": 99.0,
                        "security_level": "MAXIMUM",
                    },
                    "config": {"hash_config": {"pbkdf2_iterations": 1}},
                },
            )
            tm = TemplateManager(template_dir=d)
            evil = next(t for t in tm.list_templates() if t.metadata.name == "evil")
            # The file's self-asserted 99.0 must not survive.
            self.assertLess(evil.metadata.security_score, 99.0)

    def test_a_planted_template_does_not_rank_first(self):
        with tempfile.TemporaryDirectory() as d:
            self._drop(
                d,
                "evil.json",
                {
                    "metadata": {
                        "name": "evil",
                        "security_score": 99.0,
                        "security_level": "MAXIMUM",
                    },
                    "config": {"hash_config": {"pbkdf2_iterations": 1}},
                },
            )
            tm = TemplateManager(template_dir=d)
            names = [t.metadata.name for t in tm.list_templates()]
            # Built-in templates (real strong configs) must outrank the planted one.
            self.assertNotEqual(names[0], "evil")


class TestWeakTemplateKdfWarns(unittest.TestCase):
    def _stderr_of(self, hash_config):
        buf = io.StringIO()
        with redirect_stderr(buf):
            _warn_if_weak_template_kdf(hash_config, "some-template")
        return buf.getvalue()

    def test_weak_config_warns(self):
        out = self._stderr_of({"pbkdf2_iterations": 1})
        self.assertIn("WARNING", out)

    def test_strong_argon2_does_not_warn(self):
        out = self._stderr_of({"argon2": {"enabled": True, "memory_cost": 131072}})
        self.assertEqual(out, "")

    def test_strong_pbkdf2_alone_does_not_warn(self):
        out = self._stderr_of({"pbkdf2_iterations": 600000})
        self.assertEqual(out, "")

    def test_pbkdf2_below_the_floor_warns(self):
        # 200k clears the old 100k threshold but not the 600k OWASP floor.
        self.assertIn("WARNING", self._stderr_of({"pbkdf2_iterations": 200000}))

    def test_enabled_but_trivial_balloon_still_warns(self):
        # Balloon must clear a strength floor, not merely be "enabled" -- else a
        # planted balloon:{enabled, space_cost:1} would evade the check.
        out = self._stderr_of(
            {"balloon": {"enabled": True, "space_cost": 1}, "pbkdf2_iterations": 1}
        )
        self.assertIn("WARNING", out)

    def test_strong_balloon_does_not_warn(self):
        out = self._stderr_of({"balloon": {"enabled": True, "space_cost": 131072}})
        self.assertEqual(out, "")

    def test_hostile_shapes_do_not_raise(self):
        # Non-dict kdf entries and bool numerics must not crash the check.
        self._stderr_of({"argon2": "nope", "pbkdf2_iterations": True})
        self._stderr_of("not-a-dict")


class TestTemplateDirNotWritableByOthers(unittest.TestCase):
    def test_existing_world_writable_dir_is_tightened_by_template_manager(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "templates")
            os.makedirs(sub)
            os.chmod(sub, 0o777)
            TemplateManager(template_dir=sub)
            mode = os.stat(sub).st_mode & 0o777
            self.assertEqual(mode & 0o022, 0, f"group/other write not stripped: {oct(mode)}")

    def test_harden_helper_strips_group_other_write_preserving_read(self):
        # The encrypt --template path calls this helper directly (it never
        # constructs a TemplateManager).
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o775)
            harden_directory_permissions(d)
            mode = os.stat(d).st_mode & 0o777
            self.assertEqual(mode & 0o022, 0)  # no group/other write
            self.assertTrue(mode & 0o040)  # group read preserved (multi-user read)

    def test_harden_helper_never_raises_on_a_missing_path(self):
        harden_directory_permissions("/nonexistent/does/not/exist")


if __name__ == "__main__":
    unittest.main()
