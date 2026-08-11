#!/usr/bin/env python3
"""The legacy GUI must load its KDF settings from the per-user home path, not a
CWD-relative file, and must flag a config with no key stretching (gitlab#235,
scan F34, CWE-426).

crypt_settings.py defined CONFIG_FILE as ~/.crypt_settings.json but then
reassigned it to the bare relative name "crypt_settings.json", so the legacy Tk
GUI read/wrote whatever file sat in the launch directory. A planted CWD config
(all KDFs off, one hash round) silently downgraded every file that session.
"""

import os
import sys
import types
import unittest

# crypt_settings imports tkinter at module scope (it backs the legacy Tk GUI),
# which is absent in headless CI. Inject stub modules so the module-level
# CONFIG_FILE constant and config_provides_key_stretching() can be imported and
# tested without a display.
if "tkinter" not in sys.modules:
    _tk = types.ModuleType("tkinter")
    for _name in ("filedialog", "messagebox", "simpledialog", "ttk"):
        _sub = types.ModuleType(f"tkinter.{_name}")
        setattr(_tk, _name, _sub)
        sys.modules[f"tkinter.{_name}"] = _sub
    sys.modules["tkinter"] = _tk

from openssl_encrypt.modules import crypt_settings as cs


class TestConfigFileResolvesToHome(unittest.TestCase):
    def test_config_file_is_absolute(self):
        self.assertTrue(os.path.isabs(cs.CONFIG_FILE), cs.CONFIG_FILE)

    def test_config_file_is_the_per_user_dotfile(self):
        self.assertEqual(
            cs.CONFIG_FILE,
            os.path.join(os.path.expanduser("~"), ".crypt_settings.json"),
        )

    def test_config_file_is_not_a_bare_cwd_name(self):
        self.assertNotEqual(cs.CONFIG_FILE, "crypt_settings.json")


class TestKeyStretchingCheck(unittest.TestCase):
    def test_all_kdfs_off_and_token_hash_is_flagged(self):
        weak = {
            "sha256": 1,
            "argon2": {"enabled": False},
            "scrypt": {"enabled": False},
            "balloon": {"enabled": False},
            "pbkdf2_iterations": 0,
        }
        self.assertFalse(cs.config_provides_key_stretching(weak))

    def test_memory_hard_kdf_counts(self):
        self.assertTrue(
            cs.config_provides_key_stretching({"argon2": {"enabled": True, "memory_cost": 65536}})
        )
        self.assertTrue(
            cs.config_provides_key_stretching({"scrypt": {"enabled": True, "n": 16384}})
        )

    def test_enabled_but_degenerate_kdf_is_flagged(self):
        # gitlab#235 review N2: an enabled KDF with negligible cost params must
        # NOT count as stretching.
        self.assertFalse(
            cs.config_provides_key_stretching(
                {"argon2": {"enabled": True, "memory_cost": 8, "time_cost": 1}}
            )
        )
        self.assertFalse(cs.config_provides_key_stretching({"scrypt": {"enabled": True, "n": 2}}))

    def test_real_hash_rounds_count(self):
        self.assertTrue(cs.config_provides_key_stretching({"sha512": 10000}))

    def test_shipped_default_config_is_stretched(self):
        self.assertTrue(cs.config_provides_key_stretching(cs.DEFAULT_CONFIG))


if __name__ == "__main__":
    unittest.main()
