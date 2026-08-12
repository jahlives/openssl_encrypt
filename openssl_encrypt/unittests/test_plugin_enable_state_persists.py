#!/usr/bin/env python3
"""
`disable-plugin` must actually disable the plugin (gitlab#199).

`enable_plugin`/`disable_plugin` set `registration.enabled`, an attribute of
an in-memory `PluginRegistration` that defaults to `True` at construction.
Nothing wrote it to disk and nothing read it back -- the only construction
site never passed `enabled`, and `PluginConfigManager` carried
`{"enabled": True}` only as a default. The CLI handler built a fresh
manager, loaded every plugin, flipped the flag, printed success, and exited,
so the process died with the only copy of that state:

    $ openssl-encrypt disable-plugin --plugin-id steganography
    ✅ Plugin steganography disabled successfully
    $ openssl-encrypt list-plugins | grep -i stegano
    🟢 Enabled Steganography (v1.0.0)

This is worse than a missing feature. A user who disables a plugin *for a
security reason* gets an unambiguous success message while the plugin loads
and runs enabled on the very next invocation -- a false assurance about a
control they believe they applied. It became reachable with gitlab#179;
before that the command exited 2 with `invalid choice`.

Documented residual: a disabled plugin is still discovered and imported, so
its module-level code runs. What disabling now guarantees is that it is not
initialized and not dispatched. Refusing the import outright needs a
file-to-id map that does not exist before the module is loaded, and is not
attempted here.
"""

import shutil
import tempfile
import unittest

from openssl_encrypt.modules.plugin_system.plugin_base import PluginType
from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
from openssl_encrypt.modules.plugin_system.plugin_manager import (
    PluginManager,
    PluginRegistration,
    PluginResult,
)


class _FakePlugin:
    """The surface PluginRegistration and the manager touch.

    Not a subclass of BasePlugin: the point is to pin the manager's handling
    of the enabled flag, and a real plugin would drag in signature
    verification and a file on disk.
    """

    def __init__(self, plugin_id="fake-plugin"):
        self.plugin_id = plugin_id
        self.initialized = False

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return []

    def get_metadata(self):
        return {"id": self.plugin_id, "name": self.plugin_id, "version": "1.0.0"}

    def initialize(self, config):
        self.initialized = True
        return PluginResult.success_result("ok")


class _ManagerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.config_manager = PluginConfigManager(config_dir=self.tmp)
        self.manager = PluginManager(config_manager=self.config_manager)

    def _fresh_manager(self):
        """A second manager over the same config dir -- i.e. the next run."""
        return PluginManager(config_manager=PluginConfigManager(config_dir=self.tmp))


class TestTheStateSurvivesTheProcess(_ManagerTestCase):
    def test_disabling_is_written_to_disk(self):
        plugin = _FakePlugin()
        self.manager.plugins[plugin.plugin_id] = PluginRegistration(plugin, "/nonexistent.py")

        result = self.manager.disable_plugin(plugin.plugin_id)
        self.assertTrue(result.success)

        self.assertIs(
            self._fresh_manager().config_manager.get_plugin_config(plugin.plugin_id)["enabled"],
            False,
            "disable_plugin reported success but the next run sees it enabled",
        )

    def test_enabling_again_is_written_too(self):
        plugin = _FakePlugin()
        self.manager.plugins[plugin.plugin_id] = PluginRegistration(plugin, "/nonexistent.py")

        self.manager.disable_plugin(plugin.plugin_id)
        self.manager.enable_plugin(plugin.plugin_id)

        self.assertIs(
            self._fresh_manager().config_manager.get_plugin_config(plugin.plugin_id)["enabled"],
            True,
        )

    def test_an_untouched_plugin_stays_enabled(self):
        """The default must not become "disabled" for everything else."""
        self.assertIs(
            self.config_manager.get_plugin_config("never-touched")["enabled"],
            True,
        )

    def test_disabling_an_unknown_plugin_still_fails(self):
        """Persisting must not turn a not-found into a success."""
        result = self.manager.disable_plugin("no-such-plugin")
        self.assertFalse(result.success)
        self.assertIn("not found", result.message.lower())


class TestTheStateIsHonouredOnLoad(_ManagerTestCase):
    """Persisting is only half of it: the next run has to read it."""

    def test_a_disabled_plugin_is_registered_disabled(self):
        plugin = _FakePlugin()
        self.config_manager.update_plugin_config(plugin.plugin_id, {"enabled": False})

        manager = self._fresh_manager()
        registration = manager._register_loaded_plugin(plugin, "/nonexistent.py")

        self.assertFalse(
            registration.enabled,
            "the stored disabled state was ignored and the plugin came back enabled",
        )

    def test_a_disabled_plugin_is_not_initialized(self):
        """initialize() is where a plugin claims resources and installs hooks.

        This is the concrete thing disabling buys: the module import still
        happens (documented residual), but the plugin is never started.
        """
        plugin = _FakePlugin()
        self.config_manager.update_plugin_config(plugin.plugin_id, {"enabled": False})

        manager = self._fresh_manager()
        manager._register_loaded_plugin(plugin, "/nonexistent.py")

        self.assertFalse(plugin.initialized, "a disabled plugin was initialized")

    def test_an_enabled_plugin_is_still_initialized(self):
        """The negative arm: without it the test above passes if nothing is
        ever initialized."""
        plugin = _FakePlugin()

        manager = self._fresh_manager()
        manager._register_loaded_plugin(plugin, "/nonexistent.py")

        self.assertTrue(plugin.initialized)

    def test_a_disabled_plugin_is_not_dispatched(self):
        plugin = _FakePlugin()
        self.config_manager.update_plugin_config(plugin.plugin_id, {"enabled": False})

        manager = self._fresh_manager()
        manager._register_loaded_plugin(plugin, "/nonexistent.py")

        self.assertNotIn(
            plugin.plugin_id,
            [r.plugin.plugin_id for r in manager.get_plugins_by_type(PluginType.PRE_PROCESSOR)],
            "a disabled plugin was still dispatched",
        )

    def test_a_disabled_plugin_is_still_listed_as_disabled(self):
        """It must remain visible, or the user cannot re-enable it."""
        plugin = _FakePlugin()
        self.config_manager.update_plugin_config(plugin.plugin_id, {"enabled": False})

        manager = self._fresh_manager()
        manager._register_loaded_plugin(plugin, "/nonexistent.py")

        listed = {entry["id"]: entry for entry in manager.list_plugins() if entry}
        self.assertIn(plugin.plugin_id, listed)
        self.assertFalse(listed[plugin.plugin_id]["enabled"])


if __name__ == "__main__":
    unittest.main()
