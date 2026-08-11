#!/usr/bin/env python3
"""
Regression tests for H7: D-Bus per-caller authorization.

The D-Bus service exposed EncryptFile/DecryptFile/SecureShredFile (and the
keystore methods) with zero caller authorization, while the shipped
system-bus policy allowed any user to call them and the shipped polkit
.policy was never enforced. These tests cover the new authorization layer:

- session bus: only callers with the service's own UID are accepted
- system bus: every method is gated by polkit CheckAuthorization using the
  action ids from ch.rmrf.openssl_encrypt.policy
- fail closed: missing sender, unresolvable UID, unreachable polkit -> deny
- path policy: system mode may access system paths (that is its purpose,
  post-polkit), session mode stays restricted to home/tmp

dbus-python is not required: a minimal fake `dbus` module is injected into
sys.modules for the duration of this module's tests and removed afterwards
(never leak global state to co-resident test modules).
"""

import os
import sys
import types
import unittest
from unittest import mock

_FAKE_MODULE_NAMES = [
    "dbus",
    "dbus.service",
    "dbus.exceptions",
    "dbus.mainloop",
    "dbus.mainloop.glib",
    "gi",
    "gi.repository",
]

_saved_modules = {}
dbus_service = None


def _build_fake_dbus():
    """Create a minimal stand-in for dbus-python sufficient to import
    openssl_encrypt.modules.dbus_service and exercise its logic."""
    dbus_mod = types.ModuleType("dbus")

    class DBusException(Exception):
        def __init__(self, *args, name=None, **kwargs):
            super().__init__(*args)
            self._dbus_error_name = name

        def get_dbus_name(self):
            return self._dbus_error_name

    class NameExistsException(DBusException):
        pass

    exceptions_mod = types.ModuleType("dbus.exceptions")
    exceptions_mod.DBusException = DBusException
    exceptions_mod.NameExistsException = NameExistsException

    service_mod = types.ModuleType("dbus.service")

    class Object:
        def __init__(self, *args, **kwargs):
            pass

    class BusName:
        def __init__(self, *args, **kwargs):
            pass

    def method(*dargs, **dkwargs):
        def decorator(func):
            return func

        return decorator

    def signal(*dargs, **dkwargs):
        def decorator(func):
            return func

        return decorator

    service_mod.Object = Object
    service_mod.BusName = BusName
    service_mod.method = method
    service_mod.signal = signal

    mainloop_mod = types.ModuleType("dbus.mainloop")
    glib_mod = types.ModuleType("dbus.mainloop.glib")
    glib_mod.DBusGMainLoop = lambda set_as_default=False: None
    mainloop_mod.glib = glib_mod

    class Bus:
        pass

    dbus_mod.Bus = Bus
    dbus_mod.SessionBus = mock.MagicMock
    dbus_mod.SystemBus = mock.MagicMock
    dbus_mod.String = str
    dbus_mod.UInt32 = int
    dbus_mod.PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"
    dbus_mod.exceptions = exceptions_mod
    dbus_mod.service = service_mod
    dbus_mod.mainloop = mainloop_mod

    # dbus.Interface(obj, iface) -> just return the object so tests can put
    # CheckAuthorization etc. directly on the mock
    dbus_mod.Interface = lambda obj, iface=None, **kw: obj

    gi_mod = types.ModuleType("gi")
    gi_repository_mod = types.ModuleType("gi.repository")
    gi_repository_mod.GLib = mock.MagicMock()
    gi_mod.repository = gi_repository_mod

    return {
        "dbus": dbus_mod,
        "dbus.service": service_mod,
        "dbus.exceptions": exceptions_mod,
        "dbus.mainloop": mainloop_mod,
        "dbus.mainloop.glib": glib_mod,
        "gi": gi_mod,
        "gi.repository": gi_repository_mod,
    }


def setUpModule():
    """Install the fake dbus modules and import the service module."""
    global dbus_service
    fakes = _build_fake_dbus()
    for name in _FAKE_MODULE_NAMES:
        _saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = fakes[name]
    # Force a fresh import bound to the fakes
    sys.modules.pop("openssl_encrypt.modules.dbus_service", None)
    from openssl_encrypt.modules import dbus_service as _ds

    dbus_service = _ds


def tearDownModule():
    """Remove the fakes so no global state leaks into other test modules."""
    sys.modules.pop("openssl_encrypt.modules.dbus_service", None)
    for name in _FAKE_MODULE_NAMES:
        saved = _saved_modules.get(name)
        if saved is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = saved


def _make_service(system_bus: bool):
    """Create a CryptoService with a mocked bus connection."""
    bus = mock.MagicMock()
    service = dbus_service.CryptoService(bus, system_bus=system_bus)
    return service, bus


def _polkit_authority(answer=None, exc=None):
    """Build a mock polkit authority object returning `answer` from
    CheckAuthorization (or raising `exc`)."""
    authority = mock.MagicMock()
    if exc is not None:
        authority.CheckAuthorization.side_effect = exc
    else:
        authority.CheckAuthorization.return_value = answer
    return authority


class TestSessionBusAuthorization(unittest.TestCase):
    """Session bus: same-UID callers only (defense-in-depth)."""

    def setUp(self):
        self.service, self.bus = _make_service(system_bus=False)

    def test_same_uid_allowed(self):
        self.bus.get_unix_user.return_value = os.getuid()
        ok, err = self.service._authorize_caller(":1.42", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_foreign_uid_denied(self):
        self.bus.get_unix_user.return_value = os.getuid() + 1
        ok, err = self.service._authorize_caller(":1.42", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)
        self.assertNotEqual(err, "")

    def test_missing_sender_denied(self):
        ok, _err = self.service._authorize_caller(None, dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)
        ok, _err = self.service._authorize_caller("", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)

    def test_unresolvable_sender_denied(self):
        self.bus.get_unix_user.side_effect = RuntimeError("no such name")
        ok, _err = self.service._authorize_caller(":1.42", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)

    def test_polkit_not_consulted_on_session_bus(self):
        self.bus.get_unix_user.return_value = os.getuid()
        self.service._authorize_caller(":1.42", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.bus.get_object.assert_not_called()


class TestSystemBusAuthorization(unittest.TestCase):
    """System bus: polkit CheckAuthorization gates every caller."""

    def setUp(self):
        self.service, self.bus = _make_service(system_bus=True)
        self.bus.get_unix_user.return_value = 1000

    def test_polkit_authorized(self):
        authority = _polkit_authority(answer=(True, False, {}))
        self.bus.get_object.return_value = authority
        ok, err = self.service._authorize_caller(":1.7", dbus_service.POLKIT_ACTION_DECRYPT)
        self.assertTrue(ok)
        self.assertEqual(err, "")
        # the action id and the caller's bus name must reach polkit
        args = authority.CheckAuthorization.call_args[0]
        subject = args[0]
        self.assertEqual(subject[0], "system-bus-name")
        self.assertEqual(subject[1]["name"], ":1.7")
        self.assertEqual(args[1], dbus_service.POLKIT_ACTION_DECRYPT)

    def test_polkit_allows_user_interaction(self):
        """flags must include AllowUserInteraction (1) so the admin gets an
        auth prompt instead of a silent denial."""
        authority = _polkit_authority(answer=(True, False, {}))
        self.bus.get_object.return_value = authority
        self.service._authorize_caller(":1.7", dbus_service.POLKIT_ACTION_ENCRYPT)
        flags = authority.CheckAuthorization.call_args[0][3]
        self.assertEqual(int(flags) & 1, 1)

    def test_polkit_denied(self):
        authority = _polkit_authority(answer=(False, False, {}))
        self.bus.get_object.return_value = authority
        ok, err = self.service._authorize_caller(":1.7", dbus_service.POLKIT_ACTION_SHRED)
        self.assertFalse(ok)
        self.assertNotEqual(err, "")

    def test_polkit_unreachable_fails_closed(self):
        self.bus.get_object.side_effect = RuntimeError("polkit not running")
        ok, _err = self.service._authorize_caller(":1.7", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)

    def test_polkit_error_fails_closed(self):
        authority = _polkit_authority(exc=RuntimeError("timeout"))
        self.bus.get_object.return_value = authority
        ok, _err = self.service._authorize_caller(":1.7", dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)

    def test_missing_sender_denied(self):
        ok, _err = self.service._authorize_caller(None, dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(ok)


class TestMethodGating(unittest.TestCase):
    """Every state-touching D-Bus method must consult the authorizer with
    the correct polkit action id and refuse unauthorized callers."""

    def setUp(self):
        self.service, self.bus = _make_service(system_bus=False)
        self.denials = []

        def deny(sender, action_id):
            self.denials.append((sender, action_id))
            return False, "not authorized"

        self.service._authorize_caller = deny

    def test_encrypt_file_gated(self):
        replies = []
        self.service.EncryptFile(
            "/tmp/in",
            "/tmp/out",
            "pw",
            "aes-gcm",
            {},
            reply_handler=replies.append,
            error_handler=lambda e: self.fail(f"error_handler called: {e}"),
            sender=":1.9",
        )
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertEqual(len(replies), 1)
        success, message, op_id = replies[0]
        self.assertFalse(success)
        self.assertIn("denied", message.lower())
        self.assertEqual(op_id, "")

    def test_decrypt_file_gated(self):
        replies = []
        self.service.DecryptFile(
            "/tmp/in",
            "/tmp/out",
            "pw",
            reply_handler=replies.append,
            error_handler=lambda e: self.fail(f"error_handler called: {e}"),
            sender=":1.9",
        )
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_DECRYPT)
        success, message, _ = replies[0]
        self.assertFalse(success)
        self.assertIn("denied", message.lower())

    def test_encrypt_data_gated(self):
        success, data, message = self.service.EncryptData(b"x", "pw", "aes-gcm", {}, sender=":1.9")
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_ENCRYPT)
        self.assertFalse(success)
        self.assertEqual(bytes(data), b"")
        self.assertIn("denied", message.lower())

    def test_decrypt_data_gated(self):
        success, data, message = self.service.DecryptData(b"x", "pw", sender=":1.9")
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_DECRYPT)
        self.assertFalse(success)
        self.assertIn("denied", message.lower())

    def test_secure_shred_gated(self):
        success, message = self.service.SecureShredFile("/tmp/x", 3, sender=":1.9")
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_SHRED)
        self.assertFalse(success)
        self.assertIn("denied", message.lower())

    def test_generate_pqc_key_gated(self):
        success, key_id, message = self.service.GeneratePQCKey(
            "ML-KEM-768", "/tmp/ks", "pw", "name", sender=":1.9"
        )
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_GENERATE_KEY)
        self.assertFalse(success)
        self.assertEqual(key_id, "")
        self.assertIn("denied", message.lower())

    def test_list_pqc_keys_gated(self):
        success, keys, message = self.service.ListPQCKeys("/tmp/ks", "pw", sender=":1.9")
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_KEYSTORE)
        self.assertFalse(success)
        self.assertEqual(list(keys), [])
        self.assertIn("denied", message.lower())

    def test_delete_pqc_key_gated(self):
        success, message = self.service.DeletePQCKey("/tmp/ks", "pw", "id", sender=":1.9")
        self.assertEqual(self.denials[-1][1], dbus_service.POLKIT_ACTION_DELETE_KEY)
        self.assertFalse(success)
        self.assertIn("denied", message.lower())

    def test_authorized_caller_passes_gate(self):
        """With an allowing authorizer the method proceeds past the gate
        (SecureShredFile then fails on path validation, not authorization)."""
        self.service._authorize_caller = lambda sender, action: (True, "")
        success, message = self.service.SecureShredFile("/nonexistent-dir/x", 3, sender=":1.9")
        self.assertFalse(success)
        self.assertNotIn("denied", message.lower())


class TestPathPolicyByBusMode(unittest.TestCase):
    """System mode exists to reach root-only files (post-polkit); session
    mode stays restricted to the user's home and tmp."""

    def test_session_mode_blocks_system_paths(self):
        service, _ = _make_service(system_bus=False)
        valid, _ = service._validate_file_path("/etc/myapp/secret.conf", must_exist=False)
        self.assertFalse(valid)

    def test_session_mode_allows_home_and_tmp(self):
        service, _ = _make_service(system_bus=False)
        valid, err = service._validate_file_path("/tmp/some-file.bin", must_exist=False)
        self.assertTrue(valid, err)
        home = os.path.expanduser("~")
        if any(home.startswith(blocked) for blocked in service._blocked_paths):
            # Running as root (e.g. in CI): home is /root, which session
            # mode deliberately blocks — the session service is for
            # regular users, so the home-allowance assertion is moot here.
            self.skipTest(f"process home {home!r} is itself a blocked path in session mode")
        valid, err = service._validate_file_path(os.path.join(home, "f.bin"), must_exist=False)
        self.assertTrue(valid, err)

    def test_system_mode_allows_system_paths(self):
        service, _ = _make_service(system_bus=True)
        valid, err = service._validate_file_path("/etc/myapp/secret.conf", must_exist=False)
        self.assertTrue(valid, err)
        valid, err = service._validate_file_path("/var/lib/myapp/data.bin", must_exist=False)
        self.assertTrue(valid, err)
        # /root is unblocked in system mode (stat'ing it needs root, so
        # assert at the policy level rather than via a full validation call)
        self.assertNotIn("/root", service._blocked_paths)
        session_service, _ = _make_service(system_bus=False)
        self.assertIn("/root", session_service._blocked_paths)

    def test_system_mode_still_blocks_critical_paths(self):
        service, _ = _make_service(system_bus=True)
        for path in (
            "/etc/shadow",
            "/etc/sudoers",
            "/proc/1/mem",
            "/sys/kernel/x",
            "/boot/vmlinuz",
        ):
            valid, _ = service._validate_file_path(path, must_exist=False)
            self.assertFalse(valid, f"{path} must stay blocked even in system mode")


class TestActionIdsMatchPolicyFile(unittest.TestCase):
    """The action ids used in code must exist in the shipped polkit policy."""

    def test_action_ids_in_policy_file(self):
        policy_path = os.path.join(
            os.path.dirname(dbus_service.__file__),
            "..",
            "dbus",
            "ch.rmrf.openssl_encrypt.policy",
        )
        with open(policy_path, "r") as f:
            policy = f.read()
        for action in (
            dbus_service.POLKIT_ACTION_ENCRYPT,
            dbus_service.POLKIT_ACTION_DECRYPT,
            dbus_service.POLKIT_ACTION_SHRED,
            dbus_service.POLKIT_ACTION_KEYSTORE,
            dbus_service.POLKIT_ACTION_GENERATE_KEY,
            dbus_service.POLKIT_ACTION_DELETE_KEY,
            dbus_service.POLKIT_ACTION_CONFIGURE,
        ):
            self.assertIn(f'id="{action}"', policy)


class TestPropertiesSetAuthorization(unittest.TestCase):
    """Properties.Set must authorize the caller (gitlab#250, F12)."""

    def setUp(self):
        self.service, self.bus = _make_service(system_bus=True)
        self.iface = self.service.INTERFACE_NAME

    def test_set_denied_when_unauthorized(self):
        with mock.patch.object(self.service, "_authorize_caller", return_value=(False, "nope")):
            before = self.service.max_concurrent_ops
            with self.assertRaises(dbus_service.dbus.exceptions.DBusException) as ctx:
                self.service.Set(self.iface, "MaxConcurrentOperations", 3, sender=":1.42")
            self.assertEqual(
                ctx.exception.get_dbus_name(), "org.freedesktop.DBus.Error.AccessDenied"
            )
            # value unchanged after a denied write
            self.assertEqual(self.service.max_concurrent_ops, before)

    def test_set_uses_configure_action(self):
        with mock.patch.object(self.service, "_authorize_caller", return_value=(True, "")) as auth:
            self.service.Set(self.iface, "MaxConcurrentOperations", 4, sender=":1.42")
            auth.assert_called_once_with(":1.42", dbus_service.POLKIT_ACTION_CONFIGURE)
            self.assertEqual(self.service.max_concurrent_ops, 4)


class TestPropertiesSetValidation(unittest.TestCase):
    """Properties.Set must reject out-of-range values (gitlab#250, F13)."""

    def setUp(self):
        self.service, self.bus = _make_service(system_bus=False)
        self.iface = self.service.INTERFACE_NAME
        # Authorize every call so the tests exercise the validation, not authz.
        self._patch = mock.patch.object(self.service, "_authorize_caller", return_value=(True, ""))
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _assert_rejected(self, prop, value):
        before_moc = self.service.max_concurrent_ops
        before_to = self.service.default_timeout
        with self.assertRaises(dbus_service.dbus.exceptions.DBusException) as ctx:
            self.service.Set(self.iface, prop, value, sender=":1.1")
        self.assertEqual(ctx.exception.get_dbus_name(), "org.freedesktop.DBus.Error.InvalidArgs")
        # nothing mutated on rejection
        self.assertEqual(self.service.max_concurrent_ops, before_moc)
        self.assertEqual(self.service.default_timeout, before_to)

    def test_max_concurrent_zero_rejected(self):
        self._assert_rejected("MaxConcurrentOperations", 0)

    def test_max_concurrent_negative_rejected(self):
        self._assert_rejected("MaxConcurrentOperations", -1)

    def test_max_concurrent_huge_rejected(self):
        self._assert_rejected("MaxConcurrentOperations", 10**9)

    def test_default_timeout_zero_rejected(self):
        self._assert_rejected("DefaultTimeout", 0)

    def test_default_timeout_huge_rejected(self):
        self._assert_rejected("DefaultTimeout", 10**9)

    def test_non_integer_value_rejected(self):
        self._assert_rejected("MaxConcurrentOperations", "not-a-number")

    def test_infinite_value_rejected(self):
        # int(float('inf')) raises OverflowError -> must surface as InvalidArgs,
        # not an uncaught error (review Low finding).
        self._assert_rejected("MaxConcurrentOperations", float("inf"))

    def test_valid_values_accepted(self):
        self.service.Set(self.iface, "MaxConcurrentOperations", 8, sender=":1.1")
        self.assertEqual(self.service.max_concurrent_ops, 8)
        self.service.Set(self.iface, "DefaultTimeout", 600, sender=":1.1")
        self.assertEqual(self.service.default_timeout, 600)


if __name__ == "__main__":
    unittest.main()
