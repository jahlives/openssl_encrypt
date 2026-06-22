"""Shared in-memory mock of the ``python-pkcs11`` API for PIV backend tests.

The real ``python-pkcs11`` binding (imported as ``pkcs11``) wraps the PKCS#11
C API.  None of the PIV unit tests are allowed to touch real hardware, so this
module models the *exact* surface that ``openssl_encrypt.modules.piv_backend``
consumes:

    pkcs11.lib(path)                     -> FakeLib
    lib.get_slots(token_present=True)    -> [FakeSlot, ...]
    slot.get_token()                     -> FakeToken          (has .flags)
    token.open(rw=False, user_pin=...)   -> FakeSession        (raises on bad PIN)
    session.get_key(object_class=, key_type=) -> FakeKey
    session.get_session_info()           -> FakeSessionInfo    (has .state)
    key.key_type / key[Attribute.X] / key.sign(data, mechanism=)
    session.close()

Importing this module installs the fake ``pkcs11`` / ``pkcs11.exceptions``
modules into ``sys.modules`` so that ``import pkcs11`` inside the engine resolves
to these fakes.  Import it *before* importing the engine, mirroring the
``ykman`` stubbing pattern in ``test_yubikey_plugin.py``.

The fakes are deliberately configurable: every test builds the slot/token/key/
signature behaviour it needs via the small builder helpers at the bottom.
"""

import enum
import hashlib
import sys
import types
from typing import Callable, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Enums (subset of pkcs11 constants that the engine references)
# --------------------------------------------------------------------------- #
class Mechanism(enum.Enum):
    RSA_PKCS = "RSA_PKCS"
    RSA_PKCS_PSS = "RSA_PKCS_PSS"
    SHA256_RSA_PKCS = "SHA256_RSA_PKCS"
    EDDSA = "EDDSA"
    ECDSA = "ECDSA"


class ObjectClass(enum.Enum):
    PRIVATE_KEY = "PRIVATE_KEY"
    PUBLIC_KEY = "PUBLIC_KEY"
    CERTIFICATE = "CERTIFICATE"


class KeyType(enum.Enum):
    RSA = "RSA"
    EC = "EC"  # ECDSA (NIST curves) -> non-deterministic, rejected
    EC_EDWARDS = "EC_EDWARDS"  # Ed25519 -> deterministic, supported


class Attribute(enum.Enum):
    CLASS = "CLASS"
    KEY_TYPE = "KEY_TYPE"
    LABEL = "LABEL"
    ID = "ID"
    MODULUS_BITS = "MODULUS_BITS"
    EC_PARAMS = "EC_PARAMS"
    PRIVATE = "PRIVATE"
    SIGN = "SIGN"


# CKA_ID values OpenSC/ykcs11 assign to PIV key slots.
PIV_SLOT_ID_9A = b"\x01"
PIV_SLOT_ID_9C = b"\x02"
PIV_SLOT_ID_9D = b"\x03"
PIV_SLOT_ID_9E = b"\x04"


class TokenFlag(enum.IntFlag):
    # NB: there is deliberately NO TOKEN_PRESENT here. In real python-pkcs11
    # TOKEN_PRESENT is a SlotFlag, not a TokenFlag; keeping the mock faithful
    # ensures code that wrongly references pkcs11.TokenFlag.TOKEN_PRESENT fails
    # in tests the same way it does against real hardware.
    LOGIN_REQUIRED = 1 << 2
    USER_PIN_INITIALIZED = 1 << 3
    USER_PIN_COUNT_LOW = 1 << 16
    USER_PIN_FINAL_TRY = 1 << 17
    USER_PIN_LOCKED = 1 << 18


class SlotFlag(enum.IntFlag):
    TOKEN_PRESENT = 1 << 0
    REMOVABLE_DEVICE = 1 << 1
    HW_SLOT = 1 << 2


class UserType(enum.Enum):
    NOBODY = "NOBODY"
    USER = "USER"
    SO = "SO"


class SessionState(enum.Enum):
    RO_PUBLIC_SESSION = "RO_PUBLIC_SESSION"
    RO_USER_FUNCTIONS = "RO_USER_FUNCTIONS"
    RW_PUBLIC_SESSION = "RW_PUBLIC_SESSION"
    RW_USER_FUNCTIONS = "RW_USER_FUNCTIONS"


# --------------------------------------------------------------------------- #
# Exceptions (mirror pkcs11.exceptions hierarchy used by the engine)
# --------------------------------------------------------------------------- #
class PKCS11Error(Exception):
    """Base class, mirrors pkcs11.exceptions.PKCS11Error."""


class TokenNotPresent(PKCS11Error):
    pass


class NoSuchToken(PKCS11Error):
    pass


class PinIncorrect(PKCS11Error):
    pass


class PinLocked(PKCS11Error):
    pass


class NoSuchKey(PKCS11Error):
    pass


class MultipleObjectsReturned(PKCS11Error):
    pass


class FunctionFailed(PKCS11Error):
    pass


class SessionHandleInvalid(PKCS11Error):
    pass


class DeviceError(PKCS11Error):
    """Models a token removed / device error mid-operation."""


# --------------------------------------------------------------------------- #
# Fake object graph
# --------------------------------------------------------------------------- #
class FakeSessionInfo:
    def __init__(self, state: SessionState):
        self.state = state


class FakeKey:
    """A private key object living in a PIV slot."""

    def __init__(
        self,
        key_type: KeyType,
        *,
        signer: Callable[[bytes, Mechanism], bytes],
        modulus_bits: Optional[int] = None,
        ec_params: Optional[bytes] = None,
        label: str = "PIV AUTH key",
        key_id: bytes = PIV_SLOT_ID_9A,
        attr_error: Optional[Exception] = None,
    ):
        self.key_type = key_type
        self.key_id = key_id
        self._signer = signer
        self._attr_error = attr_error
        self._attrs: Dict[Attribute, object] = {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: key_type,
            Attribute.LABEL: label,
            Attribute.ID: key_id,
            Attribute.PRIVATE: True,
            Attribute.SIGN: True,
        }
        if modulus_bits is not None:
            self._attrs[Attribute.MODULUS_BITS] = modulus_bits
        if ec_params is not None:
            self._attrs[Attribute.EC_PARAMS] = ec_params
        self.sign_calls: List[tuple] = []

    def __getitem__(self, attribute: Attribute):
        # Reading a private (login-gated) attribute fails when not authenticated.
        if self._attr_error is not None:
            raise self._attr_error
        if attribute not in self._attrs:
            raise FunctionFailed(f"attribute not available: {attribute}")
        return self._attrs[attribute]

    def sign(self, data, mechanism: Optional[Mechanism] = None) -> bytes:
        self.sign_calls.append((bytes(data), mechanism))
        return self._signer(bytes(data), mechanism)


class FakeSession:
    def __init__(
        self,
        *,
        keys: Optional[List[FakeKey]] = None,
        state: SessionState = SessionState.RO_USER_FUNCTIONS,
        get_key_error: Optional[Exception] = None,
    ):
        self._keys = keys or []
        self._state = state
        self._get_key_error = get_key_error
        self.closed = False

    # context-manager support (python-pkcs11 sessions are context managers)
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def get_session_info(self) -> FakeSessionInfo:
        return FakeSessionInfo(self._state)

    def get_key(self, object_class=None, key_type=None, id=None, label=None) -> FakeKey:
        if self._get_key_error is not None:
            raise self._get_key_error
        matches = [
            k
            for k in self._keys
            if (object_class is None or k[Attribute.CLASS] == object_class)
            and (key_type is None or k.key_type == key_type)
            and (id is None or k.key_id == id)
            and (label is None or k[Attribute.LABEL] == label)
        ]
        if not matches:
            raise NoSuchKey("no key matching the request")
        if len(matches) > 1:
            raise MultipleObjectsReturned("more than one key matched")
        return matches[0]

    def get_objects(self, attrs=None):
        return list(self._keys)

    def close(self):
        self.closed = True


class FakeToken:
    def __init__(
        self,
        *,
        flags: TokenFlag = TokenFlag.LOGIN_REQUIRED,
        session: Optional[FakeSession] = None,
        open_error: Optional[Exception] = None,
        biometric: bool = False,
        label: str = "PIV token",
    ):
        self.flags = flags
        self.label = label
        self._session = session if session is not None else FakeSession()
        self._open_error = open_error
        self._biometric = biometric
        self.open_calls: List[dict] = []

    def open(self, rw: bool = False, user_pin=None) -> FakeSession:
        # Record exactly what the host sent (used to assert b"" on biometric flow).
        self.open_calls.append({"rw": rw, "user_pin": user_pin})
        if self._open_error is not None:
            raise self._open_error
        return self._session


class FakeSlot:
    def __init__(
        self,
        *,
        token: Optional[FakeToken] = None,
        token_error: Optional[Exception] = None,
        slot_id: int = 0,
        flags: Optional["SlotFlag"] = None,
    ):
        self.slot_id = slot_id
        self._token = token
        self._token_error = token_error
        # Real slots holding a token report SlotFlag.TOKEN_PRESENT.
        self.flags = SlotFlag.TOKEN_PRESENT if flags is None else flags

    def get_token(self) -> FakeToken:
        if self._token_error is not None:
            raise self._token_error
        if self._token is None:
            raise TokenNotPresent("no token in slot")
        return self._token


class FakeLib:
    def __init__(self, slots: Optional[List[FakeSlot]] = None):
        self._slots = slots or []

    def get_slots(self, token_present: bool = False) -> List[FakeSlot]:
        if not token_present:
            return list(self._slots)
        return [s for s in self._slots if s._token is not None or s._token_error is not None]


# --------------------------------------------------------------------------- #
# Deterministic / non-deterministic signer factories
# --------------------------------------------------------------------------- #
def deterministic_signer(sig_len: int) -> Callable[[bytes, Mechanism], bytes]:
    """Return a signer whose output depends only on the input (deterministic)."""

    def _sign(data: bytes, mechanism=None) -> bytes:
        out = b""
        counter = 0
        while len(out) < sig_len:
            out += hashlib.sha512(data + counter.to_bytes(4, "big")).digest()
            counter += 1
        return out[:sig_len]

    return _sign


def nondeterministic_signer(sig_len: int) -> Callable[[bytes, Mechanism], bytes]:
    """Return a signer that produces a different signature on every call.

    Models randomized mechanisms (ECDSA, RSA-PSS) without using a real RNG so the
    sequence is reproducible across test runs.
    """
    state = {"n": 0}

    def _sign(data: bytes, mechanism=None) -> bytes:
        state["n"] += 1
        seed = data + state["n"].to_bytes(8, "big")
        out = b""
        counter = 0
        while len(out) < sig_len:
            out += hashlib.sha512(seed + counter.to_bytes(4, "big")).digest()
            counter += 1
        return out[:sig_len]

    return _sign


# Signature lengths per supported key type (verification table item 11).
RSA2048_SIG_LEN = 256
RSA4096_SIG_LEN = 512
ED25519_SIG_LEN = 64


def make_rsa_key(bits: int = 2048, *, deterministic: bool = True, **kwargs) -> FakeKey:
    sig_len = bits // 8
    signer = deterministic_signer(sig_len) if deterministic else nondeterministic_signer(sig_len)
    return FakeKey(KeyType.RSA, signer=signer, modulus_bits=bits, **kwargs)


def make_ed25519_key(*, deterministic: bool = True, **kwargs) -> FakeKey:
    signer = (
        deterministic_signer(ED25519_SIG_LEN)
        if deterministic
        else nondeterministic_signer(ED25519_SIG_LEN)
    )
    # Ed25519 OID DER (1.3.101.112) as a realistic EC_PARAMS value.
    return FakeKey(
        KeyType.EC_EDWARDS,
        signer=signer,
        ec_params=b"\x06\x03\x2b\x65\x70",
        **kwargs,
    )


def make_ecdsa_key(*, deterministic: bool = False, **kwargs) -> FakeKey:
    """ECDSA P-256 key — non-deterministic; engine must reject it."""
    signer = deterministic_signer(64) if deterministic else nondeterministic_signer(64)
    return FakeKey(
        KeyType.EC, signer=signer, ec_params=b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", **kwargs
    )


def make_lib(*slots: FakeSlot) -> FakeLib:
    return FakeLib(list(slots))


def single_slot_lib(token: FakeToken) -> FakeLib:
    """Convenience: one slot holding the given token."""
    return FakeLib([FakeSlot(token=token, slot_id=0)])


# --------------------------------------------------------------------------- #
# sys.modules installation
# --------------------------------------------------------------------------- #
def _build_fake_modules():
    exc_mod = types.ModuleType("pkcs11.exceptions")
    for name in (
        "PKCS11Error",
        "TokenNotPresent",
        "NoSuchToken",
        "PinIncorrect",
        "PinLocked",
        "NoSuchKey",
        "MultipleObjectsReturned",
        "FunctionFailed",
        "SessionHandleInvalid",
        "DeviceError",
    ):
        setattr(exc_mod, name, globals()[name])

    pkcs11_mod = types.ModuleType("pkcs11")
    pkcs11_mod.Mechanism = Mechanism
    pkcs11_mod.ObjectClass = ObjectClass
    pkcs11_mod.KeyType = KeyType
    pkcs11_mod.Attribute = Attribute
    pkcs11_mod.TokenFlag = TokenFlag
    pkcs11_mod.SlotFlag = SlotFlag
    pkcs11_mod.UserType = UserType
    pkcs11_mod.SessionState = SessionState
    pkcs11_mod.exceptions = exc_mod
    # pkcs11.lib(path) — tests override this with .side_effect or reassignment.
    pkcs11_mod.lib = _default_lib_factory
    return pkcs11_mod, exc_mod


# Per-process holder so tests can set the lib that pkcs11.lib(path) returns.
_CURRENT_LIB: Dict[str, object] = {"lib": None, "error": None}


def _default_lib_factory(path):
    """Default pkcs11.lib(path): honours set_library()/set_library_error()."""
    if _CURRENT_LIB["error"] is not None:
        raise _CURRENT_LIB["error"]
    lib = _CURRENT_LIB["lib"]
    if lib is None:
        raise FunctionFailed("no fake library configured for this test")
    return lib


def set_library(lib: Optional[FakeLib]):
    """Configure what the next pkcs11.lib(path) call returns."""
    _CURRENT_LIB["lib"] = lib
    _CURRENT_LIB["error"] = None


def set_library_error(error: Exception):
    """Configure pkcs11.lib(path) to raise (e.g. OSError for an unloadable .so)."""
    _CURRENT_LIB["lib"] = None
    _CURRENT_LIB["error"] = error


def reset():
    _CURRENT_LIB["lib"] = None
    _CURRENT_LIB["error"] = None


def install():
    """Register the fake pkcs11 / pkcs11.exceptions modules into sys.modules.

    Direct assignment (not setdefault) so unit tests are hermetic even on a host
    that happens to have real python-pkcs11 installed.
    """
    pkcs11_mod, exc_mod = _build_fake_modules()
    sys.modules["pkcs11"] = pkcs11_mod
    sys.modules["pkcs11.exceptions"] = exc_mod
    return pkcs11_mod


# Install on import so `import pkcs11` in the engine resolves to the fake.
install()
