# HSM-geschützte Identities - Implementierungsplan

*Für Claude Code zur Implementierung*

---

## Übersicht

Erweiterung des asymmetrischen Modus (v1.4.0) um HSM-Schutz für Identity-Keys. Die privaten Schlüssel (Encryption + Signing) werden mit einer Kombination aus Passwort UND Hardware-Token geschützt.

### Wichtige Abgrenzung: Was schützt der HSM?

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ASYMMETRISCHER MODUS (v1.4.0)                        │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ SCHRITT 1: Identity Unlock (einmalig pro CLI-Aufruf)              │  │
│  │ ═══════════════════════════════════════════════════               │  │
│  │                                                                   │  │
│  │   user_password ──┐                                               │  │
│  │                   ├──▶ Argon2id ──▶ identity_key                  │  │
│  │   yubikey_pepper ─┘                      │                        │  │
│  │                                          ▼                        │  │
│  │                              ┌─────────────────────┐              │  │
│  │                              │ AES-256-GCM Decrypt │              │  │
│  │                              └──────────┬──────────┘              │  │
│  │                                         │                         │  │
│  │                                         ▼                         │  │
│  │                              ┌─────────────────────┐              │  │
│  │                              │ Private Keys (RAM)  │              │  │
│  │                              │ • encryption_priv   │              │  │
│  │                              │ • signing_priv      │              │  │
│  │                              └──────────┬──────────┘              │  │
│  │                                         │                         │  │
│  │   🔑 HSM-Touch: HIER (1x pro Aufruf)    │                         │  │
│  └─────────────────────────────────────────┼─────────────────────────┘  │
│                                            │                            │
│                                            ▼                            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ SCHRITT 2: Datei-Verschlüsselung (pro Datei, KEIN HSM)            │  │
│  │ ══════════════════════════════════════════════════════            │  │
│  │                                                                   │  │
│  │   random_password ──▶ KDF-Chain ──▶ file_key ──▶ AES-GCM(Datei)   │  │
│  │   (256-bit Zufall)                                                │  │
│  │         │                                                         │  │
│  │         ▼                                                         │  │
│  │   ML-KEM.encap(recipient_public_key) ──▶ encrypted_password       │  │
│  │                                              (in Metadaten)       │  │
│  │                                                                   │  │
│  │   ML-DSA.sign(signing_priv, metadata) ──▶ signature               │  │
│  │                                              (in Metadaten)       │  │
│  │                                                                   │  │
│  │   🔑 HSM-Touch: NICHT NÖTIG (Keys bereits im RAM)                 │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                            │                            │
│                                            ▼                            │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ SCHRITT 3: Secure Cleanup (IMMER - auch bei Fehler!)              │  │
│  │ ════════════════════════════════════════════════════              │  │
│  │                                                                   │  │
│  │   secure_memzero(encryption_priv)   ──▶  RAM überschrieben        │  │
│  │   secure_memzero(signing_priv)      ──▶  RAM überschrieben        │  │
│  │   secure_memzero(password)          ──▶  best effort              │  │
│  │                                                                   │  │
│  │   🔒 Prozess endet: Keine sensitiven Daten mehr im RAM            │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              VERGLEICH: Symmetrisch vs. Asymmetrisch                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  SYMMETRISCH (v1.3.1):                                                  │
│  ─────────────────────                                                  │
│  user_password + yubikey_pepper ──▶ KDF ──▶ file_key                    │
│                                                   │                     │
│                                                   ▼                     │
│                                           Verschlüsselt DATEI           │
│                                                   │                     │
│                                                   ▼                     │
│                                           secure_memzero(file_key)      │
│                                                                         │
│  → HSM schützt: DATEI DIREKT                                            │
│  → HSM nötig bei: JEDER Datei                                           │
│  → Keys im RAM: Nur während EINER Datei                                 │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════    │
│                                                                         │
│  ASYMMETRISCH (v1.4.0):                                                 │
│  ──────────────────────                                                 │
│  user_password + yubikey_pepper ──▶ KDF ──▶ identity_key                │
│                                                   │                     │
│                                                   ▼                     │
│                                           Entschlüsselt PRIVATE KEYS    │
│                                                   │                     │
│                                                   ▼                     │
│                                           Verarbeitet N Dateien         │
│                                                   │                     │
│                                                   ▼                     │
│                                           secure_memzero(alle Keys)     │
│                                                                         │
│  → HSM schützt: IDENTITY (Private Keys)                                 │
│  → HSM nötig bei: 1x pro CLI-Aufruf                                     │
│  → Keys im RAM: Nur während des CLI-Aufrufs                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Zusammenfassung

| Aspekt | Symmetrisch (v1.3.1) | Asymmetrisch (v1.4.0) |
|--------|----------------------|------------------------|
| **HSM schützt** | Datei direkt | Identity-Keys |
| **Datei-Key kommt von** | User-Passwort + Pepper | Random (256-bit) |
| **Yubikey-Touch bei** | Jeder Datei einzeln | Pro CLI-Aufruf (1x für N Dateien) |
| **Keys im RAM** | Nur während einer Datei | Nur während CLI-Aufruf |
| **Nach Prozess-Ende** | secure_memzero() | secure_memzero() |

### Identity Key Protection (Detail)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Identity Key Protection                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────┐  │
│  │   User      │    │   Yubikey   │    │      Key Derivation         │  │
│  │  Password   │    │    HMAC     │    │                             │  │
│  │             │    │  (Touch)    │    │  password ──┐               │  │
│  │  "secret"   │    │             │    │             ├──▶ Argon2id   │  │
│  │             │    │  HMAC-SHA1  │    │  hsm_pepper ┘    ↓          │  │
│  │             │    │  Challenge  │    │              identity_key   │  │
│  └──────┬──────┘    └──────┬──────┘    │                   ↓          │  │
│         │                  │           │         ┌─────────────────┐ │  │
│         │                  │           │         │ AES-256-GCM     │ │  │
│         └────────┬─────────┘           │         │ Decrypt         │ │  │
│                  │                     │         └────────┬────────┘ │  │
│                  ▼                     │                  │          │  │
│         ┌────────────────┐             │                  ▼          │  │
│         │ HSM Challenge  │             │     ┌────────────────────┐  │  │
│         │ = SHA256(salt  │             │     │ encryption_private │  │  │
│         │   + "identity" │             │     │ signing_private    │  │  │
│         │   + identity_  │             │     └────────────────────┘  │  │
│         │     name)      │             │                             │  │
│         └────────────────┘             └─────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

Schutz-Level:
┌──────────────────┬─────────────┬─────────────┬────────────────────────┐
│ Level            │ Passwort    │ HSM         │ Use Case               │
├──────────────────┼─────────────┼─────────────┼────────────────────────┤
│ PASSWORD_ONLY    │ ✓           │ ✗           │ Einfache Nutzung       │
│ PASSWORD_AND_HSM │ ✓           │ ✓           │ Maximale Sicherheit    │
│ HSM_ONLY         │ ✗           │ ✓           │ Automation/Scripts     │
└──────────────────┴─────────────┴─────────────┴────────────────────────┘
```

### Typischer Workflow

```bash
# 1. Identity erstellen (einmalig)
$ openssl_encrypt identity create --name alice --hsm yubikey
Enter password: ********
Touch your Yubikey...  ← HSM-Touch
✓ Identity 'alice' created!

# 2. Mehrere Dateien in EINEM Aufruf verschlüsseln
$ openssl_encrypt encrypt --for bob --sign-with alice file1.txt file2.txt file3.txt
Enter password for 'alice': ********
Touch your Yubikey...  ← HSM-Touch (einmalig pro Aufruf)
✓ 3 file(s) encrypted
# → Keys sind SOFORT nach Abschluss aus dem RAM gelöscht!

# 3. Weiterer Aufruf = erneuter Touch
$ openssl_encrypt encrypt --for bob --sign-with alice file4.txt
Touch your Yubikey...  ← Neuer HSM-Touch (neuer Prozess)
✓ 1 file(s) encrypted
```

**Sicherheitsprinzip:**
- Keys sind **NUR** während der Verarbeitung im RAM
- Nach Prozess-Ende: `secure_memzero()` löscht alle Keys
- Kein Session-Management, keine persistenten Keys
- Jeder CLI-Aufruf = neuer Touch (falls HSM aktiv)

---

## Teil 1: Datenstrukturen

### 1.1 Identity-Konfiguration erweitert

**Datei:** `~/.openssl_encrypt/identities/{name}/identity.json`

```json
{
  "version": 1,
  "name": "Alice",
  "email": "alice@example.com",
  "created_at": "2025-12-25T10:00:00Z",

  "encryption_key": {
    "algorithm": "ML-KEM-768",
    "public_key_file": "encryption_public.pem",
    "private_key_file": "encryption_private.pem",
    "fingerprint": "a1b2c3d4e5f6..."
  },

  "signing_key": {
    "algorithm": "ML-DSA-65",
    "public_key_file": "signing_public.pem",
    "private_key_file": "signing_private.pem",
    "fingerprint": "f6e5d4c3b2a1..."
  },

  "protection": {
    "level": "password_and_hsm",
    "password": {
      "kdf": "argon2id",
      "kdf_params": {
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4
      },
      "salt": "<base64: 16 bytes>"
    },
    "hsm": {
      "type": "yubikey",
      "slot": 2,
      "challenge_salt": "<base64: 32 bytes>",
      "require_touch": true
    }
  }
}
```

### 1.2 Protection Level Enum

**Datei:** `openssl_encrypt/modules/identity.py`

```python
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path


class ProtectionLevel(Enum):
    """Schutz-Level für Identity-Keys."""

    PASSWORD_ONLY = "password_only"
    """Nur Passwort - Standard, keine Hardware erforderlich."""

    PASSWORD_AND_HSM = "password_and_hsm"
    """Passwort + HSM - Maximale Sicherheit, beide Faktoren erforderlich."""

    HSM_ONLY = "hsm_only"
    """Nur HSM - Für Automation, kein Passwort-Prompt."""


@dataclass
class PasswordProtectionConfig:
    """Konfiguration für Passwort-basierten Schutz."""

    kdf: str = "argon2id"
    time_cost: int = 3
    memory_cost: int = 65536  # 64 MB
    parallelism: int = 4
    salt: bytes = field(default_factory=lambda: b"")

    def to_dict(self) -> Dict[str, Any]:
        import base64
        return {
            "kdf": self.kdf,
            "kdf_params": {
                "time_cost": self.time_cost,
                "memory_cost": self.memory_cost,
                "parallelism": self.parallelism
            },
            "salt": base64.b64encode(self.salt).decode("ascii")
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PasswordProtectionConfig":
        import base64
        params = data.get("kdf_params", {})
        return cls(
            kdf=data.get("kdf", "argon2id"),
            time_cost=params.get("time_cost", 3),
            memory_cost=params.get("memory_cost", 65536),
            parallelism=params.get("parallelism", 4),
            salt=base64.b64decode(data.get("salt", ""))
        )


@dataclass
class HSMProtectionConfig:
    """Konfiguration für HSM-basierten Schutz."""

    hsm_type: str = "yubikey"
    slot: Optional[int] = None  # None = Auto-Detect
    challenge_salt: bytes = field(default_factory=lambda: b"")
    require_touch: bool = True

    def to_dict(self) -> Dict[str, Any]:
        import base64
        return {
            "type": self.hsm_type,
            "slot": self.slot,
            "challenge_salt": base64.b64encode(self.challenge_salt).decode("ascii"),
            "require_touch": self.require_touch
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HSMProtectionConfig":
        import base64
        return cls(
            hsm_type=data.get("type", "yubikey"),
            slot=data.get("slot"),
            challenge_salt=base64.b64decode(data.get("challenge_salt", "")),
            require_touch=data.get("require_touch", True)
        )


@dataclass
class IdentityProtection:
    """Vollständige Schutz-Konfiguration für eine Identity."""

    level: ProtectionLevel
    password_config: Optional[PasswordProtectionConfig] = None
    hsm_config: Optional[HSMProtectionConfig] = None

    def requires_password(self) -> bool:
        """Prüft ob ein Passwort erforderlich ist."""
        return self.level in (ProtectionLevel.PASSWORD_ONLY, ProtectionLevel.PASSWORD_AND_HSM)

    def requires_hsm(self) -> bool:
        """Prüft ob ein HSM erforderlich ist."""
        return self.level in (ProtectionLevel.HSM_ONLY, ProtectionLevel.PASSWORD_AND_HSM)

    def to_dict(self) -> Dict[str, Any]:
        result = {"level": self.level.value}
        if self.password_config:
            result["password"] = self.password_config.to_dict()
        if self.hsm_config:
            result["hsm"] = self.hsm_config.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityProtection":
        level = ProtectionLevel(data.get("level", "password_only"))

        password_config = None
        if "password" in data:
            password_config = PasswordProtectionConfig.from_dict(data["password"])

        hsm_config = None
        if "hsm" in data:
            hsm_config = HSMProtectionConfig.from_dict(data["hsm"])

        return cls(
            level=level,
            password_config=password_config,
            hsm_config=hsm_config
        )
```

### 1.3 Erweiterte Identity-Klasse

**Datei:** `openssl_encrypt/modules/identity.py` (Fortsetzung)

```python
@dataclass
class KeyPairInfo:
    """Informationen über ein Schlüsselpaar."""

    algorithm: str
    public_key_file: str
    private_key_file: str
    fingerprint: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "public_key_file": self.public_key_file,
            "private_key_file": self.private_key_file,
            "fingerprint": self.fingerprint
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyPairInfo":
        return cls(
            algorithm=data["algorithm"],
            public_key_file=data["public_key_file"],
            private_key_file=data["private_key_file"],
            fingerprint=data["fingerprint"]
        )


@dataclass
class Identity:
    """
    Repräsentiert eine kryptographische Identität.

    Eine Identity besteht aus:
    - Einem Encryption-Keypair (ML-KEM) für Passwort-Wrapping
    - Einem Signing-Keypair (ML-DSA) für Metadaten-Signaturen
    - Schutz-Konfiguration (Passwort und/oder HSM)
    """

    name: str
    email: Optional[str]
    created_at: str

    encryption_key: KeyPairInfo
    signing_key: KeyPairInfo

    protection: IdentityProtection

    # Runtime (nicht persistiert)
    base_path: Optional[Path] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "name": self.name,
            "email": self.email,
            "created_at": self.created_at,
            "encryption_key": self.encryption_key.to_dict(),
            "signing_key": self.signing_key.to_dict(),
            "protection": self.protection.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], base_path: Optional[Path] = None) -> "Identity":
        return cls(
            name=data["name"],
            email=data.get("email"),
            created_at=data["created_at"],
            encryption_key=KeyPairInfo.from_dict(data["encryption_key"]),
            signing_key=KeyPairInfo.from_dict(data["signing_key"]),
            protection=IdentityProtection.from_dict(data["protection"]),
            base_path=base_path
        )

    def get_encryption_public_key_path(self) -> Path:
        """Pfad zum Encryption Public Key."""
        if not self.base_path:
            raise ValueError("Identity base_path not set")
        return self.base_path / self.encryption_key.public_key_file

    def get_encryption_private_key_path(self) -> Path:
        """Pfad zum verschlüsselten Encryption Private Key."""
        if not self.base_path:
            raise ValueError("Identity base_path not set")
        return self.base_path / self.encryption_key.private_key_file

    def get_signing_public_key_path(self) -> Path:
        """Pfad zum Signing Public Key."""
        if not self.base_path:
            raise ValueError("Identity base_path not set")
        return self.base_path / self.signing_key.public_key_file

    def get_signing_private_key_path(self) -> Path:
        """Pfad zum verschlüsselten Signing Private Key."""
        if not self.base_path:
            raise ValueError("Identity base_path not set")
        return self.base_path / self.signing_key.private_key_file
```

---

## Teil 2: Identity Key Protection Service

### 2.1 Haupt-Service-Klasse

**Datei:** `openssl_encrypt/modules/identity_protection.py`

```python
"""
Identity Key Protection Service.

Verantwortlich für:
- Verschlüsselung von Identity Private Keys
- Entschlüsselung mit Passwort und/oder HSM
- Integration mit Yubikey Challenge-Response
"""

import os
import hashlib
import secrets
from typing import Optional, Tuple
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

from .identity import (
    Identity, IdentityProtection, ProtectionLevel,
    PasswordProtectionConfig, HSMProtectionConfig
)


class IdentityProtectionError(Exception):
    """Basis-Exception für Identity-Protection-Fehler."""
    pass


class HSMNotAvailableError(IdentityProtectionError):
    """HSM ist nicht verfügbar oder nicht konfiguriert."""
    pass


class HSMTouchTimeoutError(IdentityProtectionError):
    """Timeout beim Warten auf HSM-Touch."""
    pass


class InvalidCredentialsError(IdentityProtectionError):
    """Passwort oder HSM-Response ungültig."""
    pass


class IdentityKeyProtection:
    """
    Service für HSM-geschützte Identity-Keys.

    SICHERHEITSMODELL:

    1. PASSWORD_ONLY:
       key = Argon2id(password, salt)

    2. PASSWORD_AND_HSM:
       hsm_pepper = HMAC-SHA1(yubikey_secret, challenge)
       key = Argon2id(password + hsm_pepper, salt)

    3. HSM_ONLY:
       hsm_pepper = HMAC-SHA1(yubikey_secret, challenge)
       key = Argon2id(hsm_pepper, salt)

    Der abgeleitete Key wird verwendet um die Private Keys
    mit AES-256-GCM zu verschlüsseln.
    """

    # Konstanten
    SALT_SIZE = 16
    CHALLENGE_SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32  # AES-256

    def __init__(self, hsm_plugin=None):
        """
        Initialisiert den Protection Service.

        Args:
            hsm_plugin: Optional - Yubikey Plugin Instanz.
                        Wird lazy geladen wenn nicht angegeben.
        """
        self._hsm_plugin = hsm_plugin
        self._hsm_checked = False

    def _get_hsm_plugin(self):
        """Lazy-Load des HSM-Plugins."""
        if self._hsm_plugin is None and not self._hsm_checked:
            self._hsm_checked = True
            try:
                from openssl_encrypt.plugins.hsm.yubikey_challenge_response import (
                    YubikeyPlugin
                )
                self._hsm_plugin = YubikeyPlugin()
            except ImportError:
                pass
        return self._hsm_plugin

    def is_hsm_available(self) -> bool:
        """Prüft ob ein HSM verfügbar ist."""
        plugin = self._get_hsm_plugin()
        if plugin is None:
            return False
        return plugin.is_available()

    def detect_hsm_slot(self) -> Optional[int]:
        """Erkennt den konfigurierten HSM-Slot."""
        plugin = self._get_hsm_plugin()
        if plugin is None:
            return None
        return plugin.detect_slot()

    def _generate_hsm_challenge(
        self,
        challenge_salt: bytes,
        identity_name: str
    ) -> bytes:
        """
        Generiert den HSM-Challenge.

        Challenge = SHA256(challenge_salt || "identity" || identity_name)

        Dies stellt sicher, dass jede Identity einen einzigartigen
        Challenge hat, selbst wenn der gleiche Yubikey verwendet wird.
        """
        challenge_input = challenge_salt + b"identity" + identity_name.encode("utf-8")
        return hashlib.sha256(challenge_input).digest()

    def _get_hsm_pepper(
        self,
        hsm_config: HSMProtectionConfig,
        identity_name: str
    ) -> bytes:
        """
        Holt den HSM-Pepper via Challenge-Response.

        Args:
            hsm_config: HSM-Konfiguration
            identity_name: Name der Identity (Teil des Challenges)

        Returns:
            20-Byte HMAC-SHA1 Response vom Yubikey

        Raises:
            HSMNotAvailableError: Yubikey nicht gefunden
            HSMTouchTimeoutError: Touch-Timeout
        """
        plugin = self._get_hsm_plugin()
        if plugin is None:
            raise HSMNotAvailableError("Yubikey plugin not available")

        if not plugin.is_available():
            raise HSMNotAvailableError(
                "No Yubikey detected. Please insert your Yubikey."
            )

        # Challenge generieren
        challenge = self._generate_hsm_challenge(
            hsm_config.challenge_salt,
            identity_name
        )

        # Slot bestimmen
        slot = hsm_config.slot
        if slot is None:
            slot = plugin.detect_slot()
            if slot is None:
                raise HSMNotAvailableError(
                    "No Challenge-Response slot configured on Yubikey. "
                    "Please configure slot 1 or 2 for HMAC-SHA1 Challenge-Response."
                )

        # Challenge-Response durchführen
        if hsm_config.require_touch:
            print("Touch your Yubikey to continue...", flush=True)

        try:
            response = plugin.challenge_response(
                challenge=challenge,
                slot=slot,
                timeout=30  # 30 Sekunden Timeout für Touch
            )
        except TimeoutError:
            raise HSMTouchTimeoutError(
                "Yubikey touch timeout. Please try again and touch your Yubikey."
            )

        return response

    def _derive_key(
        self,
        password: Optional[str],
        hsm_pepper: Optional[bytes],
        password_config: PasswordProtectionConfig
    ) -> bytes:
        """
        Leitet den Encryption-Key ab.

        Args:
            password: User-Passwort (oder None bei HSM_ONLY)
            hsm_pepper: HSM-Response (oder None bei PASSWORD_ONLY)
            password_config: KDF-Parameter

        Returns:
            32-Byte Key für AES-256-GCM
        """
        # Input zusammenbauen
        key_material = b""

        if password:
            key_material += password.encode("utf-8")

        if hsm_pepper:
            key_material += hsm_pepper

        if not key_material:
            raise ValueError("Either password or HSM pepper must be provided")

        # Argon2id KDF
        derived = hash_secret_raw(
            secret=key_material,
            salt=password_config.salt,
            time_cost=password_config.time_cost,
            memory_cost=password_config.memory_cost,
            parallelism=password_config.parallelism,
            hash_len=self.KEY_SIZE,
            type=Type.ID
        )

        return derived

    def encrypt_private_key(
        self,
        private_key_data: bytes,
        password: Optional[str],
        protection: IdentityProtection,
        identity_name: str
    ) -> bytes:
        """
        Verschlüsselt einen Private Key.

        Args:
            private_key_data: Roher Private Key (PEM oder DER)
            password: User-Passwort (falls erforderlich)
            protection: Schutz-Konfiguration
            identity_name: Name der Identity (für HSM-Challenge)

        Returns:
            Verschlüsselte Daten: nonce (12) + ciphertext + tag (16)
        """
        # HSM-Pepper holen falls erforderlich
        hsm_pepper = None
        if protection.requires_hsm():
            if protection.hsm_config is None:
                raise ValueError("HSM protection requires hsm_config")
            hsm_pepper = self._get_hsm_pepper(protection.hsm_config, identity_name)

        # Key ableiten
        if protection.password_config is None:
            raise ValueError("Password config required")

        encryption_key = self._derive_key(
            password=password if protection.requires_password() else None,
            hsm_pepper=hsm_pepper,
            password_config=protection.password_config
        )

        # AES-256-GCM Encryption
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, private_key_data, None)

        return nonce + ciphertext

    def decrypt_private_key(
        self,
        encrypted_data: bytes,
        password: Optional[str],
        protection: IdentityProtection,
        identity_name: str
    ) -> bytes:
        """
        Entschlüsselt einen Private Key.

        Args:
            encrypted_data: Verschlüsselte Daten (nonce + ciphertext + tag)
            password: User-Passwort (falls erforderlich)
            protection: Schutz-Konfiguration
            identity_name: Name der Identity (für HSM-Challenge)

        Returns:
            Entschlüsselter Private Key

        Raises:
            InvalidCredentialsError: Passwort oder HSM-Response falsch
        """
        # HSM-Pepper holen falls erforderlich
        hsm_pepper = None
        if protection.requires_hsm():
            if protection.hsm_config is None:
                raise ValueError("HSM protection requires hsm_config")
            hsm_pepper = self._get_hsm_pepper(protection.hsm_config, identity_name)

        # Key ableiten
        if protection.password_config is None:
            raise ValueError("Password config required")

        encryption_key = self._derive_key(
            password=password if protection.requires_password() else None,
            hsm_pepper=hsm_pepper,
            password_config=protection.password_config
        )

        # AES-256-GCM Decryption
        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]

        aesgcm = AESGCM(encryption_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise InvalidCredentialsError(
                "Failed to decrypt private key. "
                "Invalid password or HSM response."
            )

        return plaintext

    def create_protection_config(
        self,
        level: ProtectionLevel,
        hsm_slot: Optional[int] = None,
        require_touch: bool = True
    ) -> IdentityProtection:
        """
        Erstellt eine neue Protection-Konfiguration.

        Args:
            level: Gewünschtes Schutz-Level
            hsm_slot: HSM-Slot (None = Auto-Detect)
            require_touch: Ob Touch für HSM erforderlich ist

        Returns:
            Neue IdentityProtection-Instanz
        """
        # Password-Config (immer erstellen für Salt-Storage)
        password_config = PasswordProtectionConfig(
            salt=secrets.token_bytes(self.SALT_SIZE)
        )

        # HSM-Config falls erforderlich
        hsm_config = None
        if level in (ProtectionLevel.PASSWORD_AND_HSM, ProtectionLevel.HSM_ONLY):
            if not self.is_hsm_available():
                raise HSMNotAvailableError(
                    "HSM protection requested but no Yubikey available"
                )

            hsm_config = HSMProtectionConfig(
                hsm_type="yubikey",
                slot=hsm_slot or self.detect_hsm_slot(),
                challenge_salt=secrets.token_bytes(self.CHALLENGE_SALT_SIZE),
                require_touch=require_touch
            )

        return IdentityProtection(
            level=level,
            password_config=password_config,
            hsm_config=hsm_config
        )
```

---

## Teil 3: Identity Store Erweiterung

### 3.1 Erweiterter Identity Store

**Datei:** `openssl_encrypt/modules/identity_store.py`

```python
"""
Identity Store - Verwaltet lokale Identities.
"""

import json
import secrets
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from .identity import (
    Identity, IdentityProtection, ProtectionLevel,
    KeyPairInfo, PasswordProtectionConfig
)
from .identity_protection import (
    IdentityKeyProtection, HSMNotAvailableError,
    InvalidCredentialsError
)
from .pqc_liboqs import PQCKeyGenerator  # Bestehend
from .pqc_signing import PQCSigner  # Neu für v1.4.0


class IdentityExistsError(Exception):
    """Identity existiert bereits."""
    pass


class IdentityNotFoundError(Exception):
    """Identity nicht gefunden."""
    pass


class IdentityStore:
    """
    Verwaltet lokale Identities.

    Struktur:
    ~/.openssl_encrypt/identities/
    ├── alice/
    │   ├── identity.json
    │   ├── encryption_public.pem
    │   ├── encryption_private.pem  (verschlüsselt)
    │   ├── signing_public.pem
    │   └── signing_private.pem     (verschlüsselt)
    └── bob/
        └── ...
    """

    DEFAULT_BASE_PATH = Path("~/.openssl_encrypt/identities").expanduser()

    def __init__(
        self,
        base_path: Optional[Path] = None,
        protection_service: Optional[IdentityKeyProtection] = None
    ):
        self.base_path = base_path or self.DEFAULT_BASE_PATH
        self.protection = protection_service or IdentityKeyProtection()

        # Verzeichnis erstellen falls nötig
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _get_identity_path(self, name: str) -> Path:
        """Gibt den Pfad zum Identity-Verzeichnis zurück."""
        # Sicherstellen dass der Name sicher ist
        safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
        if not safe_name:
            raise ValueError(f"Invalid identity name: {name}")
        return self.base_path / safe_name

    def exists(self, name: str) -> bool:
        """Prüft ob eine Identity existiert."""
        identity_path = self._get_identity_path(name)
        return (identity_path / "identity.json").exists()

    def list_identities(self) -> List[str]:
        """Listet alle vorhandenen Identities."""
        identities = []
        for path in self.base_path.iterdir():
            if path.is_dir() and (path / "identity.json").exists():
                identities.append(path.name)
        return sorted(identities)

    def create(
        self,
        name: str,
        email: Optional[str] = None,
        password: Optional[str] = None,
        protection_level: ProtectionLevel = ProtectionLevel.PASSWORD_ONLY,
        hsm_slot: Optional[int] = None,
        encryption_algorithm: str = "ML-KEM-768",
        signing_algorithm: str = "ML-DSA-65"
    ) -> Identity:
        """
        Erstellt eine neue Identity.

        Args:
            name: Eindeutiger Name der Identity
            email: Optionale E-Mail-Adresse
            password: Passwort für Key-Schutz (erforderlich außer bei HSM_ONLY)
            protection_level: Schutz-Level
            hsm_slot: HSM-Slot (None = Auto-Detect)
            encryption_algorithm: PQC-KEM-Algorithmus
            signing_algorithm: PQC-Signing-Algorithmus

        Returns:
            Neue Identity-Instanz
        """
        # Prüfen ob Identity bereits existiert
        if self.exists(name):
            raise IdentityExistsError(f"Identity '{name}' already exists")

        # Passwort-Validierung
        if protection_level != ProtectionLevel.HSM_ONLY and not password:
            raise ValueError("Password required for this protection level")

        # Protection-Config erstellen
        protection = self.protection.create_protection_config(
            level=protection_level,
            hsm_slot=hsm_slot
        )

        # Verzeichnis erstellen
        identity_path = self._get_identity_path(name)
        identity_path.mkdir(parents=True, exist_ok=True)

        try:
            # Encryption-Keypair generieren (ML-KEM)
            enc_generator = PQCKeyGenerator(encryption_algorithm)
            enc_public, enc_private = enc_generator.generate_keypair()
            enc_fingerprint = self._calculate_fingerprint(enc_public)

            # Signing-Keypair generieren (ML-DSA)
            sign_generator = PQCSigner(signing_algorithm)
            sign_public, sign_private = sign_generator.generate_keypair()
            sign_fingerprint = self._calculate_fingerprint(sign_public)

            # Private Keys verschlüsseln
            enc_private_encrypted = self.protection.encrypt_private_key(
                private_key_data=enc_private,
                password=password,
                protection=protection,
                identity_name=name
            )

            sign_private_encrypted = self.protection.encrypt_private_key(
                private_key_data=sign_private,
                password=password,
                protection=protection,
                identity_name=name
            )

            # Keys speichern
            (identity_path / "encryption_public.pem").write_bytes(enc_public)
            (identity_path / "encryption_private.pem").write_bytes(enc_private_encrypted)
            (identity_path / "signing_public.pem").write_bytes(sign_public)
            (identity_path / "signing_private.pem").write_bytes(sign_private_encrypted)

            # Berechtigungen setzen (nur User)
            for key_file in identity_path.glob("*.pem"):
                key_file.chmod(0o600)

            # Identity-Objekt erstellen
            identity = Identity(
                name=name,
                email=email,
                created_at=datetime.now(timezone.utc).isoformat(),
                encryption_key=KeyPairInfo(
                    algorithm=encryption_algorithm,
                    public_key_file="encryption_public.pem",
                    private_key_file="encryption_private.pem",
                    fingerprint=enc_fingerprint
                ),
                signing_key=KeyPairInfo(
                    algorithm=signing_algorithm,
                    public_key_file="signing_public.pem",
                    private_key_file="signing_private.pem",
                    fingerprint=sign_fingerprint
                ),
                protection=protection,
                base_path=identity_path
            )

            # identity.json speichern
            with open(identity_path / "identity.json", "w") as f:
                json.dump(identity.to_dict(), f, indent=2)

            (identity_path / "identity.json").chmod(0o600)

            return identity

        except Exception as e:
            # Cleanup bei Fehler
            import shutil
            if identity_path.exists():
                shutil.rmtree(identity_path)
            raise

    def load(self, name: str) -> Identity:
        """
        Lädt eine Identity (ohne Private Keys zu entschlüsseln).

        Args:
            name: Name der Identity

        Returns:
            Identity-Instanz (nur Metadaten und Public Keys)
        """
        identity_path = self._get_identity_path(name)
        config_file = identity_path / "identity.json"

        if not config_file.exists():
            raise IdentityNotFoundError(f"Identity '{name}' not found")

        with open(config_file, "r") as f:
            data = json.load(f)

        return Identity.from_dict(data, base_path=identity_path)

    def unlock_private_keys(
        self,
        identity: Identity,
        password: Optional[str] = None
    ) -> Tuple[bytes, bytes]:
        """
        Entschlüsselt die Private Keys einer Identity.

        Args:
            identity: Geladene Identity
            password: Passwort (falls erforderlich)

        Returns:
            Tuple von (encryption_private_key, signing_private_key)
        """
        if identity.protection.requires_password() and not password:
            raise ValueError("Password required for this identity")

        # Verschlüsselte Keys laden
        enc_private_encrypted = identity.get_encryption_private_key_path().read_bytes()
        sign_private_encrypted = identity.get_signing_private_key_path().read_bytes()

        # Entschlüsseln (HSM-Touch passiert hier falls konfiguriert)
        enc_private = self.protection.decrypt_private_key(
            encrypted_data=enc_private_encrypted,
            password=password,
            protection=identity.protection,
            identity_name=identity.name
        )

        # Zweiter Key: Kein erneuter HSM-Touch nötig (gleicher Pepper)
        # ABER: Wir müssen den Pepper cachen oder erneut holen
        # Für Sicherheit: Jeden Key separat entschlüsseln
        sign_private = self.protection.decrypt_private_key(
            encrypted_data=sign_private_encrypted,
            password=password,
            protection=identity.protection,
            identity_name=identity.name
        )

        return enc_private, sign_private

    def get_public_keys(self, identity: Identity) -> Tuple[bytes, bytes]:
        """
        Gibt die Public Keys einer Identity zurück.

        Args:
            identity: Geladene Identity

        Returns:
            Tuple von (encryption_public_key, signing_public_key)
        """
        enc_public = identity.get_encryption_public_key_path().read_bytes()
        sign_public = identity.get_signing_public_key_path().read_bytes()
        return enc_public, sign_public

    def _calculate_fingerprint(self, public_key: bytes) -> str:
        """Berechnet den Fingerprint eines Public Keys."""
        digest = hashlib.sha256(public_key).hexdigest()
        # Format: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
        return ":".join(digest[i:i+4] for i in range(0, 32, 4))

    def delete(self, name: str, confirm: bool = False) -> None:
        """
        Löscht eine Identity.

        Args:
            name: Name der Identity
            confirm: Muss True sein um zu löschen
        """
        if not confirm:
            raise ValueError("Must confirm deletion with confirm=True")

        identity_path = self._get_identity_path(name)
        if not identity_path.exists():
            raise IdentityNotFoundError(f"Identity '{name}' not found")

        import shutil
        shutil.rmtree(identity_path)

    def export_public_keys(self, name: str, output_path: Path) -> None:
        """
        Exportiert die Public Keys einer Identity für Sharing.

        Args:
            name: Name der Identity
            output_path: Ziel-Datei (.pubkeys)
        """
        identity = self.load(name)
        enc_public, sign_public = self.get_public_keys(identity)

        export_data = {
            "version": 1,
            "name": identity.name,
            "email": identity.email,
            "encryption_key": {
                "algorithm": identity.encryption_key.algorithm,
                "public_key": enc_public.decode("utf-8"),  # PEM
                "fingerprint": identity.encryption_key.fingerprint
            },
            "signing_key": {
                "algorithm": identity.signing_key.algorithm,
                "public_key": sign_public.decode("utf-8"),  # PEM
                "fingerprint": identity.signing_key.fingerprint
            }
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

    def import_public_keys(
        self,
        input_path: Path,
        name: Optional[str] = None,
        trust: bool = False
    ) -> Identity:
        """
        Importiert Public Keys einer externen Identity.

        Args:
            input_path: Pfad zur .pubkeys-Datei
            name: Optionaler Override für den Namen
            trust: Muss True sein (TOFU-Bestätigung)

        Returns:
            Importierte Identity (nur Public Keys)
        """
        if not trust:
            raise ValueError(
                "Must confirm trust with trust=True. "
                "Verify fingerprints before trusting!"
            )

        with open(input_path, "r") as f:
            data = json.load(f)

        import_name = name or data["name"]

        if self.exists(import_name):
            raise IdentityExistsError(
                f"Identity '{import_name}' already exists"
            )

        # Verzeichnis erstellen
        identity_path = self._get_identity_path(import_name)
        identity_path.mkdir(parents=True, exist_ok=True)

        # Public Keys speichern
        enc_public = data["encryption_key"]["public_key"].encode("utf-8")
        sign_public = data["signing_key"]["public_key"].encode("utf-8")

        (identity_path / "encryption_public.pem").write_bytes(enc_public)
        (identity_path / "signing_public.pem").write_bytes(sign_public)

        # Identity-Config (ohne Private Keys, ohne Protection)
        identity = Identity(
            name=import_name,
            email=data.get("email"),
            created_at=datetime.now(timezone.utc).isoformat(),
            encryption_key=KeyPairInfo(
                algorithm=data["encryption_key"]["algorithm"],
                public_key_file="encryption_public.pem",
                private_key_file="",  # Kein Private Key
                fingerprint=data["encryption_key"]["fingerprint"]
            ),
            signing_key=KeyPairInfo(
                algorithm=data["signing_key"]["algorithm"],
                public_key_file="signing_public.pem",
                private_key_file="",  # Kein Private Key
                fingerprint=data["signing_key"]["fingerprint"]
            ),
            protection=IdentityProtection(
                level=ProtectionLevel.PASSWORD_ONLY,  # Dummy
                password_config=None,
                hsm_config=None
            ),
            base_path=identity_path
        )

        # identity.json speichern
        identity_data = identity.to_dict()
        identity_data["imported"] = True  # Markieren als importiert
        identity_data["imported_from"] = str(input_path)

        with open(identity_path / "identity.json", "w") as f:
            json.dump(identity_data, f, indent=2)

        return identity
```

---

## Teil 4: CLI-Integration

### 4.1 Identity-Commands

**Datei:** `openssl_encrypt/cli_identity.py`

```python
"""
CLI-Commands für Identity-Management.
"""

import click
import getpass
from pathlib import Path

from .modules.identity import ProtectionLevel
from .modules.identity_store import (
    IdentityStore, IdentityExistsError, IdentityNotFoundError
)
from .modules.identity_protection import (
    HSMNotAvailableError, HSMTouchTimeoutError, InvalidCredentialsError
)


@click.group()
def identity():
    """Identity-Management für asymmetrische Verschlüsselung."""
    pass


@identity.command("create")
@click.option("--name", "-n", required=True, help="Name der Identity")
@click.option("--email", "-e", help="E-Mail-Adresse (optional)")
@click.option(
    "--hsm",
    type=click.Choice(["none", "yubikey", "yubikey-only"]),
    default="none",
    help="HSM-Schutz: none=nur Passwort, yubikey=Passwort+Yubikey, yubikey-only=nur Yubikey"
)
@click.option("--hsm-slot", type=int, help="Yubikey-Slot (1 oder 2, default: auto)")
@click.option("--no-touch", is_flag=True, help="Kein Touch erforderlich (weniger sicher)")
def identity_create(name: str, email: str, hsm: str, hsm_slot: int, no_touch: bool):
    """Erstellt eine neue Identity."""

    store = IdentityStore()

    # Protection Level bestimmen
    if hsm == "none":
        protection_level = ProtectionLevel.PASSWORD_ONLY
    elif hsm == "yubikey":
        protection_level = ProtectionLevel.PASSWORD_AND_HSM
    elif hsm == "yubikey-only":
        protection_level = ProtectionLevel.HSM_ONLY

    # HSM-Verfügbarkeit prüfen
    if protection_level in (ProtectionLevel.PASSWORD_AND_HSM, ProtectionLevel.HSM_ONLY):
        if not store.protection.is_hsm_available():
            click.echo("Error: Yubikey not found. Please insert your Yubikey.", err=True)
            raise SystemExit(1)

        detected_slot = store.protection.detect_hsm_slot()
        if detected_slot is None:
            click.echo(
                "Error: No Challenge-Response slot configured on Yubikey.\n"
                "Please configure slot 1 or 2 for HMAC-SHA1 Challenge-Response.",
                err=True
            )
            raise SystemExit(1)

        if hsm_slot is None:
            hsm_slot = detected_slot
            click.echo(f"Using Yubikey slot {hsm_slot} (auto-detected)")

    # Passwort abfragen
    password = None
    if protection_level != ProtectionLevel.HSM_ONLY:
        password = getpass.getpass("Enter password for identity: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            click.echo("Error: Passwords do not match.", err=True)
            raise SystemExit(1)

        if len(password) < 8:
            click.echo("Warning: Password is very short. Consider using a stronger password.", err=True)

    try:
        # Identity erstellen
        click.echo(f"Creating identity '{name}'...")

        if protection_level in (ProtectionLevel.PASSWORD_AND_HSM, ProtectionLevel.HSM_ONLY):
            click.echo("Touch your Yubikey to generate keys...")

        identity = store.create(
            name=name,
            email=email,
            password=password,
            protection_level=protection_level,
            hsm_slot=hsm_slot
        )

        click.echo(f"\n✓ Identity '{name}' created successfully!\n")
        click.echo("Encryption Key Fingerprint:")
        click.echo(f"  {identity.encryption_key.fingerprint}")
        click.echo("\nSigning Key Fingerprint:")
        click.echo(f"  {identity.signing_key.fingerprint}")

        click.echo(f"\nProtection: {protection_level.value}")
        if protection_level == ProtectionLevel.PASSWORD_AND_HSM:
            click.echo("  → Both password AND Yubikey required for decryption")
        elif protection_level == ProtectionLevel.HSM_ONLY:
            click.echo("  → Only Yubikey required (no password)")

        click.echo(f"\nTo share your public keys:")
        click.echo(f"  openssl_encrypt identity export --name {name} --output {name}.pubkeys")

    except IdentityExistsError:
        click.echo(f"Error: Identity '{name}' already exists.", err=True)
        raise SystemExit(1)
    except HSMNotAvailableError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)
    except HSMTouchTimeoutError:
        click.echo("Error: Yubikey touch timeout.", err=True)
        raise SystemExit(1)


@identity.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Zeige Details")
def identity_list(verbose: bool):
    """Listet alle Identities auf."""

    store = IdentityStore()
    identities = store.list_identities()

    if not identities:
        click.echo("No identities found.")
        click.echo("Create one with: openssl_encrypt identity create --name <name>")
        return

    click.echo(f"Found {len(identities)} identity/identities:\n")

    for name in identities:
        identity = store.load(name)

        if verbose:
            click.echo(f"─── {name} ───")
            if identity.email:
                click.echo(f"  Email: {identity.email}")
            click.echo(f"  Protection: {identity.protection.level.value}")
            click.echo(f"  Encryption: {identity.encryption_key.algorithm}")
            click.echo(f"    Fingerprint: {identity.encryption_key.fingerprint[:24]}...")
            click.echo(f"  Signing: {identity.signing_key.algorithm}")
            click.echo(f"    Fingerprint: {identity.signing_key.fingerprint[:24]}...")

            # Prüfen ob importiert
            config_file = identity.base_path / "identity.json"
            import json
            with open(config_file) as f:
                data = json.load(f)
            if data.get("imported"):
                click.echo(f"  [IMPORTED - no private keys]")
            click.echo()
        else:
            protection_marker = ""
            if identity.protection.level == ProtectionLevel.PASSWORD_AND_HSM:
                protection_marker = " [HSM+PW]"
            elif identity.protection.level == ProtectionLevel.HSM_ONLY:
                protection_marker = " [HSM]"

            click.echo(f"  • {name}{protection_marker}")


@identity.command("export")
@click.option("--name", "-n", required=True, help="Name der Identity")
@click.option("--output", "-o", required=True, type=click.Path(), help="Ausgabe-Datei (.pubkeys)")
def identity_export(name: str, output: str):
    """Exportiert Public Keys zum Teilen."""

    store = IdentityStore()

    try:
        identity = store.load(name)
        output_path = Path(output)

        store.export_public_keys(name, output_path)

        click.echo(f"✓ Public keys exported to: {output_path}")
        click.echo(f"\nEncryption Key Fingerprint:")
        click.echo(f"  {identity.encryption_key.fingerprint}")
        click.echo(f"\nSigning Key Fingerprint:")
        click.echo(f"  {identity.signing_key.fingerprint}")
        click.echo("\n⚠️  Share these fingerprints via a separate channel (e.g., Signal)")
        click.echo("    so recipients can verify the keys.")

    except IdentityNotFoundError:
        click.echo(f"Error: Identity '{name}' not found.", err=True)
        raise SystemExit(1)


@identity.command("import")
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="Pubkeys-Datei")
@click.option("--name", "-n", help="Name (default: aus Datei)")
@click.option("--yes", "-y", is_flag=True, help="Fingerprints bereits verifiziert")
def identity_import(file: str, name: str, yes: bool):
    """Importiert Public Keys einer anderen Person."""

    import json

    store = IdentityStore()
    input_path = Path(file)

    # Datei lesen um Fingerprints anzuzeigen
    with open(input_path) as f:
        data = json.load(f)

    import_name = name or data["name"]

    click.echo(f"Importing identity: {import_name}")
    if data.get("email"):
        click.echo(f"Email: {data['email']}")

    click.echo(f"\nEncryption Key ({data['encryption_key']['algorithm']}):")
    click.echo(f"  Fingerprint: {data['encryption_key']['fingerprint']}")

    click.echo(f"\nSigning Key ({data['signing_key']['algorithm']}):")
    click.echo(f"  Fingerprint: {data['signing_key']['fingerprint']}")

    if not yes:
        click.echo("\n" + "="*60)
        click.echo("⚠️  TRUST ON FIRST USE (TOFU)")
        click.echo("="*60)
        click.echo("Verify these fingerprints through a separate channel")
        click.echo("(e.g., phone call, Signal message, in person)")
        click.echo("before trusting this identity!")
        click.echo("="*60 + "\n")

        if not click.confirm("Have you verified the fingerprints?"):
            click.echo("Import cancelled.")
            raise SystemExit(0)

    try:
        identity = store.import_public_keys(
            input_path=input_path,
            name=name,
            trust=True
        )

        click.echo(f"\n✓ Identity '{identity.name}' imported successfully!")
        click.echo(f"\nYou can now encrypt files for {identity.name}:")
        click.echo(f"  openssl_encrypt encrypt --for {identity.name} --input file.txt")

    except IdentityExistsError:
        click.echo(f"Error: Identity '{import_name}' already exists.", err=True)
        raise SystemExit(1)


@identity.command("show")
@click.option("--name", "-n", required=True, help="Name der Identity")
def identity_show(name: str):
    """Zeigt Details einer Identity."""

    import json

    store = IdentityStore()

    try:
        identity = store.load(name)

        config_file = identity.base_path / "identity.json"
        with open(config_file) as f:
            data = json.load(f)

        click.echo(f"Identity: {identity.name}")
        click.echo(f"Created: {identity.created_at}")
        if identity.email:
            click.echo(f"Email: {identity.email}")

        click.echo(f"\nProtection Level: {identity.protection.level.value}")
        if identity.protection.requires_hsm():
            hsm = identity.protection.hsm_config
            click.echo(f"  HSM Type: {hsm.hsm_type}")
            click.echo(f"  HSM Slot: {hsm.slot or 'auto'}")
            click.echo(f"  Require Touch: {hsm.require_touch}")

        click.echo(f"\nEncryption Key:")
        click.echo(f"  Algorithm: {identity.encryption_key.algorithm}")
        click.echo(f"  Fingerprint: {identity.encryption_key.fingerprint}")

        click.echo(f"\nSigning Key:")
        click.echo(f"  Algorithm: {identity.signing_key.algorithm}")
        click.echo(f"  Fingerprint: {identity.signing_key.fingerprint}")

        if data.get("imported"):
            click.echo(f"\n[IMPORTED]")
            click.echo(f"  Source: {data.get('imported_from', 'unknown')}")
            click.echo(f"  Note: No private keys available")

    except IdentityNotFoundError:
        click.echo(f"Error: Identity '{name}' not found.", err=True)
        raise SystemExit(1)


@identity.command("delete")
@click.option("--name", "-n", required=True, help="Name der Identity")
@click.option("--yes", "-y", is_flag=True, help="Ohne Bestätigung löschen")
def identity_delete(name: str, yes: bool):
    """Löscht eine Identity."""

    store = IdentityStore()

    if not store.exists(name):
        click.echo(f"Error: Identity '{name}' not found.", err=True)
        raise SystemExit(1)

    if not yes:
        click.echo(f"⚠️  This will permanently delete identity '{name}'!")
        click.echo("    All private keys will be lost!")

        if not click.confirm(f"Delete identity '{name}'?"):
            click.echo("Deletion cancelled.")
            raise SystemExit(0)

    store.delete(name, confirm=True)
    click.echo(f"✓ Identity '{name}' deleted.")


@identity.command("test-unlock")
@click.option("--name", "-n", required=True, help="Name der Identity")
def identity_test_unlock(name: str):
    """Testet ob die Identity entsperrt werden kann."""

    store = IdentityStore()

    try:
        identity = store.load(name)

        # Prüfen ob importiert
        config_file = identity.base_path / "identity.json"
        import json
        with open(config_file) as f:
            data = json.load(f)

        if data.get("imported"):
            click.echo(f"Identity '{name}' is imported (no private keys).")
            raise SystemExit(0)

        # Passwort abfragen
        password = None
        if identity.protection.requires_password():
            password = getpass.getpass(f"Enter password for '{name}': ")

        if identity.protection.requires_hsm():
            click.echo("Touch your Yubikey...")

        # Unlock versuchen
        enc_key, sign_key = store.unlock_private_keys(identity, password)

        click.echo(f"\n✓ Identity '{name}' unlocked successfully!")
        click.echo(f"  Encryption key: {len(enc_key)} bytes")
        click.echo(f"  Signing key: {len(sign_key)} bytes")

    except IdentityNotFoundError:
        click.echo(f"Error: Identity '{name}' not found.", err=True)
        raise SystemExit(1)
    except InvalidCredentialsError:
        click.echo("Error: Invalid password or HSM response.", err=True)
        raise SystemExit(1)
    except HSMNotAvailableError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)
    except HSMTouchTimeoutError:
        click.echo("Error: Yubikey touch timeout.", err=True)
        raise SystemExit(1)
```

---

## Teil 5: Sicherheitsüberlegungen

### 5.1 Was schützt der HSM (und was nicht)?

```
HSM SCHÜTZT:
✓ Identity Private Keys (encryption_private.pem, signing_private.pem)
✓ Zugang zu Signatur-Fähigkeit
✓ Zugang zu KEM-Decapsulation

HSM SCHÜTZT NICHT DIREKT:
✗ Einzelne Dateien (die werden mit Random-Passwort verschlüsselt)
✗ Das Random-Passwort pro Datei (das wird mit ML-KEM gewrapped)

ABER: Ohne die Private Keys (die der HSM schützt) kann niemand:
- Das gewrappte Passwort entschlüsseln → Datei nicht lesbar
- Gültige Signaturen erstellen → Kann sich nicht als du ausgeben
```

### 5.2 Threat Model

| Angriff | PASSWORD_ONLY | PASSWORD_AND_HSM | HSM_ONLY |
|---------|---------------|------------------|----------|
| Passwort-Leak | ❌ Identity kompromittiert | ✅ Yubikey fehlt | ✅ Kein Passwort |
| Yubikey gestohlen | ✅ Kein Yubikey nötig | ✅ Passwort fehlt | ❌ Identity kompromittiert |
| Backup kopiert | ⚠️ Offline-Brute-Force | ✅ Yubikey fehlt | ✅ Yubikey fehlt |
| Keylogger | ❌ Passwort abgefangen | ⚠️ Passwort, aber Touch fehlt | ✅ Nichts zu loggen |
| Malware (RAM-Dump) | ⚠️ Keys im RAM nach Unlock | ⚠️ Keys im RAM nach Unlock | ⚠️ Keys im RAM nach Unlock |

**Wichtig:** Nach dem Identity-Unlock sind die Private Keys im RAM. Der HSM schützt den *Zugang* zu den Keys, nicht die Keys selbst während sie verwendet werden.

### 5.3 Empfehlungen

```
Für maximale Sicherheit:        PASSWORD_AND_HSM
Für tägliche Nutzung:           PASSWORD_AND_HSM (mit Touch)
Für Automation/Scripting:       HSM_ONLY
Für Backup/Recovery:            PASSWORD_ONLY (offline aufbewahren)
```

### 5.4 Secure Memory - Keys sofort löschen

**Prinzip:** Keys sind NUR während der Operation im RAM, danach sofort sicher gelöscht.

```
┌─────────────────────────────────────────────────────────────────┐
│ CLI-Aufruf: openssl_encrypt encrypt --for bob --sign-with alice│
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Identity Unlock                                             │
│     └─▶ Touch Yubikey                                           │
│     └─▶ Private Keys → RAM (SecureBytes)                        │
│                                                                 │
│  2. Dateien verarbeiten                                         │
│     └─▶ file1.txt verschlüsseln + signieren                     │
│     └─▶ file2.txt verschlüsseln + signieren                     │
│     └─▶ file3.txt verschlüsseln + signieren                     │
│                                                                 │
│  3. SOFORT nach Abschluss (oder bei Fehler!)                    │
│     └─▶ secure_memzero(encryption_private)                      │
│     └─▶ secure_memzero(signing_private)                         │
│     └─▶ Prozess endet                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Ergebnis: Keys sind NIEMALS länger im RAM als unbedingt nötig.
```

**Implementierung mit SecureBytes-Wrapper:**

```python
"""
Secure Memory Management für sensitive Daten.

Verwendet die bestehenden secure_memzero Funktionen aus dem Core.
"""

import ctypes
import sys
from typing import Optional


class SecureBytes:
    """
    Wrapper für sensitive Bytes mit garantierter Löschung.

    Verwendung:
        with SecureBytes(private_key_data) as key:
            # key.data verwenden
            do_crypto_operation(key.data)
        # Nach dem Block: Daten sind sicher gelöscht

    ODER:
        key = SecureBytes(private_key_data)
        try:
            do_crypto_operation(key.data)
        finally:
            key.clear()  # Explizit löschen
    """

    def __init__(self, data: bytes):
        # Kopie als bytearray (mutable, kann überschrieben werden)
        self._data = bytearray(data)
        self._cleared = False

    @property
    def data(self) -> bytes:
        """Gibt die Daten als bytes zurück."""
        if self._cleared:
            raise ValueError("SecureBytes already cleared")
        return bytes(self._data)

    def clear(self) -> None:
        """Löscht die Daten sicher aus dem RAM."""
        if self._cleared:
            return

        secure_memzero(self._data)
        self._cleared = True

    def __enter__(self) -> "SecureBytes":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear()

    def __del__(self) -> None:
        """Fallback: Löschen wenn Objekt garbage collected wird."""
        if not self._cleared:
            self.clear()


def secure_memzero(data: bytearray) -> None:
    """
    Überschreibt einen bytearray sicher mit Nullen.

    Verwendet ctypes.memset um sicherzustellen, dass der Compiler
    die Operation nicht wegoptimiert.
    """
    if not isinstance(data, bytearray):
        raise TypeError("secure_memzero requires bytearray")

    if len(data) == 0:
        return

    # Pointer zum ersten Element
    ptr = (ctypes.c_char * len(data)).from_buffer(data)

    # Mit Nullen überschreiben
    ctypes.memset(ctypes.addressof(ptr), 0, len(data))

    # Memory barrier (verhindert Compiler-Optimierungen)
    # In Python nicht direkt möglich, aber ctypes.memset ist "opaque" genug


def secure_memzero_string(s: str) -> None:
    """
    Versucht einen String zu löschen (best effort).

    WARNUNG: Python Strings sind immutable und können vom
    Interpreter gecached werden. Diese Funktion bietet
    KEINE Garantie, ist aber besser als nichts.
    """
    # Strings in Python sind immutable - wir können nur
    # versuchen, die interne Repräsentation zu überschreiben
    if sys.implementation.name == "cpython":
        try:
            # CPython-spezifisch: Direkt in den String-Buffer schreiben
            str_ptr = ctypes.cast(id(s), ctypes.POINTER(ctypes.c_char))
            # Offset zum String-Inhalt (CPython 3.x)
            offset = sys.getsizeof("")
            for i in range(len(s)):
                str_ptr[offset + i] = b'\x00'
        except Exception:
            pass  # Best effort


class SecureKeyPair:
    """Container für ein Keypair mit sicherer Löschung."""

    def __init__(self, encryption_key: bytes, signing_key: bytes):
        self._encryption = SecureBytes(encryption_key)
        self._signing = SecureBytes(signing_key)

    @property
    def encryption_private(self) -> bytes:
        return self._encryption.data

    @property
    def signing_private(self) -> bytes:
        return self._signing.data

    def clear(self) -> None:
        """Löscht beide Keys sicher."""
        self._encryption.clear()
        self._signing.clear()

    def __enter__(self) -> "SecureKeyPair":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear()
```

**Verwendung im Identity Store:**

```python
def unlock_and_process(
    self,
    identity: Identity,
    password: Optional[str],
    processor: Callable[[SecureKeyPair], T]
) -> T:
    """
    Entsperrt Identity, führt Operation aus, löscht Keys sofort.

    Args:
        identity: Die Identity
        password: Passwort (falls erforderlich)
        processor: Funktion die mit den Keys arbeitet

    Returns:
        Ergebnis der processor-Funktion
    """
    # Keys entschlüsseln
    enc_private, sign_private = self._decrypt_private_keys(identity, password)

    # In SecureKeyPair wrappen
    with SecureKeyPair(enc_private, sign_private) as keys:
        # Originale sofort löschen
        secure_memzero(bytearray(enc_private))
        secure_memzero(bytearray(sign_private))

        # Operation ausführen
        return processor(keys)

    # Nach dem with-Block: Keys sind sicher gelöscht
```

**CLI-Integration:**

```python
@cli.command("encrypt")
@click.option("--for", "recipient", required=True)
@click.option("--sign-with", "signer", required=True)
@click.argument("files", nargs=-1)
def encrypt_asymmetric(recipient: str, signer: str, files: tuple):
    """Verschlüsselt Dateien für einen Empfänger."""

    store = IdentityStore()
    signer_identity = store.load(signer)

    # Passwort abfragen
    password = None
    if signer_identity.protection.requires_password():
        password = getpass.getpass(f"Password for '{signer}': ")

    if signer_identity.protection.requires_hsm():
        click.echo("Touch your Yubikey...")

    def process_files(keys: SecureKeyPair) -> int:
        """Verarbeitet alle Dateien mit den unlocked Keys."""
        encrypted_count = 0
        for file in files:
            encrypt_file_asymmetric(
                input_path=file,
                recipient=recipient,
                signing_key=keys.signing_private,
                # ...
            )
            encrypted_count += 1
        return encrypted_count

    # Keys sind NUR während process_files im RAM
    count = store.unlock_and_process(
        identity=signer_identity,
        password=password,
        processor=process_files
    )

    # Hier sind die Keys bereits gelöscht!
    click.echo(f"✓ {count} file(s) encrypted")
```

**Kritische Regeln:**

1. **Niemals** Keys in normalen Variablen speichern
2. **Immer** `SecureBytes` oder `SecureKeyPair` verwenden
3. **Immer** `with`-Statement oder explizites `clear()`
4. **Bei Exceptions:** `finally`-Block garantiert Löschung
5. **Passwort:** Auch `secure_memzero_string()` aufrufen (best effort)

---

## Teil 6: Implementierungsreihenfolge

### Phase 1: Datenstrukturen
1. `ProtectionLevel` Enum
2. `PasswordProtectionConfig` Dataclass
3. `HSMProtectionConfig` Dataclass
4. `IdentityProtection` Dataclass
5. Unit Tests für Serialisierung

### Phase 2: Protection Service
6. `IdentityKeyProtection._derive_key()` (Argon2id)
7. `IdentityKeyProtection._get_hsm_pepper()` (Yubikey Integration)
8. `IdentityKeyProtection.encrypt_private_key()`
9. `IdentityKeyProtection.decrypt_private_key()`
10. Unit Tests für alle Protection-Level

### Phase 3: Identity Store
11. `IdentityStore.create()` mit HSM-Support
12. `IdentityStore.unlock_private_keys()` mit HSM-Support
13. Integration Tests

### Phase 4: CLI
14. `identity create --hsm` Option
15. `identity test-unlock` Command
16. CLI-Tests

### Phase 5: Integration
17. Integration mit asymmetric encrypt/decrypt
18. End-to-End Tests
19. Dokumentation

---

## Teil 7: Testszenarien

### Unit Tests

```python
def test_password_only_roundtrip():
    """Test: Nur Passwort-Schutz."""
    protection = IdentityProtection(
        level=ProtectionLevel.PASSWORD_ONLY,
        password_config=PasswordProtectionConfig(
            salt=secrets.token_bytes(16)
        )
    )

    service = IdentityKeyProtection()

    original = b"secret private key data"
    encrypted = service.encrypt_private_key(
        private_key_data=original,
        password="test123",
        protection=protection,
        identity_name="alice"
    )

    decrypted = service.decrypt_private_key(
        encrypted_data=encrypted,
        password="test123",
        protection=protection,
        identity_name="alice"
    )

    assert decrypted == original


def test_wrong_password_fails():
    """Test: Falsches Passwort schlägt fehl."""
    # ... ähnlich wie oben, aber mit falschem Passwort
    with pytest.raises(InvalidCredentialsError):
        service.decrypt_private_key(
            encrypted_data=encrypted,
            password="wrong",
            protection=protection,
            identity_name="alice"
        )


def test_hsm_required_but_missing():
    """Test: HSM erforderlich aber nicht verfügbar."""
    protection = IdentityProtection(
        level=ProtectionLevel.PASSWORD_AND_HSM,
        # ...
    )

    service = IdentityKeyProtection(hsm_plugin=None)  # Kein HSM

    with pytest.raises(HSMNotAvailableError):
        service.encrypt_private_key(...)
```

### Integration Tests (mit echtem Yubikey)

```python
@pytest.mark.requires_yubikey
def test_hsm_roundtrip():
    """Test: HSM+Password Schutz (benötigt echten Yubikey)."""
    store = IdentityStore()

    # Identity erstellen
    identity = store.create(
        name="test_hsm",
        password="test123",
        protection_level=ProtectionLevel.PASSWORD_AND_HSM
    )

    # Unlock
    enc_key, sign_key = store.unlock_private_keys(identity, "test123")

    assert len(enc_key) > 0
    assert len(sign_key) > 0

    # Cleanup
    store.delete("test_hsm", confirm=True)
```

---

## Offene Fragen

1. **Pepper-Caching**: Soll der HSM-Pepper für beide Keys gecached werden (ein Touch) oder separat (zwei Touches)?
   - Empfehlung: Ein Touch, Pepper cachen für die Dauer der Operation

2. **HSM-Backup**: Was passiert wenn der Yubikey verloren geht?
   - Empfehlung: Bei Erstellung eine "Recovery Identity" mit PASSWORD_ONLY erstellen und offline aufbewahren

3. **Multi-HSM**: Unterstützung für mehrere Yubikeys?
   - Später: Mehrere `hsm_config` Einträge erlauben

4. **PIN-Schutz**: Yubikey OATH-PIN zusätzlich zum Touch?
   - Möglich, aber erhöht Komplexität

---

**Erstellt**: 25. Dezember 2025
**Für**: Claude Code Implementation
**Version**: 1.0
**Abhängigkeiten**:
- v1.4.0 Asymmetric Mode
- v1.3.1 Yubikey Plugin (bestehend)
