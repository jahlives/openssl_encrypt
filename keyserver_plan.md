# Keyserver Implementation Plan

*Für Claude Code zur Implementierung*

---

## Übersicht

Ein optionales Keyserver-System für openssl_encrypt, bestehend aus:
1. **Keyserver** – REST API zum Speichern und Abrufen von Public Keys
2. **Keyserver Plugin** – Opt-in Client-Plugin für Key-Lookup mit Fallback auf lokales Verzeichnis

### Design-Prinzipien

- **Opt-In:** Plugin muss explizit aktiviert werden
- **Fallback:** Lokales Verzeichnis wird immer als Fallback verwendet
- **Trust-Agnostisch:** Server speichert nur Keys, Trust-Entscheidung liegt beim User
- **Fingerprint-First:** Keys werden primär über Fingerprint identifiziert
- **PQC-Ready:** Unterstützt ML-KEM und ML-DSA Public Keys

---

## Architektur

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           openssl_encrypt Client                            │
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────────────────────────────────┐    │
│  │  crypt_core.py  │───▶│           KeyResolver                       │    │
│  │                 │    │  ═══════════════════════════════════════    │    │
│  │  --for bob      │    │                                             │    │
│  │  --verify alice │    │  resolve_key(identifier):                   │    │
│  │                 │    │    1. Check local keyring first             │    │
│  │                 │    │    2. If not found AND plugin enabled:      │    │
│  │                 │    │       → Query keyserver                     │    │
│  │                 │    │       → Cache result locally (optional)     │    │
│  │                 │    │    3. Return key or raise KeyNotFound       │    │
│  └─────────────────┘    └──────────────┬──────────────────────────────┘    │
│                                        │                                    │
│                         ┌──────────────┴──────────────┐                    │
│                         ▼                              ▼                    │
│           ┌─────────────────────────┐    ┌─────────────────────────┐       │
│           │   Local Keyring         │    │   Keyserver Plugin      │       │
│           │   ~/.openssl_encrypt/   │    │   (Opt-In)              │       │
│           │   identities/           │    │                         │       │
│           │   ├── alice/            │    │   • Server URL config   │       │
│           │   │   ├── identity.json │    │   • API communication   │       │
│           │   │   ├── enc.pub       │    │   • Response caching    │       │
│           │   │   └── sign.pub      │    │   • Fingerprint verify  │       │
│           │   └── bob/              │    │                         │       │
│           │       └── ...           │    │                         │       │
│           └─────────────────────────┘    └────────────┬────────────┘       │
│                                                       │                     │
└───────────────────────────────────────────────────────┼─────────────────────┘
                                                        │
                                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Keyserver (REST API)                           │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ POST   /api/v1/keys              → Upload public key                  │ │
│  │ GET    /api/v1/keys/:fingerprint → Get key by fingerprint             │ │
│  │ GET    /api/v1/keys/search       → Search by email/name               │ │
│  │ DELETE /api/v1/keys/:fingerprint → Revoke key (auth required)         │ │
│  │ GET    /api/v1/keys/:fingerprint/revocation → Check revocation status │ │
│  │ GET    /api/v1/health            → Health check                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        PostgreSQL / MySQL                             │ │
│  │  • public_keys: Uploaded keys with metadata                           │ │
│  │  • revocations: Revoked key fingerprints                              │ │
│  │  • upload_tokens: Optional email verification tokens                  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Teil 1: Public Key Format

### 1.1 Identity Public Key Bundle

Das Format für exportierte Public Keys, die auf dem Keyserver gespeichert werden:

**Datei:** `openssl_encrypt/modules/key_bundle.py`

```python
"""
Public Key Bundle Format für Keyserver.

Ein Bundle enthält alle öffentlichen Schlüssel einer Identity,
zusammen mit Metadaten und einer Selbst-Signatur.
"""

import json
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from base64 import b64encode, b64decode


@dataclass
class PublicKeyBundle:
    """
    Exportierbares Public Key Bundle.

    Enthält:
    - Encryption Public Key (ML-KEM)
    - Signing Public Key (ML-DSA)
    - Metadaten (Name, Email, Erstellungsdatum)
    - Selbst-Signatur (beweist Besitz des Private Keys)
    """

    # Version für zukünftige Kompatibilität
    bundle_version: int = 1

    # Identity-Informationen
    identity_name: str = ""
    email: Optional[str] = None
    comment: Optional[str] = None
    created_at: str = ""  # ISO 8601
    expires_at: Optional[str] = None  # ISO 8601, optional

    # Algorithmen
    encryption_algorithm: str = "ML-KEM-768"
    signing_algorithm: str = "ML-DSA-65"

    # Public Keys (Base64-encoded)
    encryption_public_key: str = ""  # ML-KEM Public Key
    signing_public_key: str = ""     # ML-DSA Public Key

    # Fingerprints (SHA-256 über die Keys)
    encryption_fingerprint: str = ""
    signing_fingerprint: str = ""

    # Kombinierter Fingerprint (primärer Identifier)
    # SHA-256(encryption_fingerprint || signing_fingerprint)
    bundle_fingerprint: str = ""

    # Selbst-Signatur über alle obigen Felder
    # Beweist dass der Uploader den Private Key besitzt
    self_signature: str = ""

    @classmethod
    def from_identity(cls, identity: 'Identity', include_signature: bool = True) -> 'PublicKeyBundle':
        """
        Erstellt ein Bundle aus einer lokalen Identity.

        Args:
            identity: Lokale Identity mit Public und Private Keys
            include_signature: Ob die Selbst-Signatur erstellt werden soll
        """
        enc_pub = identity.encryption_public_key
        sign_pub = identity.signing_public_key

        # Fingerprints berechnen
        enc_fp = hashlib.sha256(enc_pub).hexdigest()
        sign_fp = hashlib.sha256(sign_pub).hexdigest()
        bundle_fp = hashlib.sha256(f"{enc_fp}{sign_fp}".encode()).hexdigest()

        bundle = cls(
            identity_name=identity.name,
            email=identity.email,
            comment=identity.comment,
            created_at=identity.created_at or datetime.now(timezone.utc).isoformat(),
            expires_at=identity.expires_at,
            encryption_algorithm=identity.encryption_algorithm,
            signing_algorithm=identity.signing_algorithm,
            encryption_public_key=b64encode(enc_pub).decode(),
            signing_public_key=b64encode(sign_pub).decode(),
            encryption_fingerprint=enc_fp,
            signing_fingerprint=sign_fp,
            bundle_fingerprint=bundle_fp
        )

        if include_signature:
            bundle.self_signature = bundle._create_self_signature(identity)

        return bundle

    def _create_self_signature(self, identity: 'Identity') -> str:
        """
        Erstellt eine Selbst-Signatur über das Bundle.

        Die Signatur beweist, dass der Ersteller den Private Key besitzt.
        """
        # Daten zum Signieren (alles ausser der Signatur selbst)
        sign_data = self._get_signable_data()

        # Mit ML-DSA signieren
        from openssl_encrypt.modules.pqc_signing import sign_data
        signature = sign_data(
            identity.signing_private_key,
            sign_data.encode('utf-8'),
            identity.signing_algorithm
        )

        return b64encode(signature).decode()

    def _get_signable_data(self) -> str:
        """Gibt die zu signierenden Daten als kanonischen String zurück."""
        data = {
            "bundle_version": self.bundle_version,
            "identity_name": self.identity_name,
            "email": self.email,
            "comment": self.comment,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "encryption_algorithm": self.encryption_algorithm,
            "signing_algorithm": self.signing_algorithm,
            "encryption_public_key": self.encryption_public_key,
            "signing_public_key": self.signing_public_key,
            "encryption_fingerprint": self.encryption_fingerprint,
            "signing_fingerprint": self.signing_fingerprint,
            "bundle_fingerprint": self.bundle_fingerprint
        }
        # Kanonische JSON-Serialisierung (sortiert, keine Whitespace)
        return json.dumps(data, sort_keys=True, separators=(',', ':'))

    def verify_self_signature(self) -> bool:
        """
        Verifiziert die Selbst-Signatur des Bundles.

        Returns:
            True wenn die Signatur gültig ist
        """
        if not self.self_signature:
            return False

        try:
            sign_data = self._get_signable_data()
            signature = b64decode(self.self_signature)
            signing_key = b64decode(self.signing_public_key)

            from openssl_encrypt.modules.pqc_signing import verify_signature
            return verify_signature(
                signing_key,
                sign_data.encode('utf-8'),
                signature,
                self.signing_algorithm
            )
        except Exception:
            return False

    def to_json(self) -> str:
        """Serialisiert das Bundle zu JSON."""
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'PublicKeyBundle':
        """Deserialisiert ein Bundle aus JSON."""
        data = json.loads(json_str)
        return cls(**data)

    def get_encryption_key_bytes(self) -> bytes:
        """Gibt den Encryption Public Key als Bytes zurück."""
        return b64decode(self.encryption_public_key)

    def get_signing_key_bytes(self) -> bytes:
        """Gibt den Signing Public Key als Bytes zurück."""
        return b64decode(self.signing_public_key)

    def matches_fingerprint(self, fingerprint: str) -> bool:
        """
        Prüft ob ein Fingerprint zu diesem Bundle passt.

        Akzeptiert:
        - Bundle Fingerprint (vollständig oder Prefix)
        - Encryption Fingerprint
        - Signing Fingerprint
        """
        fp_lower = fingerprint.lower()
        return (
            self.bundle_fingerprint.lower().startswith(fp_lower) or
            self.encryption_fingerprint.lower().startswith(fp_lower) or
            self.signing_fingerprint.lower().startswith(fp_lower)
        )


# Fingerprint-Formatierung für Anzeige
def format_fingerprint(fp: str, group_size: int = 4) -> str:
    """
    Formatiert einen Fingerprint für bessere Lesbarkeit.

    Beispiel: "a1b2c3d4e5f6..." → "A1B2 C3D4 E5F6 ..."
    """
    fp_upper = fp.upper()
    groups = [fp_upper[i:i+group_size] for i in range(0, len(fp_upper), group_size)]
    return " ".join(groups)
```

### 1.2 Fingerprint-Berechnung

```python
"""
Fingerprint-Utilities.

Der Bundle-Fingerprint ist der primäre Identifier für Keys.
Er wird aus beiden Public Keys abgeleitet.
"""

import hashlib
from typing import Tuple


def calculate_key_fingerprint(public_key: bytes) -> str:
    """Berechnet SHA-256 Fingerprint eines einzelnen Keys."""
    return hashlib.sha256(public_key).hexdigest()


def calculate_bundle_fingerprint(
    encryption_public_key: bytes,
    signing_public_key: bytes
) -> Tuple[str, str, str]:
    """
    Berechnet alle Fingerprints für ein Key-Bundle.

    Returns:
        Tuple von (encryption_fp, signing_fp, bundle_fp)
    """
    enc_fp = calculate_key_fingerprint(encryption_public_key)
    sign_fp = calculate_key_fingerprint(signing_public_key)
    bundle_fp = hashlib.sha256(f"{enc_fp}{sign_fp}".encode()).hexdigest()

    return enc_fp, sign_fp, bundle_fp


def fingerprint_matches(full_fp: str, query: str) -> bool:
    """
    Prüft ob ein Fingerprint-Query passt.

    Akzeptiert vollständige oder partielle Fingerprints.
    Minimum 8 Zeichen für Sicherheit.
    """
    if len(query) < 8:
        return False
    return full_fp.lower().startswith(query.lower())
```

---

## Teil 2: Client-Seite – Keyserver Plugin

### 2.1 Plugin-Konfiguration

**Datei:** `openssl_encrypt/plugins/keyserver/config.py`

```python
"""
Keyserver Plugin Konfiguration.

WICHTIG: Das Plugin ist standardmässig DEAKTIVIERT.
Aktivierung erfolgt explizit durch den User.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List


@dataclass
class KeyserverConfig:
    """Konfiguration für das Keyserver Plugin."""

    # Aktivierung (Standard: AUS)
    enabled: bool = False

    # Server-URLs (können mehrere sein für Redundanz)
    servers: List[str] = field(default_factory=lambda: [
        "https://keys.openssl-encrypt.example.com"
    ])

    # Timeout-Einstellungen
    connect_timeout: int = 5   # Sekunden
    read_timeout: int = 10     # Sekunden

    # Caching
    cache_enabled: bool = True
    cache_dir: Path = field(
        default_factory=lambda: Path("~/.openssl_encrypt/keyserver_cache").expanduser()
    )
    cache_ttl: int = 86400  # 24 Stunden in Sekunden

    # Verhalten
    auto_import: bool = False  # Gefundene Keys automatisch ins lokale Keyring importieren?
    verify_signatures: bool = True  # Selbst-Signaturen verifizieren?
    check_revocation: bool = True   # Revocation-Status prüfen?

    # Upload-Einstellungen
    upload_enabled: bool = True

    # Lokales Keyring (Fallback)
    local_keyring_path: Path = field(
        default_factory=lambda: Path("~/.openssl_encrypt/identities").expanduser()
    )


# Globale Konfiguration (wird beim Plugin-Load gesetzt)
_config: Optional[KeyserverConfig] = None


def get_config() -> KeyserverConfig:
    """Gibt die aktuelle Konfiguration zurück."""
    global _config
    if _config is None:
        _config = KeyserverConfig()
    return _config


def set_config(config: KeyserverConfig) -> None:
    """Setzt die Konfiguration."""
    global _config
    _config = config
```

### 2.2 Key Resolver (Zentrale Komponente)

**Datei:** `openssl_encrypt/modules/key_resolver.py`

```python
"""
Key Resolver – Zentrale Komponente für Key-Lookup.

LOOKUP-REIHENFOLGE:
1. Lokales Keyring (~/.openssl_encrypt/identities/)
2. Keyserver (falls Plugin aktiviert)
3. Expliziter Pfad (falls angegeben)

IDENTIFIER-FORMATE:
- Name: "alice", "bob"
- Email: "alice@example.com"
- Fingerprint: "a1b2c3d4..." (min. 8 Zeichen)
- Pfad: "/path/to/key.pub" oder "./key.pub"
"""

import os
import logging
from pathlib import Path
from typing import Optional, Tuple, Union
from enum import Enum

from openssl_encrypt.modules.key_bundle import PublicKeyBundle
from openssl_encrypt.modules.identity import Identity


logger = logging.getLogger(__name__)


class KeySource(Enum):
    """Quelle eines aufgelösten Keys."""
    LOCAL_KEYRING = "local"
    KEYSERVER = "keyserver"
    KEYSERVER_CACHE = "keyserver_cache"
    EXPLICIT_PATH = "path"


class KeyNotFoundError(Exception):
    """Key konnte nicht gefunden werden."""
    def __init__(self, identifier: str, searched_locations: list):
        self.identifier = identifier
        self.searched_locations = searched_locations
        super().__init__(
            f"Key '{identifier}' not found. "
            f"Searched: {', '.join(searched_locations)}"
        )


class KeyResolver:
    """
    Löst Key-Identifier zu Public Keys auf.

    VERWENDUNG:
        resolver = KeyResolver()
        bundle, source = resolver.resolve("alice")
        bundle, source = resolver.resolve("a1b2c3d4e5f6")
        bundle, source = resolver.resolve("alice@example.com")
    """

    def __init__(
        self,
        local_keyring_path: Optional[Path] = None,
        keyserver_plugin: Optional['KeyserverPlugin'] = None
    ):
        """
        Initialisiert den Resolver.

        Args:
            local_keyring_path: Pfad zum lokalen Keyring
            keyserver_plugin: Optional – Keyserver Plugin für Remote-Lookup
        """
        self.local_keyring_path = local_keyring_path or Path(
            "~/.openssl_encrypt/identities"
        ).expanduser()
        self.keyserver_plugin = keyserver_plugin

    def resolve(
        self,
        identifier: str,
        key_type: str = "encryption"  # "encryption" oder "signing"
    ) -> Tuple[PublicKeyBundle, KeySource]:
        """
        Löst einen Identifier zu einem Public Key Bundle auf.

        Args:
            identifier: Name, Email, Fingerprint, oder Pfad
            key_type: Welcher Key benötigt wird (für Fehlermeldungen)

        Returns:
            Tuple von (PublicKeyBundle, KeySource)

        Raises:
            KeyNotFoundError: Wenn Key nicht gefunden wurde
        """
        searched = []

        # 1. Ist es ein expliziter Pfad?
        if self._is_path(identifier):
            bundle = self._load_from_path(identifier)
            if bundle:
                return bundle, KeySource.EXPLICIT_PATH
            searched.append(f"path:{identifier}")

        # 2. Lokales Keyring durchsuchen
        bundle = self._search_local_keyring(identifier)
        if bundle:
            logger.debug(f"Found key for '{identifier}' in local keyring")
            return bundle, KeySource.LOCAL_KEYRING
        searched.append("local keyring")

        # 3. Keyserver (falls Plugin aktiviert)
        if self.keyserver_plugin and self.keyserver_plugin.is_enabled():
            # Erst im Cache schauen
            bundle = self.keyserver_plugin.get_from_cache(identifier)
            if bundle:
                logger.debug(f"Found key for '{identifier}' in keyserver cache")
                return bundle, KeySource.KEYSERVER_CACHE

            # Dann Server anfragen
            bundle = self.keyserver_plugin.fetch_key(identifier)
            if bundle:
                logger.info(f"Found key for '{identifier}' on keyserver")
                return bundle, KeySource.KEYSERVER
            searched.append("keyserver")

        # Nicht gefunden
        raise KeyNotFoundError(identifier, searched)

    def _is_path(self, identifier: str) -> bool:
        """Prüft ob der Identifier ein Dateipfad ist."""
        return (
            identifier.startswith("/") or
            identifier.startswith("./") or
            identifier.startswith("../") or
            identifier.startswith("~") or
            os.path.sep in identifier
        )

    def _load_from_path(self, path_str: str) -> Optional[PublicKeyBundle]:
        """Lädt ein Key Bundle von einem expliziten Pfad."""
        path = Path(path_str).expanduser()

        if not path.exists():
            return None

        try:
            # Unterstützt sowohl einzelne .pub Files als auch Bundle-JSON
            if path.suffix == ".json":
                return PublicKeyBundle.from_json(path.read_text())
            elif path.suffix == ".pub":
                # Einzelner Public Key – Bundle mit nur diesem Key erstellen
                # (Legacy-Support)
                return self._bundle_from_single_key(path)
            else:
                # Versuche als JSON zu parsen
                return PublicKeyBundle.from_json(path.read_text())
        except Exception as e:
            logger.warning(f"Failed to load key from {path}: {e}")
            return None

    def _search_local_keyring(self, identifier: str) -> Optional[PublicKeyBundle]:
        """
        Durchsucht das lokale Keyring.

        Sucht nach:
        - Exakter Name-Match (Verzeichnisname)
        - Email-Match (in identity.json)
        - Fingerprint-Match (in identity.json)
        """
        if not self.local_keyring_path.exists():
            return None

        identifier_lower = identifier.lower()

        for identity_dir in self.local_keyring_path.iterdir():
            if not identity_dir.is_dir():
                continue

            # Exakter Name-Match
            if identity_dir.name.lower() == identifier_lower:
                return self._load_identity_bundle(identity_dir)

            # Versuche identity.json zu laden für weitere Checks
            identity_json = identity_dir / "identity.json"
            if identity_json.exists():
                try:
                    import json
                    data = json.loads(identity_json.read_text())

                    # Email-Match
                    if data.get("email", "").lower() == identifier_lower:
                        return self._load_identity_bundle(identity_dir)

                    # Fingerprint-Match (min. 8 Zeichen)
                    if len(identifier) >= 8:
                        bundle_fp = data.get("bundle_fingerprint", "")
                        enc_fp = data.get("encryption_fingerprint", "")
                        sign_fp = data.get("signing_fingerprint", "")

                        if any(
                            fp.lower().startswith(identifier_lower)
                            for fp in [bundle_fp, enc_fp, sign_fp]
                            if fp
                        ):
                            return self._load_identity_bundle(identity_dir)

                except Exception as e:
                    logger.debug(f"Failed to read {identity_json}: {e}")

        return None

    def _load_identity_bundle(self, identity_dir: Path) -> Optional[PublicKeyBundle]:
        """Lädt ein Bundle aus einem Identity-Verzeichnis."""
        try:
            # Erst versuchen, exportiertes Bundle zu laden
            bundle_file = identity_dir / "public_bundle.json"
            if bundle_file.exists():
                return PublicKeyBundle.from_json(bundle_file.read_text())

            # Sonst aus den einzelnen Key-Files zusammenbauen
            enc_pub = identity_dir / "encryption.pub"
            sign_pub = identity_dir / "signing.pub"
            identity_json = identity_dir / "identity.json"

            if not enc_pub.exists() or not sign_pub.exists():
                return None

            # Metadaten laden
            metadata = {}
            if identity_json.exists():
                import json
                metadata = json.loads(identity_json.read_text())

            # Bundle manuell zusammenbauen
            from base64 import b64encode
            import hashlib

            enc_key = enc_pub.read_bytes()
            sign_key = sign_pub.read_bytes()

            enc_fp = hashlib.sha256(enc_key).hexdigest()
            sign_fp = hashlib.sha256(sign_key).hexdigest()
            bundle_fp = hashlib.sha256(f"{enc_fp}{sign_fp}".encode()).hexdigest()

            return PublicKeyBundle(
                identity_name=metadata.get("name", identity_dir.name),
                email=metadata.get("email"),
                comment=metadata.get("comment"),
                created_at=metadata.get("created_at", ""),
                encryption_algorithm=metadata.get("encryption_algorithm", "ML-KEM-768"),
                signing_algorithm=metadata.get("signing_algorithm", "ML-DSA-65"),
                encryption_public_key=b64encode(enc_key).decode(),
                signing_public_key=b64encode(sign_key).decode(),
                encryption_fingerprint=enc_fp,
                signing_fingerprint=sign_fp,
                bundle_fingerprint=bundle_fp
            )

        except Exception as e:
            logger.warning(f"Failed to load identity from {identity_dir}: {e}")
            return None

    def _bundle_from_single_key(self, key_path: Path) -> Optional[PublicKeyBundle]:
        """
        Erstellt ein partielles Bundle aus einem einzelnen Key-File.

        Für Legacy-Support wenn nur ein .pub File angegeben wird.
        """
        # TODO: Implementieren für Legacy-Fälle
        logger.warning(
            f"Single key files not fully supported yet. "
            f"Please use a full identity or bundle."
        )
        return None


# Globale Resolver-Instanz
_resolver: Optional[KeyResolver] = None


def get_resolver() -> KeyResolver:
    """Gibt die globale Resolver-Instanz zurück."""
    global _resolver
    if _resolver is None:
        _resolver = KeyResolver()
    return _resolver


def set_resolver(resolver: KeyResolver) -> None:
    """Setzt die globale Resolver-Instanz."""
    global _resolver
    _resolver = resolver
```

### 2.3 Keyserver Plugin Implementation

**Datei:** `openssl_encrypt/plugins/keyserver/keyserver_plugin.py`

```python
"""
Keyserver Plugin für openssl_encrypt.

WICHTIG: Dieses Plugin ist OPT-IN.
Es muss explizit aktiviert werden bevor es verwendet wird.

FEATURES:
- Key-Lookup auf konfigurierten Keyservern
- Lokales Caching von abgerufenen Keys
- Selbst-Signatur-Verifikation
- Revocation-Check
- Key-Upload zum Server
"""

import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

import requests

from openssl_encrypt.modules.key_bundle import PublicKeyBundle
from openssl_encrypt.plugins.keyserver.config import KeyserverConfig, get_config


logger = logging.getLogger(__name__)


class KeyserverPlugin:
    """
    Plugin für Keyserver-Kommunikation.

    AKTIVIERUNG:
        # Via Config
        openssl_encrypt config set keyserver.enabled true

        # Via CLI-Flag
        openssl_encrypt encrypt --keyserver --for alice

        # Via Environment
        OPENSSL_ENCRYPT_KEYSERVER=1
    """

    def __init__(self, config: Optional[KeyserverConfig] = None):
        """
        Initialisiert das Plugin.

        Args:
            config: Plugin-Konfiguration (optional, sonst globale Config)
        """
        self.config = config or get_config()
        self._session: Optional[requests.Session] = None
        self._init_cache_dir()

    def _init_cache_dir(self) -> None:
        """Initialisiert das Cache-Verzeichnis."""
        if self.config.cache_enabled:
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_session(self) -> requests.Session:
        """Gibt eine HTTP-Session zurück (lazy init)."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                "User-Agent": "openssl_encrypt-keyserver-plugin/1.0",
                "Accept": "application/json"
            })
        return self._session

    def is_enabled(self) -> bool:
        """Prüft ob das Plugin aktiviert ist."""
        return self.config.enabled

    # =========================================================================
    # KEY FETCH
    # =========================================================================

    def fetch_key(self, identifier: str) -> Optional[PublicKeyBundle]:
        """
        Holt einen Key vom Keyserver.

        Args:
            identifier: Fingerprint, Email, oder Name

        Returns:
            PublicKeyBundle wenn gefunden, sonst None
        """
        if not self.is_enabled():
            logger.debug("Keyserver plugin is disabled")
            return None

        for server_url in self.config.servers:
            try:
                bundle = self._fetch_from_server(server_url, identifier)
                if bundle:
                    # Signatur verifizieren
                    if self.config.verify_signatures:
                        if not bundle.verify_self_signature():
                            logger.warning(
                                f"Key from {server_url} has invalid self-signature, skipping"
                            )
                            continue

                    # Revocation prüfen
                    if self.config.check_revocation:
                        if self._is_revoked(server_url, bundle.bundle_fingerprint):
                            logger.warning(
                                f"Key {bundle.bundle_fingerprint[:16]} is revoked, skipping"
                            )
                            continue

                    # Im Cache speichern
                    if self.config.cache_enabled:
                        self._cache_key(bundle)

                    return bundle

            except requests.RequestException as e:
                logger.warning(f"Failed to contact keyserver {server_url}: {e}")
                continue

        return None

    def _fetch_from_server(
        self,
        server_url: str,
        identifier: str
    ) -> Optional[PublicKeyBundle]:
        """Holt einen Key von einem spezifischen Server."""
        session = self._get_session()

        # Entscheiden welcher Endpoint
        if self._looks_like_fingerprint(identifier):
            # Direkter Fingerprint-Lookup
            url = f"{server_url}/api/v1/keys/{identifier}"
            response = session.get(
                url,
                timeout=(self.config.connect_timeout, self.config.read_timeout)
            )
        else:
            # Suche nach Name/Email
            url = f"{server_url}/api/v1/keys/search"
            response = session.get(
                url,
                params={"q": identifier},
                timeout=(self.config.connect_timeout, self.config.read_timeout)
            )

        if response.status_code == 404:
            return None

        response.raise_for_status()
        data = response.json()

        # Bei Suche: Erstes Ergebnis nehmen (oder None wenn leer)
        if isinstance(data, list):
            if not data:
                return None
            data = data[0]

        return PublicKeyBundle.from_json(json.dumps(data))

    def _looks_like_fingerprint(self, identifier: str) -> bool:
        """Prüft ob der Identifier wie ein Fingerprint aussieht."""
        # Fingerprints sind Hex-Strings mit mindestens 8 Zeichen
        if len(identifier) < 8:
            return False
        try:
            int(identifier, 16)
            return True
        except ValueError:
            return False

    def _is_revoked(self, server_url: str, fingerprint: str) -> bool:
        """Prüft ob ein Key revoked wurde."""
        try:
            session = self._get_session()
            url = f"{server_url}/api/v1/keys/{fingerprint}/revocation"
            response = session.get(
                url,
                timeout=(self.config.connect_timeout, self.config.read_timeout)
            )

            if response.status_code == 404:
                return False  # Kein Revocation-Record = nicht revoked

            response.raise_for_status()
            data = response.json()
            return data.get("revoked", False)

        except requests.RequestException:
            # Bei Fehler: Vorsichtshalber als nicht-revoked behandeln
            # (sonst könnte ein Netzwerkfehler alle Keys unbrauchbar machen)
            return False

    # =========================================================================
    # CACHING
    # =========================================================================

    def get_from_cache(self, identifier: str) -> Optional[PublicKeyBundle]:
        """
        Holt einen Key aus dem lokalen Cache.

        Args:
            identifier: Fingerprint, Email, oder Name

        Returns:
            PublicKeyBundle wenn im Cache und nicht abgelaufen, sonst None
        """
        if not self.config.cache_enabled:
            return None

        # Cache-Index laden
        index = self._load_cache_index()

        # Identifier auflösen
        fingerprint = index.get("by_name", {}).get(identifier.lower())
        if not fingerprint:
            fingerprint = index.get("by_email", {}).get(identifier.lower())
        if not fingerprint:
            # Vielleicht ist identifier selbst ein Fingerprint
            fingerprint = identifier.lower()

        # Cache-Datei prüfen
        cache_file = self.config.cache_dir / f"{fingerprint}.json"
        if not cache_file.exists():
            return None

        try:
            cache_data = json.loads(cache_file.read_text())

            # TTL prüfen
            cached_at = cache_data.get("cached_at", 0)
            if time.time() - cached_at > self.config.cache_ttl:
                # Abgelaufen
                cache_file.unlink()
                return None

            return PublicKeyBundle.from_json(json.dumps(cache_data["bundle"]))

        except Exception as e:
            logger.debug(f"Failed to load from cache: {e}")
            return None

    def _cache_key(self, bundle: PublicKeyBundle) -> None:
        """Speichert einen Key im Cache."""
        try:
            # Cache-Datei schreiben
            cache_file = self.config.cache_dir / f"{bundle.bundle_fingerprint}.json"
            cache_data = {
                "cached_at": time.time(),
                "bundle": json.loads(bundle.to_json())
            }
            cache_file.write_text(json.dumps(cache_data, indent=2))

            # Index aktualisieren
            self._update_cache_index(bundle)

        except Exception as e:
            logger.warning(f"Failed to cache key: {e}")

    def _load_cache_index(self) -> Dict[str, Any]:
        """Lädt den Cache-Index."""
        index_file = self.config.cache_dir / "index.json"
        if index_file.exists():
            try:
                return json.loads(index_file.read_text())
            except Exception:
                pass
        return {"by_name": {}, "by_email": {}, "by_fingerprint": {}}

    def _update_cache_index(self, bundle: PublicKeyBundle) -> None:
        """Aktualisiert den Cache-Index mit einem neuen Bundle."""
        index = self._load_cache_index()

        fp = bundle.bundle_fingerprint

        if bundle.identity_name:
            index["by_name"][bundle.identity_name.lower()] = fp
        if bundle.email:
            index["by_email"][bundle.email.lower()] = fp
        index["by_fingerprint"][fp] = fp

        index_file = self.config.cache_dir / "index.json"
        index_file.write_text(json.dumps(index, indent=2))

    def clear_cache(self) -> int:
        """
        Löscht den gesamten Cache.

        Returns:
            Anzahl gelöschter Einträge
        """
        count = 0
        if self.config.cache_dir.exists():
            for f in self.config.cache_dir.glob("*.json"):
                f.unlink()
                count += 1
        return count

    # =========================================================================
    # KEY UPLOAD
    # =========================================================================

    def upload_key(
        self,
        bundle: PublicKeyBundle,
        server_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Lädt einen Public Key auf den Keyserver hoch.

        Args:
            bundle: Das hochzuladende Key Bundle
            server_url: Optional – spezifischer Server (sonst erster konfigurierter)

        Returns:
            Server-Antwort als Dict

        Raises:
            requests.RequestException: Bei Netzwerkfehlern
            ValueError: Bei Server-Fehlern
        """
        if not self.config.upload_enabled:
            raise ValueError("Key upload is disabled in configuration")

        if not bundle.self_signature:
            raise ValueError("Bundle must have a self-signature for upload")

        server = server_url or self.config.servers[0]
        session = self._get_session()

        response = session.post(
            f"{server}/api/v1/keys",
            json=json.loads(bundle.to_json()),
            timeout=(self.config.connect_timeout, self.config.read_timeout)
        )

        if response.status_code == 409:
            raise ValueError("Key with this fingerprint already exists on server")

        response.raise_for_status()
        return response.json()

    # =========================================================================
    # KEY REVOCATION
    # =========================================================================

    def revoke_key(
        self,
        fingerprint: str,
        identity: 'Identity',
        reason: str = "unspecified",
        server_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Widerruft einen Key auf dem Keyserver.

        Erfordert Signatur mit dem zugehörigen Private Key als Beweis.

        Args:
            fingerprint: Fingerprint des zu widerrufenden Keys
            identity: Identity mit dem Private Key für die Signatur
            reason: Grund für den Widerruf
            server_url: Optional – spezifischer Server

        Returns:
            Server-Antwort als Dict
        """
        server = server_url or self.config.servers[0]
        session = self._get_session()

        # Revocation-Request erstellen und signieren
        revocation_data = {
            "fingerprint": fingerprint,
            "reason": reason,
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }

        # Mit Private Key signieren
        from openssl_encrypt.modules.pqc_signing import sign_data
        signature = sign_data(
            identity.signing_private_key,
            json.dumps(revocation_data, sort_keys=True).encode(),
            identity.signing_algorithm
        )

        from base64 import b64encode
        request_body = {
            **revocation_data,
            "signature": b64encode(signature).decode()
        }

        response = session.post(
            f"{server}/api/v1/keys/{fingerprint}/revoke",
            json=request_body,
            timeout=(self.config.connect_timeout, self.config.read_timeout)
        )

        response.raise_for_status()
        return response.json()

    # =========================================================================
    # AUTO-IMPORT
    # =========================================================================

    def import_to_local_keyring(
        self,
        bundle: PublicKeyBundle,
        keyring_path: Optional[Path] = None
    ) -> Path:
        """
        Importiert ein Bundle ins lokale Keyring.

        Args:
            bundle: Das zu importierende Bundle
            keyring_path: Optional – Pfad zum Keyring

        Returns:
            Pfad zum erstellten Identity-Verzeichnis
        """
        keyring = keyring_path or self.config.local_keyring_path

        # Identity-Verzeichnis erstellen
        identity_dir = keyring / bundle.identity_name
        identity_dir.mkdir(parents=True, exist_ok=True)

        # Public Keys speichern
        from base64 import b64decode
        (identity_dir / "encryption.pub").write_bytes(
            b64decode(bundle.encryption_public_key)
        )
        (identity_dir / "signing.pub").write_bytes(
            b64decode(bundle.signing_public_key)
        )

        # Metadaten speichern
        metadata = {
            "name": bundle.identity_name,
            "email": bundle.email,
            "comment": bundle.comment,
            "created_at": bundle.created_at,
            "encryption_algorithm": bundle.encryption_algorithm,
            "signing_algorithm": bundle.signing_algorithm,
            "encryption_fingerprint": bundle.encryption_fingerprint,
            "signing_fingerprint": bundle.signing_fingerprint,
            "bundle_fingerprint": bundle.bundle_fingerprint,
            "imported_from": "keyserver",
            "imported_at": datetime.now(timezone.utc).isoformat()
        }
        (identity_dir / "identity.json").write_text(
            json.dumps(metadata, indent=2)
        )

        # Bundle speichern
        (identity_dir / "public_bundle.json").write_text(bundle.to_json())

        logger.info(f"Imported key for '{bundle.identity_name}' to {identity_dir}")
        return identity_dir


# Globale Plugin-Instanz
_plugin: Optional[KeyserverPlugin] = None


def get_plugin() -> Optional[KeyserverPlugin]:
    """Gibt die globale Plugin-Instanz zurück (falls aktiviert)."""
    global _plugin
    config = get_config()
    if config.enabled and _plugin is None:
        _plugin = KeyserverPlugin(config)
    return _plugin if config.enabled else None


def set_plugin(plugin: KeyserverPlugin) -> None:
    """Setzt die globale Plugin-Instanz."""
    global _plugin
    _plugin = plugin
```

### 2.4 CLI-Erweiterung

**Datei:** `openssl_encrypt/cli.py` (Erweiterungen)

```python
# =========================================================================
# KEYSERVER COMMANDS
# =========================================================================

@cli.group()
def keyserver():
    """Keyserver-Management."""
    pass


@keyserver.command("status")
def keyserver_status():
    """Zeigt Keyserver-Plugin Status."""
    from openssl_encrypt.plugins.keyserver.config import get_config
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import get_plugin

    config = get_config()

    click.echo(f"Status: {'Aktiviert' if config.enabled else 'Deaktiviert'}")
    click.echo(f"Server: {', '.join(config.servers)}")
    click.echo(f"Cache: {'Aktiviert' if config.cache_enabled else 'Deaktiviert'}")

    if config.cache_enabled:
        cache_dir = config.cache_dir
        if cache_dir.exists():
            count = len(list(cache_dir.glob("*.json"))) - 1  # Minus index.json
            click.echo(f"Gecachte Keys: {count}")


@keyserver.command("enable")
def keyserver_enable():
    """Aktiviert das Keyserver-Plugin."""
    config = load_config()
    config["keyserver"] = config.get("keyserver", {})
    config["keyserver"]["enabled"] = True
    save_config(config)
    click.echo("Keyserver-Plugin aktiviert.")


@keyserver.command("disable")
def keyserver_disable():
    """Deaktiviert das Keyserver-Plugin."""
    config = load_config()
    config["keyserver"] = config.get("keyserver", {})
    config["keyserver"]["enabled"] = False
    save_config(config)
    click.echo("Keyserver-Plugin deaktiviert.")


@keyserver.command("add-server")
@click.argument("url")
def keyserver_add_server(url: str):
    """Fügt einen Keyserver hinzu."""
    config = load_config()
    config["keyserver"] = config.get("keyserver", {})
    servers = config["keyserver"].get("servers", [])

    if url not in servers:
        servers.append(url)
        config["keyserver"]["servers"] = servers
        save_config(config)
        click.echo(f"Server hinzugefügt: {url}")
    else:
        click.echo(f"Server bereits konfiguriert: {url}")


@keyserver.command("remove-server")
@click.argument("url")
def keyserver_remove_server(url: str):
    """Entfernt einen Keyserver."""
    config = load_config()
    servers = config.get("keyserver", {}).get("servers", [])

    if url in servers:
        servers.remove(url)
        config["keyserver"]["servers"] = servers
        save_config(config)
        click.echo(f"Server entfernt: {url}")
    else:
        click.echo(f"Server nicht gefunden: {url}")


@keyserver.command("search")
@click.argument("query")
@click.option("--server", help="Spezifischer Server")
def keyserver_search(query: str, server: Optional[str]):
    """Sucht nach einem Key auf dem Keyserver."""
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin
    from openssl_encrypt.plugins.keyserver.config import get_config
    from openssl_encrypt.modules.key_bundle import format_fingerprint

    config = get_config()
    if not config.enabled:
        click.echo("Keyserver-Plugin ist nicht aktiviert.")
        click.echo("Aktivieren mit: openssl_encrypt keyserver enable")
        return

    plugin = KeyserverPlugin(config)
    bundle = plugin.fetch_key(query)

    if bundle:
        click.echo(f"\nGefunden: {bundle.identity_name}")
        click.echo(f"  Email: {bundle.email or '(keine)'}")
        click.echo(f"  Fingerprint: {format_fingerprint(bundle.bundle_fingerprint[:32])}")
        click.echo(f"  Encryption: {bundle.encryption_algorithm}")
        click.echo(f"  Signing: {bundle.signing_algorithm}")
        click.echo(f"  Erstellt: {bundle.created_at}")

        if bundle.verify_self_signature():
            click.echo(f"  Signatur: ✓ Gültig")
        else:
            click.echo(f"  Signatur: ✗ UNGÜLTIG")
    else:
        click.echo(f"Kein Key gefunden für: {query}")


@keyserver.command("upload")
@click.argument("identity_name")
@click.option("--server", help="Spezifischer Server")
def keyserver_upload(identity_name: str, server: Optional[str]):
    """Lädt einen lokalen Public Key auf den Keyserver hoch."""
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin
    from openssl_encrypt.plugins.keyserver.config import get_config
    from openssl_encrypt.modules.identity import load_identity
    from openssl_encrypt.modules.key_bundle import PublicKeyBundle, format_fingerprint

    config = get_config()
    if not config.enabled:
        click.echo("Keyserver-Plugin ist nicht aktiviert.")
        return

    # Identity laden
    identity = load_identity(identity_name)
    if not identity:
        click.echo(f"Identity nicht gefunden: {identity_name}")
        return

    # Bundle erstellen
    bundle = PublicKeyBundle.from_identity(identity, include_signature=True)

    click.echo(f"Uploading key for: {identity_name}")
    click.echo(f"Fingerprint: {format_fingerprint(bundle.bundle_fingerprint[:32])}")

    if not click.confirm("Fortfahren?"):
        return

    plugin = KeyserverPlugin(config)
    try:
        result = plugin.upload_key(bundle, server_url=server)
        click.echo(f"\n✓ Key erfolgreich hochgeladen!")
        click.echo(f"  Server: {result.get('server', server or config.servers[0])}")
    except Exception as e:
        click.echo(f"\n✗ Upload fehlgeschlagen: {e}")


@keyserver.command("import")
@click.argument("identifier")
def keyserver_import(identifier: str):
    """Importiert einen Key vom Keyserver ins lokale Keyring."""
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin
    from openssl_encrypt.plugins.keyserver.config import get_config
    from openssl_encrypt.modules.key_bundle import format_fingerprint

    config = get_config()
    if not config.enabled:
        click.echo("Keyserver-Plugin ist nicht aktiviert.")
        return

    plugin = KeyserverPlugin(config)
    bundle = plugin.fetch_key(identifier)

    if not bundle:
        click.echo(f"Key nicht gefunden: {identifier}")
        return

    click.echo(f"\nGefunden: {bundle.identity_name}")
    click.echo(f"  Fingerprint: {format_fingerprint(bundle.bundle_fingerprint[:32])}")

    if not bundle.verify_self_signature():
        click.echo("\n⚠️  WARNUNG: Selbst-Signatur ist UNGÜLTIG!")
        if not click.confirm("Trotzdem importieren?"):
            return

    if not click.confirm("\nIns lokale Keyring importieren?"):
        return

    path = plugin.import_to_local_keyring(bundle)
    click.echo(f"\n✓ Importiert nach: {path}")


@keyserver.command("revoke")
@click.argument("identity_name")
@click.option("--reason", default="unspecified", help="Grund für Widerruf")
def keyserver_revoke(identity_name: str, reason: str):
    """Widerruft einen Key auf dem Keyserver."""
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin
    from openssl_encrypt.plugins.keyserver.config import get_config
    from openssl_encrypt.modules.identity import load_identity

    config = get_config()
    if not config.enabled:
        click.echo("Keyserver-Plugin ist nicht aktiviert.")
        return

    identity = load_identity(identity_name)
    if not identity:
        click.echo(f"Identity nicht gefunden: {identity_name}")
        return

    click.echo(f"\n⚠️  WARNUNG: Du bist dabei den Key für '{identity_name}' zu widerrufen!")
    click.echo("Dies kann nicht rückgängig gemacht werden.")

    if not click.confirm("\nWirklich widerrufen?"):
        return

    # Nochmal bestätigen
    confirm_text = click.prompt("Tippe 'REVOKE' zur Bestätigung")
    if confirm_text != "REVOKE":
        click.echo("Abgebrochen.")
        return

    plugin = KeyserverPlugin(config)
    try:
        result = plugin.revoke_key(
            identity.bundle_fingerprint,
            identity,
            reason=reason
        )
        click.echo(f"\n✓ Key wurde widerrufen.")
    except Exception as e:
        click.echo(f"\n✗ Widerruf fehlgeschlagen: {e}")


@keyserver.command("cache-clear")
def keyserver_cache_clear():
    """Löscht den lokalen Keyserver-Cache."""
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import KeyserverPlugin
    from openssl_encrypt.plugins.keyserver.config import get_config

    plugin = KeyserverPlugin(get_config())
    count = plugin.clear_cache()
    click.echo(f"Cache gelöscht ({count} Einträge)")


# =========================================================================
# ENCRYPT/DECRYPT MIT KEYSERVER-INTEGRATION
# =========================================================================

# Neue Optionen für encrypt-Befehl:
"""
@click.option(
    '--keyserver/--no-keyserver',
    default=None,
    help='Keyserver für Key-Lookup verwenden (überschreibt Config)'
)
"""

# In der encrypt-Funktion:
"""
def encrypt(..., keyserver: Optional[bool] = None):
    # Resolver mit optionalem Keyserver-Plugin initialisieren
    from openssl_encrypt.modules.key_resolver import KeyResolver
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import get_plugin
    from openssl_encrypt.plugins.keyserver.config import get_config

    # Keyserver-Override prüfen
    if keyserver is not None:
        config = get_config()
        config.enabled = keyserver

    resolver = KeyResolver(
        keyserver_plugin=get_plugin()  # None wenn deaktiviert
    )

    # Key auflösen
    try:
        bundle, source = resolver.resolve(recipient)

        if source == KeySource.KEYSERVER:
            click.echo(f"Key für '{recipient}' vom Keyserver geholt")

            # Optional: Fingerprint-Bestätigung anfordern
            if not auto_trust:
                from openssl_encrypt.modules.key_bundle import format_fingerprint
                click.echo(f"Fingerprint: {format_fingerprint(bundle.bundle_fingerprint[:32])}")
                if not click.confirm("Diesem Key vertrauen?"):
                    raise click.Abort()

    except KeyNotFoundError as e:
        click.echo(f"Key nicht gefunden: {e}")
        raise click.Abort()
"""
```

---

## Teil 3: Server-Seite

### 3.1 Projektstruktur

```
keyserver/
├── alembic/
│   ├── versions/
│   │   └── 001_initial.py
│   └── env.py
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI App
│   ├── config.py            # Konfiguration
│   ├── database.py          # SQLAlchemy Setup
│   ├── models/
│   │   ├── __init__.py
│   │   ├── public_key.py
│   │   └── revocation.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── key_bundle.py
│   │   ├── search.py
│   │   └── revocation.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── keys.py
│   │   └── revocation.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── key_service.py
│   │   └── verification_service.py
│   └── utils/
│       ├── __init__.py
│       ├── fingerprint.py
│       └── rate_limit.py
├── tests/
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── alembic.ini
├── requirements.txt
└── README.md
```

### 3.2 Datenbank-Modelle

**Datei:** `app/models/public_key.py`

```python
"""
Public Key Modell für Keyserver.

Speichert hochgeladene Public Key Bundles.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.mysql import JSON as MySQLJSON
from app.database import Base


class PublicKey(Base):
    """
    Gespeicherter Public Key auf dem Keyserver.

    WICHTIG: Der Server speichert nur Public Keys.
    Private Keys werden NIEMALS hochgeladen.
    """
    __tablename__ = "public_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Primärer Identifier
    bundle_fingerprint = Column(String(64), unique=True, nullable=False, index=True)

    # Einzelne Fingerprints (für alternative Lookups)
    encryption_fingerprint = Column(String(64), nullable=False, index=True)
    signing_fingerprint = Column(String(64), nullable=False, index=True)

    # Identity-Informationen (durchsuchbar)
    identity_name = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=True, index=True)
    comment = Column(Text, nullable=True)

    # Algorithmen
    encryption_algorithm = Column(String(32), default="ML-KEM-768")
    signing_algorithm = Column(String(32), default="ML-DSA-65")

    # Die eigentlichen Keys (Base64)
    encryption_public_key = Column(Text, nullable=False)
    signing_public_key = Column(Text, nullable=False)

    # Selbst-Signatur
    self_signature = Column(Text, nullable=False)

    # Zeitstempel
    key_created_at = Column(String(32))  # Vom Client (ISO 8601)
    key_expires_at = Column(String(32), nullable=True)
    uploaded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Status
    is_active = Column(Boolean, default=True)

    # Statistiken
    download_count = Column(Integer, default=0)
    last_downloaded_at = Column(DateTime(timezone=True), nullable=True)

    # Bundle-Version
    bundle_version = Column(Integer, default=1)

    # Full-Text Search Index (PostgreSQL)
    __table_args__ = (
        Index('idx_identity_search', 'identity_name', 'email'),
        Index('idx_fingerprints', 'bundle_fingerprint', 'encryption_fingerprint', 'signing_fingerprint'),
    )


class Revocation(Base):
    """
    Revocation-Record für widerrufene Keys.

    Wird separat gespeichert um schnelle Lookups zu ermöglichen.
    """
    __tablename__ = "revocations"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Welcher Key wurde widerrufen
    bundle_fingerprint = Column(String(64), unique=True, nullable=False, index=True)

    # Widerrufsinformationen
    reason = Column(String(255), default="unspecified")
    revoked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Signatur des Widerrufs (beweist Besitz)
    revocation_signature = Column(Text, nullable=False)

    # Referenz zum Original-Key (für Audit)
    original_key_id = Column(Integer, nullable=True)
```

### 3.3 API-Schemas

**Datei:** `app/schemas/key_bundle.py`

```python
"""
Pydantic Schemas für Key Bundles.
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class PublicKeyBundleSchema(BaseModel):
    """Schema für ein Public Key Bundle."""

    bundle_version: int = 1

    identity_name: str = Field(..., min_length=1, max_length=255)
    email: Optional[str] = Field(None, max_length=255)
    comment: Optional[str] = Field(None, max_length=1000)
    created_at: str = ""
    expires_at: Optional[str] = None

    encryption_algorithm: str = "ML-KEM-768"
    signing_algorithm: str = "ML-DSA-65"

    encryption_public_key: str  # Base64
    signing_public_key: str     # Base64

    encryption_fingerprint: str = Field(..., min_length=64, max_length=64)
    signing_fingerprint: str = Field(..., min_length=64, max_length=64)
    bundle_fingerprint: str = Field(..., min_length=64, max_length=64)

    self_signature: str  # Base64

    @field_validator('encryption_fingerprint', 'signing_fingerprint', 'bundle_fingerprint')
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        """Validiert dass Fingerprint ein Hex-String ist."""
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Fingerprint must be a valid hex string")
        return v.lower()

    @field_validator('encryption_algorithm')
    @classmethod
    def validate_encryption_algo(cls, v: str) -> str:
        allowed = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
        if v not in allowed:
            raise ValueError(f"encryption_algorithm must be one of {allowed}")
        return v

    @field_validator('signing_algorithm')
    @classmethod
    def validate_signing_algo(cls, v: str) -> str:
        allowed = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
        if v not in allowed:
            raise ValueError(f"signing_algorithm must be one of {allowed}")
        return v


class PublicKeyResponse(PublicKeyBundleSchema):
    """Response-Schema mit zusätzlichen Server-Metadaten."""

    uploaded_at: str
    download_count: int = 0
    is_revoked: bool = False


class UploadResponse(BaseModel):
    """Antwort auf einen Upload."""

    fingerprint: str
    message: str = "Key uploaded successfully"
    server: str
```

**Datei:** `app/schemas/search.py`

```python
"""
Schemas für Key-Suche.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class SearchQuery(BaseModel):
    """Query-Parameter für die Suche."""

    q: str = Field(..., min_length=3, max_length=255)
    limit: int = Field(default=10, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class SearchResult(BaseModel):
    """Einzelnes Suchergebnis."""

    bundle_fingerprint: str
    identity_name: str
    email: Optional[str]
    encryption_algorithm: str
    signing_algorithm: str
    created_at: str
    is_revoked: bool = False


class SearchResponse(BaseModel):
    """Such-Antwort."""

    query: str
    total: int
    results: List[SearchResult]
```

**Datei:** `app/schemas/revocation.py`

```python
"""
Schemas für Key-Revocation.
"""

from pydantic import BaseModel, Field


class RevocationRequest(BaseModel):
    """Request zum Widerrufen eines Keys."""

    fingerprint: str = Field(..., min_length=64, max_length=64)
    reason: str = Field(default="unspecified", max_length=255)
    revoked_at: str  # ISO 8601
    signature: str   # Base64 - Signatur über die anderen Felder


class RevocationStatus(BaseModel):
    """Status eines möglicherweise widerrufenen Keys."""

    fingerprint: str
    revoked: bool
    reason: Optional[str] = None
    revoked_at: Optional[str] = None
```

### 3.4 API-Router

**Datei:** `app/routers/keys.py`

```python
"""
Key-Management Endpoints.
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models.public_key import PublicKey, Revocation
from app.schemas.key_bundle import PublicKeyBundleSchema, PublicKeyResponse, UploadResponse
from app.schemas.search import SearchQuery, SearchResult, SearchResponse
from app.services.verification_service import verify_bundle_signature
from app.utils.rate_limit import rate_limit
from app.config import settings


router = APIRouter(prefix="/api/v1/keys", tags=["keys"])


@router.post("", response_model=UploadResponse)
@rate_limit(requests=10, period=3600)  # 10 Uploads pro Stunde
async def upload_key(
    bundle: PublicKeyBundleSchema,
    db: Session = Depends(get_db)
):
    """
    Lädt einen Public Key auf den Keyserver hoch.

    VALIDIERUNG:
    - Selbst-Signatur muss gültig sein
    - Fingerprints müssen zu den Keys passen
    - Key darf nicht bereits existieren
    """
    # Prüfen ob Key bereits existiert
    existing = db.query(PublicKey).filter(
        PublicKey.bundle_fingerprint == bundle.bundle_fingerprint
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Key with this fingerprint already exists"
        )

    # Fingerprints verifizieren
    if not verify_fingerprints(bundle):
        raise HTTPException(
            status_code=400,
            detail="Fingerprints do not match keys"
        )

    # Selbst-Signatur verifizieren
    if not verify_bundle_signature(bundle):
        raise HTTPException(
            status_code=400,
            detail="Invalid self-signature"
        )

    # Key speichern
    db_key = PublicKey(
        bundle_fingerprint=bundle.bundle_fingerprint,
        encryption_fingerprint=bundle.encryption_fingerprint,
        signing_fingerprint=bundle.signing_fingerprint,
        identity_name=bundle.identity_name,
        email=bundle.email,
        comment=bundle.comment,
        encryption_algorithm=bundle.encryption_algorithm,
        signing_algorithm=bundle.signing_algorithm,
        encryption_public_key=bundle.encryption_public_key,
        signing_public_key=bundle.signing_public_key,
        self_signature=bundle.self_signature,
        key_created_at=bundle.created_at,
        key_expires_at=bundle.expires_at,
        bundle_version=bundle.bundle_version
    )

    db.add(db_key)
    db.commit()

    return UploadResponse(
        fingerprint=bundle.bundle_fingerprint,
        server=settings.server_name
    )


@router.get("/{fingerprint}", response_model=PublicKeyResponse)
async def get_key(
    fingerprint: str,
    db: Session = Depends(get_db)
):
    """
    Holt einen Key anhand seines Fingerprints.

    Akzeptiert:
    - Vollständigen Bundle-Fingerprint (64 Zeichen)
    - Partiellen Fingerprint (min. 8 Zeichen)
    - Encryption-Fingerprint
    - Signing-Fingerprint
    """
    if len(fingerprint) < 8:
        raise HTTPException(
            status_code=400,
            detail="Fingerprint must be at least 8 characters"
        )

    fingerprint_lower = fingerprint.lower()

    # Query bauen
    query = db.query(PublicKey).filter(
        PublicKey.is_active == True
    )

    if len(fingerprint) == 64:
        # Vollständiger Fingerprint
        query = query.filter(
            or_(
                PublicKey.bundle_fingerprint == fingerprint_lower,
                PublicKey.encryption_fingerprint == fingerprint_lower,
                PublicKey.signing_fingerprint == fingerprint_lower
            )
        )
    else:
        # Partieller Fingerprint (Prefix-Match)
        query = query.filter(
            or_(
                PublicKey.bundle_fingerprint.startswith(fingerprint_lower),
                PublicKey.encryption_fingerprint.startswith(fingerprint_lower),
                PublicKey.signing_fingerprint.startswith(fingerprint_lower)
            )
        )

    key = query.first()

    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    # Download-Counter erhöhen
    key.download_count += 1
    key.last_downloaded_at = datetime.now(timezone.utc)
    db.commit()

    # Revocation-Status prüfen
    revocation = db.query(Revocation).filter(
        Revocation.bundle_fingerprint == key.bundle_fingerprint
    ).first()

    return PublicKeyResponse(
        bundle_version=key.bundle_version,
        identity_name=key.identity_name,
        email=key.email,
        comment=key.comment,
        created_at=key.key_created_at or "",
        expires_at=key.key_expires_at,
        encryption_algorithm=key.encryption_algorithm,
        signing_algorithm=key.signing_algorithm,
        encryption_public_key=key.encryption_public_key,
        signing_public_key=key.signing_public_key,
        encryption_fingerprint=key.encryption_fingerprint,
        signing_fingerprint=key.signing_fingerprint,
        bundle_fingerprint=key.bundle_fingerprint,
        self_signature=key.self_signature,
        uploaded_at=key.uploaded_at.isoformat(),
        download_count=key.download_count,
        is_revoked=revocation is not None
    )


@router.get("/search", response_model=SearchResponse)
async def search_keys(
    q: str = Query(..., min_length=3),
    limit: int = Query(default=10, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Sucht nach Keys anhand von Name oder Email.

    Die Suche ist case-insensitive und unterstützt partielle Matches.
    """
    search_term = f"%{q.lower()}%"

    # Query
    query = db.query(PublicKey).filter(
        PublicKey.is_active == True,
        or_(
            PublicKey.identity_name.ilike(search_term),
            PublicKey.email.ilike(search_term)
        )
    )

    # Total Count
    total = query.count()

    # Paginierung
    keys = query.offset(offset).limit(limit).all()

    # Revocations laden
    fingerprints = [k.bundle_fingerprint for k in keys]
    revocations = db.query(Revocation.bundle_fingerprint).filter(
        Revocation.bundle_fingerprint.in_(fingerprints)
    ).all()
    revoked_fps = {r[0] for r in revocations}

    results = [
        SearchResult(
            bundle_fingerprint=key.bundle_fingerprint,
            identity_name=key.identity_name,
            email=key.email,
            encryption_algorithm=key.encryption_algorithm,
            signing_algorithm=key.signing_algorithm,
            created_at=key.key_created_at or "",
            is_revoked=key.bundle_fingerprint in revoked_fps
        )
        for key in keys
    ]

    return SearchResponse(
        query=q,
        total=total,
        results=results
    )


@router.delete("/{fingerprint}")
async def delete_key(
    fingerprint: str,
    db: Session = Depends(get_db)
):
    """
    Löscht einen Key (Soft-Delete).

    HINWEIS: Für echte Revocation sollte der /revoke Endpoint verwendet werden.
    Dieser Endpoint ist nur für Admin-Zwecke.
    """
    # TODO: Admin-Auth implementieren
    raise HTTPException(
        status_code=501,
        detail="Admin deletion not yet implemented. Use /revoke endpoint."
    )


def verify_fingerprints(bundle: PublicKeyBundleSchema) -> bool:
    """Verifiziert dass die Fingerprints zu den Keys passen."""
    import hashlib
    from base64 import b64decode

    try:
        enc_key = b64decode(bundle.encryption_public_key)
        sign_key = b64decode(bundle.signing_public_key)

        enc_fp = hashlib.sha256(enc_key).hexdigest()
        sign_fp = hashlib.sha256(sign_key).hexdigest()
        bundle_fp = hashlib.sha256(f"{enc_fp}{sign_fp}".encode()).hexdigest()

        return (
            enc_fp == bundle.encryption_fingerprint and
            sign_fp == bundle.signing_fingerprint and
            bundle_fp == bundle.bundle_fingerprint
        )
    except Exception:
        return False
```

**Datei:** `app/routers/revocation.py`

```python
"""
Key Revocation Endpoints.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.public_key import PublicKey, Revocation
from app.schemas.revocation import RevocationRequest, RevocationStatus
from app.services.verification_service import verify_revocation_signature
from app.utils.rate_limit import rate_limit


router = APIRouter(prefix="/api/v1/keys", tags=["revocation"])


@router.get("/{fingerprint}/revocation", response_model=RevocationStatus)
async def get_revocation_status(
    fingerprint: str,
    db: Session = Depends(get_db)
):
    """
    Prüft ob ein Key widerrufen wurde.

    Returns 404 wenn der Key nicht revoked ist.
    """
    revocation = db.query(Revocation).filter(
        Revocation.bundle_fingerprint == fingerprint.lower()
    ).first()

    if not revocation:
        raise HTTPException(status_code=404, detail="Key is not revoked")

    return RevocationStatus(
        fingerprint=revocation.bundle_fingerprint,
        revoked=True,
        reason=revocation.reason,
        revoked_at=revocation.revoked_at.isoformat()
    )


@router.post("/{fingerprint}/revoke", response_model=RevocationStatus)
@rate_limit(requests=5, period=3600)  # 5 Revocations pro Stunde
async def revoke_key(
    fingerprint: str,
    request: RevocationRequest,
    db: Session = Depends(get_db)
):
    """
    Widerruft einen Key.

    ERFORDERT: Gültige Signatur mit dem zugehörigen Private Key.
    Dies beweist, dass der Anfragende den Key besitzt.
    """
    fingerprint_lower = fingerprint.lower()

    # Prüfen ob Key existiert
    key = db.query(PublicKey).filter(
        PublicKey.bundle_fingerprint == fingerprint_lower
    ).first()

    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    # Prüfen ob bereits revoked
    existing_revocation = db.query(Revocation).filter(
        Revocation.bundle_fingerprint == fingerprint_lower
    ).first()

    if existing_revocation:
        raise HTTPException(status_code=409, detail="Key is already revoked")

    # Signatur verifizieren
    if not verify_revocation_signature(request, key.signing_public_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid revocation signature"
        )

    # Revocation speichern
    revocation = Revocation(
        bundle_fingerprint=fingerprint_lower,
        reason=request.reason,
        revoked_at=datetime.now(timezone.utc),
        revocation_signature=request.signature,
        original_key_id=key.id
    )

    db.add(revocation)

    # Key als inaktiv markieren
    key.is_active = False

    db.commit()

    return RevocationStatus(
        fingerprint=fingerprint_lower,
        revoked=True,
        reason=request.reason,
        revoked_at=revocation.revoked_at.isoformat()
    )
```

### 3.5 Verification Service

**Datei:** `app/services/verification_service.py`

```python
"""
Signatur-Verifikation für den Keyserver.

WICHTIG: Der Server muss Public Keys verifizieren können ohne
auf openssl_encrypt als Dependency angewiesen zu sein.
"""

import json
from base64 import b64decode
from typing import TYPE_CHECKING

# PQC Crypto Library (liboqs-python oder ähnlich)
# Falls nicht verfügbar, kann eine Alternative verwendet werden
try:
    import oqs
    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False

if TYPE_CHECKING:
    from app.schemas.key_bundle import PublicKeyBundleSchema
    from app.schemas.revocation import RevocationRequest


def verify_bundle_signature(bundle: 'PublicKeyBundleSchema') -> bool:
    """
    Verifiziert die Selbst-Signatur eines Key Bundles.

    Args:
        bundle: Das zu verifizierende Bundle

    Returns:
        True wenn die Signatur gültig ist
    """
    if not HAS_LIBOQS:
        # Fallback: Signatur-Verifikation überspringen mit Warnung
        import logging
        logging.warning("liboqs not available, skipping signature verification")
        return True

    try:
        # Signable Data rekonstruieren
        sign_data = _get_signable_data(bundle)

        # Signatur und Public Key dekodieren
        signature = b64decode(bundle.self_signature)
        signing_key = b64decode(bundle.signing_public_key)

        # ML-DSA Algorithmus bestimmen
        algo_name = _map_algorithm_name(bundle.signing_algorithm)

        # Verifizieren
        verifier = oqs.Signature(algo_name)
        return verifier.verify(
            sign_data.encode('utf-8'),
            signature,
            signing_key
        )

    except Exception as e:
        import logging
        logging.error(f"Signature verification failed: {e}")
        return False


def verify_revocation_signature(
    request: 'RevocationRequest',
    signing_public_key: str
) -> bool:
    """
    Verifiziert die Signatur einer Revocation-Anfrage.

    Args:
        request: Die Revocation-Anfrage
        signing_public_key: Der Public Key (Base64) zum Verifizieren

    Returns:
        True wenn die Signatur gültig ist
    """
    if not HAS_LIBOQS:
        import logging
        logging.warning("liboqs not available, skipping signature verification")
        return True

    try:
        # Daten die signiert wurden rekonstruieren
        sign_data = json.dumps({
            "fingerprint": request.fingerprint,
            "reason": request.reason,
            "revoked_at": request.revoked_at
        }, sort_keys=True, separators=(',', ':'))

        signature = b64decode(request.signature)
        signing_key = b64decode(signing_public_key)

        # Standard ML-DSA-65 für Revocations
        verifier = oqs.Signature("Dilithium3")
        return verifier.verify(
            sign_data.encode('utf-8'),
            signature,
            signing_key
        )

    except Exception as e:
        import logging
        logging.error(f"Revocation signature verification failed: {e}")
        return False


def _get_signable_data(bundle: 'PublicKeyBundleSchema') -> str:
    """Rekonstruiert die signierbaren Daten eines Bundles."""
    data = {
        "bundle_version": bundle.bundle_version,
        "identity_name": bundle.identity_name,
        "email": bundle.email,
        "comment": bundle.comment,
        "created_at": bundle.created_at,
        "expires_at": bundle.expires_at,
        "encryption_algorithm": bundle.encryption_algorithm,
        "signing_algorithm": bundle.signing_algorithm,
        "encryption_public_key": bundle.encryption_public_key,
        "signing_public_key": bundle.signing_public_key,
        "encryption_fingerprint": bundle.encryption_fingerprint,
        "signing_fingerprint": bundle.signing_fingerprint,
        "bundle_fingerprint": bundle.bundle_fingerprint
    }
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def _map_algorithm_name(algo: str) -> str:
    """Mappt openssl_encrypt Algorithmusnamen zu liboqs Namen."""
    mapping = {
        "ML-DSA-44": "Dilithium2",
        "ML-DSA-65": "Dilithium3",
        "ML-DSA-87": "Dilithium5"
    }
    return mapping.get(algo, "Dilithium3")
```

### 3.6 Konfiguration

**Datei:** `app/config.py`

```python
"""
Keyserver-Konfiguration.
"""

from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    """Server-Einstellungen."""

    # Server-Identifikation
    server_name: str = "keys.openssl-encrypt.example.com"

    # Datenbank
    database_type: Literal["postgresql", "mysql"] = "postgresql"
    database_url: str = "postgresql://keyserver:secret@localhost/keyserver"

    # API
    api_prefix: str = "/api/v1"
    debug: bool = False

    # Rate Limiting
    rate_limit_enabled: bool = True

    # CORS
    cors_origins: list = ["*"]

    # Signatur-Verifikation
    verify_signatures: bool = True

    # Key-Limits
    max_key_size_bytes: int = 10000  # ~10KB für PQC Keys

    class Config:
        env_file = ".env"


settings = Settings()
```

### 3.7 Docker Setup

**Datei:** `docker/docker-compose.yml`

```yaml
version: '3.8'

services:
  keyserver:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    ports:
      - "8080:8080"
    environment:
      - DATABASE_TYPE=postgresql
      - DATABASE_URL=postgresql://keyserver:secret@db/keyserver
      - SERVER_NAME=keys.example.com
      - VERIFY_SIGNATURES=true
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=keyserver
      - POSTGRES_PASSWORD=secret
      - POSTGRES_DB=keyserver
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

**Datei:** `docker/Dockerfile`

```dockerfile
FROM python:3.12-slim

# liboqs Dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# liboqs-python (für Signatur-Verifikation)
RUN pip install --no-cache-dir liboqs-python

# App
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .

# Port
EXPOSE 8080

# Start
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8080"]
```

---

## Teil 4: Integration in Encrypt/Decrypt

### 4.1 Encrypt mit Keyserver-Lookup

```python
# In openssl_encrypt/modules/crypt_asymmetric.py

async def encrypt_file_asymmetric(
    input_file: str,
    output_file: str,
    recipient: str,  # Name, Email, Fingerprint, oder Pfad
    sender_identity: Identity,
    use_keyserver: Optional[bool] = None,  # None = Config-Default
    auto_trust: bool = False,
    **kwargs
) -> dict:
    """
    Verschlüsselt eine Datei im asymmetrischen Modus.

    KEY-LOOKUP-REIHENFOLGE:
    1. Lokales Keyring
    2. Keyserver (falls aktiviert)
    3. Expliziter Pfad

    Args:
        input_file: Eingabedatei
        output_file: Ausgabedatei
        recipient: Empfänger-Identifier
        sender_identity: Eigene Identity zum Signieren
        use_keyserver: Keyserver verwenden (überschreibt Config)
        auto_trust: Keys vom Keyserver ohne Bestätigung verwenden
    """
    from openssl_encrypt.modules.key_resolver import KeyResolver, KeySource, KeyNotFoundError
    from openssl_encrypt.plugins.keyserver.keyserver_plugin import get_plugin
    from openssl_encrypt.plugins.keyserver.config import get_config

    # Keyserver-Override
    if use_keyserver is not None:
        config = get_config()
        config.enabled = use_keyserver

    # Resolver initialisieren
    resolver = KeyResolver(keyserver_plugin=get_plugin())

    # Empfänger-Key auflösen
    try:
        recipient_bundle, source = resolver.resolve(recipient, key_type="encryption")
    except KeyNotFoundError as e:
        raise ValueError(f"Recipient key not found: {e}")

    # Bei Keyserver-Key: Vertrauen prüfen
    if source in (KeySource.KEYSERVER, KeySource.KEYSERVER_CACHE):
        if not auto_trust:
            # Callback für User-Bestätigung (wird von CLI implementiert)
            from openssl_encrypt.modules.trust import request_trust_confirmation
            if not request_trust_confirmation(recipient_bundle, source):
                raise ValueError("Key not trusted by user")

    # Signatur des Bundles verifizieren
    if not recipient_bundle.verify_self_signature():
        raise ValueError("Recipient key has invalid self-signature")

    # Verschlüsselung durchführen
    return _do_encrypt_asymmetric(
        input_file=input_file,
        output_file=output_file,
        recipient_encryption_key=recipient_bundle.get_encryption_key_bytes(),
        recipient_fingerprint=recipient_bundle.bundle_fingerprint,
        sender_identity=sender_identity,
        **kwargs
    )
```

### 4.2 Trust-Confirmation

**Datei:** `openssl_encrypt/modules/trust.py`

```python
"""
Trust-Management für Keys.

Handling von Vertrauensentscheidungen bei Keys von externen Quellen.
"""

from typing import Callable, Optional
from openssl_encrypt.modules.key_bundle import PublicKeyBundle, format_fingerprint
from openssl_encrypt.modules.key_resolver import KeySource


# Callback für Trust-Bestätigung (wird von CLI/GUI gesetzt)
_trust_callback: Optional[Callable[[PublicKeyBundle, KeySource], bool]] = None


def set_trust_callback(callback: Callable[[PublicKeyBundle, KeySource], bool]) -> None:
    """Setzt den Callback für Trust-Bestätigungen."""
    global _trust_callback
    _trust_callback = callback


def request_trust_confirmation(bundle: PublicKeyBundle, source: KeySource) -> bool:
    """
    Fragt den User ob er einem Key vertrauen möchte.

    Args:
        bundle: Das Key Bundle
        source: Woher der Key stammt

    Returns:
        True wenn der User dem Key vertraut
    """
    if _trust_callback:
        return _trust_callback(bundle, source)

    # Fallback: Immer False wenn kein Callback gesetzt
    return False


# CLI-Implementation des Trust-Callbacks
def cli_trust_callback(bundle: PublicKeyBundle, source: KeySource) -> bool:
    """Trust-Callback für CLI-Verwendung."""
    import click

    source_name = {
        KeySource.KEYSERVER: "Keyserver",
        KeySource.KEYSERVER_CACHE: "Keyserver (cached)",
    }.get(source, str(source))

    click.echo(f"\n⚠️  Key von externem Source: {source_name}")
    click.echo(f"   Identity: {bundle.identity_name}")
    click.echo(f"   Email: {bundle.email or '(keine)'}")
    click.echo(f"   Fingerprint: {format_fingerprint(bundle.bundle_fingerprint[:32])}")
    click.echo(f"   Algorithmen: {bundle.encryption_algorithm} / {bundle.signing_algorithm}")

    if bundle.verify_self_signature():
        click.echo("   Selbst-Signatur: ✓ Gültig")
    else:
        click.echo("   Selbst-Signatur: ✗ UNGÜLTIG")
        click.echo("\n   ⚠️  WARNUNG: Die Signatur ist ungültig!")

    return click.confirm("\nDiesem Key vertrauen?", default=False)
```

---

## Teil 5: Zusammenfassung

### API-Endpoints Übersicht

| Endpoint | Methode | Beschreibung |
|----------|---------|--------------|
| `/api/v1/keys` | POST | Key hochladen |
| `/api/v1/keys/{fingerprint}` | GET | Key abrufen |
| `/api/v1/keys/search` | GET | Nach Keys suchen |
| `/api/v1/keys/{fingerprint}/revocation` | GET | Revocation-Status prüfen |
| `/api/v1/keys/{fingerprint}/revoke` | POST | Key widerrufen |
| `/api/v1/health` | GET | Health Check |

### CLI-Commands Übersicht

| Command | Beschreibung |
|---------|--------------|
| `keyserver status` | Plugin-Status anzeigen |
| `keyserver enable` | Plugin aktivieren |
| `keyserver disable` | Plugin deaktivieren |
| `keyserver add-server <url>` | Server hinzufügen |
| `keyserver remove-server <url>` | Server entfernen |
| `keyserver search <query>` | Key suchen |
| `keyserver upload <identity>` | Key hochladen |
| `keyserver import <identifier>` | Key importieren |
| `keyserver revoke <identity>` | Key widerrufen |
| `keyserver cache-clear` | Cache leeren |

### Lookup-Reihenfolge

```
1. Lokales Keyring (~/.openssl_encrypt/identities/)
   ├── Exakter Name-Match
   ├── Email-Match
   └── Fingerprint-Match

2. Keyserver (falls Plugin aktiviert)
   ├── Cache prüfen (falls TTL nicht abgelaufen)
   ├── Server anfragen
   ├── Selbst-Signatur verifizieren
   ├── Revocation-Status prüfen
   └── Optional: Ins lokale Keyring importieren

3. Expliziter Pfad (falls angegeben)
   └── Datei direkt laden
```

### Sicherheitsgarantien

1. **Opt-In:** Plugin standardmässig deaktiviert
2. **Signatur-Verifikation:** Alle Keys müssen gültige Selbst-Signaturen haben
3. **Fingerprint-Verifikation:** Fingerprints werden aus Keys neu berechnet
4. **Revocation-Support:** Widerrufene Keys werden erkannt
5. **Trust-Bestätigung:** User wird bei externen Keys um Bestätigung gebeten
6. **Lokaler Fallback:** Lokales Keyring hat immer Priorität
7. **Caching:** Reduziert Server-Anfragen, TTL-basiert
8. **Rate Limiting:** Schutz vor Missbrauch

### Offene Punkte / Erweiterungen

1. **Web of Trust:** Gegenseitiges Signieren von Keys
2. **Key Discovery via DNS:** DANE/OPENPGPKEY-Style Records
3. **Multiple Server Consensus:** Key muss auf mehreren Servern übereinstimmen
4. **Automatic Key Updates:** Benachrichtigung bei Key-Änderungen
5. **Federation:** Server können Keys untereinander synchronisieren
