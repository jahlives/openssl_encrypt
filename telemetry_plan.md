# Telemetrie Plugin - Implementierungsplan

*Für Claude Code zur Implementierung*

---

## Übersicht

Ein optionales, strikt isoliertes Telemetrie-Plugin für openssl_encrypt, das anonymisierte Nutzungsstatistiken über Algorithmen und KDF-Parameter sammelt.

### Architektur

```
┌─────────────────────────────────────────────────────────────────┐
│                     openssl_encrypt Core                        │
│                                                                 │
│  ┌─────────────┐    ┌──────────────────────────────────────┐   │
│  │ crypt_core  │───▶│ TelemetryDataFilter                  │   │
│  │             │    │ ================================      │   │
│  │ Nach jeder  │    │ ERLAUBT:                             │   │
│  │ Operation   │    │  • hash_algorithms: ["sha512",...]   │   │
│  │             │    │  • kdf_algorithms: ["argon2",...]    │   │
│  │             │    │  • kdf_parameters: {memory, time}    │   │
│  │             │    │  • encryption_algo: "aes-256-gcm"    │   │
│  │             │    │  • format_version: 6 oder 7          │   │
│  │             │    │  • mode: "symmetric"/"asymmetric"    │   │
│  │             │    │  • timestamp: ISO 8601               │   │
│  │             │    │                                      │   │
│  │             │    │ BLOCKIERT:                           │   │
│  │             │    │  ✗ Passwörter                        │   │
│  │             │    │  ✗ Keys (public/private)             │   │
│  │             │    │  ✗ Salts                             │   │
│  │             │    │  ✗ Dateinamen                        │   │
│  │             │    │  ✗ Dateigrössen                      │   │
│  │             │    │  ✗ Fingerprints/Key-IDs              │   │
│  │             │    │  ✗ Plaintext/Ciphertext              │   │
│  │             │    │  ✗ IP-Adressen                       │   │
│  └─────────────┘    └──────────────┬───────────────────────┘   │
│                                    │                            │
│                                    │ Gefilterte Daten           │
│                                    ▼                            │
│                     ┌──────────────────────────────┐            │
│                     │ Plugin Interface             │            │
│                     │ on_telemetry_event(data)     │            │
│                     └──────────────┬───────────────┘            │
└────────────────────────────────────┼────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Telemetry Plugin (Optional)                   │
│                                                                 │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │ Local Buffer    │     │ API Key Manager │                   │
│  │ (SQLite)        │     │                 │                   │
│  │                 │     │ • Registration  │                   │
│  │ • Queue events  │     │ • Validation    │                   │
│  │ • Retry failed  │     │ • Refresh       │                   │
│  └────────┬────────┘     └────────┬────────┘                   │
│           │                       │                             │
│           └───────────┬───────────┘                             │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │ HTTPS Uploader  │                                │
│              │ (Batch, Async)  │                                │
│              └────────┬────────┘                                │
└───────────────────────┼─────────────────────────────────────────┘
                        │
                        │ HTTPS (TLS 1.3)
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Telemetry Server                             │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    REST API (FastAPI)                    │   │
│  │                                                          │   │
│  │  POST /api/v1/register      → API Key erhalten           │   │
│  │  POST /api/v1/telemetry     → Daten hochladen            │   │
│  │  GET  /api/v1/stats         → Aggregierte Statistiken    │   │
│  │  POST /api/v1/key/refresh   → Key erneuern               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Database (PostgreSQL / MySQL)               │   │
│  │                                                          │   │
│  │  • api_keys        - Registrierte Clients                │   │
│  │  • telemetry_raw   - Rohdaten (anonymisiert)             │   │
│  │  • telemetry_agg   - Aggregierte Statistiken             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Teil 1: Client (Plugin)

### 1.1 Core-Änderungen: TelemetryDataFilter

**Datei:** `openssl_encrypt/modules/telemetry_filter.py`

```python
"""
Telemetry Data Filter - Strikt kontrollierter Datenzugriff für Plugins.

SICHERHEITSKRITISCH: Diese Klasse ist die EINZIGE Schnittstelle zwischen
Core und Telemetrie-Plugin. Sie definiert exakt welche Daten das Plugin
sehen darf.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import hashlib


@dataclass(frozen=True)  # Immutable!
class TelemetryEvent:
    """
    Strikt typisierte, unveränderliche Telemetrie-Daten.

    ERLAUBT (öffentlich per Kerckhoff):
    - Algorithmus-Namen und Parameter
    - Format-Version und Modus
    - Zeitstempel

    NIEMALS ENTHALTEN:
    - Passwörter, Keys, Salts
    - Dateinamen, Dateigrössen
    - Fingerprints, Key-IDs
    - IP-Adressen, User-Identifikatoren
    """

    # Zeitstempel (UTC, keine Zeitzone des Users)
    timestamp: str  # ISO 8601 format

    # Operation
    operation: str  # "encrypt" oder "decrypt"
    mode: str  # "symmetric" oder "asymmetric"
    format_version: int  # 3, 4, 5, 6, oder 7

    # Hash-Konfiguration (nur Algorithmen und Runden)
    hash_algorithms: tuple  # ("sha512", "sha3_256", "blake2b")
    hash_rounds: Dict[str, int] = field(default_factory=dict)  # {"sha512": 100000, ...}

    # KDF-Konfiguration (nur Algorithmen und Parameter)
    kdf_algorithms: tuple  # ("argon2", "balloon")
    kdf_parameters: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # Beispiel: {"argon2": {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}}

    # Verschlüsselung (nur Algorithmus)
    encryption_algorithm: str  # "aes-256-gcm"

    # PQC (nur Algorithmus-Namen, KEINE Keys)
    pqc_kem_algorithm: Optional[str] = None  # "ML-KEM-768" oder None
    pqc_signing_algorithm: Optional[str] = None  # "ML-DSA-65" oder None (nur asymmetric)

    # Erfolg/Fehler (keine Details)
    success: bool = True
    error_category: Optional[str] = None  # "invalid_password", "corrupted_data", etc.


class TelemetryDataFilter:
    """
    Filter, der Metadaten in sichere TelemetryEvents umwandelt.

    SICHERHEITSGARANTIE:
    - Input: Vollständige Metadaten (inkl. sensitiver Daten)
    - Output: Nur erlaubte, anonymisierte Felder

    Diese Klasse ist der EINZIGE Weg für Plugins, Daten zu erhalten.
    """

    # Whitelist der erlaubten Hash-Algorithmen (zur Validierung)
    ALLOWED_HASH_ALGOS = frozenset([
        "sha256", "sha384", "sha512",
        "sha3_256", "sha3_384", "sha3_512",
        "blake2b", "blake2s"
    ])

    # Whitelist der erlaubten KDF-Algorithmen
    ALLOWED_KDF_ALGOS = frozenset([
        "argon2", "argon2id", "argon2i", "argon2d",
        "balloon", "scrypt", "pbkdf2"
    ])

    # Whitelist der erlaubten Verschlüsselungs-Algorithmen
    ALLOWED_ENC_ALGOS = frozenset([
        "aes-128-gcm", "aes-256-gcm",
        "chacha20-poly1305"
    ])

    # Whitelist der erlaubten PQC-Algorithmen
    ALLOWED_PQC_KEM = frozenset([
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "Kyber512", "Kyber768", "Kyber1024"
    ])

    ALLOWED_PQC_SIGN = frozenset([
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    ])

    # Erlaubte Error-Kategorien (keine sensitiven Details)
    ALLOWED_ERROR_CATEGORIES = frozenset([
        "invalid_password",
        "corrupted_data",
        "unsupported_format",
        "kdf_error",
        "encryption_error",
        "signature_invalid",
        "key_error",
        "unknown"
    ])

    @classmethod
    def filter_metadata(
        cls,
        metadata: Dict[str, Any],
        operation: str,
        success: bool = True,
        error_category: Optional[str] = None
    ) -> TelemetryEvent:
        """
        Filtert Metadaten und erstellt ein sicheres TelemetryEvent.

        Args:
            metadata: Vollständige Metadaten aus der Datei
            operation: "encrypt" oder "decrypt"
            success: Ob die Operation erfolgreich war
            error_category: Fehler-Kategorie (falls nicht erfolgreich)

        Returns:
            TelemetryEvent mit nur erlaubten Daten
        """

        # Timestamp in UTC (keine lokale Zeit!)
        timestamp = datetime.now(timezone.utc).isoformat()

        # Format und Modus extrahieren
        format_version = metadata.get("format_version", 0)
        mode = metadata.get("mode", "symmetric")

        # Hash-Konfiguration extrahieren
        hash_algos = []
        hash_rounds = {}
        hash_config = metadata.get("derivation_config", {}).get("hash_config", {})
        for algo, config in hash_config.items():
            if algo in cls.ALLOWED_HASH_ALGOS:
                hash_algos.append(algo)
                if isinstance(config, dict) and "rounds" in config:
                    hash_rounds[algo] = config["rounds"]

        # KDF-Konfiguration extrahieren
        kdf_algos = []
        kdf_params = {}
        kdf_config = metadata.get("derivation_config", {}).get("kdf_config", {})
        for algo, config in kdf_config.items():
            algo_normalized = algo.lower()
            if algo_normalized in cls.ALLOWED_KDF_ALGOS or algo_normalized.startswith("argon2"):
                kdf_algos.append(algo_normalized)
                # Nur erlaubte Parameter extrahieren
                if isinstance(config, dict):
                    kdf_params[algo_normalized] = {
                        k: v for k, v in config.items()
                        if k in ("time_cost", "memory_cost", "parallelism",
                                "space_cost", "time_cost", "delta",
                                "n", "r", "p",  # scrypt
                                "iterations")  # pbkdf2
                        and isinstance(v, (int, float))
                    }

        # Verschlüsselungs-Algorithmus
        enc_config = metadata.get("encryption", {})
        enc_algo = enc_config.get("algorithm", "unknown")
        if enc_algo not in cls.ALLOWED_ENC_ALGOS:
            enc_algo = "unknown"

        # PQC-Algorithmen (nur Namen, keine Keys!)
        pqc_kem = None
        pqc_sign = None

        if mode == "asymmetric":
            asym_config = metadata.get("asymmetric", {})

            # KEM-Algorithmus
            recipient = asym_config.get("recipient", {})
            kem_algo = recipient.get("algorithm")
            if kem_algo in cls.ALLOWED_PQC_KEM:
                pqc_kem = kem_algo

            # Signing-Algorithmus
            sender = asym_config.get("sender", {})
            sign_algo = sender.get("signing_algorithm")
            if sign_algo in cls.ALLOWED_PQC_SIGN:
                pqc_sign = sign_algo
        else:
            # Symmetric mode - check if PQC keypair is used
            pqc_config = metadata.get("pqc", {})
            kem_algo = pqc_config.get("algorithm")
            if kem_algo in cls.ALLOWED_PQC_KEM:
                pqc_kem = kem_algo

        # Error-Kategorie validieren
        if error_category and error_category not in cls.ALLOWED_ERROR_CATEGORIES:
            error_category = "unknown"

        return TelemetryEvent(
            timestamp=timestamp,
            operation=operation,
            mode=mode,
            format_version=format_version,
            hash_algorithms=tuple(sorted(hash_algos)),
            hash_rounds=hash_rounds,
            kdf_algorithms=tuple(sorted(kdf_algos)),
            kdf_parameters=kdf_params,
            encryption_algorithm=enc_algo,
            pqc_kem_algorithm=pqc_kem,
            pqc_signing_algorithm=pqc_sign,
            success=success,
            error_category=error_category
        )

    @classmethod
    def to_dict(cls, event: TelemetryEvent) -> Dict[str, Any]:
        """Konvertiert TelemetryEvent zu Dictionary für JSON-Serialisierung."""
        return {
            "timestamp": event.timestamp,
            "operation": event.operation,
            "mode": event.mode,
            "format_version": event.format_version,
            "hash_algorithms": list(event.hash_algorithms),
            "hash_rounds": event.hash_rounds,
            "kdf_algorithms": list(event.kdf_algorithms),
            "kdf_parameters": event.kdf_parameters,
            "encryption_algorithm": event.encryption_algorithm,
            "pqc_kem_algorithm": event.pqc_kem_algorithm,
            "pqc_signing_algorithm": event.pqc_signing_algorithm,
            "success": event.success,
            "error_category": event.error_category
        }
```

### 1.2 Plugin Interface Erweiterung

**Datei:** `openssl_encrypt/modules/plugin_system/plugin_base.py` (Erweiterung)

```python
# Neue Capability hinzufügen
class PluginCapability(Enum):
    # ... bestehende ...
    TELEMETRY = "telemetry"  # Darf Telemetrie-Events empfangen


class TelemetryPlugin(PluginBase):
    """
    Basis-Klasse für Telemetrie-Plugins.

    SICHERHEIT:
    - Erhält NUR TelemetryEvent-Objekte (bereits gefiltert)
    - Hat KEINEN Zugriff auf:
      - Passwörter
      - Keys (public/private)
      - Salts
      - Dateinamen/-grössen
      - Fingerprints
    """

    plugin_type = PluginType.TELEMETRY
    required_capabilities = {PluginCapability.TELEMETRY, PluginCapability.NETWORK_ACCESS}

    @abstractmethod
    def on_telemetry_event(self, event: TelemetryEvent) -> None:
        """
        Wird nach jeder Encrypt/Decrypt-Operation aufgerufen.

        Args:
            event: Gefiltertes TelemetryEvent (nur erlaubte Daten)
        """
        pass

    @abstractmethod
    def flush(self) -> None:
        """Sendet gepufferte Events zum Server."""
        pass
```

### 1.3 Telemetrie Plugin Implementation

**Datei:** `openssl_encrypt/plugins/telemetry/telemetry_plugin.py`

```python
"""
Telemetrie Plugin für openssl_encrypt.

DATENSCHUTZ:
- Sammelt nur anonymisierte Algorithmus-Statistiken
- Keine persönlichen Daten, keine Dateinamen, keine Keys
- Opt-in: Muss explizit aktiviert werden
- Alle Daten können vor dem Upload eingesehen werden
"""

import json
import sqlite3
import threading
import time
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import secrets

import requests  # Einzige Netzwerk-Abhängigkeit

from openssl_encrypt.modules.plugin_system.plugin_base import TelemetryPlugin
from openssl_encrypt.modules.telemetry_filter import TelemetryEvent, TelemetryDataFilter


logger = logging.getLogger(__name__)


@dataclass
class PluginConfig:
    """Plugin-Konfiguration."""
    server_url: str = "https://telemetry.openssl-encrypt.example.com"
    api_version: str = "v1"

    # Lokaler Buffer
    buffer_path: Path = Path("~/.openssl_encrypt/telemetry/buffer.db").expanduser()
    max_buffer_size: int = 10000  # Max Events im Buffer

    # Upload-Einstellungen
    batch_size: int = 100  # Events pro Upload
    upload_interval: int = 3600  # Sekunden (1 Stunde)
    retry_interval: int = 300  # Sekunden bei Fehler
    max_retries: int = 5

    # Timeouts
    connect_timeout: int = 10
    read_timeout: int = 30


class APIKeyManager:
    """
    Verwaltet den API-Key für die Telemetrie-Kommunikation.

    FLOW:
    1. Erster Start: Registrierung beim Server, erhält API-Key
    2. Danach: Key wird lokal gespeichert und bei Uploads verwendet
    3. Key-Rotation: Server kann neuen Key bei Refresh ausgeben
    """

    def __init__(self, config: PluginConfig):
        self.config = config
        self.key_file = config.buffer_path.parent / "api_key.json"
        self._api_key: Optional[str] = None
        self._client_id: Optional[str] = None
        self._key_expires: Optional[datetime] = None
        self._lock = threading.Lock()

        self._load_key()

    def _load_key(self) -> None:
        """Lädt gespeicherten API-Key."""
        if self.key_file.exists():
            try:
                with open(self.key_file, "r") as f:
                    data = json.load(f)
                    self._api_key = data.get("api_key")
                    self._client_id = data.get("client_id")
                    expires = data.get("expires")
                    if expires:
                        self._key_expires = datetime.fromisoformat(expires)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load API key: {e}")

    def _save_key(self) -> None:
        """Speichert API-Key lokal."""
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.key_file, "w") as f:
            json.dump({
                "api_key": self._api_key,
                "client_id": self._client_id,
                "expires": self._key_expires.isoformat() if self._key_expires else None
            }, f)
        # Nur für User lesbar
        self.key_file.chmod(0o600)

    def _generate_client_id(self) -> str:
        """
        Generiert eine anonyme Client-ID.

        WICHTIG: Keine Hardware-IDs, keine User-IDs, keine IP-Hashes!
        Nur ein zufälliger Identifier für Rate-Limiting.
        """
        return secrets.token_hex(16)

    def register(self) -> bool:
        """
        Registriert beim Server und erhält API-Key.

        Returns:
            True wenn erfolgreich, False sonst
        """
        with self._lock:
            if self._api_key and self._is_key_valid():
                return True

            try:
                self._client_id = self._generate_client_id()

                response = requests.post(
                    f"{self.config.server_url}/api/{self.config.api_version}/register",
                    json={
                        "client_id": self._client_id,
                        "client_version": "1.4.0",  # TODO: Dynamisch
                        "platform": self._get_platform_info()
                    },
                    timeout=(self.config.connect_timeout, self.config.read_timeout)
                )

                if response.status_code == 201:
                    data = response.json()
                    self._api_key = data["api_key"]
                    self._key_expires = datetime.fromisoformat(data["expires"])
                    self._save_key()
                    logger.info("Successfully registered with telemetry server")
                    return True
                else:
                    logger.error(f"Registration failed: {response.status_code}")
                    return False

            except requests.RequestException as e:
                logger.error(f"Registration request failed: {e}")
                return False

    def _get_platform_info(self) -> str:
        """
        Gibt generische Platform-Info zurück.

        WICHTIG: Nur OS-Familie, keine genauen Versionen!
        """
        import platform
        system = platform.system().lower()
        if system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        elif system == "windows":
            return "windows"
        else:
            return "other"

    def _is_key_valid(self) -> bool:
        """Prüft ob der Key noch gültig ist."""
        if not self._api_key:
            return False
        if not self._key_expires:
            return True  # Kein Ablaufdatum = unbegrenzt
        return datetime.now(timezone.utc) < self._key_expires

    def get_api_key(self) -> Optional[str]:
        """Gibt den API-Key zurück, registriert falls nötig."""
        if not self._is_key_valid():
            if not self.register():
                return None
        return self._api_key

    def refresh_key(self) -> bool:
        """Erneuert den API-Key beim Server."""
        with self._lock:
            if not self._api_key:
                return self.register()

            try:
                response = requests.post(
                    f"{self.config.server_url}/api/{self.config.api_version}/key/refresh",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={"client_id": self._client_id},
                    timeout=(self.config.connect_timeout, self.config.read_timeout)
                )

                if response.status_code == 200:
                    data = response.json()
                    self._api_key = data["api_key"]
                    self._key_expires = datetime.fromisoformat(data["expires"])
                    self._save_key()
                    return True
                elif response.status_code == 401:
                    # Key ungültig, neu registrieren
                    self._api_key = None
                    return self.register()
                else:
                    return False

            except requests.RequestException as e:
                logger.error(f"Key refresh failed: {e}")
                return False


class LocalBuffer:
    """
    SQLite-basierter lokaler Buffer für Telemetrie-Events.

    FEATURES:
    - Persistenter Storage bei Netzwerk-Ausfällen
    - FIFO-Queue mit Retry-Support
    - Automatische Bereinigung alter Events
    """

    def __init__(self, db_path: Path, max_size: int = 10000):
        self.db_path = db_path
        self.max_size = max_size
        self._lock = threading.Lock()

        self._init_db()

    def _init_db(self) -> None:
        """Initialisiert die SQLite-Datenbank."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    last_retry TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON events(created_at)
            """)
            conn.commit()

    def add(self, event: TelemetryEvent) -> None:
        """Fügt ein Event zum Buffer hinzu."""
        event_dict = TelemetryDataFilter.to_dict(event)
        event_json = json.dumps(event_dict)

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                # Alte Events löschen wenn Buffer voll
                count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if count >= self.max_size:
                    # Älteste 10% löschen
                    delete_count = self.max_size // 10
                    conn.execute(f"""
                        DELETE FROM events WHERE id IN (
                            SELECT id FROM events ORDER BY created_at ASC LIMIT {delete_count}
                        )
                    """)

                conn.execute(
                    "INSERT INTO events (event_json, created_at) VALUES (?, ?)",
                    (event_json, datetime.now(timezone.utc).isoformat())
                )
                conn.commit()

    def get_batch(self, batch_size: int = 100) -> List[tuple]:
        """
        Holt eine Batch von Events zum Upload.

        Returns:
            Liste von (id, event_dict) Tupeln
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT id, event_json FROM events
                    WHERE retry_count < 5
                    ORDER BY created_at ASC
                    LIMIT ?
                    """,
                    (batch_size,)
                ).fetchall()

                return [(row[0], json.loads(row[1])) for row in rows]

    def mark_uploaded(self, event_ids: List[int]) -> None:
        """Markiert Events als erfolgreich hochgeladen (löscht sie)."""
        if not event_ids:
            return

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                placeholders = ",".join("?" * len(event_ids))
                conn.execute(f"DELETE FROM events WHERE id IN ({placeholders})", event_ids)
                conn.commit()

    def mark_retry(self, event_ids: List[int]) -> None:
        """Erhöht Retry-Counter für fehlgeschlagene Uploads."""
        if not event_ids:
            return

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                placeholders = ",".join("?" * len(event_ids))
                conn.execute(
                    f"""
                    UPDATE events
                    SET retry_count = retry_count + 1,
                        last_retry = ?
                    WHERE id IN ({placeholders})
                    """,
                    [datetime.now(timezone.utc).isoformat()] + event_ids
                )
                conn.commit()

    def get_pending_count(self) -> int:
        """Gibt Anzahl der wartenden Events zurück."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def export_pending(self) -> List[Dict[str, Any]]:
        """
        Exportiert alle wartenden Events (für User-Inspektion).

        Erlaubt dem User zu sehen, welche Daten gesendet werden würden.
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT event_json FROM events ORDER BY created_at").fetchall()
            return [json.loads(row[0]) for row in rows]


class TelemetryUploader:
    """
    Sendet gepufferte Events zum Server.

    FEATURES:
    - Batch-Upload
    - Retry mit Exponential Backoff
    - Kompression für grosse Batches
    """

    def __init__(self, config: PluginConfig, key_manager: APIKeyManager):
        self.config = config
        self.key_manager = key_manager

    def upload_batch(self, events: List[Dict[str, Any]]) -> bool:
        """
        Lädt eine Batch von Events hoch.

        Args:
            events: Liste von Event-Dictionaries

        Returns:
            True wenn erfolgreich, False sonst
        """
        api_key = self.key_manager.get_api_key()
        if not api_key:
            logger.error("No valid API key available")
            return False

        try:
            response = requests.post(
                f"{self.config.server_url}/api/{self.config.api_version}/telemetry",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={"events": events},
                timeout=(self.config.connect_timeout, self.config.read_timeout)
            )

            if response.status_code == 200:
                logger.debug(f"Successfully uploaded {len(events)} events")
                return True
            elif response.status_code == 401:
                # Key ungültig, erneuern
                if self.key_manager.refresh_key():
                    # Retry mit neuem Key
                    return self.upload_batch(events)
                return False
            elif response.status_code == 429:
                # Rate Limited
                logger.warning("Rate limited by server, will retry later")
                return False
            else:
                logger.error(f"Upload failed: {response.status_code} - {response.text}")
                return False

        except requests.RequestException as e:
            logger.error(f"Upload request failed: {e}")
            return False


class OpenSSLEncryptTelemetryPlugin(TelemetryPlugin):
    """
    Haupt-Plugin-Klasse für Telemetrie.

    AKTIVIERUNG:
    - CLI: --telemetry
    - Config: telemetry.enabled = true
    - Env: OPENSSL_ENCRYPT_TELEMETRY=1

    DATENSCHUTZ:
    - Sammelt NUR: Algorithmen, KDF-Parameter, Format-Versionen
    - Sammelt NICHT: Passwörter, Keys, Dateinamen, IP-Adressen
    - User kann alle gepufferten Daten vor dem Upload einsehen
    """

    name = "openssl_encrypt_telemetry"
    version = "1.0.0"
    description = "Anonymous telemetry for algorithm usage statistics"
    author = "OpenSSL Encrypt Team"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

        self.plugin_config = PluginConfig()
        if config:
            # Config-Werte überschreiben
            for key, value in config.items():
                if hasattr(self.plugin_config, key):
                    setattr(self.plugin_config, key, value)

        self.key_manager = APIKeyManager(self.plugin_config)
        self.buffer = LocalBuffer(
            self.plugin_config.buffer_path,
            self.plugin_config.max_buffer_size
        )
        self.uploader = TelemetryUploader(self.plugin_config, self.key_manager)

        # Background-Upload-Thread
        self._upload_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._start_background_upload()

    def _start_background_upload(self) -> None:
        """Startet den Background-Upload-Thread."""
        self._upload_thread = threading.Thread(
            target=self._background_upload_loop,
            daemon=True
        )
        self._upload_thread.start()

    def _background_upload_loop(self) -> None:
        """Background-Loop für periodische Uploads."""
        while not self._stop_event.is_set():
            try:
                self._do_upload()
            except Exception as e:
                logger.error(f"Background upload error: {e}")

            # Warte bis zum nächsten Upload oder Stop
            self._stop_event.wait(self.plugin_config.upload_interval)

    def _do_upload(self) -> None:
        """Führt einen Upload-Zyklus durch."""
        while True:
            batch = self.buffer.get_batch(self.plugin_config.batch_size)
            if not batch:
                break

            event_ids = [item[0] for item in batch]
            events = [item[1] for item in batch]

            if self.uploader.upload_batch(events):
                self.buffer.mark_uploaded(event_ids)
            else:
                self.buffer.mark_retry(event_ids)
                break  # Bei Fehler abbrechen, später retry

    def on_telemetry_event(self, event: TelemetryEvent) -> None:
        """
        Empfängt ein gefiltertes Telemetrie-Event vom Core.

        SICHERHEIT: Das Event wurde bereits durch TelemetryDataFilter
        gefiltert und enthält nur erlaubte Daten.
        """
        self.buffer.add(event)

    def flush(self) -> None:
        """Sendet alle gepufferten Events sofort."""
        self._do_upload()

    def get_pending_events(self) -> List[Dict[str, Any]]:
        """
        Gibt alle wartenden Events zurück (für User-Inspektion).

        CLI: openssl_encrypt telemetry show-pending
        """
        return self.buffer.export_pending()

    def get_status(self) -> Dict[str, Any]:
        """Gibt Plugin-Status zurück."""
        return {
            "enabled": True,
            "pending_events": self.buffer.get_pending_count(),
            "server_url": self.plugin_config.server_url,
            "has_api_key": self.key_manager.get_api_key() is not None,
            "upload_interval": self.plugin_config.upload_interval
        }

    def shutdown(self) -> None:
        """Beendet das Plugin sauber."""
        self._stop_event.set()
        if self._upload_thread:
            self._upload_thread.join(timeout=5)

        # Letzte Events noch hochladen
        try:
            self.flush()
        except Exception as e:
            logger.error(f"Final flush failed: {e}")
```

### 1.4 Core-Integration

**Datei:** `openssl_encrypt/modules/crypt_core.py` (Erweiterung)

```python
# In encrypt_file() und decrypt_file() am Ende hinzufügen:

def _emit_telemetry_event(
    self,
    metadata: Dict[str, Any],
    operation: str,
    success: bool = True,
    error_category: Optional[str] = None
) -> None:
    """
    Emittiert ein Telemetrie-Event (falls Plugin aktiviert).

    SICHERHEIT: Verwendet TelemetryDataFilter für striktes Whitelisting.
    """
    if not self.telemetry_enabled:
        return

    try:
        # KRITISCH: Filter erstellt sicheres Event
        event = TelemetryDataFilter.filter_metadata(
            metadata=metadata,
            operation=operation,
            success=success,
            error_category=error_category
        )

        # An alle registrierten Telemetrie-Plugins senden
        for plugin in self.plugin_manager.get_plugins(PluginType.TELEMETRY):
            try:
                plugin.on_telemetry_event(event)
            except Exception as e:
                logger.warning(f"Telemetry plugin error: {e}")

    except Exception as e:
        # Telemetrie-Fehler dürfen nie die Hauptoperation stören
        logger.debug(f"Telemetry emission failed: {e}")
```

### 1.5 CLI-Erweiterung

**Datei:** `openssl_encrypt/cli.py` (Erweiterung)

```python
# Neue Telemetrie-Commands

@cli.group()
def telemetry():
    """Telemetrie-Management."""
    pass


@telemetry.command("status")
def telemetry_status():
    """Zeigt Telemetrie-Status."""
    plugin = get_telemetry_plugin()
    if not plugin:
        click.echo("Telemetrie ist nicht aktiviert.")
        click.echo("Aktivieren mit: --telemetry oder config: telemetry.enabled = true")
        return

    status = plugin.get_status()
    click.echo(f"Status: {'Aktiv' if status['enabled'] else 'Inaktiv'}")
    click.echo(f"Wartende Events: {status['pending_events']}")
    click.echo(f"Server: {status['server_url']}")
    click.echo(f"API-Key: {'Vorhanden' if status['has_api_key'] else 'Nicht registriert'}")
    click.echo(f"Upload-Intervall: {status['upload_interval']}s")


@telemetry.command("show-pending")
@click.option("--json", "as_json", is_flag=True, help="JSON-Ausgabe")
def telemetry_show_pending(as_json: bool):
    """
    Zeigt alle wartenden Events an.

    Erlaubt dem User zu sehen, welche Daten gesendet werden würden.
    """
    plugin = get_telemetry_plugin()
    if not plugin:
        click.echo("Telemetrie ist nicht aktiviert.")
        return

    events = plugin.get_pending_events()

    if not events:
        click.echo("Keine wartenden Events.")
        return

    if as_json:
        click.echo(json.dumps(events, indent=2))
    else:
        click.echo(f"Wartende Events: {len(events)}\n")
        for i, event in enumerate(events[:10], 1):  # Erste 10 zeigen
            click.echo(f"--- Event {i} ---")
            click.echo(f"  Operation: {event['operation']}")
            click.echo(f"  Mode: {event['mode']}")
            click.echo(f"  Format: v{event['format_version']}")
            click.echo(f"  Encryption: {event['encryption_algorithm']}")
            click.echo(f"  Hash: {', '.join(event['hash_algorithms'])}")
            click.echo(f"  KDF: {', '.join(event['kdf_algorithms'])}")
            if event.get('pqc_kem_algorithm'):
                click.echo(f"  PQC-KEM: {event['pqc_kem_algorithm']}")

        if len(events) > 10:
            click.echo(f"\n... und {len(events) - 10} weitere Events")


@telemetry.command("flush")
def telemetry_flush():
    """Sendet alle wartenden Events sofort."""
    plugin = get_telemetry_plugin()
    if not plugin:
        click.echo("Telemetrie ist nicht aktiviert.")
        return

    pending_before = plugin.buffer.get_pending_count()
    plugin.flush()
    pending_after = plugin.buffer.get_pending_count()

    sent = pending_before - pending_after
    click.echo(f"Gesendet: {sent} Events")
    if pending_after > 0:
        click.echo(f"Fehlgeschlagen: {pending_after} Events (werden später erneut versucht)")


@telemetry.command("clear")
@click.confirmation_option(prompt="Alle wartenden Events löschen?")
def telemetry_clear():
    """Löscht alle wartenden Events ohne sie zu senden."""
    plugin = get_telemetry_plugin()
    if not plugin:
        click.echo("Telemetrie ist nicht aktiviert.")
        return

    # SQLite direkt leeren
    import sqlite3
    with sqlite3.connect(plugin.buffer.db_path) as conn:
        conn.execute("DELETE FROM events")
        conn.commit()

    click.echo("Alle wartenden Events gelöscht.")


@telemetry.command("opt-out")
def telemetry_opt_out():
    """Deaktiviert Telemetrie und löscht alle Daten."""
    config_path = Path("~/.openssl_encrypt/config.toml").expanduser()

    # Config updaten
    click.echo("Telemetrie wird deaktiviert...")

    # Pending Events löschen
    plugin = get_telemetry_plugin()
    if plugin:
        import shutil
        telemetry_dir = plugin.plugin_config.buffer_path.parent
        if telemetry_dir.exists():
            shutil.rmtree(telemetry_dir)
            click.echo("Lokale Telemetrie-Daten gelöscht.")

    click.echo("Telemetrie deaktiviert.")
    click.echo("Um wieder zu aktivieren: --telemetry oder config: telemetry.enabled = true")
```

---

## Teil 2: Server

### 2.1 Projektstruktur

```
telemetry-server/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI App
│   ├── config.py            # Server-Konfiguration
│   ├── models/
│   │   ├── __init__.py
│   │   ├── database.py      # SQLAlchemy Models
│   │   └── schemas.py       # Pydantic Schemas
│   ├── api/
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── router.py    # API Router
│   │   │   ├── register.py  # Registration Endpoint
│   │   │   ├── telemetry.py # Telemetry Upload
│   │   │   ├── stats.py     # Statistics Endpoint
│   │   │   └── key.py       # Key Management
│   │   └── deps.py          # Dependencies
│   ├── services/
│   │   ├── __init__.py
│   │   ├── key_service.py   # API Key Logic
│   │   ├── telemetry_service.py
│   │   └── aggregation_service.py
│   └── utils/
│       ├── __init__.py
│       └── security.py
├── migrations/              # Alembic Migrations
├── tests/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

### 2.2 Datenbank-Schema

**Datei:** `app/models/database.py`

```python
"""
Datenbank-Models für Telemetrie-Server.

Unterstützt PostgreSQL und MySQL.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text, JSON,
    BigInteger, Index, ForeignKey, Enum as SQLEnum
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects import postgresql, mysql
import enum

Base = declarative_base()


class APIKeyStatus(enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class APIKey(Base):
    """
    API Keys für Client-Authentifizierung.

    DATENSCHUTZ:
    - client_id ist ein zufälliger Identifier, KEINE Hardware-ID
    - Keine IP-Adressen gespeichert
    - Keine User-bezogenen Daten
    """
    __tablename__ = "api_keys"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    # Zufällige Client-ID (vom Client generiert)
    client_id = Column(String(64), unique=True, nullable=False, index=True)

    # API Key (vom Server generiert)
    api_key_hash = Column(String(128), nullable=False, index=True)  # SHA-256 Hash

    # Metadata
    client_version = Column(String(32))  # z.B. "1.4.0"
    platform = Column(String(32))  # "linux", "macos", "windows", "other"

    # Status
    status = Column(SQLEnum(APIKeyStatus), default=APIKeyStatus.ACTIVE, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    # Rate Limiting
    requests_today = Column(Integer, default=0)
    requests_reset_at = Column(DateTime(timezone=True))

    # Relationships
    telemetry_events = relationship("TelemetryRaw", back_populates="api_key")

    __table_args__ = (
        Index("idx_api_key_status", "status"),
        Index("idx_api_key_expires", "expires_at"),
    )


class TelemetryRaw(Base):
    """
    Rohe Telemetrie-Events.

    DATENSCHUTZ:
    - Keine Dateinamen
    - Keine Keys/Passwörter
    - Keine IP-Adressen
    - Nur Algorithmus-Statistiken
    """
    __tablename__ = "telemetry_raw"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    # API Key Referenz
    api_key_id = Column(BigInteger, ForeignKey("api_keys.id"), nullable=False)
    api_key = relationship("APIKey", back_populates="telemetry_events")

    # Event Timestamp (vom Client)
    event_timestamp = Column(DateTime(timezone=True), nullable=False)

    # Server Timestamp
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Operation
    operation = Column(String(16), nullable=False)  # "encrypt" / "decrypt"
    mode = Column(String(16), nullable=False)  # "symmetric" / "asymmetric"
    format_version = Column(Integer, nullable=False)

    # Encryption
    encryption_algorithm = Column(String(32), nullable=False)

    # Hash Config (JSON)
    hash_algorithms = Column(JSON, nullable=False)  # ["sha512", "blake2b"]
    hash_rounds = Column(JSON)  # {"sha512": 100000}

    # KDF Config (JSON)
    kdf_algorithms = Column(JSON, nullable=False)  # ["argon2", "balloon"]
    kdf_parameters = Column(JSON)  # {"argon2": {"memory": 65536, ...}}

    # PQC
    pqc_kem_algorithm = Column(String(32), nullable=True)
    pqc_signing_algorithm = Column(String(32), nullable=True)

    # Status
    success = Column(Boolean, default=True)
    error_category = Column(String(32), nullable=True)

    # Aggregation Flag
    aggregated = Column(Boolean, default=False, index=True)

    __table_args__ = (
        Index("idx_telemetry_timestamp", "event_timestamp"),
        Index("idx_telemetry_mode", "mode"),
        Index("idx_telemetry_aggregated", "aggregated"),
    )


class TelemetryAggregated(Base):
    """
    Aggregierte Telemetrie-Statistiken (täglich).

    Für schnelle Abfragen und Dashboard-Anzeige.
    """
    __tablename__ = "telemetry_aggregated"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    # Aggregations-Periode
    date = Column(DateTime(timezone=True), nullable=False)  # Tag

    # Dimensionen
    mode = Column(String(16), nullable=False)
    format_version = Column(Integer, nullable=False)
    encryption_algorithm = Column(String(32), nullable=False)

    # Hash Aggregation
    hash_combination = Column(String(128))  # "sha512+blake2b"

    # KDF Aggregation
    kdf_combination = Column(String(128))  # "argon2+balloon"

    # PQC
    pqc_kem_algorithm = Column(String(32), nullable=True)
    pqc_signing_algorithm = Column(String(32), nullable=True)

    # Counts
    total_operations = Column(BigInteger, default=0)
    successful_operations = Column(BigInteger, default=0)
    failed_operations = Column(BigInteger, default=0)

    # Unique Clients (anonymisiert)
    unique_clients = Column(Integer, default=0)

    __table_args__ = (
        Index("idx_agg_date", "date"),
        Index("idx_agg_mode", "mode"),
        Index("idx_agg_pqc", "pqc_kem_algorithm"),
    )
```

### 2.3 Pydantic Schemas

**Datei:** `app/models/schemas.py`

```python
"""
Pydantic Schemas für API Request/Response Validation.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator


# === Registration ===

class RegisterRequest(BaseModel):
    """Client-Registrierung."""
    client_id: str = Field(..., min_length=16, max_length=64)
    client_version: str = Field(..., max_length=32)
    platform: str = Field(..., pattern="^(linux|macos|windows|other)$")


class RegisterResponse(BaseModel):
    """Registrierungs-Antwort mit API-Key."""
    api_key: str
    expires: datetime
    client_id: str


# === Key Management ===

class KeyRefreshRequest(BaseModel):
    """Key-Erneuerung."""
    client_id: str


class KeyRefreshResponse(BaseModel):
    """Neuer API-Key."""
    api_key: str
    expires: datetime


# === Telemetry Upload ===

class TelemetryEventSchema(BaseModel):
    """Einzelnes Telemetrie-Event."""
    timestamp: datetime
    operation: str = Field(..., pattern="^(encrypt|decrypt)$")
    mode: str = Field(..., pattern="^(symmetric|asymmetric)$")
    format_version: int = Field(..., ge=1, le=10)

    hash_algorithms: List[str]
    hash_rounds: Optional[Dict[str, int]] = None

    kdf_algorithms: List[str]
    kdf_parameters: Optional[Dict[str, Dict[str, int]]] = None

    encryption_algorithm: str

    pqc_kem_algorithm: Optional[str] = None
    pqc_signing_algorithm: Optional[str] = None

    success: bool = True
    error_category: Optional[str] = None

    @validator("hash_algorithms")
    def validate_hash_algorithms(cls, v):
        allowed = {"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"}
        for algo in v:
            if algo not in allowed:
                raise ValueError(f"Invalid hash algorithm: {algo}")
        return v

    @validator("kdf_algorithms")
    def validate_kdf_algorithms(cls, v):
        allowed = {"argon2", "argon2id", "argon2i", "argon2d", "balloon", "scrypt", "pbkdf2"}
        for algo in v:
            if algo not in allowed:
                raise ValueError(f"Invalid KDF algorithm: {algo}")
        return v


class TelemetryUploadRequest(BaseModel):
    """Batch-Upload von Events."""
    events: List[TelemetryEventSchema] = Field(..., max_items=1000)


class TelemetryUploadResponse(BaseModel):
    """Upload-Bestätigung."""
    received: int
    processed: int


# === Statistics ===

class StatsQuery(BaseModel):
    """Statistik-Abfrage."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    mode: Optional[str] = None
    group_by: str = "day"  # "day", "week", "month"


class AlgorithmStats(BaseModel):
    """Algorithmus-Statistiken."""
    algorithm: str
    count: int
    percentage: float


class ModeStats(BaseModel):
    """Modus-Statistiken."""
    mode: str
    count: int
    percentage: float


class StatsResponse(BaseModel):
    """Aggregierte Statistiken."""
    period_start: datetime
    period_end: datetime
    total_operations: int

    modes: List[ModeStats]
    encryption_algorithms: List[AlgorithmStats]
    hash_algorithms: List[AlgorithmStats]
    kdf_algorithms: List[AlgorithmStats]
    pqc_algorithms: List[AlgorithmStats]

    format_versions: Dict[int, int]  # {6: 1000, 7: 500}
    success_rate: float
```

### 2.4 API Endpoints

**Datei:** `app/api/v1/router.py`

```python
"""
API v1 Router.
"""

from fastapi import APIRouter
from . import register, telemetry, stats, key

router = APIRouter(prefix="/api/v1")

router.include_router(register.router, tags=["Registration"])
router.include_router(telemetry.router, tags=["Telemetry"])
router.include_router(stats.router, tags=["Statistics"])
router.include_router(key.router, tags=["Key Management"])
```

**Datei:** `app/api/v1/register.py`

```python
"""
Client Registration Endpoint.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from app.models.schemas import RegisterRequest, RegisterResponse
from app.services.key_service import KeyService
from app.api.deps import get_db

router = APIRouter()


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register_client(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Registriert einen neuen Client und gibt API-Key zurück.

    RATE LIMITING: Max 10 Registrierungen pro Stunde pro IP-Bereich
    (IP wird NICHT gespeichert, nur für Rate-Limiting verwendet)
    """
    key_service = KeyService(db)

    # Prüfen ob client_id bereits existiert
    existing = key_service.get_by_client_id(request.client_id)
    if existing:
        # Client existiert bereits, neuen Key generieren
        api_key, expires = key_service.regenerate_key(existing)
    else:
        # Neuer Client
        api_key, expires = key_service.create_key(
            client_id=request.client_id,
            client_version=request.client_version,
            platform=request.platform
        )

    return RegisterResponse(
        api_key=api_key,
        expires=expires,
        client_id=request.client_id
    )
```

**Datei:** `app/api/v1/telemetry.py`

```python
"""
Telemetry Upload Endpoint.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Optional

from app.models.schemas import TelemetryUploadRequest, TelemetryUploadResponse
from app.services.telemetry_service import TelemetryService
from app.services.key_service import KeyService
from app.api.deps import get_db

router = APIRouter()


async def verify_api_key(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> int:
    """Verifiziert API-Key und gibt api_key_id zurück."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )

    api_key = authorization.replace("Bearer ", "")
    key_service = KeyService(db)

    api_key_record = key_service.validate_key(api_key)
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )

    # Rate Limiting prüfen
    if not key_service.check_rate_limit(api_key_record):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )

    return api_key_record.id


@router.post("/telemetry", response_model=TelemetryUploadResponse)
async def upload_telemetry(
    request: TelemetryUploadRequest,
    api_key_id: int = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Empfängt Telemetrie-Events.

    VALIDIERUNG:
    - Gültiger API-Key erforderlich
    - Max 1000 Events pro Request
    - Events werden validiert und bereinigt
    """
    telemetry_service = TelemetryService(db)

    processed = telemetry_service.store_events(
        api_key_id=api_key_id,
        events=request.events
    )

    return TelemetryUploadResponse(
        received=len(request.events),
        processed=processed
    )
```

**Datei:** `app/api/v1/stats.py`

```python
"""
Statistics Endpoint.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.models.schemas import StatsResponse
from app.services.aggregation_service import AggregationService
from app.api.deps import get_db

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
async def get_statistics(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    mode: Optional[str] = Query(None, pattern="^(symmetric|asymmetric)$"),
    db: Session = Depends(get_db)
):
    """
    Gibt aggregierte Telemetrie-Statistiken zurück.

    Öffentlicher Endpoint (kein API-Key erforderlich).
    Zeigt nur aggregierte, anonymisierte Daten.
    """
    # Default: Letzte 30 Tage
    if not end_date:
        end_date = datetime.now(timezone.utc)
    if not start_date:
        start_date = end_date - timedelta(days=30)

    agg_service = AggregationService(db)

    return agg_service.get_statistics(
        start_date=start_date,
        end_date=end_date,
        mode=mode
    )
```

**Datei:** `app/api/v1/key.py`

```python
"""
Key Management Endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Optional

from app.models.schemas import KeyRefreshRequest, KeyRefreshResponse
from app.services.key_service import KeyService
from app.api.deps import get_db

router = APIRouter()


@router.post("/key/refresh", response_model=KeyRefreshResponse)
async def refresh_key(
    request: KeyRefreshRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Erneuert einen API-Key.

    Der alte Key wird invalidiert, ein neuer wird generiert.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )

    old_api_key = authorization.replace("Bearer ", "")
    key_service = KeyService(db)

    # Alten Key validieren
    api_key_record = key_service.validate_key(old_api_key)
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    # Client-ID muss übereinstimmen
    if api_key_record.client_id != request.client_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Client ID mismatch"
        )

    # Neuen Key generieren
    new_api_key, expires = key_service.regenerate_key(api_key_record)

    return KeyRefreshResponse(
        api_key=new_api_key,
        expires=expires
    )
```

### 2.5 Services

**Datei:** `app/services/key_service.py`

```python
"""
API Key Service.
"""

import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from app.models.database import APIKey, APIKeyStatus


class KeyService:
    """Service für API-Key Management."""

    # Key-Länge (256 bit)
    KEY_LENGTH = 32

    # Key-Gültigkeit (1 Jahr)
    KEY_VALIDITY_DAYS = 365

    # Rate Limits
    MAX_REQUESTS_PER_DAY = 10000

    def __init__(self, db: Session):
        self.db = db

    def _generate_key(self) -> str:
        """Generiert einen neuen API-Key."""
        return secrets.token_urlsafe(self.KEY_LENGTH)

    def _hash_key(self, api_key: str) -> str:
        """Hasht einen API-Key für sichere Speicherung."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def create_key(
        self,
        client_id: str,
        client_version: str,
        platform: str
    ) -> Tuple[str, datetime]:
        """
        Erstellt einen neuen API-Key.

        Returns:
            Tuple von (api_key, expires_at)
        """
        api_key = self._generate_key()
        expires_at = datetime.now(timezone.utc) + timedelta(days=self.KEY_VALIDITY_DAYS)

        record = APIKey(
            client_id=client_id,
            api_key_hash=self._hash_key(api_key),
            client_version=client_version,
            platform=platform,
            status=APIKeyStatus.ACTIVE,
            expires_at=expires_at,
            requests_reset_at=datetime.now(timezone.utc)
        )

        self.db.add(record)
        self.db.commit()

        return api_key, expires_at

    def regenerate_key(self, record: APIKey) -> Tuple[str, datetime]:
        """Generiert einen neuen Key für einen bestehenden Client."""
        api_key = self._generate_key()
        expires_at = datetime.now(timezone.utc) + timedelta(days=self.KEY_VALIDITY_DAYS)

        record.api_key_hash = self._hash_key(api_key)
        record.expires_at = expires_at
        record.status = APIKeyStatus.ACTIVE

        self.db.commit()

        return api_key, expires_at

    def validate_key(self, api_key: str) -> Optional[APIKey]:
        """
        Validiert einen API-Key.

        Returns:
            APIKey Record oder None wenn ungültig
        """
        key_hash = self._hash_key(api_key)

        record = self.db.query(APIKey).filter(
            APIKey.api_key_hash == key_hash,
            APIKey.status == APIKeyStatus.ACTIVE
        ).first()

        if not record:
            return None

        # Expiration prüfen
        if record.expires_at and record.expires_at < datetime.now(timezone.utc):
            record.status = APIKeyStatus.EXPIRED
            self.db.commit()
            return None

        # Last used aktualisieren
        record.last_used_at = datetime.now(timezone.utc)
        self.db.commit()

        return record

    def get_by_client_id(self, client_id: str) -> Optional[APIKey]:
        """Sucht APIKey nach Client-ID."""
        return self.db.query(APIKey).filter(
            APIKey.client_id == client_id
        ).first()

    def check_rate_limit(self, record: APIKey) -> bool:
        """
        Prüft Rate Limit.

        Returns:
            True wenn unter dem Limit, False wenn überschritten
        """
        now = datetime.now(timezone.utc)

        # Reset wenn neuer Tag
        if record.requests_reset_at.date() < now.date():
            record.requests_today = 0
            record.requests_reset_at = now

        if record.requests_today >= self.MAX_REQUESTS_PER_DAY:
            return False

        record.requests_today += 1
        self.db.commit()

        return True
```

**Datei:** `app/services/telemetry_service.py`

```python
"""
Telemetry Storage Service.
"""

from typing import List
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.database import TelemetryRaw
from app.models.schemas import TelemetryEventSchema


class TelemetryService:
    """Service für Telemetrie-Speicherung."""

    def __init__(self, db: Session):
        self.db = db

    def store_events(
        self,
        api_key_id: int,
        events: List[TelemetryEventSchema]
    ) -> int:
        """
        Speichert Telemetrie-Events.

        Returns:
            Anzahl erfolgreich gespeicherter Events
        """
        stored = 0

        for event in events:
            try:
                record = TelemetryRaw(
                    api_key_id=api_key_id,
                    event_timestamp=event.timestamp,
                    operation=event.operation,
                    mode=event.mode,
                    format_version=event.format_version,
                    encryption_algorithm=event.encryption_algorithm,
                    hash_algorithms=event.hash_algorithms,
                    hash_rounds=event.hash_rounds,
                    kdf_algorithms=event.kdf_algorithms,
                    kdf_parameters=event.kdf_parameters,
                    pqc_kem_algorithm=event.pqc_kem_algorithm,
                    pqc_signing_algorithm=event.pqc_signing_algorithm,
                    success=event.success,
                    error_category=event.error_category
                )
                self.db.add(record)
                stored += 1
            except Exception:
                continue

        self.db.commit()
        return stored
```

### 2.6 Docker Setup

**Datei:** `docker-compose.yml`

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://telemetry:secret@db:5432/telemetry
      # Oder für MySQL:
      # - DATABASE_URL=mysql+pymysql://telemetry:secret@db:3306/telemetry
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    # Oder für MySQL:
    # image: mysql:8
    environment:
      POSTGRES_USER: telemetry
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: telemetry
      # Für MySQL:
      # MYSQL_USER: telemetry
      # MYSQL_PASSWORD: secret
      # MYSQL_DATABASE: telemetry
      # MYSQL_ROOT_PASSWORD: rootsecret
    volumes:
      - db_data:/var/lib/postgresql/data
      # Für MySQL:
      # - db_data:/var/lib/mysql
    restart: unless-stopped

  # Optional: Aggregation Worker (Cronjob)
  aggregator:
    build: .
    command: python -m app.workers.aggregator
    environment:
      - DATABASE_URL=postgresql://telemetry:secret@db:5432/telemetry
    depends_on:
      - db
    restart: unless-stopped

volumes:
  db_data:
```

**Datei:** `Dockerfile`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY app/ app/

# Run
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Datei:** `requirements.txt`

```
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
sqlalchemy>=2.0.0
alembic>=1.12.0
pydantic>=2.5.0
python-dotenv>=1.0.0

# Database Drivers
psycopg2-binary>=2.9.0  # PostgreSQL
pymysql>=1.1.0          # MySQL
```

---

## Teil 3: Sicherheitsübersicht

### 3.1 Client-Seite

| Aspekt | Implementierung |
|--------|-----------------|
| **Datenfilterung** | `TelemetryDataFilter` - striktes Whitelist-Prinzip |
| **Sensitive Daten** | NIEMALS: Passwörter, Keys, Salts, Dateinamen, IPs |
| **Erlaubte Daten** | NUR: Algorithmen, Parameter, Format-Versionen |
| **Opt-in** | Explizite Aktivierung erforderlich |
| **Transparenz** | User kann alle Daten vor Upload einsehen |
| **Lokaler Buffer** | SQLite mit Encryption-at-rest (optional) |

### 3.2 Server-Seite

| Aspekt | Implementierung |
|--------|-----------------|
| **API-Key** | SHA-256 gehashed gespeichert |
| **Rate Limiting** | 10.000 Requests/Tag pro Client |
| **TLS** | Nur HTTPS, TLS 1.3 empfohlen |
| **Keine IPs** | IP-Adressen werden nicht gespeichert |
| **Anonymität** | client_id ist zufällig, keine Hardware-IDs |
| **Aggregation** | Rohdaten werden zu Statistiken aggregiert |

### 3.3 Datenfluss-Garantien

```
Client (Core)                     Plugin                          Server
     │                              │                                │
     │  Metadaten (vollständig)     │                                │
     │──────────────────────────────│                                │
     │                              │                                │
     │  TelemetryDataFilter         │                                │
     │  ┌─────────────────────┐     │                                │
     │  │ WHITELIST:          │     │                                │
     │  │ ✓ Algorithmen       │     │                                │
     │  │ ✓ KDF-Parameter     │     │                                │
     │  │ ✓ Format-Version    │     │                                │
     │  │                     │     │                                │
     │  │ BLOCKIERT:          │     │                                │
     │  │ ✗ Passwörter        │     │                                │
     │  │ ✗ Keys              │     │                                │
     │  │ ✗ Salts             │     │                                │
     │  │ ✗ Dateinamen        │     │                                │
     │  │ ✗ IPs               │     │                                │
     │  └─────────────────────┘     │                                │
     │                              │                                │
     │  TelemetryEvent (sicher)     │                                │
     │─────────────────────────────▶│                                │
     │                              │                                │
     │                              │  Lokaler Buffer (SQLite)       │
     │                              │  ┌──────────────────────┐      │
     │                              │  │ Events warten auf    │      │
     │                              │  │ Upload               │      │
     │                              │  └──────────────────────┘      │
     │                              │                                │
     │                              │  HTTPS POST (Batch)            │
     │                              │───────────────────────────────▶│
     │                              │                                │
     │                              │                  Validierung   │
     │                              │                  Speicherung   │
     │                              │                  Aggregation   │
     │                              │                                │
```

---

## Teil 4: Implementierungsreihenfolge

### Phase 1: Core-Integration (Client)
1. `telemetry_filter.py` - TelemetryDataFilter und TelemetryEvent
2. Plugin-Interface erweitern (TelemetryPlugin Basisklasse)
3. Unit Tests für Filter (KRITISCH!)

### Phase 2: Plugin (Client)
4. APIKeyManager
5. LocalBuffer (SQLite)
6. TelemetryUploader
7. Haupt-Plugin-Klasse
8. CLI-Commands

### Phase 3: Server
9. FastAPI Setup
10. Datenbank-Models (SQLAlchemy)
11. API-Endpoints (register, telemetry, stats, key)
12. Services (KeyService, TelemetryService, AggregationService)
13. Docker Setup

### Phase 4: Integration
14. End-to-End Tests
15. Dokumentation
16. Rate-Limiting Feintuning

---

## Teil 5: Testszenarien

### Unit Tests (Client)

```python
def test_filter_blocks_password():
    """Stellt sicher dass Passwörter NIEMALS durchkommen."""
    metadata = {
        "password": "secret123",  # Sollte ignoriert werden
        "derivation_config": {...}
    }
    event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
    assert not hasattr(event, "password")
    assert "password" not in TelemetryDataFilter.to_dict(event)

def test_filter_blocks_keys():
    """Stellt sicher dass Keys NIEMALS durchkommen."""
    metadata = {
        "asymmetric": {
            "recipient": {
                "key_id": "abc123",  # Sollte ignoriert werden
                "public_key": "...",  # Sollte ignoriert werden
                "algorithm": "ML-KEM-768"  # Sollte durchkommen
            }
        }
    }
    event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
    event_dict = TelemetryDataFilter.to_dict(event)
    assert "key_id" not in str(event_dict)
    assert "public_key" not in str(event_dict)
    assert event.pqc_kem_algorithm == "ML-KEM-768"

def test_filter_blocks_salt():
    """Stellt sicher dass Salts NIEMALS durchkommen."""
    metadata = {
        "derivation_config": {
            "salt": "base64encodedSalt==",  # Sollte ignoriert werden
            "hash_config": {"sha512": {"rounds": 100000}}
        }
    }
    event = TelemetryDataFilter.filter_metadata(metadata, "decrypt")
    event_dict = TelemetryDataFilter.to_dict(event)
    assert "salt" not in str(event_dict)
```

### Integration Tests

```python
async def test_full_flow():
    """Testet den kompletten Flow von Event bis Server."""
    # 1. Plugin aktivieren
    plugin = OpenSSLEncryptTelemetryPlugin({"server_url": "http://test-server"})

    # 2. Event generieren (wie Core es tun würde)
    event = TelemetryDataFilter.filter_metadata(
        metadata=sample_metadata,
        operation="encrypt"
    )

    # 3. An Plugin senden
    plugin.on_telemetry_event(event)

    # 4. Buffer prüfen
    assert plugin.buffer.get_pending_count() == 1

    # 5. Upload (Mock Server)
    plugin.flush()

    # 6. Server-Daten prüfen
    # ...
```

---

## Offene Entscheidungen

1. **Server-Hosting**: Wo wird der Telemetrie-Server gehostet?
2. **Datenaufbewahrung**: Wie lange werden Rohdaten aufbewahrt? (Vorschlag: 90 Tage, dann nur Aggregate)
3. **Öffentliche Stats**: Sollen aggregierte Statistiken öffentlich sein?
4. **Key-Rotation**: Automatisch oder nur auf Anfrage?

---

**Erstellt**: 25. Dezember 2025
**Für**: Claude Code Implementation
**Version**: 1.0
