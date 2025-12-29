# Cascade Encryption Parameter - Implementierungsplan

*Für Claude Code zur Implementierung*

---

## Übersicht

Einführung eines `--cascade` Parameters, der Multi-Layer-Verschlüsselung mit benutzerdefinierten Cipher-Chains ermöglicht. Jede Schicht verwendet einen unabhängigen Key, abgeleitet via HKDF mit dem Algorithmus-Namen und Bits vom Vorgänger-Key als `info`-Parameter (Verkettung).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Cascade Encryption                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  $ openssl_encrypt encrypt --cascade \                                  │
│        --algorithm aes-256-gcm,chacha20-poly1305,threefish-512 \        │
│        secret.txt                                                       │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                                                                 │   │
│  │  Password ──▶ KDF-Chain ──▶ master_key                          │   │
│  │     │             │             │                               │   │
│  │     │    ~1.3s    │             │                               │   │
│  │     ▼             ▼             ▼                               │   │
│  │  [WIPE]       [done]    ┌──────────────────────────────────┐   │   │
│  │                         │ HKDF-Expand (Chained)            │   │   │
│  │                         │                                  │   │   │
│  │  info=b"cascade:key:aes-256-gcm"                           │   │   │
│  │      │                                                     │   │   │
│  │      └──▶ key1 ─────────────────────────────────┐          │   │   │
│  │               │                                 │          │   │   │
│  │               │                                 ▼          │   │   │
│  │  info=b"cascade:key:chacha20-poly1305:" || key1[:16]       │   │   │
│  │      │                                                     │   │   │
│  │      └──▶ key2 ─────────────────────────────────┐          │   │   │
│  │               │                                 │          │   │   │
│  │               │                                 ▼          │   │   │
│  │  info=b"cascade:key:threefish-512:" || key2[:16]           │   │   │
│  │      │                                                     │   │   │
│  │      └──▶ key3                                             │   │   │
│  │                         └──────────────────────────────────┘   │   │
│  │                                                                 │   │
│  │  Encryption Chain:                                              │   │
│  │  Plaintext ──▶ AES(key1) ──▶ ChaCha(key2) ──▶ TF(key3) ──▶ Out │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Vorteile der Verkettung:                                               │
│  ✓ Password nur ~1.3s im RAM (nicht N×)                                 │
│  ✓ Keys sind sequentiell verkettet (nicht parallel berechenbar)         │
│  ✓ Extra Entropie im info-Parameter                                     │
│  ✓ Kein Performance-Overhead (HKDF ist schnell)                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Vorteile gegenüber hardcoded Cascade

| Aspekt | Hardcoded `CascadeCipher` | `--cascade` Parameter |
|--------|---------------------------|----------------------|
| Flexibilität | Fix: AES→ChaCha→TF | Beliebige Kombination |
| Reihenfolge | Fest | User-definiert |
| Anzahl Layer | Fest (3) | 2-N Layer |
| Neue Cipher | Code-Änderung nötig | Automatisch verfügbar |
| Telemetry | Ein Wert | Genaue Chain sichtbar |

---

## Teil 1: CLI Interface

### 1.1 Parameter-Definition

```bash
# Basis-Syntax
openssl_encrypt encrypt \
    --cascade \
    --algorithm <cipher1>,<cipher2>[,<cipher3>,...] \
    [--cascade-hash <hash>] \
    <files>

# Beispiele
openssl_encrypt encrypt --cascade --algorithm aes-256-gcm,chacha20 file.txt
openssl_encrypt encrypt --cascade --algorithm aes,chacha,threefish file.txt
openssl_encrypt encrypt --cascade --algorithm aes-256-gcm,chacha20-poly1305 --cascade-hash sha512 file.txt

# Kurzform mit Preset
openssl_encrypt encrypt --cascade=paranoia file.txt  # = aes,chacha,threefish

# Decrypt erkennt automatisch aus Metadaten
openssl_encrypt decrypt file.txt.enc
```

### 1.2 CLI Implementation

**Datei:** `openssl_encrypt/cli.py` (Erweiterung)

```python
import click
from typing import Optional, List, Tuple


# Cascade Presets
CASCADE_PRESETS = {
    "standard": ["aes-256-gcm", "chacha20-poly1305"],
    "paranoia": ["aes-256-gcm", "chacha20-poly1305", "threefish-512"],
    "double": ["aes-256-gcm", "chacha20-poly1305"],
    "triple": ["aes-256-gcm", "chacha20-poly1305", "threefish-512"],
}


def parse_cascade_option(value: str) -> Tuple[bool, Optional[List[str]]]:
    """
    Parst den --cascade Parameter.

    Returns:
        (is_cascade, cipher_list or None for preset)
    """
    if value is None:
        return (False, None)

    # Boolean flag
    if value == "":
        return (True, None)  # Braucht --algorithm

    # Preset?
    if value in CASCADE_PRESETS:
        return (True, CASCADE_PRESETS[value])

    # Sollte nicht passieren bei korrekter CLI-Nutzung
    return (True, None)


class CascadeParamType(click.ParamType):
    """Custom Click parameter type für --cascade."""

    name = "cascade"

    def convert(self, value, param, ctx):
        if value is None:
            return None

        # Check for preset
        if value in CASCADE_PRESETS:
            return CASCADE_PRESETS[value]

        # Boolean true (flag without value)
        if value is True or value == "":
            return True  # Signal: use --algorithm

        return value


@click.command()
@click.option(
    "--cascade",
    is_flag=False,
    flag_value=True,
    default=None,
    help="Enable cascade encryption. Use alone with --algorithm, or specify preset: standard, paranoia"
)
@click.option(
    "--algorithm", "-a",
    default="aes-256-gcm",
    help="Cipher algorithm(s). With --cascade: comma-separated list (e.g., aes-256-gcm,chacha20)"
)
@click.option(
    "--cascade-hash",
    default="sha256",
    help="Hash function for HKDF in cascade mode (default: sha256)"
)
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
def encrypt(
    cascade: Optional[str],
    algorithm: str,
    cascade_hash: str,
    files: Tuple[str, ...]
):
    """Encrypt files."""

    from .modules.registry import CipherRegistry, HashRegistry
    from .modules.cascade import CascadeEncryption

    # Parse algorithms
    if cascade:
        # Cascade mode
        if isinstance(cascade, list):
            # Preset wurde verwendet
            cipher_names = cascade
        elif cascade is True:
            # Flag ohne Wert, parse --algorithm
            cipher_names = [c.strip() for c in algorithm.split(",")]
        else:
            # Preset name
            cipher_names = CASCADE_PRESETS.get(cascade, [cascade])

        if len(cipher_names) < 2:
            raise click.UsageError(
                "Cascade mode requires at least 2 algorithms. "
                f"Got: {cipher_names}"
            )

        # Validate all ciphers exist
        registry = CipherRegistry.default()
        for name in cipher_names:
            if not registry.exists(name):
                available = ", ".join(registry.list_names())
                raise click.UsageError(
                    f"Unknown cipher: {name}. Available: {available}"
                )
            if not registry.is_available(name):
                raise click.UsageError(
                    f"Cipher '{name}' is not available. "
                    f"Install required dependencies."
                )

        click.echo(f"Cascade mode: {' → '.join(cipher_names)}")
        click.echo(f"HKDF hash: {cascade_hash}")

        # ... encryption logic mit CascadeEncryption

    else:
        # Single cipher mode (existing logic)
        cipher_name = algorithm
        click.echo(f"Cipher: {cipher_name}")
        # ... existing encryption logic
```

### 1.3 Help Text

```
$ openssl_encrypt encrypt --help

Usage: openssl_encrypt encrypt [OPTIONS] FILES...

  Encrypt files.

Options:
  -a, --algorithm TEXT   Cipher algorithm(s). With --cascade: comma-separated
                         list (e.g., aes-256-gcm,chacha20)  [default: aes-256-gcm]
  --cascade [PRESET]     Enable cascade encryption. Presets: standard (AES→ChaCha),
                         paranoia (AES→ChaCha→Threefish). Or use with --algorithm
                         for custom chain.
  --cascade-hash TEXT    Hash function for HKDF in cascade mode  [default: sha256]
  --help                 Show this message and exit.

Examples:
  # Single cipher (default)
  openssl_encrypt encrypt -a aes-256-gcm secret.txt

  # Cascade with preset
  openssl_encrypt encrypt --cascade=paranoia secret.txt

  # Custom cascade chain
  openssl_encrypt encrypt --cascade -a aes-256-gcm,chacha20 secret.txt

  # Triple cascade with custom hash
  openssl_encrypt encrypt --cascade -a aes,chacha,threefish --cascade-hash sha512 secret.txt
```

---

## Teil 2: Core Implementation

### 2.1 Cascade Encryption Module

**Datei:** `openssl_encrypt/modules/cascade.py`

```python
"""
Cascade Encryption - Multi-Layer Verschlüsselung mit HKDF Key Derivation.

Jede Schicht verwendet einen unabhängigen Key, abgeleitet via HKDF
mit dem Algorithmus-Namen als info-Parameter.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from pathlib import Path

from .registry import (
    CipherRegistry, CipherBase, HashRegistry,
    get_cipher, get_hash,
    AlgorithmNotFoundError, AuthenticationError,
)


@dataclass
class CascadeConfig:
    """Konfiguration für Cascade Encryption."""

    cipher_names: List[str]
    """Liste der Cipher in Ausführungsreihenfolge"""

    hkdf_hash: str = "sha256"
    """Hash-Funktion für HKDF"""

    def __post_init__(self):
        if len(self.cipher_names) < 2:
            raise ValueError("Cascade requires at least 2 ciphers")

    @property
    def layer_count(self) -> int:
        return len(self.cipher_names)

    def get_cipher(self, index: int) -> CipherBase:
        """Gibt den Cipher für einen Layer zurück."""
        return get_cipher(self.cipher_names[index])


@dataclass
class CascadeLayer:
    """Informationen über einen einzelnen Layer."""

    cipher_name: str
    """Kanonischer Name des Ciphers"""

    key_size: int
    """Key-Größe in Bytes"""

    nonce_size: int
    """Nonce-Größe in Bytes"""

    nonce: bytes = field(default=b"", repr=False)
    """Generierte Nonce für diesen Layer"""


class CascadeKeyDerivation:
    """
    Leitet verkettete Keys für jeden Layer via HKDF ab.

    Schema (Chained HKDF):
        key_1 = HKDF(master_key, salt, info=b"cascade:key:<cipher_1>")
        key_2 = HKDF(master_key, salt, info=b"cascade:key:<cipher_2>:" || key_1[:16])
        key_3 = HKDF(master_key, salt, info=b"cascade:key:<cipher_3>:" || key_2[:16])

        nonce_i folgt gleichem Schema mit purpose=b"nonce"

    Die Verkettung bewirkt:
    - Keys müssen sequentiell berechnet werden (nicht parallelisierbar)
    - Extra Entropie im info-Parameter durch Vorgänger-Bits
    - Erschwerter Related-Key-Analyse
    """

    # Prefix für Domain Separation
    KEY_INFO_PREFIX = b"cascade:key:"
    NONCE_INFO_PREFIX = b"cascade:nonce:"

    # Anzahl Bytes vom Vorgänger-Key für Verkettung
    CHAIN_PREFIX_LENGTH = 16  # 128 Bits

    def __init__(self, hash_name: str = "sha256"):
        """
        Args:
            hash_name: Hash-Funktion für HKDF (default: sha256)
        """
        self.hash_name = hash_name

    def derive_layer_keys(
        self,
        master_key: bytes,
        salt: bytes,
        config: CascadeConfig
    ) -> List[Tuple[bytes, bytes]]:
        """
        Leitet verkettete Keys und Nonces für alle Layer ab.

        Args:
            master_key: Der abgeleitete Hauptschlüssel (aus KDF-Chain)
            salt: Salt für HKDF (sollte zufällig sein)
            config: Cascade-Konfiguration

        Returns:
            Liste von (key, nonce) Tupeln für jeden Layer
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        # Hash-Algorithmus auswählen
        hash_algo = self._get_hash_algorithm()

        result = []
        chain_prefix = b""  # Leer für ersten Layer

        for i, cipher_name in enumerate(config.cipher_names):
            cipher = get_cipher(cipher_name)
            info = cipher.info()

            # Info mit Verkettung bauen
            key_info = self._build_chained_info(
                self.KEY_INFO_PREFIX,
                cipher_name,
                chain_prefix
            )
            nonce_info = self._build_chained_info(
                self.NONCE_INFO_PREFIX,
                cipher_name,
                chain_prefix
            )

            # Key ableiten
            key_hkdf = HKDF(
                algorithm=hash_algo,
                length=info.key_size,
                salt=salt,
                info=key_info,
                backend=default_backend(),
            )
            layer_key = key_hkdf.derive(master_key)

            # Nonce ableiten
            nonce_hkdf = HKDF(
                algorithm=hash_algo,
                length=info.nonce_size,
                salt=salt,
                info=nonce_info,
                backend=default_backend(),
            )
            layer_nonce = nonce_hkdf.derive(master_key)

            result.append((layer_key, layer_nonce))

            # Prefix für nächsten Layer: erste 16 Bytes des Keys
            chain_prefix = layer_key[:self.CHAIN_PREFIX_LENGTH]

        return result

    def _build_chained_info(
        self,
        prefix: bytes,
        cipher_name: str,
        chain_prefix: bytes,
    ) -> bytes:
        """
        Baut info-Parameter mit Verkettung.

        Format:
            Layer 1: b"cascade:key:aes-256-gcm"
            Layer 2: b"cascade:key:chacha20-poly1305:<16 bytes from key1>"
            Layer 3: b"cascade:key:threefish-512:<16 bytes from key2>"
        """
        info = prefix + cipher_name.encode("utf-8")

        if chain_prefix:
            info += b":" + chain_prefix

        return info

    def _get_hash_algorithm(self):
        """Gibt das cryptography Hash-Objekt zurück."""
        from cryptography.hazmat.primitives import hashes

        hash_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
            "sha3-256": hashes.SHA3_256(),
            "sha3-384": hashes.SHA3_384(),
            "sha3-512": hashes.SHA3_512(),
            "blake2b": hashes.BLAKE2b(64),
            "blake2s": hashes.BLAKE2s(32),
        }

        algo = hash_map.get(self.hash_name.lower())
        if algo is None:
            raise ValueError(f"Unsupported HKDF hash: {self.hash_name}")

        return algo


class CascadeEncryption:
    """
    Führt Cascade-Verschlüsselung durch.

    Usage:
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        ciphertext, metadata = cascade.encrypt(plaintext, master_key)
        plaintext = cascade.decrypt(ciphertext, master_key, metadata)
    """

    def __init__(self, config: CascadeConfig):
        """
        Args:
            config: Cascade-Konfiguration
        """
        self.config = config
        self.key_derivation = CascadeKeyDerivation(config.hkdf_hash)

        # Cipher vorab laden und validieren
        self._ciphers: List[CipherBase] = []
        for name in config.cipher_names:
            cipher = get_cipher(name)
            cipher.check_available()
            self._ciphers.append(cipher)

    def encrypt(
        self,
        plaintext: bytes,
        master_key: bytes,
        salt: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Verschlüsselt Daten durch alle Layer.

        Args:
            plaintext: Zu verschlüsselnde Daten
            master_key: Hauptschlüssel (aus KDF-Chain)
            salt: Salt für HKDF
            associated_data: AAD für alle Layer (optional)

        Returns:
            Verschlüsselter Ciphertext (alle Layer)
        """
        # Keys für alle Layer ableiten
        layer_keys = self.key_derivation.derive_layer_keys(
            master_key, salt, self.config
        )

        # Durch alle Layer verschlüsseln
        data = plaintext
        for i, cipher in enumerate(self._ciphers):
            key, nonce = layer_keys[i]
            data = cipher.encrypt(key, nonce, data, associated_data)

        return data

    def decrypt(
        self,
        ciphertext: bytes,
        master_key: bytes,
        salt: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Entschlüsselt Daten durch alle Layer (umgekehrte Reihenfolge).

        Args:
            ciphertext: Verschlüsselte Daten
            master_key: Hauptschlüssel
            salt: Salt (aus Metadaten)
            associated_data: AAD (muss mit encrypt übereinstimmen)

        Returns:
            Entschlüsselter Plaintext

        Raises:
            AuthenticationError: Wenn ein Layer fehlschlägt
        """
        # Keys für alle Layer ableiten
        layer_keys = self.key_derivation.derive_layer_keys(
            master_key, salt, self.config
        )

        # Durch alle Layer entschlüsseln (umgekehrte Reihenfolge!)
        data = ciphertext
        for i in range(len(self._ciphers) - 1, -1, -1):
            cipher = self._ciphers[i]
            key, nonce = layer_keys[i]
            try:
                data = cipher.decrypt(key, nonce, data, associated_data)
            except AuthenticationError as e:
                # Layer-Info zum Fehler hinzufügen
                raise AuthenticationError(
                    f"Cascade layer {i} ({self.config.cipher_names[i]}) "
                    f"authentication failed: {e}"
                )

        return data

    def get_total_overhead(self) -> int:
        """
        Berechnet den gesamten Overhead (alle Auth-Tags).

        Returns:
            Overhead in Bytes
        """
        total = 0
        for cipher in self._ciphers:
            total += cipher.info().tag_size
        return total

    def get_security_info(self) -> dict:
        """
        Gibt Sicherheitsinformationen über die Chain zurück.

        Returns:
            Dict mit Security-Infos
        """
        infos = [c.info() for c in self._ciphers]

        return {
            "layer_count": len(self._ciphers),
            "ciphers": [i.name for i in infos],
            "total_overhead_bytes": self.get_total_overhead(),
            # Minimum der klassischen Sicherheit
            "classical_security_bits": min(i.security_bits for i in infos),
            # Minimum der PQ-Sicherheit
            "pq_security_bits": min(i.pq_security_bits for i in infos),
            # Defense in Depth: Alle müssen gebrochen werden
            "defense_in_depth": True,
        }


# Convenience Functions

def cascade_encrypt(
    plaintext: bytes,
    master_key: bytes,
    cipher_names: List[str],
    salt: Optional[bytes] = None,
    hkdf_hash: str = "sha256",
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, dict]:
    """
    Convenience-Funktion für Cascade-Verschlüsselung.

    Args:
        plaintext: Zu verschlüsselnde Daten
        master_key: Hauptschlüssel
        cipher_names: Liste der Cipher
        salt: Salt (optional, wird generiert wenn None)
        hkdf_hash: Hash für HKDF
        associated_data: AAD

    Returns:
        (ciphertext, metadata_dict)
    """
    import secrets

    if salt is None:
        salt = secrets.token_bytes(32)

    config = CascadeConfig(cipher_names, hkdf_hash)
    cascade = CascadeEncryption(config)

    ciphertext = cascade.encrypt(plaintext, master_key, salt, associated_data)

    metadata = {
        "cascade": True,
        "cipher_chain": cipher_names,
        "hkdf_hash": hkdf_hash,
        "cascade_salt": salt,
    }

    return ciphertext, metadata


def cascade_decrypt(
    ciphertext: bytes,
    master_key: bytes,
    metadata: dict,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Convenience-Funktion für Cascade-Entschlüsselung.

    Args:
        ciphertext: Verschlüsselte Daten
        master_key: Hauptschlüssel
        metadata: Metadaten von encrypt
        associated_data: AAD

    Returns:
        Plaintext
    """
    cipher_names = metadata["cipher_chain"]
    hkdf_hash = metadata.get("hkdf_hash", "sha256")
    salt = metadata["cascade_salt"]

    config = CascadeConfig(cipher_names, hkdf_hash)
    cascade = CascadeEncryption(config)

    return cascade.decrypt(ciphertext, master_key, salt, associated_data)
```

---

## Teil 3: Metadaten-Format

### 3.1 Erweitertes Metadaten-Schema

```json
{
  "format_version": 7,
  "mode": "symmetric",

  "encryption": {
    "cascade": true,
    "cipher_chain": ["aes-256-gcm", "chacha20-poly1305", "threefish-512"],
    "hkdf_hash": "sha256",
    "cascade_salt": "<base64: 32 bytes>",

    "layer_info": [
      {
        "cipher": "aes-256-gcm",
        "key_size": 256,
        "tag_size": 16
      },
      {
        "cipher": "chacha20-poly1305",
        "key_size": 256,
        "tag_size": 16
      },
      {
        "cipher": "threefish-512",
        "key_size": 512,
        "tag_size": 16
      }
    ],

    "total_overhead": 48,
    "pq_security_bits": 128
  },

  "derivation_config": {
    "...": "existing KDF config"
  }
}
```

**Hinweis zur Verkettung:** Die HKDF-Verkettung (chain_prefix) wird deterministisch aus der `cipher_chain`-Reihenfolge berechnet. Es sind keine zusätzlichen Metadaten erforderlich - bei der Entschlüsselung werden die Keys in derselben Reihenfolge abgeleitet.

### 3.2 Nicht-Cascade Format (Kompatibilität)

```json
{
  "format_version": 7,
  "mode": "symmetric",

  "encryption": {
    "cascade": false,
    "algorithm": "aes-256-gcm",
    "nonce": "<base64: 12 bytes>",
    "key_size": 256,
    "tag_size": 16,
    "pq_security_bits": 128
  }
}
```

### 3.3 Metadaten-Klasse

**Datei:** `openssl_encrypt/modules/metadata.py` (Erweiterung)

```python
from dataclasses import dataclass, field
from typing import List, Optional
import base64


@dataclass
class CascadeEncryptionMetadata:
    """Metadaten für Cascade-Verschlüsselung."""

    cipher_chain: List[str]
    """Liste der Cipher in Reihenfolge"""

    hkdf_hash: str
    """Hash-Funktion für HKDF"""

    cascade_salt: bytes
    """Salt für HKDF (32 bytes)"""

    def to_dict(self) -> dict:
        return {
            "cascade": True,
            "cipher_chain": self.cipher_chain,
            "hkdf_hash": self.hkdf_hash,
            "cascade_salt": base64.b64encode(self.cascade_salt).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CascadeEncryptionMetadata":
        return cls(
            cipher_chain=data["cipher_chain"],
            hkdf_hash=data.get("hkdf_hash", "sha256"),
            cascade_salt=base64.b64decode(data["cascade_salt"]),
        )


@dataclass
class SingleEncryptionMetadata:
    """Metadaten für Single-Cipher-Verschlüsselung."""

    algorithm: str
    """Cipher-Name"""

    nonce: bytes
    """Nonce für diesen Cipher"""

    def to_dict(self) -> dict:
        return {
            "cascade": False,
            "algorithm": self.algorithm,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SingleEncryptionMetadata":
        return cls(
            algorithm=data["algorithm"],
            nonce=base64.b64decode(data["nonce"]),
        )


def parse_encryption_metadata(data: dict):
    """Factory-Funktion für Encryption-Metadaten."""
    if data.get("cascade", False):
        return CascadeEncryptionMetadata.from_dict(data)
    else:
        return SingleEncryptionMetadata.from_dict(data)
```

---

## Teil 4: Integration in bestehenden Code

### 4.1 crypt_core.py Anpassung

```python
# In encrypt_data()

def encrypt_data(
    self,
    plaintext: bytes,
    password: str,
    cipher_names: Optional[List[str]] = None,
    cascade: bool = False,
    cascade_hash: str = "sha256",
) -> Tuple[bytes, dict]:
    """
    Verschlüsselt Daten.

    Args:
        plaintext: Zu verschlüsselnde Daten
        password: Passwort
        cipher_names: Cipher-Namen (Liste für cascade, einzeln für normal)
        cascade: Cascade-Modus aktivieren
        cascade_hash: Hash für HKDF bei Cascade
    """
    # KDF durchführen (bestehende Logik)
    derived_key, kdf_metadata = self._derive_key(password)

    if cascade:
        # Cascade-Modus
        if cipher_names is None or len(cipher_names) < 2:
            raise ValueError("Cascade mode requires at least 2 ciphers")

        from .cascade import CascadeEncryption, CascadeConfig
        import secrets

        salt = secrets.token_bytes(32)
        config = CascadeConfig(cipher_names, cascade_hash)
        cascade_enc = CascadeEncryption(config)

        ciphertext = cascade_enc.encrypt(plaintext, derived_key, salt)

        encryption_metadata = {
            "cascade": True,
            "cipher_chain": cipher_names,
            "hkdf_hash": cascade_hash,
            "cascade_salt": base64.b64encode(salt).decode("ascii"),
            "pq_security_bits": cascade_enc.get_security_info()["pq_security_bits"],
        }

    else:
        # Single-Cipher-Modus (bestehende Logik)
        cipher_name = cipher_names[0] if cipher_names else "aes-256-gcm"
        cipher = get_cipher(cipher_name)
        nonce = cipher.generate_nonce()

        ciphertext = cipher.encrypt(derived_key, nonce, plaintext)

        encryption_metadata = {
            "cascade": False,
            "algorithm": cipher_name,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "pq_security_bits": cipher.info().pq_security_bits,
        }

    metadata = {
        "encryption": encryption_metadata,
        "derivation_config": kdf_metadata,
    }

    return ciphertext, metadata


def decrypt_data(
    self,
    ciphertext: bytes,
    password: str,
    metadata: dict,
) -> bytes:
    """
    Entschlüsselt Daten.

    Erkennt automatisch ob Cascade oder Single-Cipher verwendet wurde.
    """
    # KDF durchführen
    derived_key = self._derive_key_from_metadata(password, metadata["derivation_config"])

    encryption_meta = metadata["encryption"]

    if encryption_meta.get("cascade", False):
        # Cascade-Modus
        from .cascade import CascadeEncryption, CascadeConfig

        cipher_names = encryption_meta["cipher_chain"]
        hkdf_hash = encryption_meta.get("hkdf_hash", "sha256")
        salt = base64.b64decode(encryption_meta["cascade_salt"])

        config = CascadeConfig(cipher_names, hkdf_hash)
        cascade_enc = CascadeEncryption(config)

        return cascade_enc.decrypt(ciphertext, derived_key, salt)

    else:
        # Single-Cipher-Modus
        cipher_name = encryption_meta["algorithm"]
        nonce = base64.b64decode(encryption_meta["nonce"])

        cipher = get_cipher(cipher_name)
        return cipher.decrypt(derived_key, nonce, ciphertext)
```

---

## Teil 5: Telemetry Integration

### 5.1 Telemetry-Events

```python
# Cascade-spezifische Telemetry

def log_cascade_encryption(config: CascadeConfig):
    """Loggt Cascade-Encryption Event."""
    send_telemetry({
        "event": "encrypt",
        "cascade": True,
        "cascade_layers": config.layer_count,
        "cascade_chain": ",".join(config.cipher_names),
        "hkdf_hash": config.hkdf_hash,
    })


def log_single_encryption(cipher_name: str):
    """Loggt Single-Cipher Event."""
    send_telemetry({
        "event": "encrypt",
        "cascade": False,
        "algorithm": cipher_name,
    })
```

### 5.2 Telemetry-Filter Update

```python
# Erlaubte Werte für cascade_chain
def get_allowed_cascade_chains() -> List[str]:
    """Generiert alle gültigen Chain-Kombinationen für Filter."""
    from .registry import CipherRegistry

    ciphers = CipherRegistry.default().list_names()

    # Alle 2er und 3er Kombinationen
    chains = []
    from itertools import permutations

    for r in [2, 3]:
        for combo in permutations(ciphers, r):
            chains.append(",".join(combo))

    return chains
```

---

## Teil 6: Tests

**Datei:** `tests/test_cascade.py`

```python
"""Tests für Cascade Encryption."""

import pytest
import secrets
from openssl_encrypt.modules.cascade import (
    CascadeConfig,
    CascadeEncryption,
    CascadeKeyDerivation,
    cascade_encrypt,
    cascade_decrypt,
)
from openssl_encrypt.modules.registry import AuthenticationError


class TestCascadeConfig:
    """Tests für CascadeConfig."""

    def test_valid_config(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        assert config.layer_count == 2

    def test_minimum_two_ciphers(self):
        with pytest.raises(ValueError, match="at least 2"):
            CascadeConfig(["aes-256-gcm"])

    def test_three_ciphers(self):
        config = CascadeConfig([
            "aes-256-gcm",
            "chacha20-poly1305",
            "threefish-512"
        ])
        assert config.layer_count == 3


class TestCascadeKeyDerivation:
    """Tests für Chained HKDF Key Derivation."""

    def test_different_keys_per_layer(self):
        kd = CascadeKeyDerivation("sha256")
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        keys = kd.derive_layer_keys(master_key, salt, config)

        assert len(keys) == 2
        assert keys[0][0] != keys[1][0]  # Keys unterschiedlich
        assert keys[0][1] != keys[1][1]  # Nonces unterschiedlich

    def test_deterministic(self):
        kd = CascadeKeyDerivation("sha256")
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])

        master_key = b"fixed_master_key_32_bytes_long!!"
        salt = b"fixed_salt_32_bytes_long_here!!"

        keys1 = kd.derive_layer_keys(master_key, salt, config)
        keys2 = kd.derive_layer_keys(master_key, salt, config)

        assert keys1 == keys2

    def test_chaining_affects_keys(self):
        """Verifiziert dass Verkettung die Keys beeinflusst."""
        kd = CascadeKeyDerivation("sha256")

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        # Gleiche Cipher, andere Reihenfolge
        config1 = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        config2 = CascadeConfig(["chacha20-poly1305", "aes-256-gcm"])

        keys1 = kd.derive_layer_keys(master_key, salt, config1)
        keys2 = kd.derive_layer_keys(master_key, salt, config2)

        # Selbst wenn ein Cipher gleich ist, sind die Keys anders
        # weil die Verkettung (chain_prefix) unterschiedlich ist
        # keys1[1] (ChaCha als 2. Layer) != keys2[0] (ChaCha als 1. Layer)
        # weil keys1[1] von keys1[0] abhängt
        assert keys1[1][0] != keys2[0][0]

    def test_chain_prefix_used(self):
        """Verifiziert dass der Chain-Prefix tatsächlich genutzt wird."""
        kd = CascadeKeyDerivation("sha256")
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305", "threefish-512"])

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        keys = kd.derive_layer_keys(master_key, salt, config)

        # Manuell key2 ohne Verkettung berechnen
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        # Ohne chain_prefix
        hkdf_unchained = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"cascade:key:chacha20-poly1305",
        )
        key2_unchained = hkdf_unchained.derive(master_key)

        # keys[1][0] sollte ANDERS sein (weil es chain_prefix hat)
        assert keys[1][0] != key2_unchained

    def test_different_salts_different_keys(self):
        kd = CascadeKeyDerivation("sha256")
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])

        master_key = secrets.token_bytes(32)
        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)

        keys1 = kd.derive_layer_keys(master_key, salt1, config)
        keys2 = kd.derive_layer_keys(master_key, salt2, config)

        assert keys1[0][0] != keys2[0][0]

    def test_correct_key_sizes(self):
        kd = CascadeKeyDerivation("sha256")
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])

        keys = kd.derive_layer_keys(
            secrets.token_bytes(32),
            secrets.token_bytes(32),
            config
        )

        # AES-256: 32 bytes key, 12 bytes nonce
        assert len(keys[0][0]) == 32
        assert len(keys[0][1]) == 12

        # ChaCha20: 32 bytes key, 12 bytes nonce
        assert len(keys[1][0]) == 32
        assert len(keys[1][1]) == 12

    @pytest.mark.skipif(
        not CascadeConfig(["aes-256-gcm", "threefish-512"]).get_cipher(1).is_available(),
        reason="Threefish not installed"
    )
    def test_threefish_key_size(self):
        kd = CascadeKeyDerivation("sha256")
        config = CascadeConfig(["aes-256-gcm", "threefish-512"])

        keys = kd.derive_layer_keys(
            secrets.token_bytes(32),
            secrets.token_bytes(32),
            config
        )

        # Threefish-512: 64 bytes key, 32 bytes nonce
        assert len(keys[1][0]) == 64
        assert len(keys[1][1]) == 32


class TestCascadeEncryption:
    """Tests für CascadeEncryption."""

    def test_roundtrip_two_layers(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        plaintext = b"Hello, Cascade Encryption!"

        ciphertext = cascade.encrypt(plaintext, master_key, salt)
        decrypted = cascade.decrypt(ciphertext, master_key, salt)

        assert decrypted == plaintext

    def test_roundtrip_with_aad(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        plaintext = b"Secret data"
        aad = b"Associated data"

        ciphertext = cascade.encrypt(plaintext, master_key, salt, aad)
        decrypted = cascade.decrypt(ciphertext, master_key, salt, aad)

        assert decrypted == plaintext

    def test_wrong_aad_fails(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        ciphertext = cascade.encrypt(b"data", master_key, salt, b"correct")

        with pytest.raises(AuthenticationError):
            cascade.decrypt(ciphertext, master_key, salt, b"wrong")

    def test_tampered_ciphertext_fails(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        ciphertext = bytearray(cascade.encrypt(b"secret", master_key, salt))
        ciphertext[0] ^= 0xFF  # Tamper

        with pytest.raises(AuthenticationError):
            cascade.decrypt(bytes(ciphertext), master_key, salt)

    def test_overhead_calculation(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        # 2 × 16-byte tags
        assert cascade.get_total_overhead() == 32

    def test_ciphertext_size(self):
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        plaintext = b"x" * 100
        ciphertext = cascade.encrypt(
            plaintext,
            secrets.token_bytes(32),
            secrets.token_bytes(32)
        )

        expected_size = len(plaintext) + cascade.get_total_overhead()
        assert len(ciphertext) == expected_size

    def test_large_data(self):
        """Test mit 10 MB Daten."""
        config = CascadeConfig(["aes-256-gcm", "chacha20-poly1305"])
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        plaintext = secrets.token_bytes(10 * 1024 * 1024)

        ciphertext = cascade.encrypt(plaintext, master_key, salt)
        decrypted = cascade.decrypt(ciphertext, master_key, salt)

        assert decrypted == plaintext


class TestConvenienceFunctions:
    """Tests für cascade_encrypt/decrypt."""

    def test_roundtrip(self):
        plaintext = b"Test data"
        master_key = secrets.token_bytes(32)

        ciphertext, metadata = cascade_encrypt(
            plaintext,
            master_key,
            ["aes-256-gcm", "chacha20-poly1305"]
        )

        decrypted = cascade_decrypt(ciphertext, master_key, metadata)

        assert decrypted == plaintext

    def test_metadata_structure(self):
        _, metadata = cascade_encrypt(
            b"data",
            secrets.token_bytes(32),
            ["aes-256-gcm", "chacha20-poly1305"],
            hkdf_hash="sha512"
        )

        assert metadata["cascade"] is True
        assert metadata["cipher_chain"] == ["aes-256-gcm", "chacha20-poly1305"]
        assert metadata["hkdf_hash"] == "sha512"
        assert "cascade_salt" in metadata


class TestDifferentHashFunctions:
    """Tests für verschiedene HKDF Hash-Funktionen."""

    @pytest.mark.parametrize("hash_name", [
        "sha256",
        "sha384",
        "sha512",
        "sha3-256",
        "blake2b",
    ])
    def test_hash_function(self, hash_name):
        config = CascadeConfig(
            ["aes-256-gcm", "chacha20-poly1305"],
            hkdf_hash=hash_name
        )
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        plaintext = b"Test"

        ciphertext = cascade.encrypt(plaintext, master_key, salt)
        decrypted = cascade.decrypt(ciphertext, master_key, salt)

        assert decrypted == plaintext
```

---

## Teil 7: Sicherheitsanalyse Chained HKDF

### 7.1 Warum Verkettung?

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    VERKETTUNG VS. PARALLEL                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  OHNE Verkettung (parallel):                                            │
│  ───────────────────────────────────────────────────────────────────   │
│                                                                         │
│  master_key ──┬──▶ HKDF(info="aes")     ──▶ key1                        │
│               ├──▶ HKDF(info="chacha")  ──▶ key2    } Parallel!         │
│               └──▶ HKDF(info="threefish")──▶ key3                       │
│                                                                         │
│  Problem: Angreifer mit master_key kann alle Keys parallel berechnen    │
│           (GPU-Cluster kann 3 HKDFs gleichzeitig ausführen)             │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  MIT Verkettung (sequentiell):                                          │
│  ───────────────────────────────────────────────────────────────────   │
│                                                                         │
│  master_key ──▶ HKDF(info="aes") ──▶ key1                               │
│                                        │                                │
│                                        ▼ (key1[:16])                    │
│  master_key ──▶ HKDF(info="chacha:" || prefix1) ──▶ key2                │
│                                                       │                 │
│                                                       ▼ (key2[:16])     │
│  master_key ──▶ HKDF(info="threefish:" || prefix2) ──▶ key3             │
│                                                                         │
│  Vorteil: Keys MÜSSEN sequentiell berechnet werden                      │
│           (key2 braucht key1, key3 braucht key2)                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Sicherheitseigenschaften

| Eigenschaft | Ohne Verkettung | Mit Verkettung |
|-------------|-----------------|----------------|
| Parallelisierbar | ✗ Ja | ✓ Nein |
| Related-Key-Resistenz | Standard | Erhöht |
| Info-Entropie | Nur Cipher-Name | + 128 Bits |
| Password Exposure | ~1.3s | ~1.3s (gleich!) |
| Performance | 3× HKDF parallel | 3× HKDF sequentiell |

### 7.3 Was die Verkettung NICHT löst

```
┌─────────────────────────────────────────────────────────────────────────┐
│  GRENZEN DER VERKETTUNG                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ✗ Master-Key im RAM                                                    │
│    → master_key bleibt bis Ende der Encryption im Speicher              │
│    → Verkettung ändert daran nichts                                     │
│    → Lösung: SecureByteArray mit mlock()                                │
│                                                                         │
│  ✗ Brute-Force auf Password                                             │
│    → Verkettung macht Brute-Force NICHT teurer                          │
│    → Angreifer berechnet einmal KDF-Chain → hat master_key              │
│    → Dann sequentiell die Layer-Keys (schnell, da nur HKDF)             │
│    → Schutz kommt von KDF-Chain (Argon2, Balloon), nicht Verkettung     │
│                                                                         │
│  ✓ WAS es löst:                                                         │
│    → Erzwingt sequentielle Berechnung bei bekanntem master_key          │
│    → Erhöht Entropie im info-Parameter                                  │
│    → Minimaler Overhead, kein Nachteil                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.4 Chain-Prefix Länge

| Länge | Bits | Bewertung |
|-------|------|-----------|
| 8 bytes | 64 | Zu kurz, theoretische Kollisionsgefahr |
| **16 bytes** | **128** | **Optimal: Volle Sicherheit, kompakte Info** |
| 32 bytes | 256 | Unnötig lang, kein zusätzlicher Nutzen |

**Gewählt: 16 Bytes (128 Bits)** - Standard für kryptographische Sicherheit.

### 7.5 Info-Parameter Struktur

```
Layer 1:
  info = b"cascade:key:aes-256-gcm"
         │       │   │
         │       │   └─ Cipher-Name (Algorithmus-Bindung)
         │       └───── Purpose (key vs nonce)
         └───────────── Domain (Namespace)

Layer 2+:
  info = b"cascade:key:chacha20-poly1305:a7f3...2b1c"
         │       │   │                   │
         │       │   │                   └─ key_{n-1}[:16] (Verkettung)
         │       │   └─ Cipher-Name
         │       └───── Purpose
         └───────────── Domain
```

**Domain Separation:** Verhindert Verwechslung mit anderen HKDF-Ableitungen im System.

---

## Teil 8: Dokumentation

### 8.1 User-Dokumentation

```markdown
# Cascade Encryption

Cascade Encryption verschlüsselt Daten mehrfach mit verschiedenen Algorithmen.
Dies bietet "Defense in Depth" - wenn ein Algorithmus gebrochen wird, schützen
die anderen noch.

## Verwendung

### Preset verwenden

```bash
# Standard: AES + ChaCha (empfohlen)
openssl_encrypt encrypt --cascade=standard secret.txt

# Paranoia: AES + ChaCha + Threefish (benötigt threefish-Paket)
openssl_encrypt encrypt --cascade=paranoia secret.txt
```

### Eigene Chain definieren

```bash
# Zwei Algorithmen
openssl_encrypt encrypt --cascade --algorithm aes-256-gcm,chacha20 secret.txt

# Drei Algorithmen
openssl_encrypt encrypt --cascade --algorithm aes,chacha,threefish secret.txt

# Mit anderem HKDF-Hash
openssl_encrypt encrypt --cascade --algorithm aes,chacha --cascade-hash sha512 secret.txt
```

### Entschlüsselung

Die Entschlüsselung erkennt automatisch die verwendete Chain:

```bash
openssl_encrypt decrypt secret.txt.enc
```

## Wie es funktioniert

1. Aus deinem Passwort wird ein Master-Key abgeleitet (wie immer)
2. Für jeden Cipher wird ein eigener Key via **verketteter HKDF** abgeleitet:
   - Key 1 = HKDF(master_key, info="cascade:key:aes-256-gcm")
   - Key 2 = HKDF(master_key, info="cascade:key:chacha20:" + key1[:16])
   - Key 3 = HKDF(master_key, info="cascade:key:threefish:" + key2[:16])

   Die Verkettung (128 Bits vom Vorgänger-Key im info) erzwingt sequentielle
   Berechnung - ein Angreifer kann die Keys nicht parallel berechnen.

3. Daten werden nacheinander verschlüsselt:
   - Plaintext → AES → ChaCha → (Threefish →) Ciphertext

## Sicherheit

| Chain | PQ-Sicherheit | Overhead |
|-------|---------------|----------|
| AES + ChaCha | 128-bit | 32 bytes |
| AES + ChaCha + Threefish | 256-bit | 48 bytes |

Die PQ-Sicherheit ist die des schwächsten Glieds, aber ein Angreifer muss
ALLE Algorithmen brechen um an die Daten zu kommen.

## Wann Cascade verwenden?

- Langzeitarchivierung (>10 Jahre)
- Hochsensible Daten
- Compliance-Anforderungen
- "Belt and Suspenders" Mentalität

Für normale Nutzung ist AES-256-GCM allein bereits sehr sicher!
```

---

## Teil 9: Implementierungsreihenfolge

### Phase 1: Core (1 Tag)
1. `CascadeConfig` Dataclass
2. `CascadeKeyDerivation` mit HKDF
3. `CascadeEncryption` Klasse
4. Unit Tests für Core

### Phase 2: Integration (0.5 Tag)
5. Metadaten-Format erweitern
6. `crypt_core.py` anpassen
7. Integrationstests

### Phase 3: CLI (0.5 Tag)
8. `--cascade` Parameter
9. `--cascade-hash` Parameter
10. Presets (standard, paranoia)
11. CLI Tests

### Phase 4: Polish (0.5 Tag)
12. Telemetry
13. Dokumentation
14. Fehlerbehandlung verbessern

### Phase 5: Diversity Validation (Optional, 1 Tag)
15. `cipher_families.py` - Familie-Definitionen
16. `CascadeDiversityValidator` Klasse
17. CLI-Flags (`--no-diversity-check`, `--strict-diversity`)
18. Tests für Validator

**Geschätzter Gesamtaufwand: 2.5 Tage (+ 1 Tag optional)**

---

## Teil 10: Cipher Diversity Validierung (Optional)

### 9.1 Konzept

Warnung bei Ciphern aus gleicher kryptographischer Familie, da ein Bruch der zugrundeliegenden Primitive beide Schichten betreffen könnte.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Cipher Familien                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Familie          │ Primitive      │ Cipher                            │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  aes              │ Rijndael       │ aes-256-gcm, aes-128-gcm,         │
│                   │                │ aes-256-ctr, aes-128-cbc, ...     │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  chacha           │ ChaCha (ARX)   │ chacha20-poly1305, xchacha20,     │
│                   │                │ chacha12, chacha8                 │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  salsa            │ Salsa20 (ARX)  │ salsa20, xsalsa20                 │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  threefish        │ Threefish      │ threefish-256, threefish-512,     │
│                   │                │ threefish-1024                    │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  serpent          │ Serpent        │ serpent-256, serpent-128          │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  twofish          │ Twofish        │ twofish-256, twofish-128          │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  camellia         │ Camellia       │ camellia-256, camellia-128        │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  aria             │ ARIA           │ aria-256, aria-128                │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  sm4              │ SM4            │ sm4                               │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  blowfish         │ Blowfish       │ blowfish (legacy!)                │
│  ─────────────────┼────────────────┼─────────────────────────────────  │
│  des              │ DES            │ 3des, des (legacy!)               │
│                   │                │                                   │
│  Verwandte Familien (ähnliche Designs):                                │
│  ─────────────────────────────────────────────────────────────────────  │
│  chacha + salsa   │ Beide ARX-basiert, gleicher Designer (Bernstein)   │
│  aes + camellia   │ Beide SPN, ähnliche Struktur                       │
│                   │                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Implementation

**Datei:** `openssl_encrypt/modules/registry/cipher_families.py`

```python
"""
Cipher Family Definitions für Diversity-Validierung.

Definiert kryptographische Familien und deren Beziehungen
für die Cascade-Validierung.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from enum import Enum, auto


class DesignType(Enum):
    """Grundlegendes Cipher-Design."""
    SPN = auto()          # Substitution-Permutation Network (AES, Serpent)
    FEISTEL = auto()      # Feistel Network (DES, Twofish, Camellia)
    ARX = auto()          # Add-Rotate-XOR (ChaCha, Salsa, Threefish)
    OTHER = auto()


@dataclass
class CipherFamily:
    """Definition einer Cipher-Familie."""

    name: str
    """Familienname (z.B. 'aes', 'chacha')"""

    design_type: DesignType
    """Grundlegendes Design"""

    primitive: str
    """Zugrundeliegende Primitive (z.B. 'Rijndael', 'ChaCha')"""

    members: Set[str] = field(default_factory=set)
    """Cipher die zu dieser Familie gehören"""

    related_families: Set[str] = field(default_factory=set)
    """Verwandte Familien (ähnliches Design)"""

    designer: Optional[str] = None
    """Designer/Autor (für Related-Family Erkennung)"""

    notes: Optional[str] = None
    """Zusätzliche Hinweise"""


# Familie-Definitionen
CIPHER_FAMILIES: Dict[str, CipherFamily] = {

    # === AES / Rijndael ===
    "aes": CipherFamily(
        name="aes",
        design_type=DesignType.SPN,
        primitive="Rijndael",
        members={
            "aes-256-gcm", "aes-128-gcm", "aes-192-gcm",
            "aes-256-ctr", "aes-128-ctr", "aes-192-ctr",
            "aes-256-cbc", "aes-128-cbc", "aes-192-cbc",
            "aes-256-ccm", "aes-128-ccm",
            "aes-256-siv", "aes-128-siv",
            "aes-256-gcm-siv", "aes-128-gcm-siv",
            "aes-256-ocb", "aes-128-ocb",
            # Aliase
            "aes", "aes256", "aes128", "aes-gcm",
        },
        related_families={"camellia"},  # Ähnliche SPN-Struktur
        designer="Daemen & Rijmen",
    ),

    # === ChaCha ===
    "chacha": CipherFamily(
        name="chacha",
        design_type=DesignType.ARX,
        primitive="ChaCha",
        members={
            "chacha20-poly1305", "chacha20",
            "xchacha20-poly1305", "xchacha20",
            "chacha12", "chacha8",
            # Aliase
            "chacha",
        },
        related_families={"salsa"},  # Gleicher Designer, ähnliches Design
        designer="Daniel J. Bernstein",
    ),

    # === Salsa ===
    "salsa": CipherFamily(
        name="salsa",
        design_type=DesignType.ARX,
        primitive="Salsa20",
        members={
            "salsa20", "salsa20-poly1305",
            "xsalsa20", "xsalsa20-poly1305",
            "salsa12", "salsa8",
        },
        related_families={"chacha"},
        designer="Daniel J. Bernstein",
    ),

    # === Threefish ===
    "threefish": CipherFamily(
        name="threefish",
        design_type=DesignType.ARX,
        primitive="Threefish",
        members={
            "threefish-256", "threefish-512", "threefish-1024",
            # Aliase
            "threefish", "tf256", "tf512", "tf1024",
        },
        related_families=set(),  # Einzigartiges Design
        designer="Schneier et al.",
        notes="Part of Skein hash function (SHA-3 finalist)",
    ),

    # === Serpent ===
    "serpent": CipherFamily(
        name="serpent",
        design_type=DesignType.SPN,
        primitive="Serpent",
        members={
            "serpent-256", "serpent-128", "serpent-192",
            "serpent-256-gcm", "serpent-128-gcm",
            "serpent",
        },
        related_families=set(),
        designer="Anderson, Biham, Knudsen",
        notes="AES finalist, more conservative design",
    ),

    # === Twofish ===
    "twofish": CipherFamily(
        name="twofish",
        design_type=DesignType.FEISTEL,
        primitive="Twofish",
        members={
            "twofish-256", "twofish-128", "twofish-192",
            "twofish",
        },
        related_families={"blowfish"},  # Nachfolger
        designer="Schneier et al.",
        notes="AES finalist, successor to Blowfish",
    ),

    # === Camellia ===
    "camellia": CipherFamily(
        name="camellia",
        design_type=DesignType.FEISTEL,  # Hybrid SPN/Feistel
        primitive="Camellia",
        members={
            "camellia-256", "camellia-128", "camellia-192",
            "camellia-256-gcm", "camellia-128-gcm",
            "camellia",
        },
        related_families={"aes"},  # Ähnliche Sicherheitseigenschaften
        designer="Mitsubishi & NTT",
        notes="ISO/IEC 18033-3, similar security to AES",
    ),

    # === ARIA ===
    "aria": CipherFamily(
        name="aria",
        design_type=DesignType.SPN,
        primitive="ARIA",
        members={
            "aria-256", "aria-128", "aria-192",
            "aria-256-gcm", "aria-128-gcm",
            "aria",
        },
        related_families={"aes"},  # SPN-basiert
        designer="Korean NSRI",
        notes="Korean national standard",
    ),

    # === SM4 ===
    "sm4": CipherFamily(
        name="sm4",
        design_type=DesignType.FEISTEL,
        primitive="SM4",
        members={"sm4", "sm4-gcm", "sm4-ccm"},
        related_families=set(),
        designer="Chinese OSCCA",
        notes="Chinese national standard",
    ),

    # === Legacy (mit Warnung) ===
    "blowfish": CipherFamily(
        name="blowfish",
        design_type=DesignType.FEISTEL,
        primitive="Blowfish",
        members={"blowfish", "blowfish-cbc"},
        related_families={"twofish"},
        designer="Bruce Schneier",
        notes="LEGACY: 64-bit block size, use Twofish instead",
    ),

    "des": CipherFamily(
        name="des",
        design_type=DesignType.FEISTEL,
        primitive="DES",
        members={"des", "3des", "triple-des", "des-ede3"},
        related_families=set(),
        designer="IBM / NSA",
        notes="LEGACY: Broken (DES) or slow (3DES), do not use",
    ),

    "rc4": CipherFamily(
        name="rc4",
        design_type=DesignType.OTHER,
        primitive="RC4",
        members={"rc4", "arcfour"},
        related_families=set(),
        designer="Ron Rivest",
        notes="BROKEN: Do not use under any circumstances",
    ),
}


# Lookup-Cache: cipher_name -> family_name
_CIPHER_TO_FAMILY: Dict[str, str] = {}

def _build_lookup_cache():
    """Baut den Lookup-Cache auf."""
    global _CIPHER_TO_FAMILY
    for family_name, family in CIPHER_FAMILIES.items():
        for member in family.members:
            _CIPHER_TO_FAMILY[member.lower()] = family_name

_build_lookup_cache()


def get_cipher_family(cipher_name: str) -> Optional[CipherFamily]:
    """
    Gibt die Familie eines Ciphers zurück.

    Args:
        cipher_name: Name des Ciphers

    Returns:
        CipherFamily oder None wenn unbekannt
    """
    family_name = _CIPHER_TO_FAMILY.get(cipher_name.lower())
    if family_name:
        return CIPHER_FAMILIES[family_name]
    return None


def get_family_name(cipher_name: str) -> Optional[str]:
    """Gibt nur den Familiennamen zurück."""
    return _CIPHER_TO_FAMILY.get(cipher_name.lower())


def are_related_families(family1: str, family2: str) -> bool:
    """
    Prüft ob zwei Familien verwandt sind.

    Args:
        family1: Erste Familie
        family2: Zweite Familie

    Returns:
        True wenn verwandt
    """
    if family1 == family2:
        return True

    f1 = CIPHER_FAMILIES.get(family1)
    f2 = CIPHER_FAMILIES.get(family2)

    if not f1 or not f2:
        return False

    return family2 in f1.related_families or family1 in f2.related_families


def register_cipher_family(cipher_name: str, family_name: str) -> None:
    """
    Registriert einen neuen Cipher bei einer Familie.

    Für dynamische Erweiterung durch Plugins.
    """
    cipher_name = cipher_name.lower()
    family_name = family_name.lower()

    if family_name not in CIPHER_FAMILIES:
        raise ValueError(f"Unknown family: {family_name}")

    CIPHER_FAMILIES[family_name].members.add(cipher_name)
    _CIPHER_TO_FAMILY[cipher_name] = family_name
```

### 9.3 Diversity Validator

**Datei:** `openssl_encrypt/modules/cascade.py` (Erweiterung)

```python
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum, auto


class DiversityWarningLevel(Enum):
    """Schweregrad einer Diversity-Warnung."""
    INFO = auto()      # Hinweis, aber ok
    WARNING = auto()   # Sollte vermieden werden
    ERROR = auto()     # Sollte nicht verwendet werden


@dataclass
class DiversityWarning:
    """Eine Warnung bezüglich Cipher-Diversity."""

    level: DiversityWarningLevel
    message: str
    ciphers_involved: List[str]
    suggestion: Optional[str] = None


class CascadeDiversityValidator:
    """
    Validiert Cipher-Chains auf kryptographische Diversität.

    Warnt bei:
    - Gleiche Familie (z.B. aes-256-gcm + aes-128-ctr)
    - Verwandte Familien (z.B. chacha + salsa)
    - Legacy/gebrochene Cipher
    - Gleiches Design-Pattern übermäßig
    """

    def __init__(self, strict: bool = False):
        """
        Args:
            strict: Bei True werden Warnungen zu Fehlern
        """
        self.strict = strict

    def validate(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """
        Validiert eine Cipher-Chain.

        Args:
            cipher_names: Liste der Cipher in der Chain

        Returns:
            Liste von Warnungen (leer wenn alles ok)
        """
        from .registry.cipher_families import (
            get_cipher_family, get_family_name, are_related_families,
            CIPHER_FAMILIES, DesignType
        )

        warnings = []

        # 1. Legacy/Broken Cipher prüfen
        warnings.extend(self._check_legacy_ciphers(cipher_names))

        # 2. Gleiche Familie prüfen
        warnings.extend(self._check_same_family(cipher_names))

        # 3. Verwandte Familien prüfen
        warnings.extend(self._check_related_families(cipher_names))

        # 4. Design-Typ Diversität prüfen
        warnings.extend(self._check_design_diversity(cipher_names))

        return warnings

    def _check_legacy_ciphers(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """Prüft auf Legacy/gebrochene Cipher."""
        from .registry.cipher_families import get_cipher_family

        warnings = []
        legacy_families = {"blowfish", "des", "rc4"}
        broken_families = {"rc4", "des"}

        for cipher in cipher_names:
            family = get_cipher_family(cipher)
            if not family:
                continue

            if family.name in broken_families:
                warnings.append(DiversityWarning(
                    level=DiversityWarningLevel.ERROR,
                    message=f"Cipher '{cipher}' is BROKEN and must not be used",
                    ciphers_involved=[cipher],
                    suggestion=f"Remove '{cipher}' from the chain entirely",
                ))
            elif family.name in legacy_families:
                warnings.append(DiversityWarning(
                    level=DiversityWarningLevel.WARNING,
                    message=f"Cipher '{cipher}' is LEGACY: {family.notes}",
                    ciphers_involved=[cipher],
                    suggestion=f"Consider replacing with modern alternative",
                ))

        return warnings

    def _check_same_family(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """Prüft auf mehrere Cipher aus gleicher Familie."""
        from .registry.cipher_families import get_family_name

        warnings = []
        family_members: Dict[str, List[str]] = {}

        for cipher in cipher_names:
            family = get_family_name(cipher)
            if family:
                if family not in family_members:
                    family_members[family] = []
                family_members[family].append(cipher)

        for family, members in family_members.items():
            if len(members) > 1:
                warnings.append(DiversityWarning(
                    level=DiversityWarningLevel.WARNING,
                    message=(
                        f"Multiple ciphers from '{family}' family: {members}. "
                        f"A break in the underlying primitive would affect all layers."
                    ),
                    ciphers_involved=members,
                    suggestion=(
                        f"Consider replacing one with a cipher from a different family "
                        f"(e.g., mix AES with ChaCha or Threefish)"
                    ),
                ))

        return warnings

    def _check_related_families(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """Prüft auf verwandte Familien."""
        from .registry.cipher_families import get_family_name, are_related_families

        warnings = []
        families = [(c, get_family_name(c)) for c in cipher_names]
        families = [(c, f) for c, f in families if f]  # Filter None

        checked_pairs = set()
        for i, (cipher1, family1) in enumerate(families):
            for cipher2, family2 in families[i+1:]:
                if family1 == family2:
                    continue  # Already covered by same_family check

                pair = tuple(sorted([family1, family2]))
                if pair in checked_pairs:
                    continue
                checked_pairs.add(pair)

                if are_related_families(family1, family2):
                    warnings.append(DiversityWarning(
                        level=DiversityWarningLevel.INFO,
                        message=(
                            f"Families '{family1}' and '{family2}' are related "
                            f"(similar design principles)"
                        ),
                        ciphers_involved=[cipher1, cipher2],
                        suggestion=(
                            f"This is usually fine, but for maximum diversity "
                            f"consider using unrelated designs"
                        ),
                    ))

        return warnings

    def _check_design_diversity(self, cipher_names: List[str]) -> List[DiversityWarning]:
        """Prüft auf Diversität im Design-Typ."""
        from .registry.cipher_families import get_cipher_family, DesignType

        warnings = []
        design_counts: Dict[DesignType, List[str]] = {}

        for cipher in cipher_names:
            family = get_cipher_family(cipher)
            if family:
                design = family.design_type
                if design not in design_counts:
                    design_counts[design] = []
                design_counts[design].append(cipher)

        # Warnung wenn alle Cipher gleiches Design
        if len(design_counts) == 1 and len(cipher_names) > 2:
            design = list(design_counts.keys())[0]
            warnings.append(DiversityWarning(
                level=DiversityWarningLevel.INFO,
                message=(
                    f"All ciphers use {design.name} design pattern. "
                    f"Consider mixing designs for defense in depth."
                ),
                ciphers_involved=cipher_names,
                suggestion=(
                    f"Mix SPN (AES, Serpent) with ARX (ChaCha, Threefish) "
                    f"or Feistel (Twofish, Camellia)"
                ),
            ))

        return warnings

    def validate_and_report(
        self,
        cipher_names: List[str],
        fail_on_warning: bool = False,
        fail_on_error: bool = True
    ) -> Tuple[bool, List[DiversityWarning]]:
        """
        Validiert und gibt Ergebnis zurück.

        Args:
            cipher_names: Cipher-Chain
            fail_on_warning: Bei Warnings fehlschlagen
            fail_on_error: Bei Errors fehlschlagen

        Returns:
            (success, warnings)
        """
        warnings = self.validate(cipher_names)

        has_error = any(w.level == DiversityWarningLevel.ERROR for w in warnings)
        has_warning = any(w.level == DiversityWarningLevel.WARNING for w in warnings)

        success = True
        if fail_on_error and has_error:
            success = False
        if fail_on_warning and has_warning:
            success = False

        return success, warnings
```

### 9.4 CLI Integration

```python
@click.command()
@click.option(
    "--cascade",
    is_flag=False,
    flag_value=True,
    default=None,
    help="Enable cascade encryption"
)
@click.option(
    "--algorithm", "-a",
    default="aes-256-gcm",
    help="Cipher algorithm(s)"
)
@click.option(
    "--no-diversity-check",
    is_flag=True,
    help="Disable cipher diversity validation"
)
@click.option(
    "--strict-diversity",
    is_flag=True,
    help="Treat diversity warnings as errors"
)
def encrypt(cascade, algorithm, no_diversity_check, strict_diversity, ...):
    """Encrypt files."""

    if cascade:
        cipher_names = [c.strip() for c in algorithm.split(",")]

        # Diversity-Check (optional)
        if not no_diversity_check:
            from .modules.cascade import CascadeDiversityValidator

            validator = CascadeDiversityValidator(strict=strict_diversity)
            success, warnings = validator.validate_and_report(
                cipher_names,
                fail_on_warning=strict_diversity,
                fail_on_error=True
            )

            # Warnungen ausgeben
            for warning in warnings:
                if warning.level == DiversityWarningLevel.ERROR:
                    click.secho(f"ERROR: {warning.message}", fg="red", err=True)
                elif warning.level == DiversityWarningLevel.WARNING:
                    click.secho(f"WARNING: {warning.message}", fg="yellow", err=True)
                else:
                    click.secho(f"INFO: {warning.message}", fg="blue", err=True)

                if warning.suggestion:
                    click.echo(f"  → {warning.suggestion}", err=True)

            if not success:
                raise click.Abort()

        # ... continue with encryption
```

### 9.5 Beispiel-Ausgaben

```bash
$ openssl_encrypt encrypt --cascade -a aes-256-gcm,aes-128-ctr secret.txt
WARNING: Multiple ciphers from 'aes' family: ['aes-256-gcm', 'aes-128-ctr'].
         A break in the underlying primitive would affect all layers.
  → Consider replacing one with a cipher from a different family
    (e.g., mix AES with ChaCha or Threefish)

Proceeding with encryption...

$ openssl_encrypt encrypt --cascade -a aes-256-gcm,chacha20,salsa20 secret.txt
INFO: Families 'chacha' and 'salsa' are related (similar design principles)
  → This is usually fine, but for maximum diversity consider using unrelated designs

Proceeding with encryption...

$ openssl_encrypt encrypt --cascade -a aes-256-gcm,rc4 secret.txt
ERROR: Cipher 'rc4' is BROKEN and must not be used
  → Remove 'rc4' from the chain entirely

Aborted!

$ openssl_encrypt encrypt --cascade -a aes-256-gcm,chacha20,threefish-512 secret.txt
Cascade mode: aes-256-gcm → chacha20-poly1305 → threefish-512
✓ Optimal cipher diversity (3 different families, mixed designs)
```

---

## Offene Entscheidungen

1. **Presets erweiterbar?**
   - Config-File für eigene Presets?
   - Empfehlung: Später, erstmal hardcoded

2. **Maximum Layer?**
   - Soll es ein Limit geben?
   - Empfehlung: Soft-Limit mit Warnung bei >5

3. **Gleicher Cipher mehrfach?**
   - `--algorithm aes,aes` erlauben?
   - Empfehlung: Ja, mit Diversity-Warnung (verschiedene Keys trotzdem)

4. **Legacy: Hardcoded CascadeCipher behalten?**
   - Als Alias für `--cascade=paranoia`?
   - Empfehlung: Deprecate, aber nicht sofort entfernen

5. **Diversity-Check Default?**
   - Standardmäßig an oder aus?
   - Empfehlung: An, mit `--no-diversity-check` zum Deaktivieren

6. **Broken Cipher komplett blockieren?**
   - RC4/DES auch mit `--no-diversity-check` ablehnen?
   - Empfehlung: Ja, keine Möglichkeit gebrochene Cipher zu verwenden

7. **Familie-Definitionen extern?**
   - In Config-File auslagern für einfache Updates?
   - Empfehlung: Erstmal hardcoded, später vielleicht JSON

8. **Verwandte Familien strenger?**
   - ChaCha + Salsa als WARNING statt INFO?
   - Empfehlung: INFO reicht, sind trotzdem verschiedene Cipher

---

**Erstellt**: 28. Dezember 2025
**Für**: Claude Code Implementation
**Version**: 1.0
**Geschätzter Aufwand**: 2.5 Tage
**Abhängigkeit**: Algorithm Registry System
