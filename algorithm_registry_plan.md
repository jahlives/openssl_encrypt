# Algorithm Registry System - Implementierungsplan

*Für Claude Code zur Implementierung*

---

## Übersicht

Einführung eines einheitlichen Registry-Systems für alle kryptographischen Algorithmen. Ermöglicht modulare Erweiterung ohne Core-Änderungen.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Algorithm Registry System                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                         ┌─────────────────────┐                         │
│                         │   AlgorithmBase     │                         │
│                         │   (ABC)             │                         │
│                         ├─────────────────────┤                         │
│                         │ • info() → Info     │                         │
│                         │ • is_available()    │                         │
│                         │ • validate_params() │                         │
│                         └──────────┬──────────┘                         │
│                                    │                                    │
│            ┌───────────────────────┼───────────────────────┐            │
│            │                       │                       │            │
│            ▼                       ▼                       ▼            │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │   CipherBase    │    │    HashBase     │    │    KDFBase      │     │
│  ├─────────────────┤    ├─────────────────┤    ├─────────────────┤     │
│  │ • encrypt()     │    │ • hash()        │    │ • derive()      │     │
│  │ • decrypt()     │    │ • hash_file()   │    │ • params_info() │     │
│  │ • generate_key()│    │ • verify()      │    │ • estimate_time│      │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘     │
│           │                      │                      │              │
│           ▼                      ▼                      ▼              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │ CipherRegistry  │    │  HashRegistry   │    │  KDFRegistry    │     │
│  ├─────────────────┤    ├─────────────────┤    ├─────────────────┤     │
│  │ • aes-256-gcm   │    │ • sha256        │    │ • argon2id      │     │
│  │ • chacha20-poly │    │ • sha512        │    │ • argon2d       │     │
│  │ ○ threefish-512 │    │ • sha3-256      │    │ • balloon       │     │
│  │ ○ cascade       │    │ • sha3-512      │    │ • scrypt        │     │
│  │                 │    │ • blake2b       │    │ • pbkdf2        │     │
│  │ ○ = optional    │    │ • blake2s       │    │ • hkdf          │     │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Vorteile

| Aspekt | Vorher | Nachher |
|--------|--------|---------|
| Neuer Algorithmus | Core-Code ändern | Nur Registry erweitern |
| Algo-Info abfragen | Verstreut im Code | `registry.get(name).info()` |
| CLI-Optionen | Hardcoded | `registry.list_available()` |
| Telemetry-Filter | Manuell pflegen | `registry.allowed_values()` |
| Config-Wizard | Statische Listen | Dynamisch aus Registry |
| Verfügbarkeit prüfen | Try/except Import | `algo.is_available()` |
| Parameter-Validierung | Verstreut | `algo.validate_params()` |

---

## Teil 1: Gemeinsame Basis

### 1.1 Dateistruktur

```
openssl_encrypt/
├── modules/
│   ├── registry/
│   │   ├── __init__.py           # Public API
│   │   ├── base.py               # AlgorithmBase, AlgorithmInfo
│   │   ├── cipher_registry.py    # Cipher-Implementierungen
│   │   ├── hash_registry.py      # Hash-Implementierungen
│   │   ├── kdf_registry.py       # KDF-Implementierungen
│   │   └── utils.py              # Shared utilities
│   └── ...
└── ...
```

### 1.2 Basis-Klassen

**Datei:** `openssl_encrypt/modules/registry/base.py`

```python
"""
Basis-Klassen für das Algorithm Registry System.

Definiert gemeinsame Interfaces und Datenstrukturen für alle
kryptographischen Algorithmen (Cipher, Hash, KDF).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Optional, Dict, List, Any, Type, TypeVar, Generic,
    Callable, Tuple, ClassVar
)


class AlgorithmCategory(Enum):
    """Kategorie eines Algorithmus."""
    CIPHER = auto()
    HASH = auto()
    KDF = auto()


class SecurityLevel(Enum):
    """Sicherheitsstufe eines Algorithmus."""
    LEGACY = "legacy"           # Nicht empfohlen, nur für Kompatibilität
    STANDARD = "standard"       # Empfohlen für normale Nutzung
    HIGH = "high"               # Erhöhte Sicherheit
    PARANOID = "paranoid"       # Maximale Sicherheit (z.B. PQ-256)


@dataclass(frozen=True)
class AlgorithmInfo:
    """
    Metadaten über einen Algorithmus.
    
    Frozen dataclass für Immutability und Hashability.
    """
    # Identifikation
    name: str
    """Kanonischer Name (z.B. 'aes-256-gcm')"""
    
    display_name: str
    """Anzeigename (z.B. 'AES-256-GCM')"""
    
    category: AlgorithmCategory
    """Kategorie: CIPHER, HASH, oder KDF"""
    
    # Sicherheit
    security_bits: int
    """Klassische Sicherheit in Bits"""
    
    pq_security_bits: int
    """Post-Quantum Sicherheit in Bits (nach Grover)"""
    
    security_level: SecurityLevel
    """Empfohlene Sicherheitsstufe"""
    
    # Beschreibung
    description: str
    """Kurze Beschreibung"""
    
    # Technische Details (optional, je nach Kategorie)
    key_size: Optional[int] = None
    """Schlüsselgröße in Bytes (für Cipher/KDF)"""
    
    output_size: Optional[int] = None
    """Ausgabegröße in Bytes (für Hash)"""
    
    block_size: Optional[int] = None
    """Blockgröße in Bytes (für Cipher/Hash)"""
    
    nonce_size: Optional[int] = None
    """Nonce/IV-Größe in Bytes (für Cipher)"""
    
    tag_size: Optional[int] = None
    """Auth-Tag-Größe in Bytes (für AEAD Cipher)"""
    
    # Zusätzliche Infos
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    """Alternative Namen (z.B. ('aes', 'aes256'))"""
    
    references: Tuple[str, ...] = field(default_factory=tuple)
    """Referenzen (RFCs, Papers, etc.)"""
    
    def __post_init__(self):
        """Validierung nach Initialisierung."""
        if self.security_bits < 0:
            raise ValueError("security_bits must be non-negative")
        if self.pq_security_bits < 0:
            raise ValueError("pq_security_bits must be non-negative")


class AlgorithmError(Exception):
    """Basis-Exception für Algorithmus-Fehler."""
    pass


class AlgorithmNotAvailableError(AlgorithmError):
    """Algorithmus ist nicht verfügbar (fehlende Dependency)."""
    pass


class AlgorithmNotFoundError(AlgorithmError):
    """Algorithmus wurde nicht gefunden."""
    pass


class ValidationError(AlgorithmError):
    """Parameter-Validierung fehlgeschlagen."""
    pass


class AuthenticationError(AlgorithmError):
    """Authentifizierung fehlgeschlagen (für AEAD Cipher)."""
    pass


class AlgorithmBase(ABC):
    """
    Abstrakte Basisklasse für alle Algorithmen.
    
    Jeder konkrete Algorithmus erbt von dieser Klasse und
    implementiert die abstrakten Methoden.
    """
    
    # Class-level cache für Verfügbarkeit
    _available: ClassVar[Optional[bool]] = None
    
    @classmethod
    @abstractmethod
    def info(cls) -> AlgorithmInfo:
        """
        Gibt die Metadaten des Algorithmus zurück.
        
        Returns:
            AlgorithmInfo mit allen relevanten Informationen
        """
        pass
    
    @classmethod
    def is_available(cls) -> bool:
        """
        Prüft ob der Algorithmus verfügbar ist.
        
        Kann überschrieben werden für Algorithmen mit optionalen
        Dependencies (z.B. Threefish).
        
        Returns:
            True wenn verfügbar, False sonst
        """
        return True
    
    @classmethod
    def check_available(cls) -> None:
        """
        Prüft Verfügbarkeit und wirft Exception wenn nicht verfügbar.
        
        Raises:
            AlgorithmNotAvailableError: Wenn nicht verfügbar
        """
        if not cls.is_available():
            info = cls.info()
            raise AlgorithmNotAvailableError(
                f"Algorithm '{info.name}' is not available. "
                f"Install required dependencies."
            )
    
    @classmethod
    def get_all_names(cls) -> List[str]:
        """
        Gibt alle Namen zurück (kanonisch + Aliases).
        
        Returns:
            Liste aller Namen für diesen Algorithmus
        """
        info = cls.info()
        return [info.name] + list(info.aliases)


# Type variable für generische Registry
T = TypeVar('T', bound=AlgorithmBase)


class RegistryBase(Generic[T]):
    """
    Generische Basis-Klasse für Algorithm Registries.
    
    Verwaltet Registrierung und Lookup von Algorithmen.
    """
    
    def __init__(self):
        self._algorithms: Dict[str, Type[T]] = {}
        self._aliases: Dict[str, str] = {}  # alias -> canonical name
    
    def register(self, algorithm_class: Type[T]) -> None:
        """
        Registriert einen Algorithmus.
        
        Args:
            algorithm_class: Algorithmus-Klasse zum Registrieren
        """
        info = algorithm_class.info()
        
        # Kanonischen Namen registrieren
        self._algorithms[info.name] = algorithm_class
        
        # Aliases registrieren
        for alias in info.aliases:
            if alias in self._aliases or alias in self._algorithms:
                raise ValueError(f"Alias '{alias}' already registered")
            self._aliases[alias] = info.name
    
    def get(self, name: str) -> T:
        """
        Gibt eine Algorithmus-Instanz zurück.
        
        Args:
            name: Algorithmus-Name oder Alias
            
        Returns:
            Instanz des Algorithmus
            
        Raises:
            AlgorithmNotFoundError: Wenn nicht gefunden
            AlgorithmNotAvailableError: Wenn nicht verfügbar
        """
        algorithm_class = self.get_class(name)
        algorithm_class.check_available()
        return algorithm_class()
    
    def get_class(self, name: str) -> Type[T]:
        """
        Gibt die Algorithmus-Klasse zurück (ohne Instanziierung).
        
        Args:
            name: Algorithmus-Name oder Alias
            
        Returns:
            Algorithmus-Klasse
            
        Raises:
            AlgorithmNotFoundError: Wenn nicht gefunden
        """
        name_lower = name.lower().strip()
        
        # Direkt registriert?
        if name_lower in self._algorithms:
            return self._algorithms[name_lower]
        
        # Alias?
        if name_lower in self._aliases:
            canonical = self._aliases[name_lower]
            return self._algorithms[canonical]
        
        # Nicht gefunden
        available = self.list_names()
        raise AlgorithmNotFoundError(
            f"Algorithm '{name}' not found. Available: {', '.join(available)}"
        )
    
    def get_info(self, name: str) -> AlgorithmInfo:
        """
        Gibt nur die Metadaten zurück (ohne Verfügbarkeitsprüfung).
        
        Args:
            name: Algorithmus-Name oder Alias
            
        Returns:
            AlgorithmInfo
        """
        return self.get_class(name).info()
    
    def exists(self, name: str) -> bool:
        """
        Prüft ob ein Algorithmus existiert.
        
        Args:
            name: Algorithmus-Name oder Alias
            
        Returns:
            True wenn registriert
        """
        name_lower = name.lower().strip()
        return name_lower in self._algorithms or name_lower in self._aliases
    
    def is_available(self, name: str) -> bool:
        """
        Prüft ob ein Algorithmus verfügbar ist.
        
        Args:
            name: Algorithmus-Name oder Alias
            
        Returns:
            True wenn verfügbar
        """
        try:
            return self.get_class(name).is_available()
        except AlgorithmNotFoundError:
            return False
    
    def list_names(self, include_aliases: bool = False) -> List[str]:
        """
        Listet alle registrierten Algorithmus-Namen.
        
        Args:
            include_aliases: Auch Aliases zurückgeben
            
        Returns:
            Liste der Namen
        """
        names = list(self._algorithms.keys())
        if include_aliases:
            names.extend(self._aliases.keys())
        return sorted(names)
    
    def list_available(self) -> Dict[str, AlgorithmInfo]:
        """
        Listet alle verfügbaren Algorithmen mit Infos.
        
        Returns:
            Dict von Name -> AlgorithmInfo
        """
        result = {}
        for name, algo_class in self._algorithms.items():
            if algo_class.is_available():
                result[name] = algo_class.info()
        return result
    
    def list_all(self) -> Dict[str, Tuple[AlgorithmInfo, bool]]:
        """
        Listet alle Algorithmen (auch nicht verfügbare).
        
        Returns:
            Dict von Name -> (AlgorithmInfo, is_available)
        """
        result = {}
        for name, algo_class in self._algorithms.items():
            result[name] = (algo_class.info(), algo_class.is_available())
        return result
    
    def allowed_values(self) -> List[str]:
        """
        Gibt Liste aller erlaubten Werte zurück.
        
        Nützlich für Telemetry-Filter und Validierung.
        
        Returns:
            Liste aller Namen und Aliases
        """
        return self.list_names(include_aliases=True)
    
    def by_security_level(
        self,
        level: SecurityLevel,
        only_available: bool = True
    ) -> List[AlgorithmInfo]:
        """
        Filtert Algorithmen nach Sicherheitsstufe.
        
        Args:
            level: Gewünschte Sicherheitsstufe
            only_available: Nur verfügbare zurückgeben
            
        Returns:
            Liste von AlgorithmInfo
        """
        result = []
        for name, algo_class in self._algorithms.items():
            info = algo_class.info()
            if info.security_level == level:
                if only_available and not algo_class.is_available():
                    continue
                result.append(info)
        return result
```

### 1.3 Shared Utilities

**Datei:** `openssl_encrypt/modules/registry/utils.py`

```python
"""
Shared utilities für Registry System.
"""

import secrets
from typing import Optional


def generate_random_bytes(length: int) -> bytes:
    """Generiert kryptographisch sichere Zufallsbytes."""
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Konstant-Zeit Vergleich zweier Byte-Strings."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """PKCS#7 Padding hinzufügen."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad_pkcs7(data: bytes) -> bytes:
    """PKCS#7 Padding entfernen."""
    if not data:
        raise ValueError("Empty data")
    padding_len = data[-1]
    if padding_len == 0 or padding_len > len(data):
        raise ValueError("Invalid padding")
    for i in range(padding_len):
        if data[-(i + 1)] != padding_len:
            raise ValueError("Invalid padding")
    return data[:-padding_len]
```

---

## Teil 2: Cipher Registry

### 2.1 Cipher Base

**Datei:** `openssl_encrypt/modules/registry/cipher_registry.py`

```python
"""
Cipher Registry - Symmetrische Verschlüsselungsalgorithmen.

Unterstützte Cipher:
- AES-256-GCM (Standard)
- ChaCha20-Poly1305
- (Threefish-512 - optional)
- (Cascade - optional)
"""

from abc import abstractmethod
from typing import Optional, Dict, List, Type, ClassVar

from .base import (
    AlgorithmBase, AlgorithmInfo, AlgorithmCategory, SecurityLevel,
    RegistryBase, AuthenticationError, AlgorithmNotAvailableError,
    ValidationError
)
from .utils import generate_random_bytes


class CipherBase(AlgorithmBase):
    """
    Basis-Klasse für symmetrische Cipher.
    
    Alle Cipher implementieren AEAD (Authenticated Encryption with
    Associated Data) für integrierte Authentifizierung.
    """
    
    @abstractmethod
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Verschlüsselt Daten mit Authentifizierung.
        
        Args:
            key: Schlüssel (Länge gemäß info().key_size)
            nonce: Einmalwert (Länge gemäß info().nonce_size)
            plaintext: Zu verschlüsselnde Daten
            associated_data: Zusätzliche authentifizierte Daten (optional)
            
        Returns:
            Ciphertext mit angehängtem Auth-Tag
            
        Raises:
            ValidationError: Bei ungültigen Parametern
        """
        pass
    
    @abstractmethod
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Entschlüsselt und verifiziert Daten.
        
        Args:
            key: Schlüssel
            nonce: Einmalwert (muss mit encrypt übereinstimmen)
            ciphertext: Verschlüsselte Daten mit Auth-Tag
            associated_data: Zusätzliche authentifizierte Daten
            
        Returns:
            Entschlüsselter Plaintext
            
        Raises:
            AuthenticationError: Bei ungültigem Auth-Tag
            ValidationError: Bei ungültigen Parametern
        """
        pass
    
    def validate_key(self, key: bytes) -> None:
        """Validiert Schlüssellänge."""
        info = self.info()
        if len(key) != info.key_size:
            raise ValidationError(
                f"Key must be {info.key_size} bytes, got {len(key)}"
            )
    
    def validate_nonce(self, nonce: bytes) -> None:
        """Validiert Nonce-Länge."""
        info = self.info()
        if len(nonce) != info.nonce_size:
            raise ValidationError(
                f"Nonce must be {info.nonce_size} bytes, got {len(nonce)}"
            )
    
    @classmethod
    def generate_key(cls) -> bytes:
        """Generiert einen zufälligen Schlüssel."""
        return generate_random_bytes(cls.info().key_size)
    
    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generiert eine zufällige Nonce."""
        return generate_random_bytes(cls.info().nonce_size)


# ============================================================================
# Concrete Cipher Implementations
# ============================================================================

class AES256GCM(CipherBase):
    """
    AES-256 im GCM-Modus.
    
    Standard-Cipher mit Hardware-Beschleunigung (AES-NI).
    128-bit Post-Quantum-Sicherheit.
    """
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="aes-256-gcm",
            display_name="AES-256-GCM",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="AES-256 in Galois/Counter Mode with authentication",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=16,
            aliases=("aes-gcm", "aes256", "aes"),
            references=(
                "NIST SP 800-38D",
                "RFC 5116",
            ),
        )
    
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher = AESGCM(key)
        return cipher.encrypt(nonce, plaintext, associated_data)
    
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        
        cipher = AESGCM(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise AuthenticationError(
                "AES-256-GCM authentication failed: "
                "data may be corrupted or tampered"
            )


class ChaCha20Poly1305(CipherBase):
    """
    ChaCha20 mit Poly1305 MAC.
    
    Software-freundlicher Cipher ohne Timing-Sidechannels.
    128-bit Post-Quantum-Sicherheit.
    """
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="chacha20-poly1305",
            display_name="ChaCha20-Poly1305",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="ChaCha20 stream cipher with Poly1305 authenticator",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=64,
            aliases=("chacha20", "chacha"),
            references=(
                "RFC 8439",
                "RFC 7539",
            ),
        )
    
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CC20P1305
        cipher = CC20P1305(key)
        return cipher.encrypt(nonce, plaintext, associated_data)
    
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CC20P1305
        from cryptography.exceptions import InvalidTag
        
        cipher = CC20P1305(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise AuthenticationError(
                "ChaCha20-Poly1305 authentication failed: "
                "data may be corrupted or tampered"
            )


class Threefish512(CipherBase):
    """
    Threefish-512 mit CTR-Mode und Poly1305.
    
    Paranoia-Modus mit 256-bit Post-Quantum-Sicherheit.
    Benötigt optionale Dependency: openssl-encrypt-threefish
    """
    
    _available: ClassVar[Optional[bool]] = None
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="threefish-512",
            display_name="Threefish-512",
            category=AlgorithmCategory.CIPHER,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Threefish-512 in CTR mode with Poly1305 (256-bit PQ security)",
            key_size=64,
            nonce_size=32,
            tag_size=16,
            block_size=64,
            aliases=("threefish", "tf512"),
            references=(
                "Skein Hash Function Family (SHA-3 submission)",
            ),
        )
    
    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                import threefish_native
                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available
    
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.check_available()
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        import threefish_native
        return threefish_native.encrypt(key, nonce, plaintext, associated_data)
    
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.check_available()
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        import threefish_native
        try:
            return threefish_native.decrypt(key, nonce, ciphertext, associated_data)
        except RuntimeError as e:
            if "Authentication failed" in str(e):
                raise AuthenticationError(
                    "Threefish-512 authentication failed: "
                    "data may be corrupted or tampered"
                )
            raise


class CascadeCipher(CipherBase):
    """
    Cipher Cascade: AES-256-GCM → ChaCha20-Poly1305 → Threefish-512
    
    Defense in Depth: Wenn ein Cipher gebrochen wird, schützen die
    anderen noch. 256-bit Post-Quantum-Sicherheit.
    
    Benötigt optionale Dependency: openssl-encrypt-threefish
    """
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="cascade",
            display_name="Cascade (AES→ChaCha→Threefish)",
            category=AlgorithmCategory.CIPHER,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Triple-layer encryption: AES-256 → ChaCha20 → Threefish-512",
            key_size=64,  # Master key für HKDF
            nonce_size=32,
            tag_size=48,  # 3 × 16 bytes
            block_size=64,
            aliases=("paranoia", "triple"),
            references=(),
        )
    
    @classmethod
    def is_available(cls) -> bool:
        return Threefish512.is_available()
    
    def _derive_keys(self, master_key: bytes, nonce: bytes) -> tuple:
        """Leitet unabhängige Keys für jeden Layer ab."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        
        def derive(info: bytes, length: int) -> bytes:
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=length,
                salt=nonce[:16],
                info=info,
            )
            return hkdf.derive(master_key)
        
        return (
            derive(b"cascade-aes-256-gcm", 32),
            derive(b"cascade-chacha20-poly1305", 32),
            derive(b"cascade-threefish-512", 64),
        )
    
    def _derive_nonces(self, base_nonce: bytes) -> tuple:
        """Leitet unabhängige Nonces für jeden Layer ab."""
        import hashlib
        return (
            hashlib.sha256(b"nonce-aes" + base_nonce).digest()[:12],
            hashlib.sha256(b"nonce-chacha" + base_nonce).digest()[:12],
            hashlib.sha256(b"nonce-threefish" + base_nonce).digest(),
        )
    
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.check_available()
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        aes_key, chacha_key, tf_key = self._derive_keys(key, nonce)
        aes_nonce, chacha_nonce, tf_nonce = self._derive_nonces(nonce)
        
        # Layer 1: AES-256-GCM
        aes = AES256GCM()
        ct1 = aes.encrypt(aes_key, aes_nonce, plaintext, associated_data)
        
        # Layer 2: ChaCha20-Poly1305
        chacha = ChaCha20Poly1305()
        ct2 = chacha.encrypt(chacha_key, chacha_nonce, ct1, associated_data)
        
        # Layer 3: Threefish-512
        tf = Threefish512()
        ct3 = tf.encrypt(tf_key, tf_nonce, ct2, associated_data)
        
        return ct3
    
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        self.check_available()
        self.validate_key(key)
        self.validate_nonce(nonce)
        
        aes_key, chacha_key, tf_key = self._derive_keys(key, nonce)
        aes_nonce, chacha_nonce, tf_nonce = self._derive_nonces(nonce)
        
        # Layer 3: Threefish-512
        tf = Threefish512()
        ct2 = tf.decrypt(tf_key, tf_nonce, ciphertext, associated_data)
        
        # Layer 2: ChaCha20-Poly1305
        chacha = ChaCha20Poly1305()
        ct1 = chacha.decrypt(chacha_key, chacha_nonce, ct2, associated_data)
        
        # Layer 1: AES-256-GCM
        aes = AES256GCM()
        plaintext = aes.decrypt(aes_key, aes_nonce, ct1, associated_data)
        
        return plaintext


# ============================================================================
# Cipher Registry
# ============================================================================

class CipherRegistry(RegistryBase[CipherBase]):
    """
    Registry für symmetrische Cipher.
    
    Usage:
        cipher = CipherRegistry.default().get("aes-256-gcm")
        ciphertext = cipher.encrypt(key, nonce, plaintext)
    """
    
    _instance: ClassVar[Optional["CipherRegistry"]] = None
    
    @classmethod
    def default(cls) -> "CipherRegistry":
        """Gibt die Singleton-Instanz mit allen Standard-Ciphern zurück."""
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.register(AES256GCM)
            cls._instance.register(ChaCha20Poly1305)
            cls._instance.register(Threefish512)
            cls._instance.register(CascadeCipher)
        return cls._instance
    
    @classmethod
    def reset(cls) -> None:
        """Setzt die Singleton-Instanz zurück (für Tests)."""
        cls._instance = None


# Convenience function
def get_cipher(name: str) -> CipherBase:
    """Shortcut für CipherRegistry.default().get(name)."""
    return CipherRegistry.default().get(name)
```

---

## Teil 3: Hash Registry

### 3.1 Hash Base

**Datei:** `openssl_encrypt/modules/registry/hash_registry.py`

```python
"""
Hash Registry - Kryptographische Hash-Funktionen.

Unterstützte Hashes:
- SHA-2 Familie (SHA-256, SHA-384, SHA-512)
- SHA-3 Familie (SHA3-256, SHA3-384, SHA3-512)
- BLAKE2 (BLAKE2b, BLAKE2s)
"""

from abc import abstractmethod
from typing import Optional, BinaryIO, ClassVar
from pathlib import Path

from .base import (
    AlgorithmBase, AlgorithmInfo, AlgorithmCategory, SecurityLevel,
    RegistryBase, ValidationError
)


# Konstante für Chunk-Größe beim Datei-Hashing
HASH_CHUNK_SIZE = 65536  # 64 KB


class HashBase(AlgorithmBase):
    """
    Basis-Klasse für Hash-Funktionen.
    """
    
    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """
        Berechnet den Hash von Daten.
        
        Args:
            data: Zu hashende Daten
            
        Returns:
            Hash-Digest
        """
        pass
    
    def hash_file(self, file_path: Path) -> bytes:
        """
        Berechnet den Hash einer Datei.
        
        Args:
            file_path: Pfad zur Datei
            
        Returns:
            Hash-Digest
        """
        hasher = self._create_hasher()
        with open(file_path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.finalize()
    
    def hash_stream(self, stream: BinaryIO) -> bytes:
        """
        Berechnet den Hash eines Streams.
        
        Args:
            stream: Binärer Stream
            
        Returns:
            Hash-Digest
        """
        hasher = self._create_hasher()
        while chunk := stream.read(HASH_CHUNK_SIZE):
            hasher.update(chunk)
        return hasher.finalize()
    
    def verify(self, data: bytes, expected_hash: bytes) -> bool:
        """
        Verifiziert ob der Hash übereinstimmt.
        
        Args:
            data: Daten
            expected_hash: Erwarteter Hash
            
        Returns:
            True wenn übereinstimmt
        """
        from .utils import constant_time_compare
        actual_hash = self.hash(data)
        return constant_time_compare(actual_hash, expected_hash)
    
    def hex_digest(self, data: bytes) -> str:
        """Gibt den Hash als Hex-String zurück."""
        return self.hash(data).hex()
    
    @abstractmethod
    def _create_hasher(self):
        """Erstellt eine Hasher-Instanz für inkrementelles Hashing."""
        pass


# ============================================================================
# SHA-2 Family
# ============================================================================

class SHA256(HashBase):
    """SHA-256 (SHA-2 Familie)."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha256",
            display_name="SHA-256",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,  # Grover
            security_level=SecurityLevel.STANDARD,
            description="SHA-2 with 256-bit output",
            output_size=32,
            block_size=64,
            aliases=("sha-256", "sha2-256"),
            references=("FIPS 180-4", "RFC 6234"),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.SHA256(), backend=default_backend())


class SHA384(HashBase):
    """SHA-384 (SHA-2 Familie)."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha384",
            display_name="SHA-384",
            category=AlgorithmCategory.HASH,
            security_bits=384,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="SHA-2 with 384-bit output",
            output_size=48,
            block_size=128,
            aliases=("sha-384", "sha2-384"),
            references=("FIPS 180-4", "RFC 6234"),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.SHA384(), backend=default_backend())


class SHA512(HashBase):
    """SHA-512 (SHA-2 Familie)."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha512",
            display_name="SHA-512",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.HIGH,
            description="SHA-2 with 512-bit output",
            output_size=64,
            block_size=128,
            aliases=("sha-512", "sha2-512"),
            references=("FIPS 180-4", "RFC 6234"),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.SHA512(), backend=default_backend())


# ============================================================================
# SHA-3 Family
# ============================================================================

class SHA3_256(HashBase):
    """SHA3-256 (Keccak)."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha3-256",
            display_name="SHA3-256",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="SHA-3 (Keccak) with 256-bit output",
            output_size=32,
            block_size=136,  # Rate für SHA3-256
            aliases=("sha3256", "keccak256"),
            references=("FIPS 202",),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.SHA3_256(), backend=default_backend())


class SHA3_384(HashBase):
    """SHA3-384 (Keccak)."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha3-384",
            display_name="SHA3-384",
            category=AlgorithmCategory.HASH,
            security_bits=384,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="SHA-3 (Keccak) with 384-bit output",
            output_size=48,
            block_size=104,
            aliases=("sha3384",),
            references=("FIPS 202",),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.SHA3_384(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.SHA3_384(), backend=default_backend())


class SHA3_512(HashBase):
    """SHA3-512 (Keccak)."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha3-512",
            display_name="SHA3-512",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.HIGH,
            description="SHA-3 (Keccak) with 512-bit output",
            output_size=64,
            block_size=72,
            aliases=("sha3512",),
            references=("FIPS 202",),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.SHA3_512(), backend=default_backend())


# ============================================================================
# BLAKE2 Family
# ============================================================================

class BLAKE2b(HashBase):
    """BLAKE2b - Schneller Hash optimiert für 64-bit Plattformen."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="blake2b",
            display_name="BLAKE2b",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.HIGH,
            description="BLAKE2b with 512-bit output (fast, 64-bit optimized)",
            output_size=64,
            block_size=128,
            aliases=("blake2b-512", "blake2b512"),
            references=("RFC 7693",),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())


class BLAKE2s(HashBase):
    """BLAKE2s - Schneller Hash optimiert für 32-bit Plattformen."""
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="blake2s",
            display_name="BLAKE2s",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="BLAKE2s with 256-bit output (fast, 32-bit optimized)",
            output_size=32,
            block_size=64,
            aliases=("blake2s-256", "blake2s256"),
            references=("RFC 7693",),
        )
    
    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        digest = hashes.Hash(hashes.BLAKE2s(32), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    def _create_hasher(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return hashes.Hash(hashes.BLAKE2s(32), backend=default_backend())


# ============================================================================
# Hash Registry
# ============================================================================

class HashRegistry(RegistryBase[HashBase]):
    """
    Registry für Hash-Funktionen.
    
    Usage:
        hasher = HashRegistry.default().get("sha256")
        digest = hasher.hash(data)
    """
    
    _instance: ClassVar[Optional["HashRegistry"]] = None
    
    @classmethod
    def default(cls) -> "HashRegistry":
        """Gibt die Singleton-Instanz mit allen Standard-Hashes zurück."""
        if cls._instance is None:
            cls._instance = cls()
            # SHA-2
            cls._instance.register(SHA256)
            cls._instance.register(SHA384)
            cls._instance.register(SHA512)
            # SHA-3
            cls._instance.register(SHA3_256)
            cls._instance.register(SHA3_384)
            cls._instance.register(SHA3_512)
            # BLAKE2
            cls._instance.register(BLAKE2b)
            cls._instance.register(BLAKE2s)
        return cls._instance
    
    @classmethod
    def reset(cls) -> None:
        """Setzt die Singleton-Instanz zurück (für Tests)."""
        cls._instance = None


# Convenience function
def get_hash(name: str) -> HashBase:
    """Shortcut für HashRegistry.default().get(name)."""
    return HashRegistry.default().get(name)
```

---

## Teil 4: KDF Registry

### 4.1 KDF Base

**Datei:** `openssl_encrypt/modules/registry/kdf_registry.py`

```python
"""
KDF Registry - Key Derivation Functions.

Unterstützte KDFs:
- Argon2 (id, d, i)
- Balloon Hashing
- scrypt
- PBKDF2
- HKDF
"""

from abc import abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, ClassVar, Type

from .base import (
    AlgorithmBase, AlgorithmInfo, AlgorithmCategory, SecurityLevel,
    RegistryBase, ValidationError
)
from .utils import generate_random_bytes


@dataclass
class KDFParams:
    """
    Parameter für eine KDF.
    
    Jede KDF hat spezifische Parameter. Diese Basisklasse
    definiert gemeinsame Attribute.
    """
    # Gemeinsame Parameter
    output_length: int = 32
    """Gewünschte Ausgabelänge in Bytes"""
    
    salt_length: int = 16
    """Salt-Länge in Bytes"""


@dataclass
class Argon2Params(KDFParams):
    """Parameter für Argon2."""
    time_cost: int = 3
    """Anzahl Iterationen"""
    
    memory_cost: int = 65536
    """Speicher in KB"""
    
    parallelism: int = 4
    """Anzahl paralleler Threads"""
    
    variant: str = "id"
    """Variante: 'id', 'd', oder 'i'"""


@dataclass
class BalloonParams(KDFParams):
    """Parameter für Balloon Hashing."""
    time_cost: int = 3
    """Anzahl Iterationen"""
    
    space_cost: int = 16384
    """Speicher in KB"""
    
    parallelism: int = 1
    """Parallelität (meist 1)"""
    
    hash_function: str = "sha256"
    """Unterliegende Hash-Funktion"""


@dataclass
class ScryptParams(KDFParams):
    """Parameter für scrypt."""
    n: int = 16384
    """CPU/Memory cost parameter (power of 2)"""
    
    r: int = 8
    """Block size"""
    
    p: int = 1
    """Parallelization parameter"""


@dataclass
class PBKDF2Params(KDFParams):
    """Parameter für PBKDF2."""
    iterations: int = 600000
    """Anzahl Iterationen"""
    
    hash_function: str = "sha256"
    """Unterliegende Hash-Funktion"""


@dataclass  
class HKDFParams(KDFParams):
    """Parameter für HKDF."""
    hash_function: str = "sha256"
    """Unterliegende Hash-Funktion"""
    
    info: bytes = b""
    """Context/Application-specific info"""


class KDFBase(AlgorithmBase):
    """
    Basis-Klasse für Key Derivation Functions.
    """
    
    # Default-Parameter Klasse (überschreiben in Subklassen)
    params_class: ClassVar[Type[KDFParams]] = KDFParams
    
    @abstractmethod
    def derive(
        self,
        password: bytes,
        salt: bytes,
        params: Optional[KDFParams] = None
    ) -> bytes:
        """
        Leitet einen Schlüssel aus einem Passwort ab.
        
        Args:
            password: Passwort/Input-Keying-Material
            salt: Salt (sollte zufällig sein)
            params: KDF-Parameter (None für Defaults)
            
        Returns:
            Abgeleiteter Schlüssel
        """
        pass
    
    @classmethod
    def default_params(cls) -> KDFParams:
        """Gibt die Standard-Parameter zurück."""
        return cls.params_class()
    
    @classmethod
    def generate_salt(cls, length: Optional[int] = None) -> bytes:
        """Generiert einen zufälligen Salt."""
        if length is None:
            length = cls.default_params().salt_length
        return generate_random_bytes(length)
    
    @classmethod
    def estimate_time(cls, params: Optional[KDFParams] = None) -> float:
        """
        Schätzt die Zeit für eine Ableitung in Sekunden.
        
        Args:
            params: KDF-Parameter (None für Defaults)
            
        Returns:
            Geschätzte Zeit in Sekunden
        """
        # Überschreiben in Subklassen für genauere Schätzung
        return 0.0
    
    @classmethod
    def estimate_memory(cls, params: Optional[KDFParams] = None) -> int:
        """
        Schätzt den Speicherbedarf in Bytes.
        
        Args:
            params: KDF-Parameter (None für Defaults)
            
        Returns:
            Geschätzter Speicher in Bytes
        """
        # Überschreiben in Subklassen
        return 0
    
    @classmethod
    def validate_params(cls, params: KDFParams) -> None:
        """
        Validiert KDF-Parameter.
        
        Raises:
            ValidationError: Bei ungültigen Parametern
        """
        if params.output_length < 1:
            raise ValidationError("output_length must be positive")
        if params.salt_length < 8:
            raise ValidationError("salt_length must be at least 8 bytes")
    
    @classmethod
    def params_info(cls) -> Dict[str, Dict[str, Any]]:
        """
        Gibt Informationen über verfügbare Parameter zurück.
        
        Returns:
            Dict mit Parameter-Infos (name -> {type, default, min, max, description})
        """
        # Überschreiben in Subklassen
        return {}


# ============================================================================
# Argon2 Family
# ============================================================================

class Argon2id(KDFBase):
    """
    Argon2id - Empfohlene Variante für Passwort-Hashing.
    
    Kombiniert die Vorteile von Argon2i (Side-Channel-Resistenz)
    und Argon2d (GPU-Resistenz).
    """
    
    params_class = Argon2Params
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="argon2id",
            display_name="Argon2id",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Argon2id - recommended password hashing (memory-hard, GPU-resistant)",
            aliases=("argon2",),
            references=(
                "RFC 9106",
                "PHC Winner",
            ),
        )
    
    def derive(
        self,
        password: bytes,
        salt: bytes,
        params: Optional[Argon2Params] = None
    ) -> bytes:
        if params is None:
            params = self.default_params()
        
        self.validate_params(params)
        
        from argon2.low_level import hash_secret_raw, Type
        
        argon_type = {
            "id": Type.ID,
            "d": Type.D,
            "i": Type.I,
        }.get(params.variant, Type.ID)
        
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.output_length,
            type=argon_type,
        )
    
    @classmethod
    def estimate_time(cls, params: Optional[Argon2Params] = None) -> float:
        if params is None:
            params = cls.default_params()
        # Grobe Schätzung: ~0.1s pro time_cost bei 64MB
        base_time = 0.1
        memory_factor = params.memory_cost / 65536
        return base_time * params.time_cost * memory_factor
    
    @classmethod
    def estimate_memory(cls, params: Optional[Argon2Params] = None) -> int:
        if params is None:
            params = cls.default_params()
        return params.memory_cost * 1024  # KB zu Bytes
    
    @classmethod
    def params_info(cls) -> Dict[str, Dict[str, Any]]:
        return {
            "time_cost": {
                "type": "int",
                "default": 3,
                "min": 1,
                "max": 100,
                "description": "Number of iterations",
            },
            "memory_cost": {
                "type": "int",
                "default": 65536,
                "min": 8192,
                "max": 4194304,
                "description": "Memory usage in KB",
            },
            "parallelism": {
                "type": "int",
                "default": 4,
                "min": 1,
                "max": 64,
                "description": "Number of parallel threads",
            },
        }


class Argon2d(KDFBase):
    """
    Argon2d - Maximale GPU-Resistenz.
    
    Anfälliger für Side-Channel-Angriffe als Argon2id,
    aber stärker gegen GPU-Cracking.
    """
    
    params_class = Argon2Params
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="argon2d",
            display_name="Argon2d",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="Argon2d - maximum GPU resistance (use Argon2id for general use)",
            aliases=(),
            references=("RFC 9106",),
        )
    
    def derive(
        self,
        password: bytes,
        salt: bytes,
        params: Optional[Argon2Params] = None
    ) -> bytes:
        if params is None:
            params = Argon2Params(variant="d")
        else:
            params = Argon2Params(
                output_length=params.output_length,
                salt_length=params.salt_length,
                time_cost=params.time_cost,
                memory_cost=params.memory_cost,
                parallelism=params.parallelism,
                variant="d",
            )
        
        argon2id = Argon2id()
        return argon2id.derive(password, salt, params)
    
    @classmethod
    def estimate_time(cls, params: Optional[Argon2Params] = None) -> float:
        return Argon2id.estimate_time(params)
    
    @classmethod
    def estimate_memory(cls, params: Optional[Argon2Params] = None) -> int:
        return Argon2id.estimate_memory(params)


# ============================================================================
# Balloon Hashing
# ============================================================================

class Balloon(KDFBase):
    """
    Balloon Hashing - Memory-hard KDF mit einfacher Analyse.
    
    Beweisbar memory-hard, gute Alternative zu Argon2.
    """
    
    params_class = BalloonParams
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="balloon",
            display_name="Balloon Hashing",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Balloon Hashing - provably memory-hard KDF",
            aliases=("balloon-sha256",),
            references=("Boneh et al., 2016",),
        )
    
    @classmethod
    def is_available(cls) -> bool:
        try:
            from balloon_hashing import balloon
            return True
        except ImportError:
            # Fallback-Implementierung prüfen
            try:
                from ..balloon import balloon_hash
                return True
            except ImportError:
                return False
    
    def derive(
        self,
        password: bytes,
        salt: bytes,
        params: Optional[BalloonParams] = None
    ) -> bytes:
        self.check_available()
        
        if params is None:
            params = self.default_params()
        
        self.validate_params(params)
        
        try:
            from balloon_hashing import balloon
            return balloon(
                password,
                salt,
                space_cost=params.space_cost,
                time_cost=params.time_cost,
                parallel_cost=params.parallelism,
                output_len=params.output_length,
            )
        except ImportError:
            # Fallback
            from ..balloon import balloon_hash
            return balloon_hash(
                password,
                salt,
                space_cost=params.space_cost,
                time_cost=params.time_cost,
                output_length=params.output_length,
            )
    
    @classmethod
    def estimate_memory(cls, params: Optional[BalloonParams] = None) -> int:
        if params is None:
            params = cls.default_params()
        return params.space_cost * 1024


# ============================================================================
# scrypt
# ============================================================================

class Scrypt(KDFBase):
    """
    scrypt - Memory-hard KDF.
    
    Älterer Standard, gut unterstützt aber weniger flexibel als Argon2.
    """
    
    params_class = ScryptParams
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="scrypt",
            display_name="scrypt",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="scrypt - memory-hard KDF (older standard)",
            aliases=(),
            references=("RFC 7914",),
        )
    
    def derive(
        self,
        password: bytes,
        salt: bytes,
        params: Optional[ScryptParams] = None
    ) -> bytes:
        if params is None:
            params = self.default_params()
        
        self.validate_params(params)
        
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as CryptoScrypt
        from cryptography.hazmat.backends import default_backend
        
        kdf = CryptoScrypt(
            salt=salt,
            length=params.output_length,
            n=params.n,
            r=params.r,
            p=params.p,
            backend=default_backend(),
        )
        return kdf.derive(password)
    
    @classmethod
    def estimate_memory(cls, params: Optional[ScryptParams] = None) -> int:
        if params is None:
            params = cls.default_params()
        # scrypt memory: 128 * N * r bytes
        return 128 * params.n * params.r


# ============================================================================
# PBKDF2
# ============================================================================

class PBKDF2(KDFBase):
    """
    PBKDF2 - Ältester Standard, weit verbreitet.
    
    Nicht memory-hard, nur für Legacy/Kompatibilität empfohlen.
    """
    
    params_class = PBKDF2Params
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="pbkdf2",
            display_name="PBKDF2",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.LEGACY,
            description="PBKDF2 - legacy KDF (not memory-hard, use Argon2 instead)",
            aliases=("pbkdf2-sha256",),
            references=("RFC 8018", "NIST SP 800-132"),
        )
    
    def derive(
        self,
        password: bytes,
        salt: bytes,
        params: Optional[PBKDF2Params] = None
    ) -> bytes:
        if params is None:
            params = self.default_params()
        
        self.validate_params(params)
        
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        hash_algo = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }.get(params.hash_function.lower(), hashes.SHA256())
        
        kdf = PBKDF2HMAC(
            algorithm=hash_algo,
            length=params.output_length,
            salt=salt,
            iterations=params.iterations,
            backend=default_backend(),
        )
        return kdf.derive(password)


# ============================================================================
# HKDF
# ============================================================================

class HKDF(KDFBase):
    """
    HKDF - Key Derivation für bereits starke Schlüssel.
    
    Nicht für Passwörter! Nur für Schlüssel-Expansion.
    """
    
    params_class = HKDFParams
    
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="hkdf",
            display_name="HKDF",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="HKDF - key expansion (NOT for passwords!)",
            aliases=("hkdf-sha256",),
            references=("RFC 5869",),
        )
    
    def derive(
        self,
        password: bytes,  # Eigentlich IKM (Input Keying Material)
        salt: bytes,
        params: Optional[HKDFParams] = None
    ) -> bytes:
        if params is None:
            params = self.default_params()
        
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF as CryptoHKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        hash_algo = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }.get(params.hash_function.lower(), hashes.SHA256())
        
        hkdf = CryptoHKDF(
            algorithm=hash_algo,
            length=params.output_length,
            salt=salt if salt else None,
            info=params.info,
            backend=default_backend(),
        )
        return hkdf.derive(password)


# ============================================================================
# KDF Registry
# ============================================================================

class KDFRegistry(RegistryBase[KDFBase]):
    """
    Registry für Key Derivation Functions.
    
    Usage:
        kdf = KDFRegistry.default().get("argon2id")
        key = kdf.derive(password, salt)
    """
    
    _instance: ClassVar[Optional["KDFRegistry"]] = None
    
    @classmethod
    def default(cls) -> "KDFRegistry":
        """Gibt die Singleton-Instanz mit allen Standard-KDFs zurück."""
        if cls._instance is None:
            cls._instance = cls()
            # Argon2 family
            cls._instance.register(Argon2id)
            cls._instance.register(Argon2d)
            # Others
            cls._instance.register(Balloon)
            cls._instance.register(Scrypt)
            cls._instance.register(PBKDF2)
            cls._instance.register(HKDF)
        return cls._instance
    
    @classmethod
    def reset(cls) -> None:
        """Setzt die Singleton-Instanz zurück (für Tests)."""
        cls._instance = None
    
    def get_password_kdfs(self, only_available: bool = True) -> Dict[str, AlgorithmInfo]:
        """
        Gibt nur für Passwörter geeignete KDFs zurück.
        
        Excludiert HKDF da nicht für Passwörter geeignet.
        """
        result = {}
        exclude = {"hkdf"}
        for name, algo_class in self._algorithms.items():
            if name in exclude:
                continue
            if only_available and not algo_class.is_available():
                continue
            result[name] = algo_class.info()
        return result


# Convenience function
def get_kdf(name: str) -> KDFBase:
    """Shortcut für KDFRegistry.default().get(name)."""
    return KDFRegistry.default().get(name)
```

---

## Teil 5: Public API

### 5.1 Package __init__

**Datei:** `openssl_encrypt/modules/registry/__init__.py`

```python
"""
Algorithm Registry System.

Einheitliche Verwaltung von kryptographischen Algorithmen.

Usage:
    from openssl_encrypt.modules.registry import (
        CipherRegistry, HashRegistry, KDFRegistry,
        get_cipher, get_hash, get_kdf,
    )
    
    # Cipher
    cipher = get_cipher("aes-256-gcm")
    ciphertext = cipher.encrypt(key, nonce, plaintext)
    
    # Hash
    hasher = get_hash("sha256")
    digest = hasher.hash(data)
    
    # KDF
    kdf = get_kdf("argon2id")
    derived_key = kdf.derive(password, salt)
"""

# Base classes
from .base import (
    AlgorithmBase,
    AlgorithmInfo,
    AlgorithmCategory,
    SecurityLevel,
    RegistryBase,
    AlgorithmError,
    AlgorithmNotAvailableError,
    AlgorithmNotFoundError,
    ValidationError,
    AuthenticationError,
)

# Cipher
from .cipher_registry import (
    CipherBase,
    CipherRegistry,
    AES256GCM,
    ChaCha20Poly1305,
    Threefish512,
    CascadeCipher,
    get_cipher,
)

# Hash
from .hash_registry import (
    HashBase,
    HashRegistry,
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    BLAKE2b,
    BLAKE2s,
    get_hash,
)

# KDF
from .kdf_registry import (
    KDFBase,
    KDFParams,
    Argon2Params,
    BalloonParams,
    ScryptParams,
    PBKDF2Params,
    HKDFParams,
    KDFRegistry,
    Argon2id,
    Argon2d,
    Balloon,
    Scrypt,
    PBKDF2,
    HKDF,
    get_kdf,
)

__all__ = [
    # Base
    "AlgorithmBase",
    "AlgorithmInfo",
    "AlgorithmCategory",
    "SecurityLevel",
    "RegistryBase",
    "AlgorithmError",
    "AlgorithmNotAvailableError",
    "AlgorithmNotFoundError",
    "ValidationError",
    "AuthenticationError",
    # Cipher
    "CipherBase",
    "CipherRegistry",
    "AES256GCM",
    "ChaCha20Poly1305",
    "Threefish512",
    "CascadeCipher",
    "get_cipher",
    # Hash
    "HashBase",
    "HashRegistry",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3_256",
    "SHA3_384",
    "SHA3_512",
    "BLAKE2b",
    "BLAKE2s",
    "get_hash",
    # KDF
    "KDFBase",
    "KDFParams",
    "Argon2Params",
    "BalloonParams",
    "ScryptParams",
    "PBKDF2Params",
    "HKDFParams",
    "KDFRegistry",
    "Argon2id",
    "Argon2d",
    "Balloon",
    "Scrypt",
    "PBKDF2",
    "HKDF",
    "get_kdf",
]
```

---

## Teil 6: CLI Integration

### 6.1 Algorithmus-Listing Commands

**Datei:** `openssl_encrypt/cli_registry.py`

```python
"""
CLI Commands für Algorithm Registry.
"""

import click
from typing import Optional


@click.group()
def algorithms():
    """Listet verfügbare kryptographische Algorithmen."""
    pass


@algorithms.command("ciphers")
@click.option("--all", "show_all", is_flag=True, help="Auch nicht installierte anzeigen")
@click.option("--json", "as_json", is_flag=True, help="Ausgabe als JSON")
def list_ciphers(show_all: bool, as_json: bool):
    """Listet verfügbare Cipher."""
    from .modules.registry import CipherRegistry
    
    registry = CipherRegistry.default()
    
    if as_json:
        import json
        data = {}
        for name, (info, available) in registry.list_all().items():
            data[name] = {
                "display_name": info.display_name,
                "key_size_bits": info.key_size * 8,
                "security_bits": info.security_bits,
                "pq_security_bits": info.pq_security_bits,
                "available": available,
                "description": info.description,
            }
        click.echo(json.dumps(data, indent=2))
        return
    
    if show_all:
        ciphers = registry.list_all()
    else:
        ciphers = {name: (info, True) for name, info in registry.list_available().items()}
    
    click.echo("Cipher Algorithms:\n")
    for name, (info, available) in sorted(ciphers.items()):
        status = "✓" if available else "✗ not installed"
        click.echo(f"  {info.display_name} [{name}] {status}")
        click.echo(f"    Key: {info.key_size * 8}-bit | PQ Security: {info.pq_security_bits}-bit")
        click.echo(f"    {info.description}")
        if info.aliases:
            click.echo(f"    Aliases: {', '.join(info.aliases)}")
        click.echo()


@algorithms.command("hashes")
@click.option("--all", "show_all", is_flag=True, help="Auch nicht verfügbare anzeigen")
@click.option("--json", "as_json", is_flag=True, help="Ausgabe als JSON")
def list_hashes(show_all: bool, as_json: bool):
    """Listet verfügbare Hash-Funktionen."""
    from .modules.registry import HashRegistry
    
    registry = HashRegistry.default()
    
    if as_json:
        import json
        data = {}
        for name, info in registry.list_available().items():
            data[name] = {
                "display_name": info.display_name,
                "output_size_bits": info.output_size * 8,
                "security_bits": info.security_bits,
                "pq_security_bits": info.pq_security_bits,
                "description": info.description,
            }
        click.echo(json.dumps(data, indent=2))
        return
    
    hashes = registry.list_available()
    
    click.echo("Hash Algorithms:\n")
    
    # Gruppieren nach Familie
    families = {
        "SHA-2": ["sha256", "sha384", "sha512"],
        "SHA-3": ["sha3-256", "sha3-384", "sha3-512"],
        "BLAKE2": ["blake2b", "blake2s"],
    }
    
    for family, members in families.items():
        click.echo(f"  {family}:")
        for name in members:
            if name in hashes:
                info = hashes[name]
                click.echo(f"    {info.display_name} [{name}]")
                click.echo(f"      Output: {info.output_size * 8}-bit | PQ: {info.pq_security_bits}-bit")
        click.echo()


@algorithms.command("kdfs")
@click.option("--all", "show_all", is_flag=True, help="Auch nicht verfügbare anzeigen")
@click.option("--json", "as_json", is_flag=True, help="Ausgabe als JSON")
def list_kdfs(show_all: bool, as_json: bool):
    """Listet verfügbare Key Derivation Functions."""
    from .modules.registry import KDFRegistry
    
    registry = KDFRegistry.default()
    
    if as_json:
        import json
        data = {}
        for name, (info, available) in registry.list_all().items():
            data[name] = {
                "display_name": info.display_name,
                "security_level": info.security_level.value,
                "available": available,
                "description": info.description,
            }
        click.echo(json.dumps(data, indent=2))
        return
    
    if show_all:
        kdfs = registry.list_all()
    else:
        kdfs = {name: (info, True) for name, info in registry.list_available().items()}
    
    click.echo("Key Derivation Functions:\n")
    
    # Nach Security Level gruppieren
    by_level = {}
    for name, (info, available) in kdfs.items():
        level = info.security_level.value
        if level not in by_level:
            by_level[level] = []
        by_level[level].append((name, info, available))
    
    level_order = ["standard", "high", "paranoid", "legacy"]
    level_emoji = {
        "standard": "✓",
        "high": "⬆",
        "paranoid": "🔒",
        "legacy": "⚠",
    }
    
    for level in level_order:
        if level not in by_level:
            continue
        click.echo(f"  {level_emoji.get(level, '')} {level.upper()}:")
        for name, info, available in sorted(by_level[level]):
            status = "" if available else " [not installed]"
            click.echo(f"    {info.display_name} [{name}]{status}")
            click.echo(f"      {info.description}")
        click.echo()


@algorithms.command("info")
@click.argument("name")
def algorithm_info(name: str):
    """Zeigt Details zu einem Algorithmus."""
    from .modules.registry import CipherRegistry, HashRegistry, KDFRegistry
    
    # In allen Registries suchen
    registries = [
        ("Cipher", CipherRegistry.default()),
        ("Hash", HashRegistry.default()),
        ("KDF", KDFRegistry.default()),
    ]
    
    for category, registry in registries:
        if registry.exists(name):
            info = registry.get_info(name)
            available = registry.is_available(name)
            
            click.echo(f"\n{info.display_name}")
            click.echo("=" * len(info.display_name))
            click.echo(f"\nCategory: {category}")
            click.echo(f"Canonical Name: {info.name}")
            click.echo(f"Available: {'Yes' if available else 'No'}")
            click.echo(f"\nSecurity:")
            click.echo(f"  Classical: {info.security_bits}-bit")
            click.echo(f"  Post-Quantum: {info.pq_security_bits}-bit")
            click.echo(f"  Level: {info.security_level.value}")
            
            click.echo(f"\nDescription:")
            click.echo(f"  {info.description}")
            
            if info.aliases:
                click.echo(f"\nAliases: {', '.join(info.aliases)}")
            
            if info.key_size:
                click.echo(f"\nKey Size: {info.key_size * 8} bits ({info.key_size} bytes)")
            if info.output_size:
                click.echo(f"Output Size: {info.output_size * 8} bits ({info.output_size} bytes)")
            if info.block_size:
                click.echo(f"Block Size: {info.block_size * 8} bits ({info.block_size} bytes)")
            if info.nonce_size:
                click.echo(f"Nonce Size: {info.nonce_size * 8} bits ({info.nonce_size} bytes)")
            
            if info.references:
                click.echo(f"\nReferences:")
                for ref in info.references:
                    click.echo(f"  • {ref}")
            
            click.echo()
            return
    
    click.echo(f"Algorithm '{name}' not found.", err=True)
    click.echo("\nUse 'openssl_encrypt algorithms ciphers|hashes|kdfs' to list available algorithms.")
    raise SystemExit(1)
```

---

## Teil 7: Migration

### 7.1 Bestehenden Code migrieren

**Beispiel Migration in `crypt_core.py`:**

```python
# VORHER:
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_data(key, nonce, plaintext):
    cipher = AESGCM(key)
    return cipher.encrypt(nonce, plaintext, None)


# NACHHER:
from .registry import get_cipher

def encrypt_data(key, nonce, plaintext, cipher_name="aes-256-gcm"):
    cipher = get_cipher(cipher_name)
    return cipher.encrypt(key, nonce, plaintext, None)
```

### 7.2 Telemetry-Filter Update

```python
# VORHER (hardcoded):
ALLOWED_CIPHERS = ["aes-256-gcm", "chacha20-poly1305"]

# NACHHER (dynamisch):
from .registry import CipherRegistry
ALLOWED_CIPHERS = CipherRegistry.default().allowed_values()
```

### 7.3 Config-Wizard Update

```python
# VORHER (hardcoded):
cipher_choices = ["aes-256-gcm", "chacha20-poly1305"]

# NACHHER (dynamisch):
from .registry import CipherRegistry
cipher_choices = list(CipherRegistry.default().list_available().keys())
```

---

## Teil 8: Tests

**Datei:** `tests/test_registry.py`

```python
"""Tests für Algorithm Registry System."""

import pytest
from openssl_encrypt.modules.registry import (
    CipherRegistry, HashRegistry, KDFRegistry,
    get_cipher, get_hash, get_kdf,
    AlgorithmNotFoundError, AuthenticationError, ValidationError,
    Argon2Params,
)


class TestCipherRegistry:
    """Tests für CipherRegistry."""
    
    def test_get_aes(self):
        cipher = get_cipher("aes-256-gcm")
        assert cipher.info().name == "aes-256-gcm"
    
    def test_get_by_alias(self):
        cipher = get_cipher("aes")
        assert cipher.info().name == "aes-256-gcm"
    
    def test_not_found(self):
        with pytest.raises(AlgorithmNotFoundError):
            get_cipher("nonexistent")
    
    def test_roundtrip_aes(self):
        cipher = get_cipher("aes-256-gcm")
        key = cipher.generate_key()
        nonce = cipher.generate_nonce()
        plaintext = b"Hello, World!"
        
        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        
        assert decrypted == plaintext
    
    def test_roundtrip_chacha(self):
        cipher = get_cipher("chacha20")
        key = cipher.generate_key()
        nonce = cipher.generate_nonce()
        plaintext = b"Hello, ChaCha!"
        
        ciphertext = cipher.encrypt(key, nonce, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)
        
        assert decrypted == plaintext
    
    def test_tampered_data_fails(self):
        cipher = get_cipher("aes-256-gcm")
        key = cipher.generate_key()
        nonce = cipher.generate_nonce()
        
        ciphertext = bytearray(cipher.encrypt(key, nonce, b"Secret"))
        ciphertext[0] ^= 0xFF
        
        with pytest.raises(AuthenticationError):
            cipher.decrypt(key, nonce, bytes(ciphertext))
    
    def test_invalid_key_size(self):
        cipher = get_cipher("aes-256-gcm")
        with pytest.raises(ValidationError):
            cipher.encrypt(b"short", cipher.generate_nonce(), b"data")
    
    def test_list_available(self):
        available = CipherRegistry.default().list_available()
        assert "aes-256-gcm" in available
        assert "chacha20-poly1305" in available


class TestHashRegistry:
    """Tests für HashRegistry."""
    
    def test_sha256(self):
        hasher = get_hash("sha256")
        digest = hasher.hash(b"test")
        assert len(digest) == 32
    
    def test_sha512(self):
        hasher = get_hash("sha512")
        digest = hasher.hash(b"test")
        assert len(digest) == 64
    
    def test_blake2b(self):
        hasher = get_hash("blake2b")
        digest = hasher.hash(b"test")
        assert len(digest) == 64
    
    def test_verify(self):
        hasher = get_hash("sha256")
        data = b"test data"
        digest = hasher.hash(data)
        
        assert hasher.verify(data, digest)
        assert not hasher.verify(b"wrong", digest)
    
    def test_hex_digest(self):
        hasher = get_hash("sha256")
        hex_digest = hasher.hex_digest(b"test")
        assert len(hex_digest) == 64
        assert all(c in "0123456789abcdef" for c in hex_digest)


class TestKDFRegistry:
    """Tests für KDFRegistry."""
    
    def test_argon2id(self):
        kdf = get_kdf("argon2id")
        salt = kdf.generate_salt()
        key = kdf.derive(b"password", salt)
        assert len(key) == 32
    
    def test_argon2id_custom_params(self):
        kdf = get_kdf("argon2id")
        params = Argon2Params(
            time_cost=2,
            memory_cost=32768,
            parallelism=2,
            output_length=64,
        )
        salt = kdf.generate_salt()
        key = kdf.derive(b"password", salt, params)
        assert len(key) == 64
    
    def test_scrypt(self):
        kdf = get_kdf("scrypt")
        salt = kdf.generate_salt()
        key = kdf.derive(b"password", salt)
        assert len(key) == 32
    
    def test_pbkdf2(self):
        kdf = get_kdf("pbkdf2")
        salt = kdf.generate_salt()
        key = kdf.derive(b"password", salt)
        assert len(key) == 32
    
    def test_deterministic(self):
        kdf = get_kdf("argon2id")
        salt = b"fixed_salt_16by"
        
        key1 = kdf.derive(b"password", salt)
        key2 = kdf.derive(b"password", salt)
        
        assert key1 == key2
    
    def test_different_passwords(self):
        kdf = get_kdf("argon2id")
        salt = b"fixed_salt_16by"
        
        key1 = kdf.derive(b"password1", salt)
        key2 = kdf.derive(b"password2", salt)
        
        assert key1 != key2
```

---

## Teil 9: Implementierungsreihenfolge

### Phase 1: Base Classes (1 Tag)
1. `registry/base.py` - AlgorithmBase, AlgorithmInfo, RegistryBase
2. `registry/utils.py` - Shared utilities
3. Unit Tests für Base Classes

### Phase 2: Cipher Registry (1 Tag)
4. `registry/cipher_registry.py` - CipherBase, AES, ChaCha
5. Threefish/Cascade als Stubs (is_available=False)
6. Unit Tests für Cipher

### Phase 3: Hash Registry (0.5 Tag)
7. `registry/hash_registry.py` - Alle Hash-Implementierungen
8. Unit Tests für Hashes

### Phase 4: KDF Registry (1 Tag)
9. `registry/kdf_registry.py` - Alle KDF-Implementierungen
10. Parameter-Klassen
11. Unit Tests für KDFs

### Phase 5: Integration (1 Tag)
12. `registry/__init__.py` - Public API
13. CLI Commands (`cli_registry.py`)
14. Migration bestehender Code-Stellen

### Phase 6: Polish (0.5 Tag)
15. Dokumentation
16. Telemetry-Filter Update
17. Config-Wizard Update

**Geschätzter Gesamtaufwand: 5 Tage**

---

## Offene Entscheidungen

1. **Singleton vs Factory?**
   - Aktuell: Singleton (`Registry.default()`)
   - Alternative: Factory für bessere Testbarkeit
   - Empfehlung: Singleton mit `reset()` für Tests

2. **Plugin-System für externe Algorithmen?**
   - Entry Points für Plugins?
   - Empfehlung: Später, erstmal Core stabilisieren

3. **Deprecation Warnings für Legacy?**
   - PBKDF2 warnen?
   - Empfehlung: Ja, mit `warnings.warn()`

---

**Erstellt**: 27. Dezember 2025
**Für**: Claude Code Implementation
**Version**: 1.0
**Geschätzter Aufwand**: 5 Tage
