# Implementierungsplan: Asymmetrischer Austausch-Modus

## Übersicht

Erweiterung von `openssl_encrypt` um einen asymmetrischen Modus für sicheren Datenaustausch ohne Passwort-Sharing. Der Empfänger durchläuft weiterhin die vollständige KDF-Chain, erhält aber das Passwort asymmetrisch verschlüsselt.

### Hauptziele

1. **Kein Passwort-Sharing**: Sender verschlüsselt mit Public Key des Empfängers
2. **DoS-Schutz**: Metadaten-Signatur ermöglicht Validierung VOR der teuren KDF
3. **KDF-Chain bleibt aktiv**: Empfänger durchläuft die volle Chain (Defense in Depth)
4. **Post-Quantum-Sicherheit**: ML-KEM für Key Exchange, ML-DSA für Signaturen

---

## Architektur

### Kryptographische Komponenten

| Komponente | Algorithmus | Zweck |
|------------|-------------|-------|
| Key Encapsulation | ML-KEM-768 (default) | Passwort-Verschlüsselung für Empfänger |
| Signatur | ML-DSA-65 (default) | Metadaten-Authentifizierung (DoS-Schutz) |
| Passwort-Verschlüsselung | AES-256-GCM | Wrapping des Random-Passworts |
| Daten-Verschlüsselung | Existing (AES-GCM, ChaCha20, etc.) | Unverändert |

### Schlüssel-Typen pro User

```
Identity/
├── encryption/
│   ├── public.pem      # ML-KEM Public Key (empfängt Daten)
│   └── private.pem     # ML-KEM Private Key
└── signing/
    ├── public.pem      # ML-DSA Public Key (verifiziert Signaturen)
    └── private.pem     # ML-DSA Private Key (signiert Metadaten)
```

---

## Datenfluss

### Verschlüsselung (Sender → Empfänger)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. RANDOM PASSWORD GENERIERUNG                                  │
│    random_password = secrets.token_bytes(32)                    │
│    (256-bit Entropie, nicht user-gewählt)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. KDF-CHAIN (wie bisher)                                       │
│    random_password + salt                                       │
│         → [Hash Rounds: SHA512, BLAKE2b, etc.]                  │
│         → [KDFs: Argon2, Balloon, Scrypt, etc.]                 │
│         → encryption_key                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. DATEN VERSCHLÜSSELN (wie bisher)                             │
│    encrypt(plaintext, encryption_key) → ciphertext              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. PASSWORT FÜR EMPFÄNGER VERSCHLÜSSELN                         │
│    a) KEM.encap(recipient_public_key)                           │
│       → shared_secret + encapsulated_key                        │
│    b) AES-GCM(shared_secret, random_password)                   │
│       → encrypted_password                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. METADATEN SIGNIEREN                                          │
│    metadata = {                                                 │
│      derivation_config, asymmetric_info, encryption_info        │
│    }                                                            │
│    signature = ML-DSA.sign(sender_signing_key, metadata)        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. OUTPUT                                                       │
│    [metadata + signature]:[ciphertext]                          │
└─────────────────────────────────────────────────────────────────┘
```

### Entschlüsselung (Empfänger)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. SIGNATUR PRÜFEN (SCHNELL - VOR KDF!)                         │
│    ML-DSA.verify(sender_public_key, metadata, signature)        │
│    → FAIL: Abbruch mit Fehler "Invalid signature"               │
│    → OK: Weiter zu Schritt 2                                    │
│                                                                 │
│    ⚠️  KRITISCH: Dieser Check MUSS vor der KDF erfolgen!        │
│    Das ist der DoS-Schutz.                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. PASSWORT ENTSCHLÜSSELN                                       │
│    a) KEM.decap(recipient_private_key, encapsulated_key)        │
│       → shared_secret                                           │
│    b) AES-GCM.decrypt(shared_secret, encrypted_password)        │
│       → random_password                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. KDF-CHAIN DURCHLAUFEN                                        │
│    random_password + salt                                       │
│         → [Hash Rounds]                                         │
│         → [KDFs]                                                │
│         → encryption_key                                        │
│                                                                 │
│    Jetzt sicher, weil Metadaten bereits verifiziert!            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. DATEN ENTSCHLÜSSELN                                          │
│    decrypt(ciphertext, encryption_key) → plaintext              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Metadaten-Format (Version 6)

### Struktur

```json
{
  "format_version": 6,
  "mode": "asymmetric",

  "derivation_config": {
    "salt": "<base64: 16+ bytes>",
    "hash_config": {
      "sha512": { "rounds": 100000 },
      "blake2b": { "rounds": 50000 },
      "sha3_256": { "rounds": 25000 }
    },
    "kdf_config": {
      "argon2": {
        "enabled": true,
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 4,
        "rounds": 5,
        "type": 2
      },
      "balloon": {
        "enabled": true,
        "time_cost": 3,
        "space_cost": 65536,
        "parallelism": 4,
        "rounds": 3
      }
    }
  },

  "asymmetric": {
    "recipient": {
      "key_id": "<fingerprint oder identifier>",
      "algorithm": "ML-KEM-768",
      "encapsulated_key": "<base64: KEM ciphertext>",
      "encrypted_password": "<base64: nonce + AES-GCM ciphertext>"
    },
    "sender": {
      "key_id": "<fingerprint oder identifier>",
      "signing_algorithm": "ML-DSA-65"
    }
  },

  "hashes": {
    "original_hash": "<sha256 hex>"
  },

  "encryption": {
    "algorithm": "aes-gcm",
    "encryption_data": "aes-gcm"
  },

  "signature": {
    "algorithm": "ML-DSA-65",
    "value": "<base64: Signatur über alle Felder außer 'signature'>"
  }
}
```

### Signatur-Scope

Die Signatur deckt ab:
- `format_version`
- `mode`
- `derivation_config` (komplett)
- `asymmetric` (komplett)
- `hashes`
- `encryption`

**NICHT** signiert: `signature` selbst (logisch unmöglich)

### Kanonisierung für Signatur

Um deterministische Signaturen zu gewährleisten:

```python
import json

def canonicalize_for_signature(metadata: dict) -> bytes:
    """
    Erstellt kanonische JSON-Darstellung für Signatur.
    - Sortierte Keys
    - Keine Whitespace
    - UTF-8 Encoding
    """
    # Kopie ohne signature-Feld
    meta_copy = {k: v for k, v in metadata.items() if k != "signature"}

    # Kanonisches JSON
    canonical = json.dumps(
        meta_copy,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    )

    return canonical.encode('utf-8')
```

---

## CLI Interface

### Neue Commands

#### 1. Schlüsselpaar generieren

```bash
# Vollständiges Identity-Keypair (Encryption + Signing)
openssl_encrypt identity create \
  --name "Alice" \
  --email "alice@example.com" \
  --output ~/.openssl_encrypt/identities/alice/

# Nur Encryption-Keypair
openssl_encrypt identity create \
  --name "Alice" \
  --type encryption-only \
  --kem-algorithm ML-KEM-768 \
  --output ./alice_encryption/

# Nur Signing-Keypair
openssl_encrypt identity create \
  --name "Alice" \
  --type signing-only \
  --sig-algorithm ML-DSA-65 \
  --output ./alice_signing/
```

**Output-Struktur:**
```
~/.openssl_encrypt/identities/alice/
├── identity.json           # Metadaten (Name, Email, Fingerprints)
├── encryption_public.pem   # ML-KEM Public Key
├── encryption_private.pem  # ML-KEM Private Key (verschlüsselt mit Passwort)
├── signing_public.pem      # ML-DSA Public Key
└── signing_private.pem     # ML-DSA Private Key (verschlüsselt mit Passwort)
```

#### 2. Public Keys exportieren (zum Teilen)

```bash
# Exportiert nur öffentliche Schlüssel
openssl_encrypt identity export \
  --identity alice \
  --output alice_public_keys/

# Oder als einzelne Datei
openssl_encrypt identity export \
  --identity alice \
  --format bundle \
  --output alice.pubkeys
```

#### 3. Public Keys importieren

```bash
# Public Keys eines Kontakts importieren
openssl_encrypt identity import \
  --file bob.pubkeys \
  --name "Bob"

# Oder aus Verzeichnis
openssl_encrypt identity import \
  --dir bob_public_keys/ \
  --name "Bob"
```

#### 4. Verschlüsselung (asymmetrisch)

```bash
# Für Bob verschlüsseln, mit eigenem Key signieren
openssl_encrypt encrypt \
  --for bob \
  --sign-with alice \
  --input secret.txt \
  --output secret.txt.enc

# Mit expliziten Key-Pfaden
openssl_encrypt encrypt \
  --for-key ./bob_encryption_public.pem \
  --sign-with-key ./alice_signing_private.pem \
  --input secret.txt \
  --output secret.txt.enc

# Mit KDF-Parametern (optional, defaults werden verwendet)
openssl_encrypt encrypt \
  --for bob \
  --sign-with alice \
  --argon2-rounds 10 \
  --balloon-rounds 5 \
  --sha512-rounds 100000 \
  --input secret.txt
```

#### 5. Entschlüsselung (asymmetrisch)

```bash
# Entschlüsseln mit eigenem Key, Signatur von Alice verifizieren
openssl_encrypt decrypt \
  --key bob \
  --verify-from alice \
  --input secret.txt.enc \
  --output secret.txt

# Mit expliziten Key-Pfaden
openssl_encrypt decrypt \
  --key ./bob_encryption_private.pem \
  --verify-key ./alice_signing_public.pem \
  --input secret.txt.enc

# Ohne Signatur-Verifikation (WARNUNG wird angezeigt)
openssl_encrypt decrypt \
  --key bob \
  --no-verify \
  --input secret.txt.enc
```

#### 6. Identity-Management

```bash
# Alle bekannten Identities auflisten
openssl_encrypt identity list

# Details zu einer Identity
openssl_encrypt identity show alice

# Identity löschen
openssl_encrypt identity delete bob

# Private Key Passwort ändern
openssl_encrypt identity change-password alice
```

### Backward Compatibility

Der bestehende symmetrische Modus bleibt unverändert:

```bash
# Symmetrisch (wie bisher) - default wenn --for nicht angegeben
openssl_encrypt encrypt --input file.txt --output file.enc
openssl_encrypt decrypt --input file.enc --output file.txt

# Explizit symmetrisch
openssl_encrypt encrypt --mode symmetric --input file.txt
```

---

## Code-Änderungen

### Neue Module

#### 1. `modules/identity.py`

```python
"""
Identity Management für asymmetrischen Modus.
Verwaltet Encryption + Signing Keypairs.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
import json

@dataclass
class Identity:
    """Repräsentiert eine User-Identity mit Encryption + Signing Keys."""
    name: str
    email: Optional[str]

    # Encryption (ML-KEM)
    encryption_public_key: bytes
    encryption_private_key: Optional[bytes]  # None wenn nur public
    encryption_algorithm: str

    # Signing (ML-DSA)
    signing_public_key: bytes
    signing_private_key: Optional[bytes]  # None wenn nur public
    signing_algorithm: str

    # Metadaten
    fingerprint: str  # SHA256 der Public Keys
    created_at: str

    @classmethod
    def generate(
        cls,
        name: str,
        email: Optional[str] = None,
        kem_algorithm: str = "ML-KEM-768",
        sig_algorithm: str = "ML-DSA-65"
    ) -> "Identity":
        """Generiert neue Identity mit Encryption + Signing Keypairs."""
        ...

    @classmethod
    def load(cls, path: Path, password: Optional[str] = None) -> "Identity":
        """Lädt Identity von Disk."""
        ...

    def save(self, path: Path, password: Optional[str] = None) -> None:
        """Speichert Identity auf Disk. Private Keys werden verschlüsselt."""
        ...

    def export_public(self) -> "Identity":
        """Gibt Kopie ohne Private Keys zurück (zum Teilen)."""
        ...

    def calculate_fingerprint(self) -> str:
        """Berechnet Fingerprint aus Public Keys."""
        ...


class IdentityStore:
    """Verwaltet lokale Identity-Sammlung."""

    def __init__(self, base_path: Path = None):
        self.base_path = base_path or Path.home() / ".openssl_encrypt" / "identities"

    def list_identities(self) -> list[str]:
        """Listet alle bekannten Identity-Namen."""
        ...

    def get(self, name: str) -> Identity:
        """Lädt Identity by Name."""
        ...

    def add(self, identity: Identity) -> None:
        """Fügt neue Identity hinzu."""
        ...

    def remove(self, name: str) -> None:
        """Entfernt Identity."""
        ...

    def get_by_fingerprint(self, fingerprint: str) -> Optional[Identity]:
        """Sucht Identity by Fingerprint."""
        ...
```

#### 2. `modules/asymmetric.py`

```python
"""
Asymmetrischer Verschlüsselungs-Modus.
Implementiert Passwort-Wrapping und Signatur-Logik.
"""

import secrets
from typing import Tuple, Optional
from .identity import Identity
from .pqc import PQCipher
from .secure_memory import SecureBytes, secure_memzero

class AsymmetricEncryption:
    """Handler für asymmetrischen Modus."""

    def __init__(
        self,
        recipient: Identity,
        sender: Optional[Identity] = None,  # Für Signatur
        kem_algorithm: str = "ML-KEM-768",
        sig_algorithm: str = "ML-DSA-65"
    ):
        self.recipient = recipient
        self.sender = sender
        self.kem_algorithm = kem_algorithm
        self.sig_algorithm = sig_algorithm

    def generate_random_password(self, length: int = 32) -> bytes:
        """
        Generiert kryptographisch sicheres Random-Passwort.

        Returns:
            bytes: 256-bit Random-Passwort
        """
        return secrets.token_bytes(length)

    def wrap_password(
        self,
        password: bytes,
        recipient_public_key: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Verschlüsselt Passwort mit Recipient's Public Key.

        Args:
            password: Das zu wrappende Passwort
            recipient_public_key: ML-KEM Public Key des Empfängers

        Returns:
            Tuple[encapsulated_key, encrypted_password]
        """
        # KEM Encapsulation
        kem = PQCipher(self.kem_algorithm)
        # Hinweis: Hier brauchen wir eine Methode die nur encap macht
        # ohne die Daten zu verschlüsseln
        ...

    def unwrap_password(
        self,
        encapsulated_key: bytes,
        encrypted_password: bytes,
        recipient_private_key: bytes
    ) -> bytes:
        """
        Entschlüsselt Passwort mit Recipient's Private Key.

        Args:
            encapsulated_key: KEM Ciphertext
            encrypted_password: AES-GCM verschlüsseltes Passwort
            recipient_private_key: ML-KEM Private Key des Empfängers

        Returns:
            bytes: Entschlüsseltes Passwort
        """
        ...

    def sign_metadata(
        self,
        metadata: dict,
        sender_signing_key: bytes
    ) -> bytes:
        """
        Signiert Metadaten mit Sender's Signing Key.

        Args:
            metadata: Die zu signierenden Metadaten (ohne signature-Feld)
            sender_signing_key: ML-DSA Private Key des Senders

        Returns:
            bytes: Signatur
        """
        canonical = self._canonicalize(metadata)
        # ML-DSA Sign
        ...

    def verify_signature(
        self,
        metadata: dict,
        signature: bytes,
        sender_public_key: bytes
    ) -> bool:
        """
        Verifiziert Metadaten-Signatur.

        KRITISCH: Diese Methode MUSS vor der KDF aufgerufen werden!

        Args:
            metadata: Die signierten Metadaten
            signature: Die zu verifizierende Signatur
            sender_public_key: ML-DSA Public Key des Senders

        Returns:
            bool: True wenn Signatur gültig
        """
        canonical = self._canonicalize(metadata)
        # ML-DSA Verify
        ...

    def _canonicalize(self, metadata: dict) -> bytes:
        """Erstellt kanonische Darstellung für Signatur."""
        import json
        meta_copy = {k: v for k, v in metadata.items() if k != "signature"}
        return json.dumps(
            meta_copy,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')
```

#### 3. `modules/pqc_signing.py`

```python
"""
PQC Signatur-Implementierung (ML-DSA).
"""

from typing import Tuple
import oqs

class PQCSigner:
    """Post-Quantum Signatur mit ML-DSA."""

    SUPPORTED_ALGORITHMS = [
        "ML-DSA-44",   # NIST Level 1
        "ML-DSA-65",   # NIST Level 3 (recommended)
        "ML-DSA-87",   # NIST Level 5
    ]

    def __init__(self, algorithm: str = "ML-DSA-65"):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        self.algorithm = algorithm

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generiert ML-DSA Keypair.

        Returns:
            Tuple[public_key, private_key]
        """
        with oqs.Signature(self.algorithm) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
        return public_key, private_key

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Signiert Nachricht mit Private Key.

        Args:
            message: Zu signierende Nachricht
            private_key: ML-DSA Private Key

        Returns:
            bytes: Signatur
        """
        with oqs.Signature(self.algorithm, private_key) as signer:
            signature = signer.sign(message)
        return signature

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes
    ) -> bool:
        """
        Verifiziert Signatur.

        Args:
            message: Original-Nachricht
            signature: Zu verifizierende Signatur
            public_key: ML-DSA Public Key

        Returns:
            bool: True wenn Signatur gültig
        """
        with oqs.Signature(self.algorithm) as signer:
            return signer.verify(message, signature, public_key)
```

### Änderungen in bestehenden Modulen

#### `crypt_core.py`

Neue Funktionen hinzufügen:

```python
def encrypt_file_asymmetric(
    input_file: str,
    output_file: str,
    recipient: Identity,
    sender: Identity,
    hash_config: dict,
    algorithm: str = "aes-gcm",
    quiet: bool = False,
    progress: bool = False
) -> dict:
    """
    Verschlüsselt Datei im asymmetrischen Modus.

    Args:
        input_file: Pfad zur Eingabedatei
        output_file: Pfad zur Ausgabedatei
        recipient: Identity des Empfängers (braucht encryption_public_key)
        sender: Identity des Senders (braucht signing_private_key)
        hash_config: KDF-Konfiguration
        algorithm: Symmetrischer Algorithmus

    Returns:
        dict: Metadaten der verschlüsselten Datei
    """
    ...


def decrypt_file_asymmetric(
    input_file: str,
    output_file: str,
    recipient: Identity,
    sender_public_key: bytes,
    quiet: bool = False,
    progress: bool = False
) -> bytes:
    """
    Entschlüsselt Datei im asymmetrischen Modus.

    WICHTIG: Verifiziert Signatur VOR der KDF!

    Args:
        input_file: Pfad zur verschlüsselten Datei
        output_file: Pfad zur Ausgabedatei
        recipient: Eigene Identity (braucht encryption_private_key)
        sender_public_key: Public Signing Key des Senders für Verifikation

    Returns:
        bytes: Entschlüsselter Inhalt

    Raises:
        SignatureVerificationError: Bei ungültiger Signatur (VOR KDF!)
        DecryptionError: Bei anderen Fehlern
    """
    ...
```

#### `crypt_cli.py`

Neue CLI-Argumente:

```python
# Asymmetric mode arguments
asymmetric_group = parser.add_argument_group('Asymmetric Mode')

asymmetric_group.add_argument(
    '--for', '--recipient',
    dest='recipient',
    help='Recipient identity name or public key file'
)

asymmetric_group.add_argument(
    '--for-key',
    dest='recipient_key',
    help='Explicit path to recipient encryption public key'
)

asymmetric_group.add_argument(
    '--sign-with',
    dest='sign_identity',
    help='Sender identity name for signing'
)

asymmetric_group.add_argument(
    '--sign-with-key',
    dest='sign_key',
    help='Explicit path to sender signing private key'
)

asymmetric_group.add_argument(
    '--key',
    dest='decrypt_identity',
    help='Own identity for decryption'
)

asymmetric_group.add_argument(
    '--verify-from',
    dest='verify_identity',
    help='Sender identity for signature verification'
)

asymmetric_group.add_argument(
    '--no-verify',
    action='store_true',
    help='Skip signature verification (DANGEROUS - shows warning)'
)
```

---

## Sicherheitsüberlegungen

### DoS-Schutz

```
KRITISCHER ABLAUF BEI ENTSCHLÜSSELUNG:

1. Metadaten parsen (schnell)
2. Signatur extrahieren (schnell)
3. ⚠️  SIGNATUR VERIFIZIEREN (schnell, ~1ms) ⚠️
   │
   ├─→ FAIL: Sofortiger Abbruch
   │         "Error: Invalid metadata signature"
   │         KDF wird NICHT ausgeführt!
   │
   └─→ OK: Weiter
       │
       ▼
4. Passwort entschlüsseln (schnell, KEM decap)
5. KDF-Chain ausführen (teuer, aber jetzt sicher)
6. Daten entschlüsseln
```

### Ohne Signatur-Verifikation

Wenn `--no-verify` verwendet wird:

```
⚠️  WARNING: Signature verification disabled!
⚠️  This file's metadata has NOT been authenticated.
⚠️  A malicious actor could have manipulated the KDF parameters.

DECRYPTION COST ESTIMATE
========================
[... existing estimate output ...]

⚠️  Proceeding without signature verification.
⚠️  Press Ctrl+C within 5 seconds to cancel.
```

### Private Key Schutz

Private Keys werden verschlüsselt gespeichert:

```python
def save_private_key(private_key: bytes, path: Path, password: str) -> None:
    """
    Speichert Private Key verschlüsselt.

    - KDF: Argon2id (time=3, memory=65536, parallelism=4)
    - Encryption: AES-256-GCM
    - Format: Salt (16) + Nonce (12) + Ciphertext + Tag (16)
    """
    salt = secrets.token_bytes(16)

    # Key ableiten
    key = argon2.low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )

    # Verschlüsseln
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, private_key, None)

    # Speichern
    with open(path, 'wb') as f:
        f.write(salt + nonce + ciphertext)
```

### Trust on First Use (TOFU)

Bei erstem Import eines Public Keys:

```
⚠️  NEW IDENTITY: "Bob" (bob@example.com)
    Encryption Key Fingerprint: SHA256:a3b4c5d6e7f8...
    Signing Key Fingerprint:    SHA256:1a2b3c4d5e6f...

    Trust this identity? [y/N]
```

---

## Testszenarien

### Unit Tests

```python
class TestAsymmetricMode:
    """Tests für asymmetrischen Modus."""

    def test_identity_generation(self):
        """Identity-Generierung mit Encryption + Signing Keys."""
        ...

    def test_password_wrap_unwrap(self):
        """Passwort-Wrapping Roundtrip."""
        ...

    def test_metadata_signature(self):
        """Signatur-Erstellung und -Verifikation."""
        ...

    def test_signature_verification_before_kdf(self):
        """Kritisch: Signatur MUSS vor KDF geprüft werden."""
        ...

    def test_manipulated_metadata_rejected(self):
        """Manipulierte Metadaten werden erkannt."""
        ...

    def test_wrong_recipient_key_fails(self):
        """Entschlüsselung mit falschem Key schlägt fehl."""
        ...

    def test_encrypt_decrypt_roundtrip(self):
        """Vollständiger Encrypt/Decrypt-Zyklus."""
        ...

    def test_large_file_handling(self):
        """Große Dateien werden korrekt verarbeitet."""
        ...


class TestDoSProtection:
    """Tests für DoS-Schutz durch Signatur."""

    def test_invalid_signature_no_kdf(self):
        """Bei ungültiger Signatur wird KDF nicht ausgeführt."""
        # Misst Zeit: Muss < 100ms sein
        ...

    def test_manipulated_kdf_params_detected(self):
        """Manipulierte KDF-Parameter werden durch Signatur erkannt."""
        ...

    def test_missing_signature_warning(self):
        """Fehlende Signatur zeigt Warnung."""
        ...
```

### Integration Tests

```python
class TestCLIAsymmetric:
    """CLI Integration Tests."""

    def test_identity_create_command(self):
        """openssl_encrypt identity create"""
        ...

    def test_identity_export_import(self):
        """Export und Import von Public Keys."""
        ...

    def test_encrypt_for_recipient(self):
        """openssl_encrypt encrypt --for bob"""
        ...

    def test_decrypt_with_verification(self):
        """openssl_encrypt decrypt --verify-from alice"""
        ...

    def test_decrypt_no_verify_warning(self):
        """--no-verify zeigt Warnung."""
        ...
```

---

## Migration / Backward Compatibility

### Format-Version 6

- Version 6 ist nur für asymmetrischen Modus
- Bestehende Versionen (3, 4, 5) bleiben für symmetrischen Modus
- Tool erkennt automatisch den Modus anhand der Metadaten

```python
def detect_mode(metadata: dict) -> str:
    """Erkennt Verschlüsselungsmodus aus Metadaten."""
    if metadata.get("mode") == "asymmetric":
        return "asymmetric"
    if "asymmetric" in metadata:
        return "asymmetric"
    return "symmetric"
```

### CLI Defaults

- Ohne `--for`: Symmetrischer Modus (wie bisher)
- Mit `--for`: Asymmetrischer Modus

---

## Offene Fragen

1. **Multiple Recipients**: Soll eine Datei für mehrere Empfänger verschlüsselbar sein?
   - Würde bedeuten: Mehrere `encrypted_password` Einträge
   - Komplexer, aber für Gruppen nützlich

2. **Key Revocation**: Wie werden kompromittierte Keys widerrufen?
   - Externe Revocation List?
   - Expiration Dates auf Keys?

3. **Key Discovery**: Wie findet man Public Keys von anderen?
   - Keyserver?
   - Out-of-band (Email, etc.)?

4. **Hybrid Mode**: Soll es einen Modus geben der sowohl Passwort als auch asymmetrisch akzeptiert?
   - Empfänger kann entweder mit Passwort oder Private Key entschlüsseln

---

## Implementierungs-Reihenfolge

### Phase 1: Grundlagen
1. [ ] `modules/pqc_signing.py` - ML-DSA Wrapper
2. [ ] `modules/identity.py` - Identity-Klasse
3. [ ] Unit Tests für Phase 1

### Phase 2: Asymmetric Core
4. [ ] `modules/asymmetric.py` - Hauptlogik
5. [ ] Metadaten-Format v6
6. [ ] Unit Tests für Phase 2

### Phase 3: Integration
7. [ ] `crypt_core.py` - Neue Encrypt/Decrypt-Funktionen
8. [ ] Signatur-Verifikation VOR KDF sicherstellen
9. [ ] Integration Tests

### Phase 4: CLI
10. [ ] CLI-Argumente hinzufügen
11. [ ] Identity-Management Commands
12. [ ] CLI Tests

### Phase 5: Polish
13. [ ] Dokumentation
14. [ ] Error Messages
15. [ ] Edge Cases
