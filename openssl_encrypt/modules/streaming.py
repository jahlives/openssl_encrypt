"""Streaming chunked encryption/decryption for large files.

This module implements per-chunk AEAD encryption that keeps memory usage
constant (~2-3 MB) regardless of file size. Each chunk is independently
encrypted with its own HKDF-derived nonce and authentication tag.

Format version 12 uses a binary chunked payload:
    base64(JSON_metadata) : OESC <payload_version:u32le> [chunks...] <chunk_count:u32le> <hmac_commitment:32B>

Each chunk:
    [chunk_index: u32le] [ciphertext_len: u32le] [ciphertext + AEAD tag]

Security properties:
    - Nonce reuse prevention: HKDF-derived per-chunk from random 8-byte prefix + chunk index
    - Chunk reordering detection: chunk index bound in per-chunk AAD
    - Chunk truncation detection: chunk count in per-chunk AAD + trailer HMAC
    - Metadata tampering detection: metadata is AAD for every chunk's AEAD
"""

import base64
import hashlib
import hmac as hmac_module
import logging
import os
import secrets
import struct
from typing import Callable, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypt_errors import AuthenticationError, DecryptionError, EncryptionError, ValidationError
from .secure_memory import secure_memzero

logger = logging.getLogger(__name__)

# Constants
STREAMING_MAGIC = b"OESC"
PAYLOAD_VERSION = 1
DEFAULT_CHUNK_SIZE = 1048576  # 1 MB
DEFAULT_STREAMING_THRESHOLD = 10485760  # 10 MB

# Algorithms that support streaming (AEAD ciphers only)
STREAMING_SUPPORTED_ALGORITHMS = {
    "aes-gcm",
    "chacha20-poly1305",
    "xchacha20-poly1305",
    "aes-gcm-siv",
    "aes-ocb3",
    "aes-siv",
    "threefish-512",
    "threefish-1024",
    "cascade",
}

# Algorithms that do NOT support streaming
STREAMING_UNSUPPORTED_ALGORITHMS = {
    "fernet",
    "camellia",
    "ml-kem-512-hybrid",
    "ml-kem-768-hybrid",
    "ml-kem-1024-hybrid",
    "kyber512-hybrid",
    "kyber768-hybrid",
    "kyber1024-hybrid",
    "ml-kem-512-chacha20",
    "ml-kem-768-chacha20",
    "ml-kem-1024-chacha20",
    "hqc-128-hybrid",
    "hqc-192-hybrid",
    "hqc-256-hybrid",
    "mayo-1-hybrid",
    "mayo-3-hybrid",
    "mayo-5-hybrid",
    "cross-128-hybrid",
    "cross-192-hybrid",
    "cross-256-hybrid",
}


def _get_nonce_size(algorithm: str) -> int:
    """Get the appropriate nonce size for a given algorithm.

    Args:
        algorithm: Algorithm name string.

    Returns:
        Nonce size in bytes.
    """
    nonce_sizes = {
        "aes-gcm": 12,
        "chacha20-poly1305": 12,
        "xchacha20-poly1305": 12,  # We derive 12-byte nonces for the underlying cipher
        "aes-gcm-siv": 12,
        "aes-ocb3": 12,
        "aes-siv": 16,
        "threefish-512": 32,
        "threefish-1024": 64,
    }
    return nonce_sizes.get(algorithm, 12)


def derive_chunk_nonce(nonce_prefix: bytes, chunk_index: int, nonce_size: int = 12) -> bytes:
    """Derive a unique per-chunk nonce using HKDF-SHA256.

    Each chunk gets a deterministic, unique nonce derived from a random
    prefix and its chunk index. This prevents nonce reuse even across
    files encrypted with the same key.

    Args:
        nonce_prefix: Random 8-byte prefix generated per encryption.
        chunk_index: Zero-based chunk index.
        nonce_size: Required nonce size in bytes.

    Returns:
        Derived nonce of nonce_size bytes.

    Raises:
        ValidationError: If inputs are invalid.
    """
    if not isinstance(nonce_prefix, (bytes, bytearray)):
        raise ValidationError("nonce_prefix must be bytes")
    if len(nonce_prefix) < 8:
        raise ValidationError("nonce_prefix must be at least 8 bytes")
    if chunk_index < 0:
        raise ValidationError("chunk_index must be non-negative")

    info = b"oesc-chunk-nonce:" + struct.pack(">I", chunk_index)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=nonce_size,
        salt=nonce_prefix,
        info=info,
    )
    return hkdf.derive(nonce_prefix + struct.pack(">I", chunk_index))


def build_chunk_aad(metadata_b64: bytes, chunk_index: int, chunk_count: int) -> bytes:
    """Build per-chunk AAD that binds each chunk to its position.

    The AAD includes:
    - The full base64-encoded metadata (same as one-shot AEAD binding)
    - The chunk index (prevents reordering)
    - The total chunk count (prevents truncation)

    Args:
        metadata_b64: Base64-encoded metadata bytes.
        chunk_index: Zero-based index of this chunk.
        chunk_count: Total number of chunks.

    Returns:
        AAD bytes for this chunk.
    """
    return (
        metadata_b64 + b":" + struct.pack(">I", chunk_index) + b":" + struct.pack(">I", chunk_count)
    )


def encrypt_chunk(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: Optional[bytes],
    algorithm: str,
) -> bytes:
    """Encrypt a single chunk using the specified algorithm.

    Returns only the ciphertext + AEAD tag (no nonce prefix), since
    nonces are derived deterministically.

    Args:
        key: Encryption key.
        nonce: Per-chunk nonce (derived via derive_chunk_nonce).
        plaintext: Chunk data to encrypt.
        aad: Additional authenticated data.
        algorithm: Algorithm name string.

    Returns:
        Ciphertext with AEAD tag appended.

    Raises:
        EncryptionError: If encryption fails.
        ValidationError: If algorithm is unsupported.
    """
    try:
        if algorithm == "aes-gcm":
            cipher = AESGCM(key)
            return cipher.encrypt(nonce, plaintext, aad)

        elif algorithm == "aes-siv":
            cipher = AESSIV(key)
            return cipher.encrypt(plaintext, [aad] if aad else None)

        elif algorithm == "chacha20-poly1305":
            cipher = ChaCha20Poly1305(key)
            return cipher.encrypt(nonce, plaintext, aad)

        elif algorithm == "xchacha20-poly1305":
            # Import from crypt_core to reuse the XChaCha20 wrapper
            from .crypt_core import XChaCha20Poly1305 as XChaCha20

            cipher = XChaCha20(key)
            return cipher.encrypt(nonce, plaintext, aad)

        elif algorithm == "aes-gcm-siv":
            cipher = AESGCMSIV(key)
            return cipher.encrypt(nonce, plaintext, aad)

        elif algorithm == "aes-ocb3":
            cipher = AESOCB3(key)
            return cipher.encrypt(nonce, plaintext, aad)

        elif algorithm == "threefish-512":
            import threefish_native

            return threefish_native.encrypt_512(key, nonce, plaintext, aad)

        elif algorithm == "threefish-1024":
            import threefish_native

            return threefish_native.encrypt_1024(key, nonce, plaintext, aad)

        elif algorithm == "cascade":
            # Cascade is handled at StreamingEncryptor level
            raise ValidationError("Cascade encryption must be handled via StreamingEncryptor")

        else:
            raise ValidationError(f"Unsupported streaming algorithm: {algorithm}")

    except (ValidationError, AuthenticationError):
        raise
    except Exception as e:
        raise EncryptionError(f"Chunk encryption failed: {e}", original_exception=e)


def decrypt_chunk(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: Optional[bytes],
    algorithm: str,
) -> bytes:
    """Decrypt a single chunk using the specified algorithm.

    Args:
        key: Decryption key.
        nonce: Per-chunk nonce (derived via derive_chunk_nonce).
        ciphertext: Encrypted chunk data with AEAD tag.
        aad: Additional authenticated data (must match what was used during encryption).
        algorithm: Algorithm name string.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        AuthenticationError: If AEAD authentication fails.
        DecryptionError: If decryption fails for other reasons.
        ValidationError: If algorithm is unsupported.
    """
    try:
        if algorithm == "aes-gcm":
            cipher = AESGCM(key)
            return cipher.decrypt(nonce, ciphertext, aad)

        elif algorithm == "aes-siv":
            cipher = AESSIV(key)
            return cipher.decrypt(ciphertext, [aad] if aad else None)

        elif algorithm == "chacha20-poly1305":
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ciphertext, aad)

        elif algorithm == "xchacha20-poly1305":
            from .crypt_core import XChaCha20Poly1305 as XChaCha20

            cipher = XChaCha20(key)
            return cipher.decrypt(nonce, ciphertext, aad)

        elif algorithm == "aes-gcm-siv":
            cipher = AESGCMSIV(key)
            return cipher.decrypt(nonce, ciphertext, aad)

        elif algorithm == "aes-ocb3":
            cipher = AESOCB3(key)
            return cipher.decrypt(nonce, ciphertext, aad)

        elif algorithm == "threefish-512":
            import threefish_native

            return threefish_native.decrypt_512(key, nonce, ciphertext, aad)

        elif algorithm == "threefish-1024":
            import threefish_native

            return threefish_native.decrypt_1024(key, nonce, ciphertext, aad)

        elif algorithm == "cascade":
            raise ValidationError("Cascade decryption must be handled via StreamingDecryptor")

        else:
            raise ValidationError(f"Unsupported streaming algorithm: {algorithm}")

    except (ValidationError, AuthenticationError):
        raise
    except Exception as e:
        # Check for authentication errors
        if "tag" in str(e).lower() or "authentication" in str(e).lower():
            raise AuthenticationError(f"Chunk authentication failed: {e}")
        raise DecryptionError(f"Chunk decryption failed: {e}", original_exception=e)


def should_use_streaming(
    file_size: int,
    algorithm: str,
    threshold: int = DEFAULT_STREAMING_THRESHOLD,
    no_streaming: bool = False,
    input_is_bytes: bool = False,
) -> bool:
    """Determine whether to use streaming mode for encryption.

    Args:
        file_size: Size of the input file in bytes.
        algorithm: Algorithm name string.
        threshold: File size threshold for streaming (default: 10 MB).
        no_streaming: If True, always returns False (user disabled streaming).
        input_is_bytes: If True, input is in-memory bytes (no streaming).

    Returns:
        True if streaming should be used.
    """
    if no_streaming:
        return False
    if input_is_bytes:
        return False
    if algorithm in STREAMING_UNSUPPORTED_ALGORITHMS:
        return False
    if algorithm not in STREAMING_SUPPORTED_ALGORITHMS:
        return False
    return file_size >= threshold


def calculate_hash_streaming(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate SHA-256 hash of a file using streaming reads.

    This avoids loading the entire file into memory.

    Args:
        file_path: Path to the file to hash.
        chunk_size: Read buffer size in bytes.

    Returns:
        Hexadecimal SHA-256 hash string.

    Raises:
        ValidationError: If file_path is invalid.
    """
    if not file_path or not isinstance(file_path, str):
        raise ValidationError("file_path must be a non-empty string")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class StreamingEncryptor:
    """Two-pass streaming encryptor for large files.

    Pass 1: Hash the entire file (streaming SHA-256).
    Pass 2: Encrypt the file chunk by chunk.

    The output format is:
        base64(JSON_metadata) : OESC <payload_version:u32le> [chunks...] <chunk_count:u32le> <hmac:32B>

    Each chunk in the payload:
        [chunk_index: u32le] [ciphertext_len: u32le] [ciphertext + AEAD tag]
    """

    def __init__(
        self,
        key: bytes,
        algorithm: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        cascade_encryptor=None,
        cascade_salt: Optional[bytes] = None,
        format_version: Optional[int] = None,
    ):
        """Initialize the streaming encryptor.

        Args:
            key: Encryption key.
            algorithm: Algorithm name string.
            chunk_size: Size of each plaintext chunk in bytes.
            cascade_encryptor: CascadeEncryption instance for cascade mode.
            cascade_salt: Salt for cascade key derivation.
            format_version: File format version. For v12+, HMAC key uses HKDF.
        """
        self.key = key
        self.algorithm = algorithm
        self.chunk_size = chunk_size
        self.cascade_encryptor = cascade_encryptor
        self.cascade_salt = cascade_salt
        self.format_version = format_version
        self.nonce_prefix = secrets.token_bytes(8)
        self.nonce_size = _get_nonce_size(algorithm)

    def _derive_hmac_key(self) -> bytearray:
        """Derive the HMAC key for trailer authentication.

        For format_version >= 12, uses HKDF with domain separation.
        For legacy formats, uses SHA-256(key || constant).

        Returns:
            32-byte HMAC key as bytearray (mutable so caller can secure_memzero it)
        """
        if self.format_version is not None and self.format_version >= 12:
            return bytearray(
                HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"openssl_encrypt-streaming-hmac-key",
                ).derive(self.key)
            )
        else:
            return bytearray(hashlib.sha256(self.key + b"oesc-trailer-hmac").digest())

    def hash_file(self, file_path: str) -> str:
        """Pass 1: Compute streaming SHA-256 hash.

        Args:
            file_path: Path to the input file.

        Returns:
            Hexadecimal SHA-256 hash of the file.
        """
        return calculate_hash_streaming(file_path, self.chunk_size)

    def encrypt_file(
        self,
        input_file: str,
        output_file: str,
        metadata_b64: bytes,
        chunk_count: int,
        quiet: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bool:
        """Pass 2: Encrypt file chunk by chunk, writing streaming output.

        The output format is:
            metadata_b64 : OESC <payload_version:u32le> [chunks...] <chunk_count:u32le> <hmac:32B>

        Args:
            input_file: Path to the plaintext file.
            output_file: Path for the encrypted output file.
            metadata_b64: Base64-encoded metadata (used as AAD prefix).
            chunk_count: Pre-calculated total number of chunks.
            quiet: Suppress progress output.
            progress_callback: Optional callback(chunk_index, chunk_count).

        Returns:
            True on success.

        Raises:
            EncryptionError: If encryption fails.
        """
        # Collect all chunk tags for the trailer HMAC
        chunk_tags: List[bytes] = []

        with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
            # Write metadata + separator
            fout.write(metadata_b64)
            fout.write(b":")

            # Write magic + payload version
            fout.write(STREAMING_MAGIC)
            fout.write(struct.pack("<I", PAYLOAD_VERSION))

            chunk_index = 0
            while True:
                plaintext = fin.read(self.chunk_size)
                if not plaintext:
                    break

                # Derive per-chunk nonce
                nonce = derive_chunk_nonce(self.nonce_prefix, chunk_index, self.nonce_size)

                # Build per-chunk AAD
                aad = build_chunk_aad(metadata_b64, chunk_index, chunk_count)

                # Encrypt the chunk
                if self.algorithm == "cascade" and self.cascade_encryptor:
                    ciphertext = self.cascade_encryptor.encrypt(
                        plaintext,
                        self.key,
                        self.cascade_salt,
                        associated_data=aad,
                        chunk_nonce=nonce,
                    )
                else:
                    ciphertext = encrypt_chunk(self.key, nonce, plaintext, aad, self.algorithm)

                # Collect tag material (last 16 bytes of ciphertext for HMAC)
                tag_material = ciphertext[-16:] if len(ciphertext) >= 16 else ciphertext
                chunk_tags.append(tag_material)

                # Write chunk: [index:u32le] [ciphertext_len:u32le] [ciphertext]
                fout.write(struct.pack("<I", chunk_index))
                fout.write(struct.pack("<I", len(ciphertext)))
                fout.write(ciphertext)

                if progress_callback:
                    progress_callback(chunk_index, chunk_count)

                chunk_index += 1

            if chunk_index != chunk_count:
                raise EncryptionError(
                    f"Chunk count mismatch: expected {chunk_count}, wrote {chunk_index}"
                )

            # Write trailer: chunk_count + HMAC commitment
            fout.write(struct.pack("<I", chunk_count))

            # HMAC-SHA256 over concatenation of all chunk tags
            hmac_key = self._derive_hmac_key()
            try:
                tag_concatenation = b"".join(chunk_tags)
                trailer_hmac = hmac_module.new(hmac_key, tag_concatenation, hashlib.sha256).digest()
                fout.write(trailer_hmac)
            finally:
                secure_memzero(hmac_key)

        return True

    def get_chunk_count(self, file_size: int) -> int:
        """Calculate the number of chunks for a given file size.

        Args:
            file_size: Size of the input file in bytes.

        Returns:
            Number of chunks (at least 1 for non-empty files).
        """
        if file_size == 0:
            return 0
        return (file_size + self.chunk_size - 1) // self.chunk_size


class StreamingDecryptor:
    """Streaming decryptor for chunked encrypted files (format v12).

    Reads and decrypts chunks sequentially, verifying per-chunk AAD
    and the global trailer HMAC.
    """

    def __init__(
        self,
        key: bytes,
        algorithm: str,
        nonce_prefix: bytes,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        cascade_decryptor=None,
        cascade_salt: Optional[bytes] = None,
        format_version: Optional[int] = None,
    ):
        """Initialize the streaming decryptor.

        Args:
            key: Decryption key.
            algorithm: Algorithm name string.
            nonce_prefix: The nonce prefix from metadata.
            chunk_size: Expected chunk size (from metadata).
            cascade_decryptor: CascadeEncryption instance for cascade mode.
            cascade_salt: Salt for cascade key derivation.
            format_version: File format version. For v12+, HMAC key uses HKDF.
        """
        self.key = key
        self.algorithm = algorithm
        self.nonce_prefix = nonce_prefix
        self.chunk_size = chunk_size
        self.nonce_size = _get_nonce_size(algorithm)
        self.cascade_decryptor = cascade_decryptor
        self.cascade_salt = cascade_salt
        self.format_version = format_version

    def _derive_hmac_key(self) -> bytearray:
        """Derive the HMAC key for trailer authentication.

        For format_version >= 12, uses HKDF with domain separation.
        For legacy formats, uses SHA-256(key || constant).

        Returns:
            32-byte HMAC key as bytearray (mutable so caller can secure_memzero it)
        """
        if self.format_version is not None and self.format_version >= 12:
            return bytearray(
                HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"openssl_encrypt-streaming-hmac-key",
                ).derive(self.key)
            )
        else:
            return bytearray(hashlib.sha256(self.key + b"oesc-trailer-hmac").digest())

    # Maximum allowed ciphertext per chunk: chunk_size + generous AEAD overhead.
    # Prevents memory exhaustion from a crafted ciphertext_len field.
    _MAX_CHUNK_OVERHEAD = 1024  # AEAD tag + padding headroom

    def decrypt_file(
        self,
        input_file: str,
        output_file: Optional[str],
        metadata_b64: bytes,
        expected_chunk_count: int,
        original_hash: Optional[str] = None,
        quiet: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Union[bool, bytes]:
        """Decrypt a streaming-format file chunk by chunk.

        Reads the file incrementally so memory usage stays bounded
        regardless of file size.

        Args:
            input_file: Path to the encrypted file.
            output_file: Path for decrypted output (None for in-memory return).
            metadata_b64: Base64-encoded metadata (used as AAD prefix).
            expected_chunk_count: Expected chunk count from metadata.
            original_hash: Expected SHA-256 hash of the original file (if available).
            quiet: Suppress progress output.
            progress_callback: Optional callback(chunk_index, chunk_count).

        Returns:
            True on success (when output_file specified), or decrypted bytes.

        Raises:
            AuthenticationError: If chunk authentication or trailer HMAC fails.
            DecryptionError: If decryption fails.
        """
        max_ciphertext_len = self.chunk_size + self._MAX_CHUNK_OVERHEAD
        chunk_index = 0

        with open(input_file, "rb") as fin:
            # --- Locate the colon separator (metadata : payload) ---
            # Read in small blocks to avoid loading the whole file.
            colon_pos = -1
            search_buf = b""
            while True:
                block = fin.read(8192)
                if not block:
                    break
                search_buf += block
                idx = search_buf.find(b":")
                if idx != -1:
                    colon_pos = idx
                    break
            if colon_pos == -1:
                raise DecryptionError("Invalid streaming file: no metadata separator found")

            payload_start = colon_pos + 1

            # --- Read and verify header (magic + version = 8 bytes) ---
            fin.seek(payload_start)
            header = fin.read(8)
            if len(header) < 8:
                raise DecryptionError("Invalid streaming payload: file too short")

            if header[:4] != STREAMING_MAGIC:
                raise DecryptionError("Invalid streaming payload: missing OESC magic")

            payload_version = struct.unpack("<I", header[4:8])[0]
            if payload_version != PAYLOAD_VERSION:
                raise DecryptionError(f"Unsupported streaming payload version: {payload_version}")

            # --- Read trailer (last 36 bytes of file) ---
            file_size = fin.seek(0, 2)  # seek to end
            payload_len = file_size - payload_start
            if payload_len < 8 + 36:
                raise DecryptionError("Streaming payload too short for header + trailer")

            trailer_offset = file_size - 36
            fin.seek(trailer_offset)
            trailer_data = fin.read(36)
            trailer_chunk_count = struct.unpack("<I", trailer_data[:4])[0]
            trailer_hmac = trailer_data[4:]

            if trailer_chunk_count != expected_chunk_count:
                raise AuthenticationError(
                    f"Chunk count mismatch: metadata says {expected_chunk_count}, "
                    f"trailer says {trailer_chunk_count}"
                )

            # --- Stream through chunks ---
            chunks_end = trailer_offset  # byte offset where chunks end
            fin.seek(payload_start + 8)  # position after header

            chunk_tags: List[bytes] = []
            hash_ctx = hashlib.sha256() if original_hash else None

            # For in-memory return when output_file is None
            decrypted_chunks: Optional[List[bytes]] = [] if output_file is None else None
            fout = None
            try:
                if output_file is not None:
                    fout = open(output_file, "wb")

                while fin.tell() < chunks_end:
                    # Read chunk header (8 bytes)
                    chunk_hdr = fin.read(8)
                    if len(chunk_hdr) < 8:
                        raise DecryptionError("Truncated chunk header")

                    stored_index = struct.unpack("<I", chunk_hdr[:4])[0]
                    ciphertext_len = struct.unpack("<I", chunk_hdr[4:8])[0]

                    if stored_index != chunk_index:
                        raise AuthenticationError(
                            f"Chunk index mismatch: expected {chunk_index}, got {stored_index}"
                        )

                    # Validate chunk size to prevent memory exhaustion
                    if ciphertext_len > max_ciphertext_len:
                        raise DecryptionError(
                            f"Chunk {chunk_index} ciphertext length {ciphertext_len} exceeds "
                            f"maximum allowed {max_ciphertext_len}"
                        )

                    if fin.tell() + ciphertext_len > chunks_end:
                        raise DecryptionError(
                            f"Chunk {chunk_index} ciphertext extends beyond payload"
                        )

                    ciphertext = fin.read(ciphertext_len)
                    if len(ciphertext) != ciphertext_len:
                        raise DecryptionError(f"Chunk {chunk_index} read truncated")

                    # Collect tag material for HMAC verification
                    tag_material = ciphertext[-16:] if len(ciphertext) >= 16 else ciphertext
                    chunk_tags.append(tag_material)

                    # Derive per-chunk nonce
                    nonce = derive_chunk_nonce(self.nonce_prefix, chunk_index, self.nonce_size)

                    # Build per-chunk AAD
                    aad = build_chunk_aad(metadata_b64, chunk_index, expected_chunk_count)

                    # Decrypt the chunk
                    if self.algorithm == "cascade" and self.cascade_decryptor:
                        plaintext = self.cascade_decryptor.decrypt(
                            ciphertext,
                            self.key,
                            self.cascade_salt,
                            associated_data=aad,
                            chunk_nonce=nonce,
                        )
                    else:
                        plaintext = decrypt_chunk(self.key, nonce, ciphertext, aad, self.algorithm)

                    # Write / collect plaintext
                    if fout is not None:
                        fout.write(plaintext)
                    else:
                        decrypted_chunks.append(plaintext)

                    if hash_ctx is not None:
                        hash_ctx.update(plaintext)

                    if progress_callback:
                        progress_callback(chunk_index, expected_chunk_count)

                    chunk_index += 1

            finally:
                if fout is not None:
                    fout.close()

        if chunk_index != expected_chunk_count:
            raise AuthenticationError(
                f"Decrypted {chunk_index} chunks, expected {expected_chunk_count}"
            )

        # Verify trailer HMAC
        hmac_key = self._derive_hmac_key()
        try:
            tag_concatenation = b"".join(chunk_tags)
            computed_hmac = hmac_module.new(hmac_key, tag_concatenation, hashlib.sha256).digest()
        finally:
            secure_memzero(hmac_key)

        if not hmac_module.compare_digest(computed_hmac, trailer_hmac):
            # If we wrote to a file, remove the unverified output
            if output_file is not None and os.path.exists(output_file):
                os.remove(output_file)
            raise AuthenticationError(
                "Trailer HMAC verification failed: file integrity compromised"
            )

        # Verify original hash if provided
        if original_hash:
            if hash_ctx is not None:
                computed_hash = hash_ctx.hexdigest()
            else:
                full_plaintext = b"".join(decrypted_chunks) if decrypted_chunks else b""
                computed_hash = hashlib.sha256(full_plaintext).hexdigest()
            if computed_hash != original_hash:
                if output_file is not None and os.path.exists(output_file):
                    os.remove(output_file)
                raise AuthenticationError("Original content hash mismatch after decryption")

        # Return result
        if output_file is None:
            return b"".join(decrypted_chunks) if decrypted_chunks else b""

        return True


def parse_size_string(size_str: str) -> int:
    """Parse a human-readable size string (e.g., '1M', '512K', '4M') to bytes.

    Args:
        size_str: Size string with optional K/M/G suffix.

    Returns:
        Size in bytes.

    Raises:
        ValueError: If the format is invalid.
    """
    size_str = size_str.strip().upper()
    multipliers = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}

    if size_str[-1] in multipliers:
        try:
            return int(size_str[:-1]) * multipliers[size_str[-1]]
        except ValueError:
            raise ValueError(f"Invalid size format: {size_str}")
    else:
        try:
            return int(size_str)
        except ValueError:
            raise ValueError(f"Invalid size format: {size_str}")
