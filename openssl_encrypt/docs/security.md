# Security Policy

## 1. Security Philosophy
`openssl_encrypt` is designed with a **Defense in Depth** approach. Our security model doesn't just focus on data confidentiality but emphasizes **Metadata Integrity** and **Quantum Resistance**.

We believe in transparency; therefore, our cryptographic choices are documented to allow for public audit and verification.

---

## 2. Cryptographic Standards & AEAD
A core requirement of this tool is the cryptographic binding of file metadata (the JSON header) to the encrypted payload. This is achieved through **Authenticated Encryption with Associated Data (AEAD)**.

### 2.1 Metadata Binding (AAD)

#### AEAD Algorithms (Full AAD Binding)
The following ciphers implement true AEAD, where the Base64-encoded metadata header is cryptographically bound to the ciphertext via Associated Data (AAD):

**Pure AEAD Algorithms:**
* **AES-256-GCM**: Standard hardware-accelerated AEAD with AAD binding
* **ChaCha20-Poly1305**: Software-efficient AEAD with AAD binding
* **XChaCha20-Poly1305**: Extended-nonce AEAD with AAD binding
* **AES-256-SIV**: Deterministic AEAD with AAD binding (nonce-misuse resistant)
* **AES-GCM-SIV**: Misuse-resistant AEAD with AAD binding
* **AES-OCB3**: OCB mode AEAD with AAD binding

**Post-Quantum Hybrid Algorithms (18 total):**
All PQC hybrid algorithms use AEAD ciphers for their symmetric encryption layer:
* **ML-KEM** variants (512, 768, 1024, with AES-GCM or ChaCha20-Poly1305)
* **HQC** variants (128, 192, 256)
* **MAYO** variants (1, 3, 5)
* **CROSS** variants (128, 192, 256)
* **Kyber** variants (512, 768, 1024) - deprecated

For these algorithms:
- Metadata is created BEFORE encryption
- Metadata is passed as AAD to the cipher
- Any modification to metadata causes authentication failure
- No `encrypted_hash` is stored (redundant with AAD protection)

#### Non-AEAD Algorithms (Hash-Based Verification)
The following algorithms use hash-based integrity verification:

* **Fernet**: Uses internal HMAC (no AAD support per specification)
* **Camellia**: Uses HMAC-SHA256 for authentication

For these algorithms:
- Metadata is created AFTER encryption
- `encrypted_hash` is included in metadata
- Verification via hash comparison (not AAD)

### 2.2 Note on Fernet
Fernet is included for compatibility with the Python `cryptography` ecosystem.
* **Limitation:** The Fernet specification does not natively support Associated Data (AAD).
* **Security Bound:** While the payload integrity is guaranteed, the metadata header is not cryptographically bound to the Fernet token via AAD. Hash-based verification is used instead.

---

## 3. Post-Quantum Cryptography (PQC)
To protect against the future threat of Cryptographically Relevant Quantum Computers (CRQC), this tool utilizes a hybrid KEM (Key Encapsulation Mechanism) layer.
* **Supported Algorithms:** HQC, CROSS, and MAYO.
* **Mechanism:** The PQC secret is fused with a hardened KDF output (Argon2id/RandomX) to derive the final session key.

---

## 4. Reporting a Vulnerability
We welcome security researchers and users to report any potential vulnerabilities. To protect our users, we ask you to follow a responsible disclosure process.

### How to report:
1.  **Do not open a public issue.**
2.  Please use the **[GitHub Security Advisory](https://github.com/jahlives/openssl_encrypt/security/advisories/new)** feature to report vulnerabilities privately.
3.  Include a detailed description, steps to reproduce, and a Proof of Concept (PoC) if possible.

### What to report:
We are particularly interested in reports concerning:
* Bypassing the AEAD metadata binding.
* Flaws in the KDF chain (Argon2id + RandomX fusion).
* Implementation errors in the PQC wrappers.

---

## 5. Anti-Oracle Policy
To mitigate side-channel and padding oracle attacks, `openssl_encrypt` implements a strict **generic error policy**.
* Any failure (KDF mismatch, Header corruption, or Tag verification failure) returns an identical `Decryption Failed` error.
* We will not provide granular error messages that could leak information about the internal state of the cryptographic stack.
