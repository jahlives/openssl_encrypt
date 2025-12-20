# Security Policy

## 1. Security Philosophy
`openssl_encrypt` is designed with a **Defense in Depth** approach. Our security model doesn't just focus on data confidentiality but emphasizes **Metadata Integrity** and **Quantum Resistance**. 

We believe in transparency; therefore, our cryptographic choices are documented to allow for public audit and verification.

---

## 2. Cryptographic Standards & AEAD
A core requirement of this tool is the cryptographic binding of file metadata (the JSON header) to the encrypted payload. This is achieved through **Authenticated Encryption with Associated Data (AEAD)**.

### 2.1 Metadata Binding (AAD)
The following ciphers are implemented as AEAD/DAE, meaning the Base64-encoded metadata header is fed into the cipher as **Associated Data (AAD)**. Any modification to the header will result in an authentication failure.

* **AES-256-GCM:** Standard hardware-accelerated AEAD.
* **ChaCha20-Poly1305:** Standard software-efficient AEAD.
* **AES-256-SIV (Deterministic AEAD):** Our most robust mode. It provides **Nonce-Misuse Resistance** and uses the S2V construction to bind metadata even more tightly to the encryption process.



### 2.2 Note on Fernet
Fernet is included for compatibility with the Python `cryptography` ecosystem. 
* **Limitation:** The Fernet specification does not natively support Associated Data (AAD). 
* **Security Bound:** While the payload integrity is guaranteed, the metadata header is not cryptographically bound to the Fernet token. This is a documented design trade-off for interoperability.

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
