# Technical Architecture: openssl_encrypt

## 1. Security Philosophy
The architecture of `openssl_encrypt` is built on a "Defense in Depth" strategy. Unlike standard encryption tools, it focuses on three pillars to ensure long-term data sovereignty:
* **Quantum Resistance:** Neutralizing the threat of future large-scale quantum computers (CRQC).
* **Hardware-Hardened Key Derivation:** Maximizing the cost of brute-force attacks by using memory-hard and CPU-hard algorithms.
* **Cryptographic Binding:** Ensuring that metadata (headers) and payload (data) are inseparable, preventing any form of structural tampering.

---

## 2. The Hybrid Encryption Flow
To achieve maximum security, the tool employs a **"Double-Wrap"** mechanism that layers classical cryptography with Post-Quantum algorithms.

### Step 1: Post-Quantum Layer (Inner Wrap)
A high-entropy secret ($S_{pqc}$) is generated using a NIST-standardized Post-Quantum Key Encapsulation Mechanism (KEM). 
* **Algorithms:** Supports **HQC** (Hamming Quasi-Cyclic), **CROSS**, and **MAYO**.
* **Purpose:** This layer ensures that even if an adversary "harvests" the data today, it cannot be decrypted by a quantum computer in the future.

### Step 2: Hardened KDF Chain (Outer Wrap)
The user password is not used directly but serves as the input for a multi-stage, sequential Key Derivation Function (KDF) chain:
1.  **Memory-Hard Stage:** Utilizes **Argon2id** or **Balloon Hashing** to prevent efficient GPU/ASIC parallelization.
2.  **CPU-Hard Stage:** Utilizes **RandomX** to force single-threaded execution, leveling the playing field against specialized hardware.
3.  **Entropy Fusion:** The output of the KDF chain is cryptographically combined with the PQC secret to derive the final session key ($K_{final}$).



---

## 3. Symmetric Encryption & Integrity Models
`openssl_encrypt` supports two distinct levels of integrity protection. The primary difference lies in how the metadata (JSON header) is cryptographically handled.

### 3.1 Advanced AEAD Models (Metadata Binding)
The core ciphers in this tool utilize **Authenticated Encryption with Associated Data (AEAD)**. In this flow, the Base64-encoded metadata header is treated as **Associated Data (AAD)**. This creates a cryptographic "binding" between the header and the ciphertext.

* **AES-256-GCM:** The industry standard for high-performance encryption. It leverages hardware acceleration (AES-NI).
* **ChaCha20-Poly1305:** A modern AEAD construction (RFC 8439). Exceptionally fast in software-defined environments.
* **AES-256-SIV (Deterministic AEAD):** The most robust option. Following RFC 5297, it offers **Nonce-Misuse Resistance**. Even if a nonce is repeated, the integrity of the data remains absolute. The metadata is bound via the **S2V (Synthetic Initialization Vector)** construction.



### 3.2 Standard Authenticated Model (Payload Integrity)
For broad compatibility and legacy support, the tool includes the **Fernet** protocol.
* **Fernet (AES-128-CBC + HMAC-SHA256):** Provides high-level "Authenticated Encryption" for the file payload.
* **Architectural Note:** The Fernet specification does not natively support AAD (Associated Data). Consequently, while the **payload** is fully protected against tampering, the **metadata header** is not cryptographically bound to the Fernet token.



---

## 4. Security Comparison Matrix

| Feature | AES-GCM / ChaCha-Poly | AES-SIV (DAE) | Fernet |
| :--- | :--- | :--- | :--- |
| **Bit Strength** | 256-bit | 256-bit | 128-bit |
| **Integrity Type** | Native AEAD | Misuse-Resistant AEAD | HMAC-SHA256 |
| **Metadata Binding** | **Full (via AAD)** | **Strongest (via S2V)** | None (Payload Only) |
| **PQC Protection** | Enabled | Enabled | Enabled |
| **Best For** | Performance & Security | Maximum Robustness | Interoperability |

---

## 5. Key Derivation Integrity (Hardened Salt Policy)
A critical design decision in `openssl_encrypt` is the use of **strictly random, non-deterministic salts**. 

### 5.1 Resistance to Pre-computation & Fast-Fail Attacks
We consciously avoid embedding any information derived from the user's password (such as hashes of password fragments) into the salt or the metadata. While "password-derived salts" might seem like an extra layer of security, they introduce two major vulnerabilities:

1. **Information Leakage:** Even a salted hash of password fragments reveals entropy characteristics of the original password, reducing the search space for an attacker.
2. **KDF-Bypass (Fast-Fail):** If an attacker can verify a password's validity by checking a "cheap" hash in the metadata, they can bypass the expensive KDF chain (Argon2id + RandomX). They could test millions of passwords per second and only execute the heavy KDF for the few that pass the "cheap" pre-check.

### 5.2 The "Slow-Failure" Principle
In our architecture, the only way to verify if a password is correct is to:
1. Complete the full **Argon2id** memory-hard cycle.
2. Complete the full **RandomX** CPU-hard cycle.
3. Attempt an **AEAD decryption** with the resulting key.

This ensures that every single guess in a brute-force attack incurs the **maximum computational cost**, effectively neutralizing high-speed cracking attempts.
---

## 6. Salt Independence & Brute-Force Resistance

A fundamental design principle of `openssl_encrypt` is the strict separation of the **User Password** and the **Cryptographic Salt**. 

### 6.1 Why we avoid Password-Derived Salts
During development, the idea of mixing parts of the user's password into the salt (even at runtime) was evaluated and rejected for the following cryptographic reasons:

* **Correlating Entropy:** A salt is intended to be an independent variable. Mixing password fragments into the salt creates a correlation between the two inputs. In high-assurance cryptography, the salt must remain strictly independent of the secret to ensure the KDF (Argon2id) operates at its maximum theoretical strength.
* **Code Transparency vs. Obscurity:** According to Kerckhoffs's Principle, the security of a system should reside solely in the secrecy of the password, not the secrecy of the algorithm. If an attacker knows the algorithm (which is public in open-source), "hiding" password fragments in the salt at runtime provides no additional security, as the attacker's cracking tools will simply replicate that logic.
* **The "Slow-Failure" Guarantee:** By keeping the salt 100% random and stored in the metadata, we force an attacker to use the exact salt provided. This ensures that the attacker **cannot avoid** the massive computational overhead of the Argon2id and RandomX chain. There are no "fast-fail" shortcuts; every single guess requires the full execution of the hardened KDF stack.

### 6.2 Implementation Conclusion
The current implementation utilizes a **CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)** to generate a fresh, unique salt for every encryption operation. This ensures that:
1. Identical passwords result in different ciphertexts.
2. Rainbow table attacks are mathematically impossible.
3. The workload for a brute-force attacker is maximized by the full complexity of the KDF chain.
---
## 7. Anti-Oracle Policy (Generic Errors)
To prevent side-channel and padding oracle attacks, the application implements a strict **generic error policy**. 
* Any failure during KDF derivation, metadata parsing, or AEAD verification returns an identical `Decryption Failed` message. 
* This prevents an attacker from gaining information about which specific layer of the security stack they have successfully bypassed.
