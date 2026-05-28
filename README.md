# Sirius Vault

Sirius Vault is a zero-trust, local-first secure file vault and password manager built with Python and PyQt6. Designed with uncompromising security principles, it ensures that your sensitive data remains completely localized and protected against both persistent threats and memory-based attacks.

## Key Features

* **Encryption:** Utilizes chunked **AES-GCM** for authenticated file encryption and **Argon2id** for robust key derivation.
* **Integrated Password Manager:** A secure environment to store credentials with a dynamic strength auditor and random password generator.
* **In-Memory Multimedia Preview:** Safely view images and play video/audio files directly within the vault. Files are decrypted to a temporary location, played, and securely shredded from the disk the millisecond the preview window closes.
* **Advanced Memory Hygiene (Zero-Trust):**
  * Cryptographic keys are wiped from RAM immediately upon locking the vault or closing the application.
  * Inactivity timeout automatically locks the vault and purges the session.
* **Ghost Clipboard Integration:** Sensitive data (like copied passwords) is sent to the clipboard using native OS DWORD flags that explicitly bypass Windows Cloud Sync and `Win+V` Clipboard History, auto-clearing after 30 seconds.
* **Anti-Tamper & Lockout Mechanism:** Built-in HMAC verification protects the configuration files from tampering, alongside progressive lockouts to thwart brute-force attacks.
* **Secure Deletion (Shredding):** Uses multi-pass overwriting (`ba+`) to securely erase plaintext files and original folders from the disk, preventing recovery via forensic tools.

## Technical Architecture

Unlike standard vault applications, Sirius Vault operates on a strict isolated architecture:
1. **Master Key Separation:** The Vault and the Password Manager use isolated cryptographic keys. Accessing one does not expose the memory footprint of the other.
2. **Authenticated Encryption with Associated Data (AEAD):** AES-GCM ensures that any tampering or "bit-rot" in the encrypted `.enc` files is instantly detected, preventing the execution of malicious payloads.
3. **No Cloud, No Telemetry:** 100% offline. The user holds the absolute authority over the generated `SYSTEM_SALT` and the physical `.env` files.
