
---
# FileSeal

FileSeal is an **offline, browser-based file encryption tool**.  
All encryption and decryption happens locally using the Web Crypto API.  
There is **no backend, no uploads, and no accounts**.

Live demo: [https://fileseal.pages.dev/](https://fileseal.pages.dev/)

---

## What FileSeal does

- Encrypts any file into a single opaque `.fs` container
- Decrypts `.fs` containers back to the original file
- Preserves original filename and MIME type inside encrypted metadata
- Runs entirely in the browser (offline-capable)

---

## What FileSeal is _not_

- Not a cloud service
- Not a file-sharing tool
- Not a password manager
- Not a recovery system (forgotten passwords cannot be recovered)
---
## Technical overview

- **Key derivation:** PBKDF2 (SHA-256)
- **Encryption:** AES-256-GCM
- **Randomness:** `crypto.getRandomValues`
- **Environment:** Browser (Web Crypto API)

### **Container format (`.fs`)**
```
[ Plain header ]
- magic: "FILESEAL" (8 bytes)
- version: 1 byte
- salt: 16 bytes
- iv: 12 bytes

[ Encrypted payload (AES-GCM) ]
- metadata length (uint32, big-endian)
- metadata JSON (filename, MIME type)
- raw file bytes
  
```

The output filename is intentionally **opaque** (random `.fs` name).  
The original filename is restored only after successful decryption.

---

## Threat model

FileSeal is designed to protect against:

- Curious servers
- Cloud storage providers
- Accidental file exposure

FileSeal does **not** protect against:

- Malware on the user’s device
- Weak passwords
- Keylogging or compromised browsers

---
## Limitations

- Files are processed fully in memory (browser memory limits apply)
- Rendering of decrypted files depends on external viewers
- Large or complex PDFs may fail to render in some browser PDF viewers  
    (files remain byte-accurate)

---

## Why this exists

This project exists as a **portfolio and learning artifact** demonstrating:

- Client-side cryptography
- Binary data handling in browsers
- Clear threat modeling
- Scope discipline and offline-first design

---

## License

MIT
