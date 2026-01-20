# Cryptex

Cryptex is a small, browser-based tool for encrypting files locally.

Everything happens **on your device** using the Web Crypto API.  
There’s no backend, no uploads, no tracking, and no accounts. Once the page loads, it can be used completely offline.

> Formerly known as **FileSeal**.  
> Cryptex remains backward-compatible with existing FileSeal v1 containers.

---
## What this tool is for

Cryptex exists for one simple job:  
**take a file, encrypt it, and give you back a single encrypted container**.

You might use it if you want to:

- encrypt files before storing them somewhere untrusted
- move files between devices without leaking contents
- experiment with client-side cryptography in the browser
- keep a simple, offline encryption workflow

That’s it. No extra features, no ecosystem.

---
## What Cryptex can do

- Encrypt any file into a single encrypted container (`.ctx`)
- Decrypt encrypted containers back to the original file
- Read legacy FileSeal v1 containers (`.fs`)
- Preserve the original filename and MIME type inside encrypted metadata
- Run entirely in the browser, including offline

---
## What Cryptex does _not_ do

- No password recovery
- No user accounts

If you lose the password, the data is gone. That’s intentional.

---

## Technical overview

- **Key derivation:** PBKDF2 (SHA-256)
- **Encryption:** AES-256-GCM
- **Randomness:** `crypto.getRandomValues`
- **Environment:** Browser (Web Crypto API)
- **Execution model:** Client-side only, no network dependency

---
## Container format

#### Cryptex v2.1 (`.ctx`)

```
[ Plain header ]
- magic: "CRYPTEX\0" (8 bytes)
- version: 0x02
- salt: 16 bytes
- iv: 12 bytes

[ Encrypted payload (AES-GCM) ]
- metadata length (uint32, big-endian)
- metadata JSON (filename, MIME type)
- raw file bytes
```

### Legacy support: FileSeal v1 (`.fs`)

Cryptex can decrypt containers produced by FileSeal v1:

```
- magic: "FILESEAL"
- version: 0x01
```

Legacy containers are **read-only**.  
Cryptex always writes the latest format.

---

## Filenames and metadata

- Encrypted output filenames are intentionally **opaque and random**
- Original filenames and MIME types are stored **inside encrypted metadata**
- Filenames are restored only after successful decryption

This prevents metadata leakage from encrypted containers.

---

## Threat model

Cryptex is meant to protect against:

- curious servers
- cloud storage inspection
- accidental file exposure
- untrusted networks

Cryptex does **not** protect against:

- malware on the user’s device
- weak or reused passwords
- keylogging
- compromised browsers or operating systems

---

## Limitations

- Files are processed fully in memory  
    (browser memory limits apply)
- Rendering of decrypted files depends on external viewers
- Some large or complex PDFs may fail to render in browser viewers  
    (files remain byte-accurate)

---

## Why this exists

This project exists as a **learning and portfolio artifact**, demonstrating:

- Client-side cryptography in browsers
- Binary container formats
- Backward-compatible format evolution
- Clear threat modeling
- Offline-first, scope-limited design

Cryptex is intentionally small, explicit, and boring by design.

---

## License

MIT
