/*
  FileSeal v1 — Lock

  Container format (plaintext header):
  [ 8  bytes ] magic      "FILESEAL"
  [ 1  byte  ] version    0x01
  [ 16 bytes ] salt
  [ 12 bytes ] iv

  Encrypted payload (AES-256-GCM):
  [ 4 bytes ] metadata length (uint32, big-endian)
  [ n bytes ] metadata JSON (utf-8)
  [ m bytes ] file bytes
*/

// =====================
// Constants
// =====================
const MAGIC = new TextEncoder().encode("FILESEAL"); // 8 bytes
const VERSION = 1;

const MAGIC_LEN = 8;
const VERSION_LEN = 1;
const SALT_LEN = 16;
const IV_LEN = 12;

const HEADER_LEN = MAGIC_LEN + VERSION_LEN + SALT_LEN + IV_LEN;
const PBKDF2_ITERS = 250000;

// =====================
// DOM
// =====================
const form = document.getElementById("form");
const fileInput = document.getElementById("file");
const passwordInput = document.getElementById("password");
const status = document.getElementById("status");
const lockBtn = document.getElementById("lockBtn");
const fileNameEl = document.getElementById("fileName");

// =====================
// Helpers
// =====================

if (fileInput && fileNameEl) {
  fileInput.addEventListener("change", () => {
    fileNameEl.textContent =
      fileInput.files.length > 0
        ? fileInput.files[0].name
        : "No file chosen";
  });
}


function setStatus(msg, isError = false) {
  status.textContent = msg;
  status.style.color = isError ? "#a33" : "#222";
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
}

// =====================
// Main
// =====================
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  setStatus("");

  const file = fileInput.files[0];
  if (!file) return setStatus("No file selected", true);

  const password = passwordInput.value;
  if (!password || password.length < 8) {
    return setStatus("Password must be at least 8 characters", true);
  }

  lockBtn.disabled = true;

  try {
    setStatus("Reading file...");
    const fileBytes = new Uint8Array(await file.arrayBuffer());

    // ---------------------
    // Metadata (encrypted)
    // ---------------------
    const meta = {
      name: file.name,
      type: file.type || "application/octet-stream",
    };

    const metaJson = JSON.stringify(meta);
    const metaBytes = new TextEncoder().encode(metaJson);

    const metaLenBuf = new ArrayBuffer(4);
    new DataView(metaLenBuf).setUint32(0, metaBytes.length, false);

    // ---------------------
    // Build payload
    // ---------------------
    const payload = new Uint8Array(
      4 + metaBytes.length + fileBytes.length
    );

    let p = 0;
    payload.set(new Uint8Array(metaLenBuf), p); p += 4;
    payload.set(metaBytes, p); p += metaBytes.length;
    payload.set(fileBytes, p);

    // ---------------------
    // Crypto
    // ---------------------
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));

    setStatus("Deriving key...");
    const key = await deriveKey(password, salt.buffer);

    setStatus("Encrypting...");
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        payload
      )
    );

    // ---------------------
    // Assemble container
    // ---------------------
    const out = new Uint8Array(HEADER_LEN + ciphertext.length);
    let o = 0;

    out.set(MAGIC, o); o += MAGIC_LEN;
    out[o] = VERSION;  o += VERSION_LEN;
    out.set(salt, o);  o += SALT_LEN;
    out.set(iv, o);    o += IV_LEN;
    out.set(ciphertext, o);

    // ---------------------
    // Opaque filename
    // ---------------------
    const name = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    const blob = new Blob([out], { type: "application/octet-stream" });

    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name + ".fs";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);

    setStatus("File encrypted (.fs container created)");
  } catch (err) {
    setStatus("Encryption failed: " + (err.message || err), true);
  } finally {
    lockBtn.disabled = false;
  }


});
