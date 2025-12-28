/*
  FileSeal v1 — Unlock

  Expects container format:

  [ 8  bytes ] magic      "FILESEAL"
  [ 1  byte  ] version    0x01
  [ 16 bytes ] salt
  [ 12 bytes ] iv
  [ n bytes  ] AES-GCM encrypted payload

  Payload (after decrypt):
  [ 4 bytes ] metadata length (uint32, big-endian)
  [ n bytes ] metadata JSON
  [ m bytes ] file bytes
*/

// =====================
// Constants
// =====================
const MAGIC_TEXT = "FILESEAL";
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
const unlockBtn = document.getElementById("unlockBtn");
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
    ["decrypt"]
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
  if (!password) return setStatus("Password required", true);

  unlockBtn.disabled = true;

  try {
    setStatus("Reading container...");
    const buf = new Uint8Array(await file.arrayBuffer());

    if (buf.length < HEADER_LEN) {
      throw new Error("Invalid FileSeal container (too small)");
    }

    // ---------------------
    // Header parsing
    // ---------------------
    const magic = new TextDecoder().decode(buf.slice(0, MAGIC_LEN));
    if (magic !== MAGIC_TEXT) {
      throw new Error("Invalid FileSeal container (magic mismatch)");
    }

    const version = buf[MAGIC_LEN];
    if (version !== 1) {
      throw new Error("Unsupported FileSeal version");
    }

    const saltOff = MAGIC_LEN + VERSION_LEN;
    const ivOff   = saltOff + SALT_LEN;
    const ctOff   = ivOff + IV_LEN;

    const salt = buf.slice(saltOff, saltOff + SALT_LEN);
    const iv   = buf.slice(ivOff, ivOff + IV_LEN);
    const ct   = buf.slice(ctOff);

    // ---------------------
    // Decrypt
    // ---------------------
    setStatus("Deriving key...");
    const key = await deriveKey(password, salt.buffer);

    setStatus("Decrypting...");
    let plaintext;
    try {
      plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          ct
        )
      );
    } catch {
      throw new Error("Decryption failed (wrong password or corrupted file)");
    }

    if (plaintext.length < 4) {
      throw new Error("Invalid decrypted payload");
    }

    // ---------------------
    // Payload parsing
    // ---------------------
    const view = new DataView(
      plaintext.buffer,
      plaintext.byteOffset,
      plaintext.byteLength
    );

    const metaLen = view.getUint32(0, false);
    const metaStart = 4;
    const metaEnd = metaStart + metaLen;

    if (metaEnd > plaintext.length) {
      throw new Error("Invalid metadata length");
    }

    const metaJson = new TextDecoder().decode(
      plaintext.slice(metaStart, metaEnd)
    );

    let meta;
    try {
      meta = JSON.parse(metaJson);
    } catch {
      throw new Error("Invalid metadata JSON");
    }

    if (!meta.name || !meta.type) {
      throw new Error("Missing metadata fields");
    }

const fileBytes = new Uint8Array(
  plaintext.buffer,
  plaintext.byteOffset + metaEnd,
  plaintext.byteLength - metaEnd
);


    // ---------------------
    // Restore file
    // ---------------------
   // ---------------------
// Restore file (force download)
// ---------------------

// Prevent browser PDF viewer hijack
const mime =
  meta.type === "application/pdf"
    ? "application/octet-stream"
    : meta.type;

const blob = new Blob([fileBytes.buffer], { type: mime });
const url = URL.createObjectURL(blob);

const a = document.createElement("a");
a.href = url;
a.download = meta.name;
a.style.display = "none";

document.body.appendChild(a);

// Force a real user-style click (prevents navigation)
a.dispatchEvent(
  new MouseEvent("click", {
    bubbles: true,
    cancelable: true,
    view: window,
  })
);

document.body.removeChild(a);
URL.revokeObjectURL(url);


    setStatus("File restored successfully");
  } catch (err) {
    setStatus(err.message || String(err), true);
  } finally {
    unlockBtn.disabled = false;
  }
    

});
