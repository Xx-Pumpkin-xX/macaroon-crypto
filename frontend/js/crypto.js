// Client-side encryption. The file key K is created here and never leaves the
// browser: it only travels in the URL fragment (#k=...), which browsers do not
// send to the server.
//
// Blob format (API spec 2.1):
//   plaintext = UTF-8 JSON {"name": "...", "text": "..."}
//   blob      = nonce (12 bytes) || AES-256-GCM(K, nonce, plaintext)

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64uEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const std = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function toHex(bytes, limit = Infinity) {
  const shown = bytes.length > limit ? bytes.slice(0, limit) : bytes;
  const hex = Array.from(shown, (b) => b.toString(16).padStart(2, "0")).join("");
  return bytes.length > limit ? `${hex}…` : hex;
}

export function utf8(text) {
  return enc.encode(text);
}

/** A fresh 256-bit file key, returned as raw bytes. */
export function newFileKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function aesKey(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** Encrypt {name, text} with K. A new nonce is used on every call. */
export async function encryptFile(name, text, rawKey) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify({ name, text }));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, await aesKey(rawKey), plaintext),
  );
  const blob = new Uint8Array(nonce.length + sealed.length);
  blob.set(nonce, 0);
  blob.set(sealed, nonce.length);
  return blob;
}

/** Decrypt a blob. Throws if K is wrong or the blob was modified (GCM tag). */
export async function decryptBlob(blob, rawKey) {
  if (blob.length < 12 + 16) throw new Error("blob too short");
  const nonce = blob.slice(0, 12);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    await aesKey(rawKey),
    blob.slice(12),
  );
  const parsed = JSON.parse(dec.decode(plain));
  if (typeof parsed.name !== "string" || typeof parsed.text !== "string") {
    throw new Error("unexpected plaintext");
  }
  return parsed;
}

/** HMAC-SHA256(key, message), both as bytes. */
export async function hmac(keyBytes, messageBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, messageBytes));
}
