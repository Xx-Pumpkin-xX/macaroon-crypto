// Read and extend macaroon tokens in the browser.
//
// The server issues pymacaroons v1 tokens: unpadded base64url of a list of
// packets, each "LLLL" (4 hex digits, total packet length) + "key value\n".
// Keys used here: location, identifier, cid (one per caveat), signature
// (32 raw bytes).
//
// This module never verifies a token: only the server, which holds the root
// key, can do that. It is used to show a token's caveats and, in the attack
// lab, to build modified tokens the way an attacker could.

import { b64uDecode, b64uEncode, hmac, utf8 } from "./crypto.js";

const ascii = new TextDecoder("utf-8", { fatal: true });

export function parseToken(token) {
  const bytes = b64uDecode(token);
  const out = { location: "", identifier: "", caveats: [], signature: null };
  let i = 0;
  while (i < bytes.length) {
    const size = parseInt(ascii.decode(bytes.slice(i, i + 4)), 16);
    if (!Number.isFinite(size) || size < 6 || i + size > bytes.length) {
      throw new Error("malformed token");
    }
    const body = bytes.slice(i + 4, i + size - 1); // drop trailing "\n"
    const space = body.indexOf(0x20);
    const key = ascii.decode(body.slice(0, space));
    const value = body.slice(space + 1);
    if (key === "signature") out.signature = value;
    else if (key === "cid") out.caveats.push(ascii.decode(value));
    else if (key === "location") out.location = ascii.decode(value);
    else if (key === "identifier") out.identifier = ascii.decode(value);
    i += size;
  }
  if (!out.signature) throw new Error("token has no signature");
  return out;
}

function packet(key, valueBytes) {
  const keyBytes = utf8(key);
  const size = 4 + keyBytes.length + 1 + valueBytes.length + 1;
  const head = utf8(size.toString(16).padStart(4, "0"));
  const out = new Uint8Array(size);
  out.set(head, 0);
  out.set(keyBytes, 4);
  out[4 + keyBytes.length] = 0x20;
  out.set(valueBytes, 5 + keyBytes.length);
  out[size - 1] = 0x0a;
  return out;
}

/** Re-encode a parsed token. The signature is copied as is, not recomputed. */
export function serializeToken({ location, identifier, caveats, signature }) {
  const parts = [packet("location", utf8(location)), packet("identifier", utf8(identifier))];
  for (const c of caveats) parts.push(packet("cid", utf8(c)));
  parts.push(packet("signature", signature));
  const total = parts.reduce((n, p) => n + p.length, 0);
  const all = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  return b64uEncode(all);
}

/**
 * Add a caveat the legitimate way: new signature = HMAC(old signature, caveat).
 * Anyone holding a token can do this without the root key.
 */
export async function appendCaveat(token, caveat) {
  const m = parseToken(token);
  const signature = await hmac(m.signature, utf8(caveat));
  return serializeToken({ ...m, caveats: [...m.caveats, caveat], signature });
}

const RANK = { read: 0, edit: 1, full: 2 };

/** Summarise caveats the way the server's rules read them (display only). */
export function describeToken(token) {
  const m = parseToken(token);
  const ops = [];
  const expiries = [];
  const shareIds = [];
  for (const c of m.caveats) {
    let match;
    if ((match = /^op = (read|edit|full)$/.exec(c))) ops.push(match[1]);
    else if ((match = /^expires < ([0-9]{1,12})$/.exec(c))) expiries.push(Number(match[1]));
    else if ((match = /^share_id = ([0-9a-f]{16})$/.exec(c))) shareIds.push(match[1]);
  }
  const op = ops.length ? ops.reduce((a, b) => (RANK[a] <= RANK[b] ? a : b)) : null;
  return {
    fileId: m.identifier,
    caveats: m.caveats,
    op,
    expiresAt: expiries.length ? Math.min(...expiries) : null,
    shareIds,
    signature: m.signature,
  };
}

export function rank(op) {
  return RANK[op] ?? -1;
}
