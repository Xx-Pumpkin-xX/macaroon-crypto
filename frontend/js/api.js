// Thin wrapper over the six endpoints in docs/spec/api-spec.md.
// Every request is also reported to the "What the server sees" log, so the
// page can show exactly what left the browser.

import { toHex } from "./crypto.js";

const listeners = new Set();
export function onRequest(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export const MESSAGES = {
  missing_token: "No access token was sent with the request.",
  invalid_token: "This link is not genuine: it was changed, forged or belongs to another file.",
  expired: "This link has expired.",
  revoked: "The owner revoked this link.",
  forbidden: "This link does not allow that action.",
  not_found: "This file no longer exists.",
  too_large: "The file is over the 1 MiB limit.",
  bad_request: "The request was not accepted.",
  internal_error: "The server hit an unexpected error.",
  network: "Could not reach the server. Is the backend running?",
};

export class ApiError extends Error {
  constructor(status, code, detail) {
    super(MESSAGES[code] || detail || code);
    this.status = status;
    this.code = code;
  }
}

function shortToken(token) {
  return token.length > 26 ? `${token.slice(0, 12)}…${token.slice(-10)}` : token;
}

async function call(method, path, { token, blob, json } = {}) {
  const headers = {};
  let body;
  let sent = "no body";
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  if (blob) {
    headers["Content-Type"] = "application/octet-stream";
    body = blob;
    sent = `${blob.length.toLocaleString("en")} bytes of ciphertext: ${toHex(blob, 14)}`;
  } else if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
    sent = body;
  }
  const entry = {
    at: new Date(),
    method,
    path,
    auth: token === undefined ? "none" : `Bearer ${shortToken(token)} (${token.length} chars)`,
    sent,
    // Everything that crossed the wire, for the "key never sent" check.
    raw: [method, path, headers.Authorization || "", typeof body === "string" ? body : ""].join("\n"),
    rawBytes: blob || null,
    status: null,
    code: null,
  };
  let response;
  try {
    response = await fetch(path, { method, headers, body, cache: "no-store", referrerPolicy: "no-referrer" });
  } catch {
    entry.status = 0;
    entry.code = "network";
    listeners.forEach((fn) => fn(entry));
    throw new ApiError(0, "network");
  }
  entry.status = response.status;
  if (!response.ok) {
    let data = {};
    try {
      data = await response.json();
    } catch {
      /* non-JSON error */
    }
    entry.code = data.error || "error";
    listeners.forEach((fn) => fn(entry));
    throw new ApiError(response.status, data.error || "bad_request", data.message);
  }
  listeners.forEach((fn) => fn(entry));
  return response;
}

export async function upload(blob) {
  return (await call("POST", "/api/files", { blob })).json(); // {file_id, token}
}

export async function download(fileId, token) {
  const r = await call("GET", `/api/files/${encodeURIComponent(fileId)}`, { token });
  return { blob: new Uint8Array(await r.arrayBuffer()), permission: r.headers.get("X-Permission") };
}

export async function replace(fileId, token, blob) {
  await call("PUT", `/api/files/${encodeURIComponent(fileId)}`, { token, blob });
}

export async function share(token, op, expiresIn) {
  return (await call("POST", "/api/share", { token, json: { op, expires_in: expiresIn } })).json();
}

export async function revoke(token, shareId) {
  await call("POST", "/api/revoke", { token, json: { share_id: shareId } });
}

export async function remove(fileId, token) {
  await call("DELETE", `/api/files/${encodeURIComponent(fileId)}`, { token });
}

/** Raw call used by the attack lab: returns status/code instead of throwing. */
export async function probe(method, path, opts) {
  try {
    const r = await call(method, path, opts);
    return { status: r.status, code: "ok", permission: r.headers.get("X-Permission") };
  } catch (e) {
    return { status: e.status, code: e.code };
  }
}
