// Attack lab: each scenario attacks the real backend the way an outsider or a
// link holder could, then compares the server's answer with what the design
// promises. IDs refer to tests/ACCEPTANCE_PLAN.md (Part 2).

import * as api from "./api.js";
import { encryptFile, newFileKey } from "./crypto.js";
import { appendCaveat, parseToken, serializeToken } from "./macaroon.js";

async function freshFile() {
  const key = newFileKey();
  const blob = await encryptFile("lab.txt", "Attack lab sample file.", key);
  const { file_id, token } = await api.upload(blob);
  return { fileId: file_id, owner: token, key };
}

async function readShare(owner) {
  return (await api.share(owner, "read", 3600)).token;
}

const get = (fileId, token) => api.probe("GET", `/api/files/${fileId}`, { token });

export const SCENARIOS = [
  {
    id: "A13",
    title: "A Read link tries to edit",
    has: "A Read link",
    tries: "Upload new content with PUT",
    expect: { status: 403, code: "forbidden" },
    async run() {
      const f = await freshFile();
      const token = await readShare(f.owner);
      return api.probe("PUT", `/api/files/${f.fileId}`, { token, blob: new Uint8Array(40) });
    },
  },
  {
    id: "A07",
    title: "A Read holder adds “op = full” itself",
    has: "A Read link and the HMAC rule",
    tries: "Append op = full with a correct new signature, then edit",
    expect: { status: 403, code: "forbidden" },
    async run() {
      const f = await freshFile();
      const token = await appendCaveat(await readShare(f.owner), "op = full");
      return api.probe("PUT", `/api/files/${f.fileId}`, { token, blob: new Uint8Array(40) });
    },
    note: "The new token is genuine, but the lowest op wins, so it is still Read.",
  },
  {
    id: "A05",
    title: "Change a caveat’s text",
    has: "A Read link",
    tries: "Rewrite “op = read” as “op = full”, keep the signature",
    expect: { status: 401, code: "invalid_token" },
    async run() {
      const f = await freshFile();
      const m = parseToken(await readShare(f.owner));
      const caveats = m.caveats.map((c) => (c === "op = read" ? "op = full" : c));
      return get(f.fileId, serializeToken({ ...m, caveats }));
    },
  },
  {
    id: "A04",
    title: "Remove a caveat",
    has: "A Read link",
    tries: "Delete the “op = read” caveat, keep the signature",
    expect: { status: 401, code: "invalid_token" },
    async run() {
      const f = await freshFile();
      const m = parseToken(await readShare(f.owner));
      const caveats = m.caveats.filter((c) => c !== "op = read");
      return get(f.fileId, serializeToken({ ...m, caveats }));
    },
    note: "Undoing a caveat needs the previous signature, and HMAC cannot be reversed.",
  },
  {
    id: "A02",
    title: "Forge the signature",
    has: "A file ID",
    tries: "Send a token whose signature is 32 zero bytes",
    expect: { status: 401, code: "invalid_token" },
    async run() {
      const f = await freshFile();
      const m = parseToken(f.owner);
      return get(f.fileId, serializeToken({ ...m, signature: new Uint8Array(32) }));
    },
  },
  {
    id: "A03",
    title: "Use a link on another file",
    has: "A valid link for file A",
    tries: "Open file B with it",
    expect: { status: 401, code: "invalid_token" },
    async run() {
      const a = await freshFile();
      const b = await freshFile();
      return get(b.fileId, a.owner);
    },
  },
  {
    id: "A10",
    title: "Add a caveat the server doesn’t know",
    has: "A Read link",
    tries: "Append “admin = true” with a correct signature",
    expect: { status: 401, code: "invalid_token" },
    async run() {
      const f = await freshFile();
      return get(f.fileId, await appendCaveat(await readShare(f.owner), "admin = true"));
    },
    note: "Unknown caveats are rejected: ignoring one would silently drop a restriction.",
  },
  {
    id: "A12",
    title: "Flood the token with caveats",
    has: "A Read link",
    tries: "Append 21 more caveats (the limit is 20 in total)",
    expect: { status: 401, code: "invalid_token" },
    async run() {
      const f = await freshFile();
      let token = await readShare(f.owner);
      for (let i = 0; i < 21; i += 1) token = await appendCaveat(token, "op = read");
      return get(f.fileId, token);
    },
  },
  {
    id: "A08",
    title: "Use an expired link",
    has: "A Read link",
    tries: "Narrow it to an expiry one second in the past",
    expect: { status: 403, code: "expired" },
    async run() {
      const f = await freshFile();
      const past = Math.floor(Date.now() / 1000) - 1;
      return get(f.fileId, await appendCaveat(await readShare(f.owner), `expires < ${past}`));
    },
  },
  {
    id: "A09",
    title: "Revoke a link that was shared further",
    has: "B’s Read link, and C’s link made from it",
    tries: "Owner revokes B’s share, then C opens the file",
    expect: { status: 403, code: "revoked" },
    async run() {
      const f = await freshFile();
      const b = await api.share(f.owner, "read", 3600);
      const c = await api.share(b.token, "read", 3600);
      const other = await readShare(f.owner);
      await api.revoke(f.owner, b.share_id);
      const result = await get(f.fileId, c.token);
      const sibling = await get(f.fileId, other);
      return {
        ...result,
        extra: sibling.status === 200 ? "An unrelated share still works (200)." : `Unrelated share got ${sibling.status}.`,
        extraOk: sibling.status === 200,
      };
    },
  },
  {
    id: "A14",
    title: "Guess a file ID, no token",
    has: "Only a file ID",
    tries: "Download it without any token",
    expect: { status: 401, code: "missing_token" },
    async run() {
      const f = await freshFile();
      return get(f.fileId, undefined);
    },
  },
  {
    id: "DEL",
    title: "Open a link after the file is deleted",
    has: "A Read link",
    tries: "Owner deletes the file, then the link is opened",
    expect: { status: 404, code: "not_found" },
    async run() {
      const f = await freshFile();
      const token = await readShare(f.owner);
      await api.remove(f.fileId, f.owner);
      return get(f.fileId, token);
    },
    note: "Deleting the file deletes its root key, so no token can be verified any more.",
  },
];

export async function runScenario(s) {
  try {
    const r = await s.run();
    const ok = r.status === s.expect.status && r.code === s.expect.code && r.extraOk !== false;
    return { ...r, ok };
  } catch (e) {
    return { status: e.status ?? 0, code: e.code ?? "error", ok: false, extra: e.message };
  }
}
