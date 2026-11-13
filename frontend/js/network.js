// Network map: six people and one server. Every button sends a real request
// to the running backend; the map animates the request, shows which server
// check passed or failed, and explains the answer in plain words.

import * as api from "./api.js";
import { decryptBlob, encryptFile, newFileKey } from "./crypto.js";
import { parseToken, serializeToken } from "./macaroon.js";
import { $, fill, h, reducedMotion, sleep } from "./dom.js";

const NS = "http://www.w3.org/2000/svg";
const W = 1000;
const H = 640;
const POS = {
  server: [500, 320],
  alice: [140, 92],
  bob: [140, 320],
  dave: [140, 548],
  carol: [860, 92],
  eve: [860, 320],
  mallory: [860, 548],
};

const ACTORS = [
  { id: "alice", name: "Alice", who: "Owner. Uploaded the file." },
  { id: "bob", name: "Bob", who: "Got a Read link from Alice." },
  { id: "carol", name: "Carol", who: "Got an Edit link from Alice." },
  { id: "dave", name: "Dave", who: "Got a Read link that Bob made from his own." },
  { id: "eve", name: "Eve", who: "Saw the file ID in a log. Has no link." },
  { id: "mallory", name: "Mallory", who: "Copied Bob's link, changed read to edit." },
];

// Hand-overs happen outside the system (chat, email); the server never sees them.
const GIVES = [
  { id: "give-bob", from: "alice", to: "bob", label: "Read link", d: "M140,92 L140,320" },
  { id: "give-carol", from: "alice", to: "carol", label: "Edit link", d: "M140,92 Q500,-10 860,92" },
  { id: "give-dave", from: "bob", to: "dave", label: "Read link made by Bob", d: "M140,320 L140,548" },
  { id: "give-mallory", from: "bob", to: "mallory", label: "copied, then edited", d: "M140,320 Q520,700 860,548", bad: true },
];

// Server checks in the order of api-spec.md §3.1 (steps 2–3 folded into 3).
const CHECKS = [
  { label: "Token sent", fails: "missing_token" },
  { label: "File exists (root key found)", fails: "not_found" },
  { label: "Signature matches the root key", fails: "invalid_token" },
  { label: "Not expired", fails: "expired" },
  { label: "Not revoked", fails: "revoked" },
  { label: "Allows this action", fails: "forbidden" },
];

const SAMPLE = "Crypto midterm, meeting notes\n- Backend: 6 endpoints merged\n- Demo on Friday\n";
const OP_LABEL = { read: "Read", edit: "Edit", full: "Full control" };

let state;
let busy = false;

function svgEl(name, attrs, parent) {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  parent?.appendChild(node);
  return node;
}

const now = () => new Date().toLocaleTimeString("en-GB");
const shortId = (s) => (s ? `${s.slice(0, 6)}…` : "");

/* ------------------------------------------------------------------ build */

function buildMap(root) {
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "net-svg", "aria-hidden": "true" });
  const edges = svgEl("g", {}, svg);
  for (const a of ACTORS) {
    const [x, y] = POS[a.id];
    svgEl("path", { id: `req-${a.id}`, d: `M${x},${y} L${POS.server[0]},${POS.server[1]}`, class: "edge edge-req" }, edges);
  }
  for (const g of GIVES) {
    const p = svgEl("path", { id: g.id, d: g.d, class: `edge edge-give${g.bad ? " edge-stolen" : ""}` }, edges);
    p.dataset.label = g.label;
  }
  const labels = svgEl("g", { class: "edge-labels" }, svg);
  for (const g of GIVES) {
    const path = svg.querySelector(`#${g.id}`);
    // place after the svg is attached (getPointAtLength needs layout in some browsers)
    queueMicrotask(() => {
      const L = path.getTotalLength();
      const pt = path.getPointAtLength(L * (g.id === "give-carol" ? 0.5 : g.id === "give-mallory" ? 0.55 : 0.5));
      const vertical = g.id === "give-bob" || g.id === "give-dave";
      const t = svgEl("text", { x: pt.x + (vertical ? 10 : 0), y: pt.y + (vertical ? 4 : g.id === "give-mallory" ? 18 : -8), class: `edge-label${g.bad ? " bad" : ""}`, "text-anchor": vertical ? "start" : "middle" }, labels);
      t.textContent = g.label;
    });
  }
  svgEl("g", { id: "packets" }, svg);
  root.append(svg);

  // Set through the CSSOM: the CSP blocks style="" attributes.
  const place = (node, id) => {
    const [x, y] = POS[id];
    node.style.left = `${(x / W) * 100}%`;
    node.style.top = `${(y / H) * 100}%`;
    return node;
  };

  const server = h(
    "article",
    { class: "node node-server", id: "node-server", "aria-labelledby": "srv-title" },
    h("h3", { id: "srv-title" }, "Server"),
    h("ul", { class: "holds", id: "srv-holds" }, h("li", { class: "chip chip-dim" }, "waiting for a file")),
    h("ol", { class: "checks", id: "srv-checks" }, CHECKS.map((c) => h("li", { class: "check" }, h("span", { class: "mark", "aria-hidden": "true" }, "·"), c.label))),
    h("p", { class: "srv-revoked", id: "srv-revoked" }, "Revoked shares: none"),
  );
  root.append(place(server, "server"));

  for (const a of ACTORS) {
    const open = h("button", { type: "button", class: "btn btn-small", disabled: true, "data-act": "open", "data-who": a.id }, "Open");
    const save = h("button", { type: "button", class: "btn btn-small btn-ghost", disabled: true, "data-act": "save", "data-who": a.id }, "Save");
    root.append(
      place(h(
        "article",
        { class: `node node-actor actor-${a.id}`, id: `node-${a.id}`, "aria-labelledby": `n-${a.id}` },
        h("header", {}, h("h3", { id: `n-${a.id}` }, a.name), h("p", { class: "who" }, a.who)),
        h("ul", { class: "holds", id: `holds-${a.id}` }, h("li", { class: "chip chip-dim" }, "nothing yet")),
        h("div", { class: "node-actions" }, open, save),
        h("p", { class: "stamp", id: `stamp-${a.id}`, "aria-live": "polite" }),
      ), a.id),
    );
  }
}

function buildMatrix(tbody) {
  fill(
    tbody,
    ACTORS.map((a) =>
      h(
        "tr",
        { id: `row-${a.id}` },
        h("th", { scope: "row" }, a.name),
        h("td", { class: "m-has", id: `has-${a.id}` }, "—"),
        h("td", { class: "m-cell", id: `m-${a.id}-open` }, "not tried"),
        h("td", { class: "m-cell", id: `m-${a.id}-save` }, "not tried"),
      ),
    ),
  );
}

/* -------------------------------------------------------------- animation */

function mapVisible() {
  const svg = $(".net-svg");
  return svg && svg.getBoundingClientRect().width > 0 && getComputedStyle(svg).display !== "none";
}

function travel(pathId, cls, label, ms = 520, reverse = false) {
  if (reducedMotion() || !mapVisible()) return Promise.resolve();
  const path = document.getElementById(pathId);
  const layer = $("#packets");
  const L = path.getTotalLength();
  const g = svgEl("g", { class: `pkt ${cls}` }, layer);
  svgEl("circle", { r: 9 }, g);
  const t = svgEl("text", { x: 14, y: 5 }, g);
  t.textContent = label;
  return new Promise((resolve) => {
    const t0 = performance.now();
    const step = (tm) => {
      const p = Math.min(1, (tm - t0) / ms);
      const e = p < 0.5 ? 2 * p * p : 1 - (-2 * p + 2) ** 2 / 2;
      const pt = path.getPointAtLength(L * (reverse ? 1 - e : e));
      g.setAttribute("transform", `translate(${pt.x},${pt.y})`);
      if (p < 1) requestAnimationFrame(step);
      else {
        g.remove();
        resolve();
      }
    };
    requestAnimationFrame(step);
  });
}

/* ------------------------------------------------------------------ views */

function chip(text, cls) {
  return h("li", { class: `chip ${cls}` }, text);
}

function drawHolds(id) {
  const a = state.actors[id];
  const list = $(`#holds-${id}`);
  const items = [];
  if (a.token) items.push(chip(`token: ${a.forged ? "edited by hand" : OP_LABEL[a.op]}`, a.forged ? "chip-bad" : `chip-${a.op}`));
  else items.push(chip(a.fileIdOnly ? "file ID only, no token" : "no token", "chip-dim"));
  items.push(a.hasKey ? chip("key k", "chip-k") : chip("no key k", "chip-dim"));
  fill(list, items);
  const has = $(`#has-${id}`);
  if (has) has.textContent = `${a.token ? (a.forged ? "edited token" : `${OP_LABEL[a.op]} token`) : "no token"}${a.hasKey ? " + k" : ""}`;
}

function drawServer() {
  const holds = $("#srv-holds");
  if (!state.fileId) {
    fill(holds, chip("waiting for a file", "chip-dim"));
  } else if (state.deleted) {
    fill(holds, chip("file and root key deleted", "chip-bad"));
  } else {
    fill(holds, chip(`root key for ${shortId(state.fileId)}`, "chip-full"), chip(`blob, ${state.blobSize} B, unreadable`, "chip-dim"), chip("never receives k", "chip-k-no"));
  }
  $("#srv-revoked").textContent = state.revoked.length ? `Revoked shares: ${state.revoked.map((s) => s.slice(0, 8)).join(", ")}` : "Revoked shares: none";
}

function showChecks(code) {
  const failAt = code === "ok" ? -1 : CHECKS.findIndex((c) => c.fails === code);
  [...$("#srv-checks").children].forEach((li, i) => {
    li.className = "check";
    const mark = li.querySelector(".mark");
    if (failAt === -1 || i < failAt) {
      li.classList.add("pass");
      mark.textContent = "✓";
    } else if (i === failAt) {
      li.classList.add("fail");
      mark.textContent = "✗";
    } else {
      li.classList.add("unreached");
      mark.textContent = "·";
    }
  });
}

function stamp(id, ok, text) {
  const s = $(`#stamp-${id}`);
  s.className = `stamp ${ok ? "granted" : "denied"}`;
  fill(s, h("strong", {}, ok ? "ACCESS GRANTED" : "ACCESS DENIED"), h("span", {}, text));
  const node = $(`#node-${id}`);
  node.classList.toggle("is-ok", ok);
  node.classList.toggle("is-bad", !ok);
  const edge = document.getElementById(`req-${id}`);
  edge?.classList.toggle("ok", ok);
  edge?.classList.toggle("bad", !ok);
}

function narrate(kind, who, head, body) {
  const log = $("#net-log");
  log.querySelector(".empty")?.remove();
  log.prepend(h("li", { class: `ev ev-${kind}` }, h("p", { class: "ev-head" }, h("span", { class: "ev-time" }, now()), h("span", { class: "ev-who" }, who), h("strong", {}, head)), body ? h("p", { class: "ev-body" }, body) : null));
  while (log.children.length > 30) log.lastChild.remove();
}

function explain(a, action, code, extra) {
  const verb = action === "open" ? "open the file" : "save a change";
  const tokenDesc = a.token ? (a.forged ? "the token she edited by hand" : `a ${OP_LABEL[a.op]} token`) : "no token at all";
  const lead = `${a.name} tried to ${verb} with ${tokenDesc}.`;
  switch (code) {
    case "ok":
      return action === "open"
        ? `${lead} The server rebuilt the HMAC chain with its root key, got the same signature, and every caveat held. It sent back the encrypted blob; ${a.name}'s browser decrypted it with k: “${extra}”.`
        : `${lead} The token allows editing, so the server stored the new blob. It was encrypted in ${a.name}'s browser with k, so the server still cannot read it.`;
    case "missing_token":
      return `${lead} Knowing the file ID is not enough: without a token the server stops at the first check.`;
    case "invalid_token":
      return `${lead} The server recomputed the HMAC chain from its root key and got a different signature, because a caveat was changed. Changing “read” to “edit” would need the signature from before that caveat, and HMAC cannot be run backwards.`;
    case "forbidden":
      return `${lead} The signature is genuine, but the token says op = ${a.op}. Saving needs edit, so the server refused.`;
    case "revoked":
      return `${lead} The signature is genuine, but the token carries share_id = ${shortId(a.shareId)}, which Alice revoked. Every link made from that share carries the same caveat, so they all stop working.`;
    case "expired":
      return `${lead} The token's expiry time has passed.`;
    case "not_found":
      return `${lead} Alice deleted the file and its root key, so there is nothing to check the token against.`;
    default:
      return `${lead} The server answered ${code}.`;
  }
}

function setButtons() {
  const ready = !!state.fileId;
  document.querySelectorAll("#net-map [data-act]").forEach((b) => (b.disabled = busy || !ready));
  $("#net-setup").disabled = busy || ready;
  $("#net-test").disabled = busy || !ready;
  $("#net-revoke").disabled = busy || !ready || state.deleted || state.revoked.length > 0;
  $("#net-delete").disabled = busy || !ready || state.deleted;
  $("#net-reset").disabled = busy;
  document.querySelectorAll(".net-steps li").forEach((li, i) => li.classList.toggle("done", state.step > i));
}

async function guarded(fn) {
  if (busy) return;
  busy = true;
  setButtons();
  try {
    await fn();
  } catch (err) {
    narrate("bad", "Page", err.status ? `${err.status} ${err.code}` : "Error", err.message);
  } finally {
    busy = false;
    setButtons();
  }
}

/* ---------------------------------------------------------------- actions */

async function handOut() {
  state.text = SAMPLE;
  state.key = newFileKey();
  const blob = await encryptFile("meeting-notes.txt", SAMPLE, state.key);
  await travel("req-alice", "pkt-info", "POST");
  const { file_id, token } = await api.upload(blob);
  state.fileId = file_id;
  state.blobSize = blob.length;
  Object.assign(state.actors.alice, { token, op: "full", hasKey: true });
  drawServer();
  drawHolds("alice");
  narrate("info", "Alice", "Uploaded meeting-notes.txt", `Her browser made a random key k and encrypted the file before sending it. The server stored ${blob.length} bytes it cannot read and made a root key for the file. Alice's own link has Full control.`);

  const bob = await api.share(token, "read", 3600);
  await travel("give-bob", "pkt-give", "link");
  Object.assign(state.actors.bob, { token: bob.token, op: "read", hasKey: true, shareId: bob.share_id });
  drawHolds("bob");

  const carol = await api.share(token, "edit", 3600);
  await travel("give-carol", "pkt-give", "link");
  Object.assign(state.actors.carol, { token: carol.token, op: "edit", hasKey: true, shareId: carol.share_id });
  drawHolds("carol");
  narrate("info", "Alice", "Sent two links by chat", "A Read link to Bob and an Edit link to Carol. Each link is Alice's token plus three caveats (op, expires, share_id) and the key k after the #. The links never pass through the server.");

  const dave = await api.share(bob.token, "read", 3600);
  await travel("give-dave", "pkt-give", "link");
  Object.assign(state.actors.dave, { token: dave.token, op: "read", hasKey: true, shareId: bob.share_id, ownShare: dave.share_id });
  drawHolds("dave");
  narrate("info", "Bob", "Made a link for Dave from his own", "Bob can only narrow his link, never widen it. Dave's token keeps all of Bob's caveats, including Bob's share_id, and adds new ones.");

  const m = parseToken(bob.token);
  const forged = serializeToken({ ...m, caveats: m.caveats.map((c) => (c === "op = read" ? "op = edit" : c)) });
  await travel("give-mallory", "pkt-bad", "copy");
  Object.assign(state.actors.mallory, { token: forged, op: "edit", hasKey: true, forged: true });
  drawHolds("mallory");
  Object.assign(state.actors.eve, { fileIdOnly: true });
  drawHolds("eve");
  narrate("bad", "Mallory", "Copied Bob's link and edited it", "She changed the caveat “op = read” to “op = edit” and kept the signature. She also has k, so she can decrypt anything the server sends her. Eve only knows the file ID.");
  state.step = 1;
}

async function attempt(id, action, fast = false) {
  const a = state.actors[id];
  const name = a.name;
  const path = `req-${id}`;
  const ms = fast ? 300 : 520;
  let newText;
  let blob;
  if (action === "save") {
    newText = `${state.text.trimEnd()}\n- Edited by ${name} at ${now()}\n`;
    blob = a.hasKey ? await encryptFile("meeting-notes.txt", newText, state.key) : crypto.getRandomValues(new Uint8Array(64));
  }
  const server = $("#node-server");
  await travel(path, "pkt-info", action === "open" ? "GET" : "PUT", ms);
  server.classList.add("checking");
  let code = "ok";
  let status = action === "open" ? 200 : 204;
  let extra = "";
  try {
    if (action === "open") {
      const { blob: got } = await api.download(state.fileId, a.token);
      const file = await decryptBlob(got, state.key);
      extra = file.text.split("\n").filter(Boolean).at(-1);
    } else {
      await api.replace(state.fileId, a.token, blob);
      state.text = newText;
    }
  } catch (err) {
    if (err.status === undefined) throw err;
    code = err.code;
    status = err.status;
  }
  showChecks(code);
  if (!fast) await sleep(240);
  server.classList.remove("checking");
  const ok = code === "ok";
  await travel(path, ok ? "pkt-ok" : "pkt-bad", String(status), ms, true);
  stamp(id, ok, ok ? `${status} ${action === "open" ? "opened" : "saved"}` : `${status} ${code}`);
  const cell = $(`#m-${id}-${action}`);
  cell.className = `m-cell ${ok ? "ok" : "bad"}`;
  cell.textContent = ok ? `✓ ${status} ${action === "open" ? "opened" : "saved"}` : `✗ ${status} ${code}`;
  narrate(ok ? "ok" : "bad", name, `${action === "open" ? "Open" : "Save"}: ${status} ${ok ? "OK" : code}`, explain(a, action, code, extra));
}

async function testEveryone(actions = ["open", "save"]) {
  for (const a of ACTORS) for (const act of actions) await attempt(a.id, act, true);
}

async function revokeBob() {
  const bob = state.actors.bob;
  await travel("req-alice", "pkt-info", "POST");
  await api.revoke(state.actors.alice.token, bob.shareId);
  await travel("req-alice", "pkt-ok", "204", 520, true);
  state.revoked.push(bob.shareId);
  drawServer();
  for (const id of ["bob", "dave"]) $(`#node-${id}`).classList.add("is-revoked");
  document.getElementById("give-bob").classList.add("cut");
  document.getElementById("give-dave").classList.add("cut");
  narrate("info", "Alice", "Revoked Bob's share", `The server added share_id ${shortId(bob.shareId)} to this file's revoked list. Bob's token has it, and so does Dave's, because Dave's link was made from Bob's. Carol's link has a different share_id. Now everyone tries again.`);
  state.step = 3;
  await testEveryone();
}

async function deleteFile() {
  await travel("req-alice", "pkt-info", "DELETE");
  await api.remove(state.fileId, state.actors.alice.token);
  await travel("req-alice", "pkt-ok", "204", 520, true);
  state.deleted = true;
  drawServer();
  narrate("info", "Alice", "Deleted the file", "The server removed the blob and the file's root key. Without the root key no token for this file can be verified, so every link is dead, including Alice's own. Everyone tries once more.");
  state.step = 4;
  await testEveryone();
}

function reset() {
  state = {
    step: 0,
    fileId: null,
    key: null,
    text: "",
    blobSize: 0,
    deleted: false,
    revoked: [],
    actors: Object.fromEntries(ACTORS.map((a) => [a.id, { ...a, token: undefined, op: null, hasKey: false }])),
  };
  for (const a of ACTORS) {
    const node = $(`#node-${a.id}`);
    node.classList.remove("is-ok", "is-bad", "is-revoked");
    fill($(`#holds-${a.id}`), chip("nothing yet", "chip-dim"));
    const s = $(`#stamp-${a.id}`);
    s.className = "stamp";
    fill(s);
  }
  document.querySelectorAll(".edge").forEach((e) => e.classList.remove("ok", "bad", "cut"));
  buildMatrix($("#net-matrix tbody"));
  showChecks(null);
  [...$("#srv-checks").children].forEach((li) => {
    li.className = "check";
    li.querySelector(".mark").textContent = "·";
  });
  drawServer();
  fill($("#net-log"), h("li", { class: "empty" }, "Nothing has happened yet. Start with step 1."));
  setButtons();
}

export function setupNetwork() {
  const root = $("#net-map");
  if (!root) return;
  buildMap(root);
  reset();
  root.addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    guarded(() => attempt(b.dataset.who, b.dataset.act));
  });
  $("#net-setup").addEventListener("click", () => guarded(handOut));
  $("#net-test").addEventListener("click", () =>
    guarded(async () => {
      await testEveryone();
      state.step = Math.max(state.step, 2);
    }),
  );
  $("#net-revoke").addEventListener("click", () => guarded(revokeBob));
  $("#net-delete").addEventListener("click", () => guarded(deleteFile));
  $("#net-reset").addEventListener("click", () => {
    if (!busy) reset();
  });
}
