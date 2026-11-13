import * as api from "./api.js";
import { b64uDecode, b64uEncode, decryptBlob, encryptFile, hmac, newFileKey, toHex, utf8 } from "./crypto.js";
import { describeToken, rank } from "./macaroon.js";
import { SCENARIOS, runScenario } from "./lab.js";
import { lineChart } from "./charts.js";
import { AES, BENCH_META, TOKENS } from "./data.js";
import { $, fill, h } from "./dom.js";
import { setupNetwork } from "./network.js";
import { setupIntro } from "./intro.js";

const PAGE = document.body.dataset.page; // home, demo, network, how, lab, results, view
const OP_NAME = { read: "Read", edit: "Edit", full: "Full control" };
const SAMPLE = {
  name: "meeting-notes.txt",
  text: "Crypto midterm, meeting notes\n\n- Backend: 6 endpoints merged\n- Tests: 449 passing\n- Demo on Friday\n",
};

function when(ts) {
  if (!ts) return "No expiry";
  const d = new Date(ts * 1000);
  const past = d.getTime() <= Date.now();
  const s = d.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  return past ? `Expired ${s}` : `Until ${s}`;
}

function badge(op) {
  return h("span", { class: `perm perm-${op}` }, h("span", { class: "perm-dot", "aria-hidden": "true" }), OP_NAME[op] || op);
}

function buildLink(fileId, token, keyB64) {
  const base = `${location.origin}/view.html`;
  return `${base}#f=${encodeURIComponent(fileId)}&t=${encodeURIComponent(token)}&k=${encodeURIComponent(keyB64)}`;
}

export function parseLink(text) {
  const url = new URL(text.trim(), location.origin);
  const params = new URLSearchParams(url.hash.slice(1));
  const f = params.get("f");
  const t = params.get("t");
  const k = params.get("k");
  if (!f || !t || !k) throw new Error("A link needs f, t and k after the #.");
  return { fileId: f, token: t, keyB64: k };
}

/** Show a link split into its three parts. */
function linkAnatomy(link) {
  const { fileId, token, keyB64 } = parseLink(link);
  const shortT = `${token.slice(0, 10)}…${token.slice(-8)}`;
  return h(
    "div",
    { class: "anatomy" },
    h(
      "p",
      { class: "anatomy-link", title: link },
      h("span", { class: "seg-base" }, `${location.host}/view.html`),
      h("span", { class: "seg-hash" }, "#"),
      h("span", { class: "seg seg-f" }, `f=${fileId}`),
      h("span", { class: "seg-amp" }, "&"),
      h("span", { class: "seg seg-t" }, `t=${shortT}`),
      h("span", { class: "seg-amp" }, "&"),
      h("span", { class: "seg seg-k" }, `k=${keyB64.slice(0, 8)}…`),
    ),
    h(
      "ul",
      { class: "anatomy-key" },
      h("li", { class: "key-f" }, h("strong", { text: "f" }), " file ID: picks the file"),
      h("li", { class: "key-t" }, h("strong", { text: "t" }), ` token: what this link may do (${token.length} chars)`),
      h("li", { class: "key-k" }, h("strong", { text: "k" }), " file key: only your browser uses it, never sent"),
    ),
  );
}

function copyButton(text, label = "Copy link") {
  const btn = h("button", { type: "button", class: "btn btn-quiet" }, label);
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
    } catch {
      window.prompt("Copy this link:", text);
    }
    setTimeout(() => (btn.textContent = label), 1500);
  });
  return btn;
}

function errorBox(err) {
  return h(
    "div",
    { class: "notice notice-error", role: "alert" },
    h("strong", { text: err.status ? `${err.status} ${err.code}` : "Error" }),
    h("p", { text: err.message }),
  );
}

function expirySelect(name) {
  return h(
    "select",
    { name, class: "select" },
    h("option", { value: "60" }, "1 minute"),
    h("option", { value: "3600", selected: true }, "1 hour"),
    h("option", { value: "86400" }, "1 day"),
    h("option", { value: "604800" }, "7 days"),
  );
}

function permissionPicker(name, maxOp) {
  const wrap = h("div", { class: "seg-control", role: "radiogroup", "aria-label": "Permission" });
  for (const op of ["read", "edit", "full"]) {
    const id = `${name}-${op}`;
    const disabled = rank(op) > rank(maxOp);
    wrap.append(
      h("input", { type: "radio", name, id, value: op, checked: op === "read", disabled }),
      h("label", { for: id, class: `perm-${op}` }, OP_NAME[op]),
    );
  }
  return wrap;
}

/* ------------------------------------------------------------------ wire */

const knownKeys = new Set(); // base64url keys that must never reach the server
let wireCount = 0;
let wireLeaks = 0;

function containsBytes(hay, needle) {
  outer: for (let i = 0; i + needle.length <= hay.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

function setupWire() {
  const log = $("#wire-log");
  const check = $("#key-check");
  if (!log) return;
  api.onRequest((e) => {
    wireCount += 1;
    let leaked = false;
    for (const k of knownKeys) {
      if (e.raw.includes(k) || (e.rawBytes && containsBytes(e.rawBytes, b64uDecode(k)))) leaked = true;
    }
    if (leaked) wireLeaks += 1;
    const ok = e.status >= 200 && e.status < 300;
    log.prepend(
      h(
        "li",
        { class: ok ? "wire-ok" : "wire-err" },
        h("span", { class: "wire-time", text: e.at.toLocaleTimeString("en-GB") }),
        h("span", { class: "wire-req", text: `${e.method} ${e.path}` }),
        h("span", { class: "wire-status", text: e.status ? `${e.status}${e.code ? ` ${e.code}` : ""}` : "no answer" }),
        h("span", { class: "wire-detail", text: `Authorization: ${e.auth}` }),
        h("span", { class: "wire-detail", text: `Body: ${e.sent}` }),
      ),
    );
    while (log.children.length > 40) log.lastChild.remove();
    check.textContent = `File key k found in ${wireLeaks} of ${wireCount} request${wireCount === 1 ? "" : "s"} so far.`;
    check.classList.toggle("leak", wireLeaks > 0);
  });
}

/* --------------------------------------------------------------- owner */

const owner = { file: null, upload: null, shares: [] };

function setupOwner() {
  const pane = $("#owner");
  if (!pane) return;
  const input = $("#file-input");
  const chosen = $("#file-chosen");
  const go = $("#upload-btn");
  const body = $("#owner-body");

  function pick(name, text) {
    owner.file = { name, text };
    chosen.textContent = `${name}, ${utf8(text).length.toLocaleString("en")} bytes`;
    go.disabled = false;
  }

  input.addEventListener("change", async () => {
    const f = input.files[0];
    if (!f) return;
    if (!/\.txt$/i.test(f.name) && f.type !== "text/plain") {
      chosen.textContent = "Only text files (.txt) are supported.";
      go.disabled = true;
      return;
    }
    pick(f.name, await f.text());
  });
  const drop = $("#drop");
  drop.addEventListener("dragover", (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", async (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const f = e.dataTransfer.files[0];
    if (f) pick(f.name, await f.text());
  });
  $("#sample-btn").addEventListener("click", () => pick(SAMPLE.name, SAMPLE.text));

  go.addEventListener("click", async () => {
    go.disabled = true;
    go.textContent = "Encrypting…";
    try {
      const key = newFileKey();
      const keyB64 = b64uEncode(key);
      knownKeys.add(keyB64);
      const blob = await encryptFile(owner.file.name, owner.file.text, key);
      const { file_id, token } = await api.upload(blob);
      owner.upload = { fileId: file_id, token, keyB64, blobSize: blob.length };
      owner.shares = [];
      renderOwner();
      updateHowLink(buildLink(file_id, token, keyB64));
    } catch (err) {
      fill(body, errorBox(err));
    } finally {
      go.textContent = "Encrypt and upload";
      go.disabled = !owner.file;
    }
  });
}

function renderOwner() {
  const body = $("#owner-body");
  const u = owner.upload;
  $("#owner-start").hidden = true;
  const link = buildLink(u.fileId, u.token, u.keyB64);

  const sharesList = h("ul", { class: "shares" });
  const drawShares = () => {
    fill(sharesList, );
    if (!owner.shares.length) sharesList.append(h("li", { class: "empty", text: "No links yet. Create one above." }));
    for (const s of owner.shares) {
      const row = h(
        "li",
        { class: s.revoked ? "share revoked" : "share" },
        badge(s.op),
        h("span", { class: "share-when", text: s.revoked ? "Revoked" : when(s.expires_at) }),
        h("code", { class: "share-id", title: "share_id", text: s.share_id }),
        h(
          "span",
          { class: "share-actions" },
          h("button", { type: "button", class: "btn btn-quiet", onclick: () => openAsRecipient(s.link) }, "Open as recipient"),
          copyButton(s.link, "Copy"),
          s.revoked
            ? null
            : h(
                "button",
                {
                  type: "button",
                  class: "btn btn-quiet btn-warn",
                  onclick: async () => {
                    try {
                      await api.revoke(u.token, s.share_id);
                      s.revoked = true;
                      drawShares();
                      refreshRecipient();
                    } catch (err) {
                      row.append(errorBox(err));
                    }
                  },
                },
                "Revoke",
              ),
        ),
      );
      sharesList.append(row);
    }
  };
  drawShares();

  const form = h("form", { class: "share-form" }, permissionPicker("owner-op", "full"), expirySelect("owner-exp"), h("button", { type: "submit", class: "btn" }, "Create link"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const op = form.querySelector("input[name=owner-op]:checked").value;
    const exp = Number(form.querySelector("select").value);
    try {
      const s = await api.share(u.token, op, exp);
      s.link = buildLink(u.fileId, s.token, u.keyB64);
      owner.shares.unshift(s);
      drawShares();
    } catch (err) {
      form.after(errorBox(err));
    }
  });

  const del = h("button", { type: "button", class: "btn btn-danger" }, "Delete file");
  del.addEventListener("click", async () => {
    try {
      await api.remove(u.fileId, u.token);
      fill(body,
        h("div", { class: "notice" }, h("strong", { text: "File deleted." }), h("p", { text: "Its root key is gone too, so every link for it now returns 404. Try opening one on the right." })),
        h("button", { type: "button", class: "btn", onclick: resetOwner }, "Start again"),
      );
      refreshRecipient();
    } catch (err) {
      body.append(errorBox(err));
    }
  });

  fill(body,
    h("p", { class: "done", text: `Uploaded ${owner.file.name}: the server stored ${u.blobSize.toLocaleString("en")} bytes it cannot read.` }),
    h("h3", { text: "Your link (Full control)" }),
    linkAnatomy(link),
    h("div", { class: "row" }, h("button", { type: "button", class: "btn btn-quiet", onclick: () => openAsRecipient(link) }, "Open as recipient"), copyButton(link)),
    h("h3", { text: "Create a link for someone else" }),
    form,
    sharesList,
    h("div", { class: "row row-end" }, del),
  );
}

function resetOwner() {
  owner.upload = null;
  owner.shares = [];
  fill($("#owner-body"));
  $("#owner-start").hidden = false;
}

/* ----------------------------------------------------------- recipient */

let current = null; // {fileId, token, keyB64, link}

function openAsRecipient(link) {
  const input = $("#link-input");
  if (input) input.value = link;
  openLink(link);
  if (PAGE === "demo" && window.matchMedia("(max-width: 900px)").matches) $("#recipient").scrollIntoView({ behavior: "smooth" });
}

function refreshRecipient() {
  if (current) openLink(current.link, true);
}

async function openLink(link, quiet = false) {
  const out = $("#recipient-body");
  let parsed;
  try {
    parsed = parseLink(link);
  } catch (err) {
    fill(out, errorBox(err));
    return;
  }
  current = { ...parsed, link };
  knownKeys.add(parsed.keyB64);
  if (!quiet) fill(out, h("p", { class: "muted", text: "Opening…" }));
  let info;
  try {
    info = describeToken(parsed.token);
  } catch {
    info = null;
  }
  try {
    const { blob, permission } = await api.download(parsed.fileId, parsed.token);
    const file = await decryptBlob(blob, b64uDecode(parsed.keyB64));
    renderRecipient(file, permission, info);
  } catch (err) {
    fill(out, errorBox(err), info ? chainView(info) : null);
  }
}

function chainView(info) {
  const list = h("ol", { class: "chain" });
  info.caveats.forEach((c) => {
    const op = /^op = (\w+)$/.exec(c);
    const exp = /^expires < (\d+)$/.exec(c);
    list.append(
      h(
        "li",
        { class: op ? `cav cav-${op[1]}` : "cav" },
        h("code", { text: c }),
        exp ? h("span", { class: "cav-note", text: when(Number(exp[1])).replace("Until", "until") }) : null,
      ),
    );
  });
  return h(
    "div",
    { class: "chain-wrap" },
    h("h3", { text: "Caveats in this token" }),
    list,
    h("p", { class: "fine", text: "Each caveat was added with HMAC(previous signature, caveat). The lowest op wins; the earliest expiry wins." }),
  );
}

function renderRecipient(file, permission, info) {
  const out = $("#recipient-body");
  const canEdit = rank(permission) >= rank("edit");
  const area = h("textarea", { class: "content", rows: 8, readonly: !canEdit, "aria-label": "File content" });
  area.value = file.text;

  const actions = h("div", { class: "row" });
  if (canEdit) {
    const save = h("button", { type: "button", class: "btn" }, "Save changes");
    save.addEventListener("click", async () => {
      try {
        const blob = await encryptFile(file.name, area.value, b64uDecode(current.keyB64));
        await api.replace(current.fileId, current.token, blob);
        save.textContent = "Saved";
        setTimeout(() => (save.textContent = "Save changes"), 1500);
      } catch (err) {
        actions.after(errorBox(err));
      }
    });
    actions.append(save);
  } else {
    const tryEdit = h("button", { type: "button", class: "btn btn-quiet" }, "Try to save anyway");
    tryEdit.addEventListener("click", async () => {
      try {
        const blob = await encryptFile(file.name, area.value, b64uDecode(current.keyB64));
        await api.replace(current.fileId, current.token, blob);
      } catch (err) {
        actions.after(errorBox(err));
      }
    });
    actions.append(tryEdit);
  }

  // Share further: never above this link's own level.
  const shareOut = h("div", { class: "share-out" });
  const form = h("form", { class: "share-form" }, permissionPicker("rec-op", permission), expirySelect("rec-exp"), h("button", { type: "submit", class: "btn btn-quiet" }, "Create a narrower link"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const op = form.querySelector("input[name=rec-op]:checked").value;
    try {
      const s = await api.share(current.token, op, Number(form.querySelector("select").value));
      const link = buildLink(current.fileId, s.token, current.keyB64);
      fill(shareOut,
        h("p", { class: "done", text: `New ${OP_NAME[s.op]} link. It keeps every caveat above and adds three more.` }),
        linkAnatomy(link),
        h("div", { class: "row" }, h("button", { type: "button", class: "btn btn-quiet", onclick: () => openAsRecipient(link) }, "Open this link"), copyButton(link)),
      );
    } catch (err) {
      fill(shareOut, errorBox(err));
    }
  });

  const extra = [];
  if (permission === "full") {
    const rid = h("input", { class: "input", placeholder: "share_id to revoke", "aria-label": "share_id to revoke", pattern: "[0-9a-f]{16}" });
    const rbtn = h("button", { type: "button", class: "btn btn-quiet btn-warn" }, "Revoke");
    const rmsg = h("div");
    rbtn.addEventListener("click", async () => {
      try {
        await api.revoke(current.token, rid.value.trim());
        fill(rmsg, h("p", { class: "done", text: "Revoked." }));
      } catch (err) {
        fill(rmsg, errorBox(err));
      }
    });
    extra.push(h("h3", { text: "Revoke a share" }), h("div", { class: "row" }, rid, rbtn), rmsg);
  }

  fill(out,
    h("div", { class: "file-head" }, h("h3", { class: "file-name", text: file.name }), badge(permission), h("span", { class: "muted", text: info ? when(info.expiresAt) : "" })),
    area,
    actions,
    info ? chainView(info) : null,
    h("h3", { text: "Share further" }),
    form,
    shareOut,
    ...extra,
  );
}

function setupRecipient() {
  const form = $("#open-form");
  if (!form) return;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    openLink($("#link-input").value);
  });
  if (PAGE === "view" && location.hash.length > 1) {
    const link = location.href;
    $("#link-input").value = link;
    openLink(link);
  }
}

/* ------------------------------------------------------------ explainer */

function updateHowLink(link) {
  const slot = $("#how-link");
  if (slot) fill(slot, linkAnatomy(link), h("p", { class: "fine", text: "This is the owner link you just created." }));
}

async function setupSandbox() {
  const root = $("#sandbox");
  if (!root) return;
  const rootKey = crypto.getRandomValues(new Uint8Array(32));
  const id = "demo-file";
  const caveats = [{ text: "op = full", stripped: false }];
  const rows = $("#sb-rows", root);
  const verdict = $("#sb-verdict", root);
  $("#sb-root", root).textContent = toHex(rootKey, 8);

  async function chain(list) {
    let sig = await hmac(rootKey, utf8(id));
    const sigs = [sig];
    for (const c of list) {
      sig = await hmac(sig, utf8(c));
      sigs.push(sig);
    }
    return sigs;
  }

  async function draw() {
    const honest = await chain(caveats.map((c) => c.text));
    const kept = caveats.filter((c) => !c.stripped).map((c) => c.text);
    const recomputed = (await chain(kept)).at(-1);
    const tokenSig = honest.at(-1);
    fill(rows,
      h("li", { class: "sb-row sb-start" }, h("span", { class: "sb-cav" }, h("code", { text: `identifier "${id}"` })), h("code", { class: "sb-sig", text: toHex(honest[0], 6) })),
    );
    caveats.forEach((c, i) => {
      const toggle = h("button", { type: "button", class: "btn btn-quiet btn-small" }, c.stripped ? "Put back" : "Strip it");
      toggle.addEventListener("click", () => {
        c.stripped = !c.stripped;
        draw();
      });
      const op = /^op = (\w+)$/.exec(c.text);
      rows.append(
        h(
          "li",
          { class: `sb-row${c.stripped ? " stripped" : ""}` },
          h("span", { class: op ? `sb-cav cav-${op[1]}` : "sb-cav" }, h("code", { text: c.text })),
          h("code", { class: "sb-sig", text: toHex(honest[i + 1], 6) }),
          i === 0 ? h("span", { class: "sb-pad" }) : toggle,
        ),
      );
    });
    const match = toHex(recomputed) === toHex(tokenSig);
    const ops = kept.map((c) => /^op = (\w+)$/.exec(c)).filter(Boolean).map((m) => m[1]);
    const effective = ops.reduce((a, b) => (rank(a) <= rank(b) ? a : b), "full");
    fill(verdict,
      h("p", {}, "Signature in the token: ", h("code", { text: toHex(tokenSig, 6) })),
      h("p", {}, "Server recomputes from the root key: ", h("code", { text: toHex(recomputed, 6) })),
      h(
        "p",
        { class: match ? "verdict ok" : "verdict bad", role: "status" },
        match ? `Match: accepted as ${OP_NAME[effective]}.` : "Mismatch: rejected as 401 invalid_token. A stripped caveat cannot be hidden.",
      ),
    );
  }

  root.querySelectorAll("[data-add]").forEach((btn) =>
    btn.addEventListener("click", () => {
      let text = btn.dataset.add;
      if (text === "expires") text = `expires < ${Math.floor(Date.now() / 1000) + 86400}`;
      if (text === "share") text = `share_id = ${toHex(crypto.getRandomValues(new Uint8Array(8)))}`;
      if (caveats.length >= 8) return;
      caveats.push({ text, stripped: false });
      draw();
    }),
  );
  $("#sb-reset", root).addEventListener("click", () => {
    caveats.splice(1);
    draw();
  });
  await draw();
}

function setupTree() {
  const tree = $("#tree");
  if (!tree) return;
  const btn = $("#tree-btn");
  btn.addEventListener("click", () => {
    const on = tree.classList.toggle("revoked");
    btn.textContent = on ? "Undo" : "Revoke S1";
    btn.setAttribute("aria-pressed", String(on));
  });
}

/* ------------------------------------------------------------ attack lab */

function setupLab() {
  const list = $("#lab-list");
  if (!list) return;
  const summary = $("#lab-summary");
  const results = new Map();
  const updateSummary = () => {
    const done = [...results.values()];
    const good = done.filter((r) => r.ok).length;
    summary.textContent = done.length ? `${good} of ${done.length} scenarios run so far behaved as designed.` : "";
    const meter = $("#lab-meter");
    if (meter) {
      meter.value = done.length;
      meter.max = SCENARIOS.length;
    }
    const bar = $("#lab-bar");
    if (bar) bar.textContent = `[${"#".repeat(done.length)}${".".repeat(SCENARIOS.length - done.length)}] ${done.length}/${SCENARIOS.length}`;
  };
  const runners = SCENARIOS.map((s) => {
    const out = h("div", { class: "lab-result", "aria-live": "polite" }, h("span", { class: "muted", text: "Not run yet" }));
    const btn = h("button", { type: "button", class: "btn btn-quiet" }, "Run");
    const run = async () => {
      btn.disabled = true;
      fill(out, h("span", { class: "muted", text: "Running…" }));
      const r = await runScenario(s);
      results.set(s.id, r);
      row.classList.toggle("is-ok", r.ok);
      row.classList.toggle("is-bad", !r.ok);
      fill(out,
        h("span", { class: r.ok ? "verdict ok" : "verdict bad", text: `${r.ok ? "As designed" : "Unexpected"}: ${r.status} ${r.code}` }),
        r.extra ? h("span", { class: "fine", text: r.extra }) : null,
      );
      btn.disabled = false;
      updateSummary();
    };
    btn.addEventListener("click", run);
    const row = h(
        "li",
        { class: "lab-row" },
        h("span", { class: "lab-id", text: s.id }),
        h(
          "div",
          { class: "lab-what" },
          h("h3", { text: s.title }),
          h("p", {}, h("span", { class: "muted", text: "Has: " }), s.has),
          h("p", {}, h("span", { class: "muted", text: "Tries: " }), s.tries),
          s.note ? h("p", { class: "fine", text: s.note }) : null,
        ),
        h("div", { class: "lab-expect" }, h("span", { class: "muted", text: "Expected" }), h("code", { text: `${s.expect.status} ${s.expect.code}` })),
        out,
        btn,
      );
    list.append(row);
    return run;
  });
  const all = $("#lab-all");
  all.addEventListener("click", async () => {
    all.disabled = true;
    results.clear();
    updateSummary();
    for (const run of runners) await run();
    all.disabled = false;
  });
}

/* --------------------------------------------------------------- results */

function setupCharts() {
  // Validated against the black surface (dataviz validator, dark mode).
  const BLUE = "#1aa3c9";
  const ORANGE = "#c27d00";
  const t1 = $("#chart-size");
  if (!t1) return;
  lineChart(t1, {
    caption: "Token size in bytes against number of caveats, 1 to 50",
    series: [{ name: "Token size", color: BLUE, points: TOKENS.map((r) => ({ x: r.caveats, y: r.bytes })) }],
    xLabel: "Caveats in the token",
    xName: "Caveats",
    yLabel: "Bytes",
    xTicks: [1, 10, 20, 30, 40, 50],
    yFormat: (v) => v.toLocaleString("en"),
    shadeFrom: 20,
    shadeLabel: "Rejected by the server (limit: 20)",
  });
  lineChart($("#chart-verify"), {
    caption: "Verify time in microseconds against number of caveats",
    series: [
      { name: "HMAC check only (library)", short: "HMAC only", color: BLUE, points: TOKENS.map((r) => ({ x: r.caveats, y: r.library_us })) },
      { name: "Full check (app, all rules)", short: "Full check", color: ORANGE, points: TOKENS.filter((r) => r.app_us !== null).map((r) => ({ x: r.caveats, y: r.app_us })) },
    ],
    xLabel: "Caveats in the token",
    xName: "Caveats",
    yLabel: "Microseconds",
    xTicks: [1, 10, 20, 30, 40, 50],
    yFormat: (v) => (v >= 10 || v === 0 ? Math.round(v).toString() : v.toFixed(1)),
    shadeFrom: 20,
    shadeLabel: "App rejects these before the full check",
  });
  const sizeLabel = (b) => (b >= 1048000 ? "1 MiB" : b >= 1024 ? `${Math.round(b / 1024)} KiB` : `${b} B`);
  lineChart($("#chart-aes"), {
    caption: "AES-256-GCM throughput in MiB per second against plaintext size",
    series: [
      { name: "Encrypt", color: BLUE, points: AES.map((r) => ({ x: r.bytes, y: r.encrypt })), labelDy: -8 },
      { name: "Decrypt", color: ORANGE, points: AES.map((r) => ({ x: r.bytes, y: r.decrypt })), labelDy: 8 },
    ],
    xLog: true,
    xLabel: "Plaintext size (log scale)",
    xName: "Size",
    yLabel: "MiB per second",
    xTicks: AES.map((r) => r.bytes),
    xFormat: sizeLabel,
    yFormat: (v) => Math.round(v).toLocaleString("en"),
  });
  const meta = $("#bench-meta");
  if (meta) meta.textContent = `Measured by Part 2 on ${BENCH_META.processor}, Python ${BENCH_META.python.split(" ")[0]}, ${BENCH_META.statistic} over ${BENCH_META.samples} samples. AES numbers are Python's cryptography library, not the browser.`;
}

/* ------------------------------------------------------------------ boot */

setupWire();
setupOwner();
setupRecipient();
setupSandbox();
setupTree();
setupLab();
setupCharts();
setupNetwork();
setupIntro();
