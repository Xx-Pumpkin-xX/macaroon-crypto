// Home page: a short terminal session that types itself out once, telling the
// whole story of the project in eight steps. Static when motion is reduced.

import { $, h, reducedMotion, sleep } from "./dom.js";

const SCRIPT = [
  ["cmd", "alice$ upload meeting-notes.txt"],
  ["out", "encrypting in this browser with AES-256-GCM. The key k stays here."],
  ["out", "server stored 213 bytes it cannot read."],
  ["cmd", "alice$ share --with bob --allow read --for 1h"],
  ["out", "bob's link: view.html#f=q3J8xY2m…&t=MDAyMWxv…&k=Rk9xS1d3…"],
  ["cmd", "bob$ open link"],
  ["ok", "200 OK         ACCESS GRANTED   bob decrypts the note with k"],
  ["cmd", "bob$ save changes"],
  ["bad", "403 forbidden  ACCESS DENIED    the link only allows read"],
  ["cmd", "mallory$ edit bob's token: op = read → op = edit"],
  ["bad", "401 invalid    ACCESS DENIED    the signature no longer matches"],
  ["cmd", "alice$ revoke bob"],
  ["bad", "403 revoked    bob, and dave who got a link from bob, are cut off"],
];

export async function setupIntro() {
  const screen = $("#intro-screen");
  if (!screen) return;
  const replay = $("#intro-replay");
  let run = 0;

  async function play() {
    const mine = ++run;
    screen.replaceChildren();
    const still = reducedMotion();
    for (const [kind, text] of SCRIPT) {
      if (mine !== run) return;
      const line = h("div", { class: `tl tl-${kind}` });
      screen.append(line);
      if (still) {
        line.textContent = text;
        continue;
      }
      if (kind === "cmd") {
        for (let i = 1; i <= text.length; i += 1) {
          if (mine !== run) return;
          line.textContent = text.slice(0, i);
          await sleep(22);
        }
        await sleep(260);
      } else {
        line.textContent = text;
        await sleep(kind === "out" ? 220 : 520);
      }
    }
    screen.append(h("div", { class: "tl tl-cmd" }, "alice$ ", h("span", { class: "cursor", "aria-hidden": "true" })));
  }

  replay?.addEventListener("click", play);
  play();
}
