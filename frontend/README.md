# Frontend (Part 3)

Plain HTML, CSS and JavaScript modules. No build step and no CDN, so the demo
works offline. The backend serves this folder: start it as in the root README,
then open http://127.0.0.1:8000/. The backend serves only these pages and the `css`, `js` and `fonts` folders.

## Pages

| Page | What it shows |
|---|---|
| `index.html` | Overview: the idea in one screen, an example session, where to look next |
| `network.html` | Network map: Alice (owner), Bob (Read), Carol (Edit), Dave (Read, re-shared by Bob), Eve (file ID only), Mallory (Bob's link with read changed to edit). Every button calls the real backend; the server card shows which check passed or stopped the request, and a table records who can open and save. Steps: hand out links, test everyone, revoke Bob, delete the file |
| `demo.html` | Owner and Recipient side by side, plus "What the server sees", a log of every request with a live check that the file key `k` never appears in one |
| `how.html` | Blob layout, link anatomy, an HMAC-chain sandbox (throwaway key in the browser), the server's checks in order, a revocation tree |
| `lab.html` | 12 attacks against the running backend, compared with the design (IDs from `tests/ACCEPTANCE_PLAN.md`) |
| `results.html` | Test counts, benchmark charts, comparison table, pentest findings, limits |
| `view.html` | What a recipient opens from a shared link |

## Code

| File | Job |
|---|---|
| `js/crypto.js` | File key, AES-256-GCM blob (`nonce ‖ ciphertext ‖ tag`), base64url, HMAC |
| `js/macaroon.js` | Read pymacaroons v1 tokens, re-encode them, append a caveat with `HMAC(sig, caveat)`. Never verifies: only the server can |
| `js/api.js` | The six endpoints, error messages, request log |
| `js/network.js` | Network map page |
| `js/lab.js` | Attack lab scenarios |
| `js/intro.js` | Example session on the overview page |
| `js/charts.js` | SVG line charts with tooltip, keyboard and data table |
| `js/data.js` | Generated from `tests/results/*.csv` and `metadata.json` |
| `js/dom.js` | Small DOM helpers |
| `js/app.js` | Page logic; each page only runs the parts whose elements it has |
| `fonts/` | VT323 and IBM Plex Mono (SIL Open Font License, `fonts/OFL.txt`) |

## Rules from the design

- A random 256-bit `k` per file; the browser encrypts `{name, text}` with
  AES-256-GCM and a new 12-byte nonce on every upload and edit.
- Links are `view.html#f=<file_id>&t=<token>&k=<key>`. Everything after `#`
  stays in the browser; the token goes in the `Authorization` header.
- `Referrer-Policy: no-referrer` on every page; the backend also sends a
  Content-Security-Policy that only allows scripts, styles and fonts from itself.

The token format check in `macaroon.js` was verified against pymacaroons:
parsing and re-encoding gives the identical token, and appending a caveat gives
the same signature as `Macaroon.add_first_party_caveat`.
