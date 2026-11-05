# Frontend (Part 3: Trâm, Phong)

Plain HTML + JavaScript. Uses the browser's WebCrypto API, no crypto library.

Pages: upload (text files only), share (pick Read / Edit / Full Control + expiry), open link (download + decrypt), edit (re-encrypt with the same K and upload), revoke, delete.

Rules from the design:

- Generate a random 256-bit key K per file; AES-256-GCM; store the nonce with the ciphertext
- K lives only after `#` in the URL, so the browser never sends it to the server
- Send the macaroon in a request header, not in the URL path or query
- Set `<meta name="referrer" content="no-referrer">`
