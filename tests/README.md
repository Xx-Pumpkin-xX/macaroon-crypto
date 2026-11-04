# Tests (Part 2: Đạt, Nam)

Run with `pytest tests/`. Benchmarks go in `tests/bench/` and write their results to `tests/results/`.

## Acceptance tests (all must pass)

- [ ] 1. A valid token verifies
- [ ] 2. Random or garbage signature is rejected
- [ ] 3. A token for file A cannot open file B
- [ ] 4. Removing any caveat is rejected
- [ ] 5. Editing a caveat (`read` → `admin`) is rejected
- [ ] 6. Reordering caveats is rejected
- [ ] 7. Adding caveats never increases permissions
- [ ] 8. An expired token is rejected
- [ ] 9. A revoked share_id is rejected, including tokens derived from it
- [ ] 10. An unknown caveat is rejected
- [ ] 11. Same root key, id and caveats give the same signature as an independent HMAC-SHA256 recomputation
- [ ] 12. Oversized tokens (too many caveats, too long) are rejected

## Benchmarks

- Token size and verify time vs number of caveats (1 to 50): HMAC (macaroon) vs Ed25519 chain
- AES-GCM throughput vs file size
- Record machine, Python version, number of runs; report the median
