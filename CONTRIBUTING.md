# Contributing

## Branches

- `main` is protected. Nobody pushes to it directly.
- Branch name = `<part>/<short-topic>`, for example `p1/revoke-endpoint`, `p2/benchmark-hmac`, `p3/api-spec`.
- One topic per branch. Small pull requests get reviewed faster.

```bash
git checkout main && git pull
git checkout -b p1/revoke-endpoint
# ... work ...
git add <files>
git commit -m "backend: add POST /revoke with share_id check"
git push -u origin p1/revoke-endpoint
# then open a pull request on GitHub
```

## Commit messages

`<area>: <what changed>`, where area is `backend`, `frontend`, `tests`, `docs` or `repo`.

## Pull requests

- Fill in the checklist in the PR template.
- Thịnh reviews and merges. Changes under `docs/` are also reviewed by Phong.
- If the change affects the API or caveat format, update `docs/spec/` in the same PR.

## Never commit

- Root keys, `.env` files, any secret
- Uploaded or encrypted files from local testing (`storage/`)
- Virtual environments, `__pycache__`, `node_modules`

## Writing

The report must be written by us ("anti-AI" rule). Specs and README files can be short and plain.
