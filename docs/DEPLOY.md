# Deploying the demo on PythonAnywhere

The demo needs a real server: it keeps each file's root key secret, stores the
encrypted blobs and keeps the revoked-share list. A static host (GitHub Pages,
Netlify) cannot do that. PythonAnywhere's free account can, and it fits the
design:

- **One web worker.** The server runs as a single process, which is what the
  share/revoke lock needs (pentest finding F01).
- **A persistent disk (512 MiB).** Files, root keys and revocations survive
  restarts. Each upload is at most 1 MiB.
- **HTTPS** on `<username>.pythonanywhere.com`, which WebCrypto requires.

The site is public: anyone with the address can upload a file. Turn it off
(Web tab → Disable) when it is no longer needed.

## 1. Account

Sign up for a free ("Beginner") account at pythonanywhere.com. The username
becomes the address: `https://<username>.pythonanywhere.com`. Below,
replace `<username>` with it.

## 2. Code and packages

Open **Consoles → Bash** and run:

```bash
git clone https://github.com/Xx-Pumpkin-xX/macaroon-crypto.git
cd macaroon-crypto/backend
python3.13 -m venv ~/.venvs/macaroon      # any python3.10 or newer that the console has
source ~/.venvs/macaroon/bin/activate
python -m pip install -r requirements.txt
python -m pip install ./pymacaroons
```

## 3. Web app

On the **Web** tab:

1. **Add a new web app** → **Manual configuration** (not the Flask quickstart) →
   the same Python version as the virtualenv above.
2. **Virtualenv**: `/home/<username>/.venvs/macaroon`
3. **WSGI configuration file**: open it, delete everything, and paste:

   ```python
   import sys

   sys.path.insert(0, "/home/<username>/macaroon-crypto/backend")

   from app import create_app

   application = create_app()
   ```

4. **Security** → **Force HTTPS**: on.
5. Press **Reload**, then open `https://<username>.pythonanywhere.com/`.

Check: the Network map page runs all four steps, and the Attack lab shows
"12 of 12 scenarios run so far behaved as designed".

## Updating after a merge to main

```bash
cd ~/macaroon-crypto
git pull
# only if backend/requirements.txt changed:
source ~/.venvs/macaroon/bin/activate && python -m pip install -r backend/requirements.txt
```

Then **Web → Reload**.

## Keeping it running

A free web app stops after one month unless it is extended. On the **Web**
tab, press the button that extends it ("Run until 1 month from today") before
then.

## Data and logs

- Uploaded data lives in `~/macaroon-crypto/backend/storage/`. It is in
  `.gitignore`, so `git pull` never touches it.
- To wipe all demo data: `rm -rf ~/macaroon-crypto/backend/storage`, then
  **Reload**. Every existing link stops working.
- Disk use: `du -sh ~/macaroon-crypto/backend/storage`
- **Web → Log files**: the error log shows crashes. The server log records only
  method, path, status and error code: never tokens, keys or file contents.
