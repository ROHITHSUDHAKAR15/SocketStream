# SocketStream

A end-to-end encrypted web chat where **the server never sees your messages or your private key**.
Encryption happens entirely in the browser with the WebCrypto API; the Flask backend is a
zero-knowledge relay that only ever stores public keys and ciphertext.

> Rewritten from an earlier version that generated keys on the server and stored private keys in
> the database. That design could read every message — this one cannot. See
> [What changed](#what-changed-from-the-old-version).

---

## How it works (60-second version)

- **Keys are born in your browser.** On registration, your browser generates an RSA-OAEP 2048
  keypair. The **public** key is sent to the server; the **private** key never leaves the device.
- **Your private key is wrapped with your password** (PBKDF2-SHA256, 200k iterations → AES-256-GCM)
  and kept in `localStorage`. The server stores only a bcrypt hash of your password, so it cannot
  derive the wrapping key.
- **Every message uses hybrid encryption.** A fresh AES-256-GCM content key encrypts the text; that
  key is RSA-wrapped to each recipient's public key. The server stores one ciphertext row per
  recipient and relays it verbatim.
- **The server is a dumb pipe.** It authenticates users, stores public keys + ciphertext, and pushes
  ciphertext to recipients over WebSocket (with HTTP polling as a fallback). It has no code that can
  decrypt anything.

For the full threat model and honest limitations, read [SECURITY.md](SECURITY.md).
For the deeper design, read [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Quick start

```bash
git clone https://github.com/ROHITHSUDHAKAR15/SocketStream.git
cd SocketStream

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python simple_secure_server.py
```

Then open **https://localhost:5000**. The server generates a self-signed certificate on first run,
so your browser will warn you once — that's expected for local development; proceed past it.

> WebCrypto requires a *secure context*: HTTPS, or plain HTTP on `localhost` (localhost is treated as
> secure). So the app works over plain HTTP locally too — handy behind a TLS-terminating proxy.

### Configuration (environment variables)

| Variable           | Default     | Purpose                                                        |
|--------------------|-------------|----------------------------------------------------------------|
| `SS_HOST`          | `127.0.0.1` | Bind address.                                                  |
| `SS_PORT`          | `5000`      | Port.                                                          |
| `SS_DEBUG`         | `0`         | Flask debug mode (keep `0` outside development).               |
| `SS_TLS`           | `auto`      | `off` disables HTTPS (e.g. behind a proxy / local HTTP test).  |
| `SS_COOKIE_SECURE` | `1`         | Send the session cookie only over HTTPS.                       |
| `SS_SECRET_KEY`    | *(file)*    | Flask secret; if unset, persisted to `.flask_secret`.          |
| `SS_DB`            | `secure_messaging.db` | SQLite database path.                               |

See [.env.example](.env.example) for a copy-paste starting point.

### Docker

```bash
docker compose up --build
# → https://localhost:5000
```

---

## Features

- **Genuine end-to-end encryption** — RSA-OAEP-2048 key wrapping + AES-256-GCM message content,
  all in-browser via WebCrypto. The server cannot read messages.
- **Direct & broadcast messaging** — broadcasts are encrypted individually per recipient (no
  plaintext fan-out).
- **Real-time delivery** — Flask-SocketIO pushes ciphertext to recipients; HTTP polling is the
  automatic fallback.
- **Password-wrapped key custody** — your private key is encrypted at rest in the browser and
  unlocked per session with your password.
- **Encrypted key backup** — export/import a password-encrypted key file to use your account on a
  new device.
- **Hardening** — bcrypt password hashing, per-IP login rate limiting, HttpOnly/SameSite cookies,
  XSS-safe rendering (`textContent`, never `innerHTML`), input validation, persisted secret key.

---

## Testing

```bash
pip install -r requirements.txt
pytest -q
```

The suite (`tests/test_server.py`) verifies the server behaves as a zero-knowledge relay — including
`test_db_never_stores_private_keys` (the schema has no private-key column) and
`test_server_has_no_crypto_helpers` (the server has no decrypt code) — plus auth, validation, rate
limiting, per-recipient ciphertext relay, and the message cursor.

---

## Project structure

```
simple_secure_server.py   Flask zero-knowledge relay (auth, public keys, ciphertext, realtime)
static/js/crypto.js       WebCrypto module (keygen, wrap/unwrap, encrypt/decrypt) — runs in browser
static/js/socket.io.min.js Vendored Socket.IO client (no external CDN dependency)
static/css/style.css      Themed UI (design tokens, light + dark)
templates/                register / login / chat (all crypto is client-side)
tests/test_server.py      Pytest suite proving the relay never holds plaintext or private keys
generate_certificates.py  Self-signed cert generator for local HTTPS
Dockerfile, docker-compose.yml, .github/workflows/ci.yml
SECURITY.md, ARCHITECTURE.md
```

---

## What changed from the old version

| | Old version | This version |
|---|---|---|
| Key generation | On the **server** | In the **browser** (WebCrypto) |
| Private key storage | **Plaintext in the database** | Password-wrapped in the browser only |
| Who can read messages | **The server** (it had the keys + decrypt code) | Only sender & recipient |
| Message rendering | `innerHTML` (stored-XSS risk) | `textContent` (inert) |
| Broadcast | In-memory, lost on restart | Per-recipient ciphertext, persisted |
| Secret key | Regenerated each restart (sessions broke) | Persisted |
| Config | Hard-coded, `debug=True` on `0.0.0.0` | Env-driven, safe defaults |

---

## License

MIT — see [LICENSE](LICENSE).
