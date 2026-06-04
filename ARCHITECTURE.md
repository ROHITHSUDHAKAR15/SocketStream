# Architecture

SocketStream is split into two trust domains: a **browser** that owns all secrets and does all
cryptography, and a **server** that is a zero-knowledge relay. The server is deliberately incapable
of reading messages — it has no private keys and no decryption code.

```
┌─────────────────────────────┐         HTTPS / WSS          ┌──────────────────────────────┐
│  Browser (trusted)          │  ───────────────────────────▶ │  Flask server (untrusted)    │
│                             │                               │                              │
│  crypto.js (WebCrypto)      │   register: { public_key }    │  auth (bcrypt, sessions)     │
│   • RSA-OAEP-2048 keygen    │ ───────────────────────────▶ │  rate limiting (per IP)      │
│   • PBKDF2 → AES-GCM wrap   │                               │                              │
│   • per-msg AES-256-GCM     │   send: { recipient:ct, … }   │  SQLite                      │
│   • RSA-wrap content key    │ ───────────────────────────▶ │   users(public_key)          │
│                             │                               │   messages(ciphertext)       │
│  localStorage: wrapped SK   │   new_message (ciphertext)    │                              │
│  sessionStorage: unlocked   │ ◀─────────────────────────── │  Socket.IO relay → room=user │
└─────────────────────────────┘   poll /api/messages?since    └──────────────────────────────┘
```

## Components

### Browser — `static/js/crypto.js` (`SSCrypto`)

All cryptography lives here. Nothing in this file ever sends a private key or plaintext to the
server.

- **Identity:** `generateIdentity()` creates an RSA-OAEP-2048 (SHA-256) keypair. The public key is
  exported SPKI → base64 for the server; the private key stays as a non-extractable-by-default
  `CryptoKey` in memory and as PKCS#8 only when wrapping it for local storage.
- **Private-key custody:** `wrapPrivateKey(privateKey, password)` derives an AES-256-GCM key via
  PBKDF2-SHA256 (200k iterations, random salt) and encrypts the PKCS#8 key. The result
  (`{v, salt, iv, data}`, all base64) is stored in `localStorage` under `ss_pk_<username>`.
  `unwrapPrivateKey()` reverses it; a wrong password fails AES-GCM authentication and throws.
- **Per-session unlock:** the unwrapped `CryptoKey` is cached in `sessionStorage`
  (`ss_sk_<username>`) so the chat tab can encrypt/decrypt without re-entering the password, and is
  gone when the tab closes.
- **Message encryption (`encryptFor`):** generate a random AES-256-GCM content key + 12-byte IV,
  encrypt the plaintext, then RSA-OAEP-wrap the content key to the recipient's public key. Wire
  format, base64-encoded:

  ```
  [ RSA-wrapped AES key | 256 bytes ][ IV | 12 bytes ][ AES-GCM ciphertext | N bytes ]
  ```

- **Decryption (`decrypt`):** split the blob, RSA-unwrap the content key with the private key,
  AES-GCM-decrypt the body.

### Browser — templates

- `register.html` — generates the identity, wraps the private key, POSTs only the public key, caches
  the unlocked key, redirects to chat.
- `login.html` — authenticates against the server, then unlocks the locally-wrapped key (or an
  imported backup) with the password. Authentication and key-unlock are independent: you can be
  logged in but key-less on a new device until you import a backup.
- `simple_chat.html` — loads the unlocked key, fetches peers' public keys from `/api/users`,
  encrypts outgoing messages per recipient, and renders incoming ciphertext after decrypting.
  Rendering uses `textContent`, so a decrypted message can never inject HTML.

### Server — the `socketstream` package

`simple_secure_server.py` is a thin entrypoint; the relay itself lives in the `socketstream`
package, layered by concern so each piece is small and independently testable:

- `config.py` — an immutable `Config` value object, read once from the environment.
- `models.py` — the domain entities (`User`, `Message`) and the shapes they take on the wire.
- `storage.py` — a `Database` that owns the SQLite connection + write lock, with `UserRepository`
  and `MessageRepository` on top. Hand-written SQL, no ORM. The repositories speak in domain
  objects, never raw rows.
- `security.py` — a `Validator` (input limits), a `RateLimiter` (per-IP login throttle), and the
  `login_required` decorator. Pure policy, no database access.
- `realtime.py` — a `RealtimeGateway` wrapping Flask-SocketIO behind an interface; if the library
  is absent it is simply `disabled` and clients fall back to polling.
- `app.py` — the `create_app` factory wires these into a `Services` bundle on `app.extensions` and
  registers a route blueprint whose views hold no state of their own.

It authenticates users and shuttles ciphertext. It imports no asymmetric-crypto library and has no
`encrypt`/`decrypt` helpers — verified by a unit test that scans every module in the package.

- **Auth:** bcrypt password hashing; per-IP login rate limiting
  (`LOGIN_MAX_ATTEMPTS` in `LOGIN_WINDOW_SECONDS`); HttpOnly + SameSite=Lax cookies; secret key
  read from `SS_SECRET_KEY` or persisted to `.flask_secret` (so sessions survive restarts).
- **Storage (SQLite):**
  - `users(id, username UNIQUE, password_hash, public_key, created_at)` — **no private-key column.**
  - `messages(id, sender, recipient, ciphertext, msg_type, created_at)` — one row per recipient,
    indexed on `recipient`.
- **APIs:**
  - `POST /register` — validates username (`^[A-Za-z0-9_]{3,32}$`), password length, and public-key
    size; stores the bcrypt hash + public key.
  - `POST /login` — rate-limited; generic "invalid username or password" on failure.
  - `GET /api/users` — returns `{username, public_key}` for key discovery.
  - `POST /api/send_message` — body `{type, recipients: {username: ciphertext}}`; validates each
    recipient exists and each ciphertext is within size limits; inserts one row per recipient and
    emits a real-time `new_message` (carrying the row **id**, so clients dedup correctly).
  - `GET /api/messages?since=<id>` — returns the caller's ciphertext rows after a cursor.
- **Real-time:** Flask-SocketIO (`threading` async mode). On connect, an unauthenticated socket is
  disconnected; an authenticated one joins a room named after the username. Messages are pushed to
  `room=recipient`. If WebSockets are unavailable, the client falls back to 4-second polling.

## Data flow: sending a direct message

1. Browser fetches the recipient's public key from `/api/users` (cached in `pubKeys`).
2. `encryptFor(recipientPublicKey, text)` produces ciphertext for the recipient, and a second
   ciphertext is produced for the sender's *own* public key (the self-copy, so the sender can read
   their history). No plaintext self-copy is ever stored.
3. `POST /api/send_message` with `{recipient: ct, sender: ctSelf}`.
4. The server inserts one row per recipient and emits `new_message` (with the new row id) to each
   recipient's room.
5. Each recipient receives the ciphertext via socket (or the next poll), dedups on id, decrypts with
   their private key, and renders the plaintext with `textContent`.

The server, the database, and anyone with network access see only ciphertext at every step.

## Why this shape

- **Smallest trusted computing base.** Putting all crypto in one browser module (`crypto.js`) keeps
  the secret-handling surface tiny and auditable, and lets the server be a relay that's trivially
  testable without a browser.
- **Testability over maximal secrecy.** We use ordinary bcrypt login plus a password-wrapped local
  key, rather than a password-authenticated-key-exchange (PAKE) scheme. This is easy to reason about
  and unit-test; the tradeoff (the server learns *that* you logged in, and key roaming is manual via
  backup files) is documented in [SECURITY.md](SECURITY.md).
- **Honest real-time.** The UI's connection badge reflects the actual socket state (Live vs Polling)
  instead of claiming "Connected" unconditionally.

See [SECURITY.md](SECURITY.md) for the threat model and the limitations this design does **not**
address (browser trust, metadata visibility, no forward secrecy, no public-key authentication / MITM
on first contact, self-signed TLS).
