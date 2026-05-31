"""
SocketStream - end-to-end encrypted chat.

The server is a zero-knowledge relay: it stores public keys and ciphertext only.
All key generation, encryption, and decryption happen in the browser (WebCrypto).
The server never sees a private key or a plaintext message - see SECURITY.md.
"""
import os
import re
import time
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from functools import wraps

import bcrypt
from flask import (
    Flask, render_template, request, jsonify, session, redirect, url_for
)

# Optional real-time layer. The app works without it (clients fall back to polling).
try:
    from flask_socketio import SocketIO, join_room, disconnect
    _HAS_SOCKETIO = True
except Exception:  # pragma: no cover - optional dependency
    _HAS_SOCKETIO = False

DB_PATH = os.environ.get("SS_DB", "secure_messaging.db")
SECRET_FILE = os.environ.get("SS_SECRET_FILE", ".flask_secret")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MIN_PASSWORD_LEN = 8
MAX_PUBKEY_LEN = 4000          # base64 SPKI of an RSA-2048 key is ~600 bytes
MAX_CIPHERTEXT_LEN = 100_000   # bounds a hybrid-encrypted message blob
MAX_RECIPIENTS = 500
LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 300

db_lock = threading.Lock()
_login_attempts = {}  # ip -> list[timestamp]
_attempts_lock = threading.Lock()


def _load_secret_key() -> bytes:
    """Persist the session secret so restarts don't invalidate every session."""
    env = os.environ.get("SS_SECRET_KEY")
    if env:
        return env.encode()
    try:
        with open(SECRET_FILE, "rb") as f:
            data = f.read().strip()
            if data:
                return data
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32).encode()
    try:
        with open(SECRET_FILE, "wb") as f:
            f.write(key)
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass  # fall back to an ephemeral key if the file isn't writable
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SS_COOKIE_SECURE", "1") == "1",
    JSON_SORT_KEYS=False,
)

socketio = SocketIO(app, cors_allowed_origins=[], async_mode="threading") if _HAS_SOCKETIO else None


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    with db_lock, get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sender      TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                ciphertext  TEXT NOT NULL,
                msg_type    TEXT NOT NULL DEFAULT 'direct',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient, id)"
        )


def get_user(username: str):
    with db_lock, get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def create_user(username: str, password_hash: str, public_key: str) -> bool:
    with db_lock, get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
                (username, password_hash, public_key),
            )
            return True
        except sqlite3.IntegrityError:
            return False


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return jsonify({"success": False, "message": "Not authenticated"}), 401
        return view(*args, **kwargs)

    return wrapped


def _rate_limited(key: str) -> bool:
    now = time.time()
    with _attempts_lock:
        hits = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = hits
        return len(hits) >= LOGIN_MAX_ATTEMPTS


def _record_attempt(key: str) -> None:
    with _attempts_lock:
        _login_attempts.setdefault(key, []).append(time.time())


def _valid_pubkey(pk) -> bool:
    return isinstance(pk, str) and 0 < len(pk) <= MAX_PUBKEY_LEN


def _valid_ciphertext(ct) -> bool:
    return isinstance(ct, str) and 0 < len(ct) <= MAX_CIPHERTEXT_LEN


# --------------------------------------------------------------------------- #
# Page routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("chat"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    public_key = data.get("public_key") or ""

    if not USERNAME_RE.match(username):
        return jsonify({"success": False, "message": "Username must be 3-32 chars: letters, digits, underscore"}), 400
    if len(password) < MIN_PASSWORD_LEN:
        return jsonify({"success": False, "message": f"Password must be at least {MIN_PASSWORD_LEN} characters"}), 400
    if not _valid_pubkey(public_key):
        return jsonify({"success": False, "message": "Missing or invalid public key"}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if not create_user(username, password_hash, public_key):
        return jsonify({"success": False, "message": "Username already exists"}), 409

    session["username"] = username
    return jsonify({"success": True, "message": "Registration successful"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    ip = request.remote_addr or "unknown"
    if _rate_limited(ip):
        return jsonify({"success": False, "message": "Too many attempts, try again later"}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = get_user(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        _record_attempt(ip)
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    session["username"] = username
    return jsonify({"success": True, "message": "Login successful"})


@app.route("/chat")
def chat():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("simple_chat.html", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "realtime": bool(socketio)})


@app.route("/api/me")
@login_required
def me():
    user = get_user(session["username"])
    return jsonify({"success": True, "username": session["username"],
                    "public_key": user["public_key"] if user else None})


@app.route("/api/users")
@login_required
def get_users():
    with db_lock, get_db() as conn:
        rows = conn.execute("SELECT username, public_key FROM users ORDER BY username").fetchall()
    users = [{"username": r["username"], "public_key": r["public_key"]} for r in rows]
    return jsonify({"success": True, "users": users})


@app.route("/api/send_message", methods=["POST"])
@login_required
def send_message():
    data = request.get_json(silent=True) or {}
    msg_type = data.get("type", "direct")
    recipients = data.get("recipients")  # {username: ciphertext} including a self-copy

    if msg_type not in ("direct", "broadcast"):
        return jsonify({"success": False, "message": "Invalid message type"}), 400
    if not isinstance(recipients, dict) or not recipients:
        return jsonify({"success": False, "message": "No recipients"}), 400
    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({"success": False, "message": "Too many recipients"}), 400

    sender = session["username"]
    delivered = []  # (id, recipient, ciphertext) for real-time push
    with db_lock, get_db() as conn:
        known = {r["username"] for r in conn.execute("SELECT username FROM users").fetchall()}
        for recipient, ciphertext in recipients.items():
            if recipient not in known:
                return jsonify({"success": False, "message": f"Unknown recipient: {recipient}"}), 400
            if not _valid_ciphertext(ciphertext):
                return jsonify({"success": False, "message": "Invalid ciphertext"}), 400
        # Insert one row per recipient, capturing each row id so the real-time
        # event can carry it — the client dedups on id across socket + polling.
        for recipient, ciphertext in recipients.items():
            cur = conn.execute(
                "INSERT INTO messages (sender, recipient, ciphertext, msg_type) VALUES (?, ?, ?, ?)",
                (sender, recipient, ciphertext, msg_type),
            )
            delivered.append((cur.lastrowid, recipient, ciphertext))

    # Push to connected recipients in real time (ciphertext only).
    if socketio:
        ts = datetime.now(timezone.utc).isoformat()
        for msg_id, recipient, ciphertext in delivered:
            socketio.emit(
                "new_message",
                {"id": msg_id, "sender": sender, "recipient": recipient,
                 "ciphertext": ciphertext, "msg_type": msg_type, "created_at": ts},
                room=recipient,
            )

    return jsonify({"success": True, "delivered": len(delivered)})


@app.route("/api/messages")
@login_required
def get_messages():
    me_ = session["username"]
    try:
        since = int(request.args.get("since", 0))
    except (TypeError, ValueError):
        since = 0

    with db_lock, get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, sender, recipient, ciphertext, msg_type, created_at
            FROM messages
            WHERE recipient = ? AND id > ?
            ORDER BY id ASC
            LIMIT 200
            """,
            (me_, since),
        ).fetchall()

    messages = [dict(r) for r in rows]
    return jsonify({"success": True, "messages": messages})


# --------------------------------------------------------------------------- #
# WebSocket events (optional)
# --------------------------------------------------------------------------- #
if socketio:

    @socketio.on("connect")
    def _on_connect():
        username = session.get("username")
        if not username:
            disconnect()
            return False
        join_room(username)
        return None


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
def _ssl_context():
    if os.environ.get("SS_TLS", "auto") == "off":
        return None  # e.g. behind a TLS-terminating proxy, or local http testing
    cert, key = "server.crt", "server.key"
    if os.path.exists(cert) and os.path.exists(key):
        return (cert, key)
    print("WARNING: server.crt/server.key not found - run 'python generate_certificates.py'. "
          "Starting WITHOUT TLS.")
    return None


def main():
    init_database()
    host = os.environ.get("SS_HOST", "127.0.0.1")
    port = int(os.environ.get("SS_PORT", "5000"))
    debug = os.environ.get("SS_DEBUG", "0") == "1"
    ctx = _ssl_context()
    scheme = "https" if ctx else "http"

    print("Starting SocketStream (end-to-end encrypted chat)")
    print(f"  URL:       {scheme}://localhost:{port}")
    print(f"  Real-time: {'WebSocket (Flask-SocketIO)' if socketio else 'polling (install flask-socketio for live)'}")
    print(f"  TLS:       {'on' if ctx else 'OFF'}   Debug: {'on' if debug else 'off'}")

    run_kwargs = dict(host=host, port=port, debug=debug)
    if ctx:
        run_kwargs["ssl_context"] = ctx
    if socketio:
        run_kwargs["allow_unsafe_werkzeug"] = True
        socketio.run(app, **run_kwargs)
    else:
        app.run(**run_kwargs)


if __name__ == "__main__":
    main()
