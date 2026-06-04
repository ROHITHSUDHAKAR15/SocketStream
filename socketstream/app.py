"""HTTP layer: the application factory and the route blueprint.

The factory wires the pieces together — config, database, repositories,
validator, rate limiter, realtime gateway — into a ``Services`` bundle that it
stashes on ``app.extensions``. The blueprint's views pull that bundle out and
orchestrate it; they hold no state of their own. This is the seam that lets a
test build an app against a throwaway database with one call.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import bcrypt
from flask import (
    Blueprint, Flask, current_app, jsonify, redirect, render_template,
    request, session, url_for,
)

from .config import Config
from .realtime import RealtimeGateway
from .security import RateLimiter, Validator, login_required
from .storage import Database, MessageRepository, UserRepository

BASE_DIR = Path(__file__).resolve().parent.parent
EXTENSION_KEY = "socketstream"


@dataclass
class Services:
    """The collaborators a request handler may need, assembled once at startup."""

    config: Config
    users: UserRepository
    messages: MessageRepository
    validator: Validator
    rate_limiter: RateLimiter
    realtime: RealtimeGateway


bp = Blueprint("socketstream", __name__)


def _services() -> Services:
    return current_app.extensions[EXTENSION_KEY]


def _fail(message: str, status: int):
    return jsonify({"success": False, "message": message}), status


# --------------------------------------------------------------------------- #
# Page routes
# --------------------------------------------------------------------------- #
@bp.route("/")
def index():
    if "username" in session:
        return redirect(url_for("socketstream.chat"))
    return render_template("login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    services = _services()
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    public_key = data.get("public_key") or ""

    if not services.validator.username(username):
        return _fail("Username must be 3-32 chars: letters, digits, underscore", 400)
    if not services.validator.password(password):
        return _fail(
            f"Password must be at least {services.config.min_password_len} characters",
            400,
        )
    if not services.validator.public_key(public_key):
        return _fail("Missing or invalid public key", 400)

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if not services.users.create(username, password_hash, public_key):
        return _fail("Username already exists", 409)

    session["username"] = username
    return jsonify({"success": True, "message": "Registration successful"})


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    services = _services()
    client = request.remote_addr or "unknown"
    if services.rate_limiter.is_limited(client):
        return _fail("Too many attempts, try again later", 429)

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    stored_hash = services.users.password_hash(username)
    if not stored_hash or not bcrypt.checkpw(password.encode(), stored_hash.encode()):
        services.rate_limiter.record(client)
        return _fail("Invalid username or password", 401)

    session["username"] = username
    return jsonify({"success": True, "message": "Login successful"})


@bp.route("/chat")
def chat():
    if "username" not in session:
        return redirect(url_for("socketstream.login"))
    return render_template("simple_chat.html", username=session["username"])


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("socketstream.login"))


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "realtime": _services().realtime.enabled})


@bp.route("/api/me")
@login_required
def me():
    user = _services().users.get(session["username"])
    return jsonify({
        "success": True,
        "username": session["username"],
        "public_key": user.public_key if user else None,
    })


@bp.route("/api/users")
@login_required
def get_users():
    users = _services().users.list_all()
    return jsonify({
        "success": True,
        "users": [user.directory_entry() for user in users],
    })


@bp.route("/api/send_message", methods=["POST"])
@login_required
def send_message():
    services = _services()
    data = request.get_json(silent=True) or {}
    msg_type = data.get("type", "direct")
    recipients = data.get("recipients")  # {username: ciphertext}, incl. a self-copy

    if msg_type not in ("direct", "broadcast"):
        return _fail("Invalid message type", 400)
    if not isinstance(recipients, dict) or not recipients:
        return _fail("No recipients", 400)
    if len(recipients) > services.config.max_recipients:
        return _fail("Too many recipients", 400)

    known = services.users.usernames()
    for recipient, ciphertext in recipients.items():
        if recipient not in known:
            return _fail(f"Unknown recipient: {recipient}", 400)
        if not services.validator.ciphertext(ciphertext):
            return _fail("Invalid ciphertext", 400)

    delivered = services.messages.deliver(session["username"], msg_type, recipients)
    for message in delivered:
        services.realtime.notify(message)

    return jsonify({"success": True, "delivered": len(delivered)})


@bp.route("/api/messages")
@login_required
def get_messages():
    try:
        since = int(request.args.get("since", 0))
    except (TypeError, ValueError):
        since = 0

    messages = _services().messages.inbox(session["username"], since=since)
    return jsonify({
        "success": True,
        "messages": [message.to_public_dict() for message in messages],
    })


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #
def create_app(config: Config = None) -> Flask:
    """Assemble and return a configured Flask application."""
    config = config or Config.from_env()

    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.config.update(
        SECRET_KEY=config.resolve_secret_key(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.cookie_secure,
        JSON_SORT_KEYS=False,
    )

    database = Database(config.db_path)
    database.initialize()

    realtime = RealtimeGateway()
    realtime.init_app(app)

    app.extensions[EXTENSION_KEY] = Services(
        config=config,
        users=UserRepository(database),
        messages=MessageRepository(database),
        validator=Validator(config),
        rate_limiter=RateLimiter(config.login_max_attempts, config.login_window_seconds),
        realtime=realtime,
    )
    app.register_blueprint(bp)
    return app
