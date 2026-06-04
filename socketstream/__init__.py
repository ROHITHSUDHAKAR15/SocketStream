"""SocketStream — a zero-knowledge, end-to-end encrypted chat relay.

The package is layered so each concern lives on its own:

    config    immutable runtime settings (read once from the environment)
    models    the domain entities (User, Message) and their wire shapes
    storage   hand-written SQLite — Database + repositories, no ORM
    security  input validation, login rate limiting, the auth decorator
    realtime  optional WebSocket delivery, degrading to polling
    app       the application factory that wires it all together

The server never holds a private key or a plaintext message; all cryptography
lives in the browser (`static/js/crypto.js`). See ARCHITECTURE.md.
"""
from __future__ import annotations

from .app import create_app
from .config import Config

__all__ = ["create_app", "Config"]
