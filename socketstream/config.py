"""Configuration for the SocketStream relay.

Everything the app needs to run is captured in a single immutable ``Config``
value object. Reading it from the environment is one explicit step
(``Config.from_env``); the rest of the code just receives a ``Config`` and never
touches ``os.environ`` again. That keeps the configuration surface in one place
and makes the app trivial to construct differently in tests.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Optional


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) == "1"


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration."""

    # Storage / server
    db_path: str = "secure_messaging.db"
    secret_file: str = ".flask_secret"
    secret_key: Optional[bytes] = None
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    cookie_secure: bool = True
    tls: str = "auto"  # "auto" | "off"

    # Validation / safety limits
    min_password_len: int = 8
    max_pubkey_len: int = 4000          # base64 SPKI of an RSA-2048 key is ~600 bytes
    max_ciphertext_len: int = 100_000   # bounds one hybrid-encrypted message blob
    max_recipients: int = 500
    login_max_attempts: int = 10
    login_window_seconds: int = 300

    @classmethod
    def from_env(cls) -> "Config":
        """Build a config from environment variables, falling back to defaults."""
        return cls(
            db_path=os.environ.get("SS_DB", "secure_messaging.db"),
            secret_file=os.environ.get("SS_SECRET_FILE", ".flask_secret"),
            secret_key=(os.environ["SS_SECRET_KEY"].encode()
                        if os.environ.get("SS_SECRET_KEY") else None),
            host=os.environ.get("SS_HOST", "127.0.0.1"),
            port=int(os.environ.get("SS_PORT", "5000")),
            debug=_flag("SS_DEBUG"),
            cookie_secure=_flag("SS_COOKIE_SECURE", "1"),
            tls=os.environ.get("SS_TLS", "auto"),
        )

    def resolve_secret_key(self) -> bytes:
        """Return a stable session secret.

        Preference order: an explicit ``secret_key`` (env or test), then a value
        persisted in ``secret_file`` (so sessions survive restarts), and finally
        a fresh ephemeral key if the file cannot be read or written.
        """
        if self.secret_key:
            return self.secret_key
        try:
            with open(self.secret_file, "rb") as handle:
                persisted = handle.read().strip()
                if persisted:
                    return persisted
        except FileNotFoundError:
            pass

        key = secrets.token_hex(32).encode()
        try:
            with open(self.secret_file, "wb") as handle:
                handle.write(key)
            os.chmod(self.secret_file, 0o600)
        except OSError:
            pass  # fall back to an ephemeral key if the file isn't writable
        return key
