"""Authentication and input-safety concerns.

Three small, single-purpose pieces: a ``Validator`` that enforces the shape of
untrusted input against the configured limits, a ``RateLimiter`` that throttles
login attempts per client, and a ``login_required`` decorator. None of these
touch the database — they are pure policy, easy to test in isolation.
"""
from __future__ import annotations

import re
import time
import threading
from functools import wraps
from typing import Dict, List

from flask import jsonify, session

from .config import Config


class Validator:
    """Validates untrusted request fields against the configured limits."""

    USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

    def __init__(self, config: Config) -> None:
        self._config = config

    def username(self, value: object) -> bool:
        return isinstance(value, str) and bool(self.USERNAME_RE.match(value))

    def password(self, value: object) -> bool:
        return isinstance(value, str) and len(value) >= self._config.min_password_len

    def public_key(self, value: object) -> bool:
        return isinstance(value, str) and 0 < len(value) <= self._config.max_pubkey_len

    def ciphertext(self, value: object) -> bool:
        return isinstance(value, str) and 0 < len(value) <= self._config.max_ciphertext_len


class RateLimiter:
    """A sliding-window limiter keyed by an arbitrary string (e.g. client IP)."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> List[float]:
        return [t for t in self._hits.get(key, []) if now - t < self._window]

    def is_limited(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            recent = self._recent(key, now)
            self._hits[key] = recent
            return len(recent) >= self._max_attempts

    def record(self, key: str) -> None:
        with self._lock:
            self._hits.setdefault(key, []).append(time.time())

    def reset(self) -> None:
        """Clear all recorded attempts (used between tests)."""
        with self._lock:
            self._hits.clear()


def login_required(view):
    """Reject unauthenticated callers with a 401 before the view runs."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return jsonify({"success": False, "message": "Not authenticated"}), 401
        return view(*args, **kwargs)

    return wrapped
