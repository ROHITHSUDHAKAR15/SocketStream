"""Real-time delivery over WebSockets — an optional capability.

Flask-SocketIO is wrapped behind a small gateway so the rest of the app depends
on an interface, not the library. If the dependency is missing the gateway is
simply ``disabled`` and the app keeps working: clients fall back to polling the
message cursor. Each authenticated socket joins a room named after its user, and
messages are pushed to ``room=recipient`` — only ciphertext ever crosses it.
"""
from __future__ import annotations

from typing import Optional

from flask import Flask, session

from .models import Message


class RealtimeGateway:
    """Adapts Flask-SocketIO; degrades gracefully to polling when absent."""

    def __init__(self) -> None:
        self._socketio = None

    @property
    def enabled(self) -> bool:
        return self._socketio is not None

    @property
    def socketio(self):
        return self._socketio

    def init_app(self, app: Flask) -> None:
        """Attach a SocketIO server to the app, if the library is installed."""
        try:
            from flask_socketio import SocketIO, join_room, disconnect
        except Exception:  # pragma: no cover - optional dependency
            self._socketio = None
            return

        self._socketio = SocketIO(app, cors_allowed_origins=[],
                                  async_mode="threading")

        @self._socketio.on("connect")
        def _on_connect():
            username = session.get("username")
            if not username:
                disconnect()
                return False
            join_room(username)
            return None

    def notify(self, message: Message) -> None:
        """Push a single ciphertext row to its recipient's room."""
        if self._socketio is None:
            return
        self._socketio.emit(
            "new_message",
            message.realtime_payload(),
            room=message.recipient,
        )

    def run(self, app: Flask, **kwargs) -> None:
        """Run the SocketIO server (werkzeug dev server, threading mode)."""
        kwargs.setdefault("allow_unsafe_werkzeug", True)
        self._socketio.run(app, **kwargs)
