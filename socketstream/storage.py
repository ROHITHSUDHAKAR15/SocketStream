"""Persistence layer — hand-written SQLite, no ORM.

A thin ``Database`` owns the connection lifecycle and a process-wide lock (SQLite
tolerates one writer at a time). Two repositories sit on top of it and speak in
domain objects, so the rest of the app never sees a cursor or a raw row. The
schema deliberately has no column that could hold a private key or a plaintext
message.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator, List, Optional, Set

from .models import Message, User


class Database:
    """Owns the SQLite file, the connection lifecycle, and the write lock."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection under the write lock, committing on success."""
        with self._lock:
            conn = sqlite3.connect(self._path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def initialize(self) -> None:
        """Create the schema if it does not yet exist."""
        with self.connect() as conn:
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
                "CREATE INDEX IF NOT EXISTS idx_messages_recipient "
                "ON messages(recipient, id)"
            )


class UserRepository:
    """Reads and writes users; returns ``User`` objects, never rows."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def get(self, username: str) -> Optional[User]:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return User.from_row(row) if row else None

    def password_hash(self, username: str) -> Optional[str]:
        """Fetch only the stored bcrypt hash (kept off the ``User`` entity)."""
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["password_hash"] if row else None

    def create(self, username: str, password_hash: str, public_key: str) -> bool:
        """Insert a user; return False if the username is already taken."""
        with self._db.connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, public_key) "
                    "VALUES (?, ?, ?)",
                    (username, password_hash, public_key),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def list_all(self) -> List[User]:
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT id, username, public_key FROM users ORDER BY username"
            ).fetchall()
        return [User.from_row(row) for row in rows]

    def usernames(self) -> Set[str]:
        with self._db.connect() as conn:
            rows = conn.execute("SELECT username FROM users").fetchall()
        return {row["username"] for row in rows}


class MessageRepository:
    """Stores and retrieves ciphertext, addressed one row per recipient."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def deliver(self, sender: str, msg_type: str,
                recipients: dict) -> List[Message]:
        """Persist one ciphertext row per recipient and return the saved rows.

        Each returned ``Message`` carries its new row id, so the realtime layer
        can push an id the client will dedup on.
        """
        delivered: List[Message] = []
        with self._db.connect() as conn:
            for recipient, ciphertext in recipients.items():
                cursor = conn.execute(
                    "INSERT INTO messages (sender, recipient, ciphertext, msg_type) "
                    "VALUES (?, ?, ?, ?)",
                    (sender, recipient, ciphertext, msg_type),
                )
                delivered.append(Message(
                    sender=sender,
                    recipient=recipient,
                    ciphertext=ciphertext,
                    msg_type=msg_type,
                    id=cursor.lastrowid,
                ))
        return delivered

    def inbox(self, recipient: str, since: int = 0,
              limit: int = 200) -> List[Message]:
        """Return ciphertext addressed to ``recipient`` after the ``since`` cursor."""
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, sender, recipient, ciphertext, msg_type, created_at
                FROM messages
                WHERE recipient = ? AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (recipient, since, limit),
            ).fetchall()
        return [Message.from_row(row) for row in rows]
