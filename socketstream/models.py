"""Domain entities.

These are the only two things the relay knows about: a ``User`` (a username and
a public key) and a ``Message`` (a ciphertext addressed to one recipient). They
are immutable value objects that know how to build themselves from a database
row and how to present themselves on the wire. No plaintext, no private keys —
the types themselves make that impossible to store.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class User:
    username: str
    public_key: str
    id: Optional[int] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        return cls(
            username=row["username"],
            public_key=row["public_key"],
            id=row["id"] if "id" in row.keys() else None,
        )

    def directory_entry(self) -> dict:
        """The public view used for key discovery (`GET /api/users`)."""
        return {"username": self.username, "public_key": self.public_key}


@dataclass(frozen=True)
class Message:
    sender: str
    recipient: str
    ciphertext: str
    msg_type: str = "direct"
    id: Optional[int] = None
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Message":
        return cls(
            sender=row["sender"],
            recipient=row["recipient"],
            ciphertext=row["ciphertext"],
            msg_type=row["msg_type"],
            id=row["id"],
            created_at=row["created_at"],
        )

    def to_public_dict(self) -> dict:
        """Shape returned by the polling cursor (`GET /api/messages`)."""
        return {
            "id": self.id,
            "sender": self.sender,
            "recipient": self.recipient,
            "ciphertext": self.ciphertext,
            "msg_type": self.msg_type,
            "created_at": self.created_at,
        }

    def realtime_payload(self) -> dict:
        """Shape pushed over the socket.

        Carries the row ``id`` so a client receiving the same message over both
        the socket and the polling fallback can dedup on it. If the row was
        created without a timestamp (the DB default fills one in asynchronously),
        synthesize one so the client always has something to render.
        """
        payload = self.to_public_dict()
        if payload["created_at"] is None:
            payload["created_at"] = datetime.now(timezone.utc).isoformat()
        return payload
