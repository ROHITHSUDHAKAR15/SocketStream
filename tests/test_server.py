"""
Tests for the SocketStream relay server.

The server is meant to be zero-knowledge: it stores public keys and ciphertext
only. These tests pin that contract down - in particular that there is no place
for a private key or a plaintext message to land on the server.
"""
import os
import sqlite3
import tempfile

import pytest

# Configure the app for testing BEFORE importing it (config is read at import).
_TMP = tempfile.mkdtemp()
os.environ["SS_DB"] = os.path.join(_TMP, "test.db")
os.environ["SS_SECRET_KEY"] = "test-secret-not-persisted"
os.environ["SS_COOKIE_SECURE"] = "0"  # test client speaks http

import simple_secure_server as srv  # noqa: E402

# A throwaway but well-formed-looking public key blob (server only bounds length).
FAKE_PUBKEY = "AAAA" + "B" * 200
FAKE_CIPHERTEXT = "Q" * 400


@pytest.fixture()
def fresh_db():
    if os.path.exists(srv.DB_PATH):
        os.remove(srv.DB_PATH)
    srv.init_database()
    srv._login_attempts.clear()
    yield


@pytest.fixture()
def client(fresh_db):
    srv.app.config["TESTING"] = True
    return srv.app.test_client()


def register(client, username, password="Secret123!", pubkey=FAKE_PUBKEY):
    return client.post("/register", json={"username": username, "password": password, "public_key": pubkey})


# --- health & auth --------------------------------------------------------- #
def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json()["status"] == "ok"


def test_api_requires_auth(client):
    assert client.get("/api/users").status_code == 401


# --- registration validation ---------------------------------------------- #
def test_register_success(client):
    r = register(client, "alice")
    assert r.status_code == 200 and r.get_json()["success"] is True


@pytest.mark.parametrize("username", ["ab", "has space", "bad!", "x" * 33])
def test_register_bad_username(client, username):
    assert register(client, username).status_code == 400


def test_register_short_password(client):
    assert register(client, "alice", password="short").status_code == 400


def test_register_missing_pubkey(client):
    assert register(client, "alice", pubkey="").status_code == 400


def test_register_duplicate(client):
    register(client, "alice")
    client.get("/logout")
    assert register(client, "alice").status_code == 409


# --- login ----------------------------------------------------------------- #
def test_login_wrong_password(client):
    register(client, "alice")
    client.get("/logout")
    assert client.post("/login", json={"username": "alice", "password": "nope"}).status_code == 401


def test_login_success(client):
    register(client, "alice")
    client.get("/logout")
    r = client.post("/login", json={"username": "alice", "password": "Secret123!"})
    assert r.status_code == 200 and r.get_json()["success"] is True


# --- messaging relay ------------------------------------------------------- #
def test_direct_message_roundtrip(client):
    register(client, "alice")
    bob = srv.app.test_client()
    register(bob, "bob")

    # alice -> bob, plus a self-copy for alice. Distinct ciphertext per recipient.
    ct_bob = "BOB" + FAKE_CIPHERTEXT
    ct_self = "SELF" + FAKE_CIPHERTEXT
    r = client.post("/api/send_message", json={
        "type": "direct",
        "recipients": {"bob": ct_bob, "alice": ct_self},
    })
    assert r.status_code == 200 and r.get_json()["delivered"] == 2

    # bob receives exactly the ciphertext meant for him - untouched by the server.
    bob_msgs = bob.get("/api/messages").get_json()["messages"]
    assert [m["ciphertext"] for m in bob_msgs] == [ct_bob]
    assert bob_msgs[0]["sender"] == "alice"

    # alice sees only her own self-copy.
    alice_msgs = client.get("/api/messages").get_json()["messages"]
    assert [m["ciphertext"] for m in alice_msgs] == [ct_self]


def test_send_unknown_recipient_rejected(client):
    register(client, "alice")
    r = client.post("/api/send_message", json={"type": "direct", "recipients": {"ghost": FAKE_CIPHERTEXT}})
    assert r.status_code == 400


def test_send_oversized_ciphertext_rejected(client):
    register(client, "alice")
    r = client.post("/api/send_message", json={
        "type": "direct",
        "recipients": {"alice": "X" * (srv.MAX_CIPHERTEXT_LEN + 1)},
    })
    assert r.status_code == 400


def test_messages_since_cursor(client):
    register(client, "alice")
    client.post("/api/send_message", json={"type": "broadcast", "recipients": {"alice": "one" + FAKE_CIPHERTEXT}})
    first = client.get("/api/messages").get_json()["messages"]
    assert len(first) == 1
    last_id = first[0]["id"]
    # Nothing new since the last id.
    assert client.get(f"/api/messages?since={last_id}").get_json()["messages"] == []


# --- zero-knowledge contract ---------------------------------------------- #
def test_db_never_stores_private_keys(client):
    register(client, "alice")
    conn = sqlite3.connect(srv.DB_PATH)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    conn.close()
    # No column could hold a private key; the server only knows the public key.
    assert "public_key" in cols
    assert not any("private" in c.lower() or "secret" in c.lower() for c in cols)


def test_server_has_no_crypto_helpers(client):
    # The relay must not contain server-side encrypt/decrypt of messages.
    for forbidden in ("encrypt_message", "decrypt_message", "generate_key_pair"):
        assert not hasattr(srv, forbidden)
