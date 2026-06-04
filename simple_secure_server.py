"""SocketStream entrypoint.

The application itself lives in the ``socketstream`` package; this module just
builds it from the environment and runs it. ``app`` is exposed at module level
so WSGI servers (and the test suite, historically) can import it.

The server is a zero-knowledge relay: it stores public keys and ciphertext only.
All key generation, encryption, and decryption happen in the browser (WebCrypto).
The server never sees a private key or a plaintext message — see SECURITY.md.
"""
from __future__ import annotations

import os

from socketstream import Config, create_app

config = Config.from_env()
app = create_app(config)


def _ssl_context(cfg: Config):
    """Pick a TLS context: explicit-off, a cert pair if present, or none."""
    if cfg.tls == "off":
        return None  # e.g. behind a TLS-terminating proxy, or local http testing
    cert, key = "server.crt", "server.key"
    if os.path.exists(cert) and os.path.exists(key):
        return (cert, key)
    print("WARNING: server.crt/server.key not found - run "
          "'python generate_certificates.py'. Starting WITHOUT TLS.")
    return None


def main() -> None:
    realtime = app.extensions["socketstream"].realtime
    ctx = _ssl_context(config)
    scheme = "https" if ctx else "http"

    print("Starting SocketStream (end-to-end encrypted chat)")
    print(f"  URL:       {scheme}://localhost:{config.port}")
    print(f"  Real-time: {'WebSocket (Flask-SocketIO)' if realtime.enabled else 'polling (install flask-socketio for live)'}")
    print(f"  TLS:       {'on' if ctx else 'OFF'}   Debug: {'on' if config.debug else 'off'}")

    run_kwargs = dict(host=config.host, port=config.port, debug=config.debug)
    if ctx:
        run_kwargs["ssl_context"] = ctx

    if realtime.enabled:
        realtime.run(app, **run_kwargs)
    else:
        app.run(**run_kwargs)


if __name__ == "__main__":
    main()
