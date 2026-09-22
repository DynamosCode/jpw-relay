"""
JPWBridge v4 — Token Relay Server
===================================
Receives tokens from the hook APK and serves them to the bot.

The Hook APK POSTs to /token whenever it captures:
  - integrity   : Play Integrity JWT from Google
  - enc_session : X-Enc-Session header value (sessionRef)
  - auth        : Authorization header

The bot GETs /token/latest to get the freshest token set before
firing UpdateWorkOrder (Reached) — which requires Play Integrity.

Run:
    pip install flask
    python relay_server.py

Or deploy on Render.com (matches demo APK URL: jpw-bot-sxxd.onrender.com):
    gunicorn relay_server:app -b 0.0.0.0:10000

Endpoints:
    POST /token         <- hook APK sends here
    GET  /token/latest  <- bot reads from here
    GET  /health        <- health check
    GET  /status        <- show current token state
"""

from flask import Flask, request, jsonify
from threading import Lock
from datetime import datetime
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("relay")

app = Flask(__name__)
_lock = Lock()

# In-memory token store
_store = {
    "integrity"   : {"token": "", "ts": 0, "pkg": ""},
    "enc_session" : {"token": "", "ts": 0, "pkg": ""},
    "auth"        : {"token": "", "ts": 0, "pkg": ""},
}
_history = []  # last 20 received tokens

TOKEN_TTL = 55 * 60  # 55 minutes


def is_fresh(entry: dict) -> bool:
    return entry["token"] and (time.time() - entry["ts"]) < TOKEN_TTL


# ── Receive from hook APK ────────────────────────────────────────────────────

@app.route("/token", methods=["POST"])
def receive_token():
    try:
        data = request.get_json(force=True, silent=True) or {}
        token_type = data.get("type", "")
        token = data.get("token", "")
        pkg = data.get("pkg", "")
        ts = data.get("ts", 0) / 1000  # ms to seconds

        if not token_type or not token:
            return jsonify({"ok": False, "error": "missing type or token"}), 400

        if token_type not in _store:
            return jsonify({"ok": False, "error": f"unknown type: {token_type}"}), 400

        with _lock:
            _store[token_type] = {
                "token" : token,
                "ts"    : ts or time.time(),
                "pkg"   : pkg,
                "extra" : data.get("extra", {}),
            }
            _history.insert(0, {
                "type" : token_type,
                "token": token[:30] + "...",
                "ts"   : datetime.fromtimestamp(ts or time.time()).isoformat(),
            })
            if len(_history) > 20:
                _history.pop()

        log.info(f"✅ received {token_type} from {pkg} (len={len(token)})")
        return jsonify({"ok": True, "type": token_type})

    except Exception as e:
        log.error(f"receive_token error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Serve to bot ─────────────────────────────────────────────────────────────

@app.route("/token/latest", methods=["GET"])
def get_latest_tokens():
    """
    Returns the freshest token set.
    Bot calls this before firing UpdateWorkOrder (Reached).

    Response:
    {
        "ok": true,
        "integrity": { "token": "eyJ...", "fresh": true, "age_s": 45 },
        "enc_session": { "token": "abc123...", "fresh": true, "age_s": 10 },
        "ready": true   // true if BOTH integrity and enc_session are fresh
    }
    """
    with _lock:
        now = time.time()
        result = {}
        for t_type, entry in _store.items():
            age = now - entry["ts"] if entry["ts"] else None
            result[t_type] = {
                "token" : entry["token"],
                "fresh" : is_fresh(entry),
                "age_s" : round(age, 1) if age is not None else None,
            }
        ready = result["integrity"]["fresh"] and result["enc_session"]["fresh"]
        return jsonify({"ok": True, "ready": ready, **result})


@app.route("/token/integrity", methods=["GET"])
def get_integrity_token():
    """Quick endpoint — just the integrity token."""
    with _lock:
        entry = _store["integrity"]
        if not entry["token"]:
            return jsonify({"ok": False, "error": "no token yet"}), 404
        age = time.time() - entry["ts"] if entry["ts"] else 0
        return jsonify({
            "ok"    : True,
            "token" : entry["token"],
            "fresh" : is_fresh(entry),
            "age_s" : round(age, 1),
        })


# ── Health / Status ──────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "jpwbridge-relay-v4"})


@app.route("/status", methods=["GET"])
def status():
    with _lock:
        now = time.time()
        out = {}
        for t_type, entry in _store.items():
            age = now - entry["ts"] if entry["ts"] else None
            out[t_type] = {
                "has_token" : bool(entry["token"]),
                "fresh"     : is_fresh(entry),
                "age_s"     : round(age, 1) if age else None,
                "preview"   : entry["token"][:20] + "..." if entry["token"] else "",
            }
        return jsonify({
            "ok"     : True,
            "tokens" : out,
            "history": _history[:10],
        })


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("JPWBridge relay server starting on :10000")
    app.run(host="0.0.0.0", port=10000, debug=False)
