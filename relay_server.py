"""
JPWBridge Token Relay Server v4.1
==================================
Compatible with JPWBridge V3 APK hook module.

APK sends to:  POST /api/integrity/ingest
Headers:       X-Ingest-Secret, User-Agent: JPWBridge/2.0
Body:          {token, nonce, secret, tech_id}

Bot reads from: GET /token/latest
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

_store = {
    "integrity"   : {"token": "", "ts": 0, "tech_id": "", "nonce": ""},
    "enc_session" : {"token": "", "ts": 0},
}
_history = []
TOKEN_TTL = 55 * 60  # 55 min

def is_fresh(entry):
    return bool(entry["token"]) and (time.time() - entry["ts"]) < TOKEN_TTL


APK_SECRET = 'ZX5w8onRqMXX3fH7jkWO0xUn2vDWsuj7KS6e_lQC5cI'

# ── APK V3 ingest endpoint ───────────────────────────────────────────────────

@app.route("/api/integrity/ingest", methods=["POST"])
def ingest():
    """
    JPWBridge V3 APK posts here.
    Headers: X-Ingest-Secret, User-Agent: JPWBridge/2.0
    Body: {token, nonce, secret, tech_id}
    """
    try:
        # Validate secret from header
        incoming_secret = request.headers.get("X-Ingest-Secret", "")
        if incoming_secret and incoming_secret != APK_SECRET:
            log.warning(f"Invalid secret: {incoming_secret[:10]}...")
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        data    = request.get_json(force=True, silent=True) or {}
        token   = data.get("token", "").strip()
        nonce   = data.get("nonce", "")
        tech_id = data.get("tech_id", "") or data.get("techId", "")
        secret  = data.get("secret", "")

        if not token:
            return jsonify({"ok": False, "error": "no token"}), 400

        now = time.time()
        with _lock:
            _store["integrity"] = {
                "token"  : token,
                "ts"     : now,
                "tech_id": tech_id,
                "nonce"  : nonce,
                "secret" : secret,
            }
            _history.insert(0, {
                "type" : "integrity",
                "token": token[:25] + "...",
                "ts"   : datetime.fromtimestamp(now).isoformat(),
                "tech" : tech_id,
            })
            if len(_history) > 50:
                _history.pop()

        log.info(f"✅ ingest tech={tech_id} len={len(token)} nonce={nonce[:10]}")
        return jsonify({"ok": True, "queued": 1})

    except Exception as e:
        log.error(f"ingest error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Generic token endpoint (from hook APK v4) ────────────────────────────────

@app.route("/token", methods=["POST"])
def receive_token():
    try:
        data       = request.get_json(force=True, silent=True) or {}
        token_type = data.get("type", "integrity")
        token      = data.get("token", "").strip()
        tech_id    = data.get("tech_id", "")

        if not token:
            return jsonify({"ok": False, "error": "no token"}), 400

        now = time.time()
        with _lock:
            if token_type in _store:
                _store[token_type]["token"] = token
                _store[token_type]["ts"]    = now
            else:
                _store["integrity"]["token"] = token
                _store["integrity"]["ts"]    = now

            _history.insert(0, {
                "type" : token_type,
                "token": token[:25] + "...",
                "ts"   : datetime.fromtimestamp(now).isoformat(),
                "tech" : tech_id,
            })
            if len(_history) > 50:
                _history.pop()

        log.info(f"✅ token/{token_type} len={len(token)}")
        return jsonify({"ok": True})

    except Exception as e:
        log.error(f"token error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Bot reads from here ───────────────────────────────────────────────────────

@app.route("/token/latest", methods=["GET"])
def get_latest():
    with _lock:
        now   = time.time()
        integ = _store["integrity"]
        enc   = _store["enc_session"]
        age_i = round(now - integ["ts"], 1) if integ["ts"] else None
        age_e = round(now - enc["ts"], 1) if enc["ts"] else None
        return jsonify({
            "ok"       : True,
            "ready"    : is_fresh(integ),
            "integrity": {
                "token"  : integ["token"],
                "fresh"  : is_fresh(integ),
                "age_s"  : age_i,
                "tech_id": integ.get("tech_id", ""),
            },
            "enc_session": {
                "token": enc["token"],
                "fresh": is_fresh(enc),
                "age_s": age_e,
            },
        })


@app.route("/token/integrity", methods=["GET"])
def get_integrity():
    with _lock:
        e = _store["integrity"]
        if not e["token"]:
            return jsonify({"ok": False, "error": "no token yet — open JPW app on phone"}), 404
        age = round(time.time() - e["ts"], 1) if e["ts"] else 0
        return jsonify({
            "ok"    : True,
            "token" : e["token"],
            "fresh" : is_fresh(e),
            "age_s" : age,
            "tech"  : e.get("tech_id", ""),
        })


# ── APK config endpoints ──────────────────────────────────────────────────────

@app.route("/config.json", methods=["GET"])
def config_json():
    """APK reads this to get backend URL"""
    host = request.host_url.rstrip("/")
    return jsonify({
        "backend": host,
        "ingest" : "/api/integrity/ingest",
        "version": "4",
    })


@app.route("/backend.txt", methods=["GET"])
def backend_txt():
    """APK V3 reads relay URL from here"""
    return request.host_url.rstrip("/"), 200, {"Content-Type": "text/plain"}


# ── Health / Status ───────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "jpwbridge-relay-v4.1"})


@app.route("/status", methods=["GET"])
def status():
    with _lock:
        now = time.time()
        out = {}
        for t_type, entry in _store.items():
            age = round(now - entry["ts"], 1) if entry.get("ts") else None
            out[t_type] = {
                "has_token" : bool(entry.get("token")),
                "fresh"     : is_fresh(entry),
                "age_s"     : age,
                "tech"      : entry.get("tech_id", ""),
                "preview"   : entry.get("token", "")[:20] + "..." if entry.get("token") else "",
            }
        return jsonify({
            "ok"     : True,
            "tokens" : out,
            "history": _history[:10],
        })


if __name__ == "__main__":
    log.info("JPWBridge relay v4.1 starting on :10000")
    app.run(host="0.0.0.0", port=10000, debug=False)
