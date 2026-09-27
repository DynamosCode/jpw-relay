"""
JPW Relay Server v2
====================
POST /push          ← LSposed pushes fresh token here
GET  /token/latest  ← Bot fetches latest token
GET  /status        ← Debug info
"""
import time
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory store — single latest token
_store = {
    "token": "",
    "tech_id": "",
    "pushed_at": 0,
    "type": "integrity",
}

API_KEY = os.environ.get("API_KEY", "jpw2025secret")  # set in Render env vars

@app.route("/push", methods=["POST"])
def push():
    data = request.get_json(force=True, silent=True) or {}
    key  = data.get("api_key") or request.headers.get("X-API-Key", "")
    if key != API_KEY:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    token   = data.get("token") or data.get("integrity_token") or ""
    tech_id = data.get("tech_id") or ""
    tok_type = data.get("type", "integrity")

    if not token:
        return jsonify({"ok": False, "error": "token required"}), 400

    _store["token"]     = token
    _store["tech_id"]   = tech_id
    _store["pushed_at"] = time.time()
    _store["type"]      = tok_type

    age = 0
    return jsonify({"ok": True, "tech_id": tech_id, "type": tok_type})

@app.route("/token/latest", methods=["GET"])
def token_latest():
    now = time.time()
    age = round(now - _store["pushed_at"], 1) if _store["pushed_at"] else None
    tok = _store["token"]
    fresh = bool(tok and age is not None and age < 300)

    return jsonify({
        "ok": True,
        "ready": fresh,
        "integrity": {
            "token":   tok if fresh else "",
            "age_s":   age,
            "fresh":   fresh,
            "tech_id": _store["tech_id"],
        },
        "enc_session": {
            "token": "",
            "age_s": None,
            "fresh": False,
        }
    })

@app.route("/status", methods=["GET"])
def status():
    now = time.time()
    age = round(now - _store["pushed_at"], 1) if _store["pushed_at"] else None
    return jsonify({
        "ok": True,
        "token_age_s": age,
        "tech_id": _store["tech_id"],
        "fresh": bool(_store["token"] and age and age < 300),
        "has_token": bool(_store["token"]),
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
