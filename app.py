import time
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

_store = {
    "token": "",
    "tech_id": "",
    "pushed_at": 0,
    "type": "integrity",
}

API_KEY = os.environ.get("API_KEY", "jpw2025secret")
INGEST_SECRET = os.environ.get("INGEST_SECRET") or API_KEY


def _store_token(token: str, tech_id: str = "", tok_type: str = "integrity"):
    _store["token"]     = token
    _store["tech_id"]   = tech_id
    _store["pushed_at"] = time.time()
    _store["type"]      = tok_type


@app.route("/api/integrity/ingest", methods=["POST"])
def ingest():
    secret = request.headers.get("X-Ingest-Secret", "")
    if secret != INGEST_SECRET:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or data.get("integrityToken") or data.get("integrity_token") or "")
    tech_id = (data.get("techId") or data.get("tech_id") or data.get("technician_id") or "")
    if not token:
        return jsonify({"ok": False, "error": "token field required"}), 400
    _store_token(token, tech_id, "integrity")
    return jsonify({"ok": True, "tech_id": tech_id, "type": "integrity"})


@app.route("/push", methods=["POST"])
def push():
    data = request.get_json(force=True, silent=True) or {}
    key  = data.get("api_key") or request.headers.get("X-API-Key", "")
    if key != API_KEY:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    token    = data.get("token") or data.get("integrity_token") or ""
    tech_id  = data.get("tech_id") or ""
    tok_type = data.get("type", "integrity")
    if not token:
        return jsonify({"ok": False, "error": "token required"}), 400
    _store_token(token, tech_id, tok_type)
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
        "fresh": bool(_store["token"] and age is not None and age < 300),
        "has_token": bool(_store["token"]),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
