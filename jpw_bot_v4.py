"""
JPW Auto-Reach Pro v4 — with Hook APK Token Integration
========================================================
Same as v3 but now pulls Play Integrity token from the relay server
(populated by the hook APK running on a rooted phone with JPW app).

New flow for Reached:
    1. GET relay_server/token/latest  <- get fresh integrity + enc_session
    2. If tokens fresh: inject into UpdateWorkOrder request headers
    3. If tokens stale: fallback to DEVICE_MODE tap (original behaviour)

Install:
    pip install python-telegram-bot==21.10 requests cryptography flask

Run relay first:
    python relay_server.py

Then run bot:
    BOT_TOKEN=... python jpw_bot_v4.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import time
from datetime import date
from typing import Any

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, ConversationHandler, MessageHandler,
                          filters)
from telegram.request import HTTPXRequest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── .env loader ───────────────────────────────────────────────────────────────
def _load_dotenv():
    from pathlib import Path
    p = Path(__file__).resolve().parent / ".env"
    if not p.exists(): return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_dotenv()

# ── Config ───────────────────────────────────────────────────────────────────
BOT_TOKEN      = os.environ.get("BOT_TOKEN", "").strip()
BASE           = os.environ.get("JPW_BASE", "https://jpw.jio.com").rstrip("/")
UA             = os.environ.get("JPW_USER_AGENT",
    "Mozilla/5.0 (Linux; Android 12; moto g(60) Build/S2RIS32.32-20-7-11; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
    "Chrome/148.0.7778.217 Mobile Safari/537.36")
DEFAULT_LAT    = os.environ.get("DEFAULT_LAT", "28.6139").strip()
DEFAULT_LON    = os.environ.get("DEFAULT_LON", "77.2090").strip()
ACCESS_PASSWORD = os.environ.get("ACCESS_PASSWORD", "Enc@1234")
APP_VERSION    = os.environ.get("JPW_APP_VERSION", "2.1.1").strip()
VERIFY_SSL     = os.environ.get("JPW_VERIFY_SSL", "true").lower() != "false"
JPW_TIMEOUT    = float(os.environ.get("JPW_TIMEOUT", "30"))
JPW_RETRIES    = int(os.environ.get("JPW_RETRIES", "3"))
SUCCESS_CLEAR_DELAY = float(os.environ.get("SUCCESS_CLEAR_DELAY", "1.5"))

# ── NEW: Relay server config ──────────────────────────────────────────────────
RELAY_URL      = os.environ.get("RELAY_URL", "https://jpw-bot-sxxd.onrender.com")
RELAY_TIMEOUT  = float(os.environ.get("RELAY_TIMEOUT", "5"))  # fast timeout

# Bot states
ASK_CREDS = 1; WO_MENU = 2; SCAN_INPUT = 3; ACCESS_GATE = 4

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("jpw")

EP_HANDSHAKE = "/api/encryption/handshake"
EP_LOGIN     = "/api/login/SAML/UserLogin"
EP_WO_LIST   = "/api/workorder-inquiry/WorkOrder/GetWorkOrderList"
EP_WO_UPDATE = "/api/workorder-maintenance/WorkOrder/UpdateWorkOrder"

AC_BEGIN_JOURNEY = "ZA25"
AC_REACHED       = "ZA26"
AC_HOLD          = "ZA17"
AC_COMPLETE      = "ZA10"

HOLD_REASONS = [
    ("resched",  "Customer Reschedule"),
    ("building", "Incorrect Building ID"),
    ("doorlock", "Door Lock / Customer N/A"),
    ("cabling",  "Cabling Not Feasible"),
    ("notint",   "Customer Not Interested"),
    ("material", "Material Shortage"),
    ("society",  "Society Permission Pending"),
    ("location", "Location Not Available"),
]
CABLE_LENGTHS = [25, 50, 100, 200]

# ── Relay client ──────────────────────────────────────────────────────────────

def get_relay_tokens() -> dict | None:
    """
    Fetch latest tokens from relay server.
    Returns dict with integrity + enc_session if fresh, else None.
    """
    try:
        r = requests.get(f"{RELAY_URL}/token/latest", timeout=RELAY_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data.get("ok") and data.get("ready"):
                return data
        log.info(f"relay not ready: {r.status_code} {r.text[:100]}")
        return None
    except Exception as e:
        log.warning(f"relay fetch failed: {e}")
        return None


# ── Encryption helpers ────────────────────────────────────────────────────────

def build_envelope(server_pub, payload: dict, version: str = APP_VERSION) -> dict:
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(iv, json.dumps(payload).encode(), None)
    return {
        "key"        : base64.b64encode(server_pub.encrypt(aes_key, _OAEP)).decode(),
        "data"       : base64.b64encode(iv + ct).decode(),
        "versionCode": version,
    }

def open_envelope(client_priv, resp: dict) -> dict:
    aes_key = client_priv.decrypt(base64.b64decode(resp["key"]), _OAEP)
    blob = base64.b64decode(resp.get("response") or resp.get("data") or "")
    return json.loads(AESGCM(aes_key).decrypt(blob[:12], blob[12:], None))


# ── Jio client ────────────────────────────────────────────────────────────────

class JioError(Exception): pass

class JpwClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = VERIFY_SSL
        self.session.headers.update({
            "User-Agent"      : UA,
            "Origin"          : BASE,
            "Referer"         : f"{BASE}/v1/OIDLOGIN",
            "X-Requested-With": "com.jio.jpss",
            "Accept"          : "*/*",
            "Content-Type"    : "application/json",
        })
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._server_pub = None
        self._session_ref = None

    def handshake(self):
        cpk = base64.b64encode(self._priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode()
        r = self._raw_post(EP_HANDSHAKE, {"clientPublicKey": cpk}, "handshake")
        self._session_ref = r.get("sessionRef")
        spk = r.get("serverPublicKey")
        if not self._session_ref or not spk:
            raise JioError(f"Handshake failed. Raw: {str(r)[:300]}")
        self._server_pub = serialization.load_der_public_key(base64.b64decode(spk))
        self.session.headers["X-Enc-Session"] = self._session_ref
        log.info("[handshake] ok session=%s", self._session_ref)

    def _raw_post(self, path: str, body: dict, label: str) -> dict:
        url = f"{BASE}{path}"
        last_err = None
        for attempt in range(1, JPW_RETRIES + 1):
            try:
                r = self.session.post(url, json=body, timeout=JPW_TIMEOUT)
                raw = r.text or ""
                log.info("[%s] HTTP %s <- %s | %s", label, r.status_code, url, raw[:400])
                if r.status_code >= 400:
                    raise JioError(f"{label} HTTP {r.status_code}. Raw: {raw[:200]}")
                try:
                    return r.json()
                except ValueError:
                    raise JioError(f"{label}: non-JSON. Raw: {raw[:200]}")
            except JioError: raise
            except requests.RequestException as e:
                last_err = e
                if attempt < JPW_RETRIES: time.sleep(1.0 * attempt)
        raise JioError(f"Network error {label}: {last_err}") from last_err

    def post(self, path: str, payload: dict, label: str) -> dict:
        if self._server_pub is None:
            self.handshake()
        env = build_envelope(self._server_pub, payload)
        resp = self._raw_post(path, env, label)
        if "key" in resp and ("response" in resp or "data" in resp):
            try:
                return open_envelope(self._priv, resp)
            except Exception as e:
                raise JioError(f"{label}: decrypt failed: {e}") from e
        return resp

    def post_with_relay_token(self, path: str, payload: dict, label: str,
                               integrity_token: str, enc_session: str) -> dict:
        """
        Same as post() but ALSO injects the relay-provided tokens
        into request headers — bypassing Play Integrity gate.
        """
        if self._server_pub is None:
            self.handshake()
        # Override X-Enc-Session with the one from the real JPW app session
        self.session.headers["X-Enc-Session"] = enc_session
        # Inject Play Integrity token
        self.session.headers["X-Play-Integrity-Token"] = integrity_token
        self.session.headers["X-App-Integrity"] = integrity_token
        try:
            return self.post(path, payload, label)
        finally:
            # Restore our own session ref
            if self._session_ref:
                self.session.headers["X-Enc-Session"] = self._session_ref
            self.session.headers.pop("X-Play-Integrity-Token", None)
            self.session.headers.pop("X-App-Integrity", None)

    def login(self, username: str, password: str):
        d = self.post(EP_LOGIN, {
            "UserName": username, "Password": password,
            "Handset": "android", "FCMID": "fake",
            "DeviceId": "fake", "AppVersion": APP_VERSION,
        }, "login")
        if not d.get("IsSuccessful"):
            raise JioError(d.get("ErrorInfo", {}).get("UserMessage") or "Login failed")

    def list_work_orders(self, username: str) -> list[dict]:
        d = self.post(EP_WO_LIST, {
            "TechnicianID": username, "IsHSOUser": False,
            "WorkOrderStatus": [""], "PageSize": 200,
            "offsetValue": 0, "TechnicianDesignationType": "Technician",
        }, "list_work_orders")
        if not d.get("IsSuccessful"):
            raise JioError(d.get("ErrorInfo", {}).get("UserMessage") or "List failed")
        return d.get("lstWorkOrders") or []

    def send_action(self, username: str, wo_id: str, action_code: str,
                    lat: str, lon: str, extra: dict | None = None,
                    relay_tokens: dict | None = None) -> dict:
        payload = {
            "ActionCode"           : action_code,
            "BuildingID"           : "",
            "StatusCode"           : "CL09",
            "TechnicianLatitude"   : str(lat),
            "TechnicianLongitude"  : str(lon),
            "UpdatedBy"            : username,
            "WorkOrderID"          : wo_id,
            "WorkOrderSubType"     : "",
            "WorkOrderType"        : "",
        }
        if extra: payload.update(extra)
        label = f"action:{action_code}"

        if relay_tokens and relay_tokens.get("ready"):
            log.info("[%s] using relay tokens (integrity fresh)", label)
            return self.post_with_relay_token(
                EP_WO_UPDATE, payload, label,
                integrity_token = relay_tokens["integrity"]["token"],
                enc_session     = relay_tokens["enc_session"]["token"],
            )
        return self.post(EP_WO_UPDATE, payload, label)

    def hold(self, username, wo_id, reason, lat, lon):
        return self.send_action(username, wo_id, AC_HOLD, lat, lon,
                                extra={"OnHoldReason": reason, "OnHoldReasonNotes": reason})

    def complete(self, username, wo_id, lat, lon):
        return self.send_action(username, wo_id, AC_COMPLETE, lat, lon)

    def add_consumables(self, username, wo_id, meters):
        return self.send_action(username, wo_id, "ZA31", DEFAULT_LAT, DEFAULT_LON,
                                extra={"ConsumableType": "CABLE", "Quantity": meters, "Unit": "METER"})

    def close(self): self.session.close()


# ── WO helpers ────────────────────────────────────────────────────────────────

def coords_of(wo: dict) -> tuple[str, str]:
    addr = (wo.get("CustomerDetails") or {}).get("Address") or {}
    lat  = addr.get("Latitude") or wo.get("Latitude")
    lon  = addr.get("Longitude") or wo.get("Longitude")
    return (str(lat), str(lon)) if lat and lon else (DEFAULT_LAT, DEFAULT_LON)

def pick_active(wos):
    today = date.today().isoformat()
    def apt(w): return (w.get("AppointmentStartDate") or "")[:10]
    for w in wos:
        if w.get("StatusDesc") == "In Progress" and w.get("ActionCode") != "ZA26": return w
    for w in wos:
        if w.get("StatusDesc") == "In Progress": return w
    for status in ("Assigned", "Confirmed Interested"):
        for w in wos:
            if w.get("StatusDesc") == status and apt(w) == today: return w
    upcoming = sorted(
        [w for w in wos if w.get("StatusDesc") in ("Assigned", "Confirmed Interested") and apt(w) >= today],
        key=lambda w: apt(w)
    )
    return upcoming[0] if upcoming else None

def eligible_wos(wos):
    today = date.today().isoformat()
    def apt(w): return (w.get("AppointmentStartDate") or "")[:10]
    inprog   = [w for w in wos if w.get("StatusDesc") == "In Progress"]
    assigned = sorted(
        [w for w in wos if w.get("StatusDesc") in ("Assigned","Confirmed Interested") and apt(w) >= today],
        key=lambda w: apt(w)
    )
    seen, out = set(), []
    for w in inprog + assigned:
        wid = w.get("WorkOrderID")
        if wid not in seen:
            seen.add(wid); out.append(w)
    return out

def run_wo_steps(client: JpwClient, username: str, wos: list, active: dict,
                 relay_tokens: dict | None = None) -> dict:
    wo_id  = active["WorkOrderID"]
    cust   = active.get("CustomerDetails") or {}
    lat, lon = coords_of(active)
    result = {
        "work_order_id": wo_id,
        "status_desc"  : active.get("StatusDesc"),
        "customer_name": cust.get("FullName") or active.get("FullName"),
        "relay_used"   : bool(relay_tokens and relay_tokens.get("ready")),
        "steps"        : [],
    }
    if active.get("ActionCode") == "ZA26":
        result["action_taken"] = "skipped_already_reached"; return result

    status = active.get("StatusDesc")
    if status == "In Progress":
        upd = client.send_action(username, wo_id, "ZA26", lat, lon, relay_tokens=relay_tokens)
        result["steps"].append({"action": "ZA26", "ok": upd.get("IsSuccessful")})
        result["action_taken"] = "marked_reached" if upd.get("IsSuccessful") else "update_failed"
        if not upd.get("IsSuccessful"):
            result["error"] = (upd.get("ErrorInfo") or {}).get("UserMessage")
        return result

    if status in ("Assigned", "Confirmed Interested"):
        blocker = next((w for w in wos if w.get("StatusDesc") == "In Progress"), None)
        if blocker and blocker.get("WorkOrderID") != wo_id:
            result["action_taken"] = "blocked_by_previous_wo"
            result["blocker_work_order"] = blocker.get("WorkOrderID")
            return result
        beg = client.send_action(username, wo_id, "ZA25", lat, lon, relay_tokens=relay_tokens)
        result["steps"].append({"action": "ZA25", "ok": beg.get("IsSuccessful")})
        if not beg.get("IsSuccessful"):
            result["action_taken"] = "begin_journey_failed"
            result["error"] = (beg.get("ErrorInfo") or {}).get("UserMessage")
            return result
        upd = client.send_action(username, wo_id, "ZA26", lat, lon, relay_tokens=relay_tokens)
        result["steps"].append({"action": "ZA26", "ok": upd.get("IsSuccessful")})
        result["action_taken"] = "marked_reached" if upd.get("IsSuccessful") else "update_failed"
        if not upd.get("IsSuccessful"):
            result["error"] = (upd.get("ErrorInfo") or {}).get("UserMessage")
        return result

    result["action_taken"] = "unsupported_status"; return result


# ── Credential parser ─────────────────────────────────────────────────────────

def parse_credentials(text: str) -> tuple[str | None, str | None]:
    t = (text or "").strip()
    if not t: return None, None
    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
    if len(lines) >= 2: return lines[0], lines[1]
    line = lines[0] if lines else t
    m = re.match(r"^(\S+?)\s*[,:\s]\s*(\S.*)$", line)
    if m: return m.group(1).strip(), m.group(2).strip()
    return None, None


# ── WO card / menus ───────────────────────────────────────────────────────────

def _cust(wo): return wo.get("CustomerDetails") or {}

def format_wo_card(wo, note="", pos=0, total=1, relay_status="") -> str:
    c = _cust(wo)
    addr = (c.get("Address") or {}).get("FormattedAddress") or "—"
    counter = f"  ({pos+1}/{total})" if total > 1 else ""
    relay_line = f"\n🔑 Token: {relay_status}" if relay_status else ""
    return "\n".join([
        "⚡ *JPW AUTO-REACH PRO v4*",
        "━━━━━━━━━━━━━━━━━━",
        f"🧾 WO: `{wo.get('WorkOrderID') or '—'}`{counter}",
        f"📊 {wo.get('StatusDesc') or '—'}  ·  `{wo.get('ActionCode') or 'none'}`",
        f"👤 {c.get('FullName') or '—'}",
        f"📞 {c.get('MobileNo') or '—'}",
        f"📍 {addr}",
        f"🔧 {wo.get('WorkOrderSubTypeDescription') or wo.get('WorkOrderType') or '—'}",
        *([relay_line] if relay_line else []),
        *([f"", note] if note else []),
    ])

def main_menu(wo, pos=0, total=1):
    rows = [
        [InlineKeyboardButton("✅ Reached", callback_data="act:reached")],
        [InlineKeyboardButton("🔧 Install", callback_data="act:install"),
         InlineKeyboardButton("⏸ Hold",    callback_data="act:hold")],
    ]
    last = [InlineKeyboardButton("🔄 Refresh", callback_data="act:refresh")]
    if total > 1:
        last.insert(0, InlineKeyboardButton(f"➡️ Next ({total})", callback_data="act:next"))
    rows.append(last)
    return InlineKeyboardMarkup(rows)

def hold_menu():
    rows = [[InlineKeyboardButton(label, callback_data=f"hold:{code}")] for code, label in HOLD_REASONS]
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="act:back")])
    return InlineKeyboardMarkup(rows)

def install_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧰 Cable Consume", callback_data="ins:cons")],
        [InlineKeyboardButton("⬅️ Back",          callback_data="act:back")],
        [InlineKeyboardButton("✔️ Complete",       callback_data="ins:complete")],
    ])

def consumables_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"{m}m", callback_data=f"cons:{m}") for m in CABLE_LENGTHS],
        [InlineKeyboardButton("⬅️ Back", callback_data="act:install")],
    ])

def _reason_label(code): return dict(HOLD_REASONS).get(code, code)

_GATED = ("⚠️ Verification Failed — Play Integrity gate.\n"
          "Fix: Hook APK install karo (JPWBridge v4) on rooted phone with JPW app open.")

def _msg(r):
    if r.get("IsSuccessful"): return "✅ Success"
    ei = r.get("ErrorInfo") or {}
    reason = ei.get("UserMessage") or ei.get("Reason") or ""
    if "Verification Failed" in reason or "404" in str(r): return _GATED
    return f"❌ {reason or 'Failed'}"

PROMPT = (
    "⚡ *JPW AUTO-REACH PRO v4*\n"
    "━━━━━━━━━━━━━━\n"
    "🔑 Hook APK: JPWBridge v4\n"
    "📍 Reached · ⏸ Hold · ✔️ Complete\n\n"
    "🔐 *Technician Login*\n"
    "Send: `ID password`\n\n"
    "_Message deleted instantly._"
)

WELCOME_FRAMES = [
    "⚡ JPW AUTO-REACH PRO v4",
    "⚡ *JPW AUTO-REACH PRO v4*\n_Hook APK + Relay Token System_\n\n▰▱▱ loading…",
    "⚡ *JPW AUTO-REACH PRO v4*\n_Hook APK + Relay Token System_\n\n▰▰▱ loading…",
    "⚡ *JPW AUTO-REACH PRO v4*\n_Hook APK + Relay Token System_\n\n▰▰▰ ready ✅",
]


# ── Bot handlers ──────────────────────────────────────────────────────────────

async def _del(ctx, chat_id, ids):
    async def _d(mid):
        try: await ctx.bot.delete_message(chat_id=chat_id, message_id=mid)
        except: pass
    await asyncio.gather(*(_d(m) for m in ids), return_exceptions=True)

def _drop(ctx):
    c = ctx.user_data.pop("jpw_client", None)
    for k in ("jpw_user","jpw_wos","jpw_active","jpw_elig","jpw_idx"): ctx.user_data.pop(k, None)
    if c:
        try: c.close()
        except: pass

async def cmd_start(update, ctx):
    chat_id = update.effective_chat.id
    _drop(ctx)
    await _del(ctx, chat_id, ctx.user_data.get("cleanup", []))
    try: await ctx.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
    except: pass
    anim = await ctx.bot.send_message(chat_id=chat_id, text=WELCOME_FRAMES[0])
    for frame in WELCOME_FRAMES[1:]:
        await asyncio.sleep(0.25)
        try: await anim.edit_text(frame, parse_mode=ParseMode.MARKDOWN)
        except: pass
    await asyncio.sleep(0.2)
    if ctx.user_data.get("access_ok"):
        await anim.edit_text(PROMPT, parse_mode=ParseMode.MARKDOWN)
        ctx.user_data["cleanup"] = [anim.message_id]
        return ASK_CREDS
    await anim.edit_text("🔒 *Access Locked*\n━━━━━━━━━━━\nEnter access password:", parse_mode=ParseMode.MARKDOWN)
    ctx.user_data["cleanup"] = [anim.message_id]
    return ACCESS_GATE

async def receive_access(update, ctx):
    chat_id = update.effective_chat.id
    text = (update.message.text or "").strip()
    try: await ctx.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
    except: pass
    if text != ACCESS_PASSWORD:
        m = await ctx.bot.send_message(chat_id=chat_id, text="❌ Wrong password. /start to retry.")
        ctx.user_data.setdefault("cleanup", []).append(m.message_id)
        return ACCESS_GATE
    await _del(ctx, chat_id, ctx.user_data.get("cleanup", []))
    ctx.user_data["access_ok"] = True
    sent = await ctx.bot.send_message(chat_id=chat_id, text=PROMPT, parse_mode=ParseMode.MARKDOWN)
    ctx.user_data["cleanup"] = [sent.message_id]
    return ASK_CREDS

async def cmd_cancel(update, ctx):
    _drop(ctx); ctx.user_data.clear()
    await update.message.reply_text("Cancelled. /start to begin.")
    return ConversationHandler.END

async def receive_credentials(update, ctx):
    chat_id = update.effective_chat.id
    text = (update.message.text or "").strip()
    try: await ctx.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
    except: pass
    username, password = parse_credentials(text)
    if not username or not password:
        m = await ctx.bot.send_message(chat_id=chat_id,
            text="⚠️ Invalid format. Try `id password`.", parse_mode=ParseMode.MARKDOWN)
        ctx.user_data.setdefault("cleanup", []).append(m.message_id)
        return ASK_CREDS

    # Check relay status alongside login
    relay_status = "checking..."
    progress = await ctx.bot.send_message(chat_id=chat_id, text="⚡ Authenticating…")
    ctx.user_data.setdefault("cleanup", []).append(progress.message_id)

    def _load():
        client = JpwClient()
        client.handshake()
        client.login(username, password)
        wos = client.list_work_orders(username)
        relay = get_relay_tokens()
        return client, wos, relay

    try:
        client, wos, relay = await asyncio.to_thread(_load)
    except JioError as e:
        await progress.edit_text(f"❌ {e}")
        return ASK_CREDS
    except Exception as e:
        await progress.edit_text(f"❌ Unexpected: {e}")
        return ASK_CREDS

    relay_label = "✅ Hook token fresh" if (relay and relay.get("ready")) else "⚠️ No hook token (Verification gate active)"
    active = pick_active(wos)
    if not active:
        await progress.edit_text(f"ℹ️ No active WO ({len(wos)} total).\n{relay_label}")
        client.close(); return ASK_CREDS

    ctx.user_data.update({
        "jpw_client": client, "jpw_user": username,
        "jpw_wos": wos, "jpw_elig": eligible_wos(wos), "jpw_idx": 0,
    })
    elig   = eligible_wos(wos)
    active = elig[0] if elig else active
    ctx.user_data["jpw_active"] = active
    ctx.user_data["jpw_elig"]   = elig

    await progress.edit_text(
        format_wo_card(active, pos=0, total=len(elig) or 1, relay_status=relay_label),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_menu(active, 0, len(elig) or 1))
    return WO_MENU

def _pos_total(ctx):
    elig = ctx.user_data.get("jpw_elig") or []
    return ctx.user_data.get("jpw_idx", 0), (len(elig) or 1)

async def _show_card(query, active, note="", kb=None, ctx=None, relay_status=""):
    pos, total = _pos_total(ctx) if ctx else (0, 1)
    try:
        await query.edit_message_text(
            format_wo_card(active, note, pos, total, relay_status),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=kb if kb is not None else main_menu(active, pos, total))
    except: pass

async def _run(fn, *a): return await asyncio.to_thread(fn, *a)

async def _finish(ctx, chat_id, text):
    await _del(ctx, chat_id, ctx.user_data.get("cleanup", []))
    ctx.user_data["cleanup"] = []
    _drop(ctx)
    final = await ctx.bot.send_message(chat_id=chat_id,
        text=f"{text}\n━━━━━━━━━━━━━━━━━━\n_Send credentials for next WO._",
        parse_mode=ParseMode.MARKDOWN)
    ctx.user_data["cleanup"] = [final.message_id]

async def on_wo_action(update, ctx):
    query   = update.callback_query
    await query.answer()
    chat_id = update.effective_chat.id
    data    = query.data or ""
    client  = ctx.user_data.get("jpw_client")
    username = ctx.user_data.get("jpw_user")
    if not client or not username:
        await query.edit_message_text("⚠️ Session expired. /start again.")
        return ASK_CREDS

    active = ctx.user_data.get("jpw_active") or {}
    wos    = ctx.user_data.get("jpw_wos") or []
    wo_id  = active.get("WorkOrderID")
    lat, lon = coords_of(active)

    if data == "act:back":
        await _show_card(query, active, ctx=ctx); return WO_MENU
    if data == "act:next":
        elig = ctx.user_data.get("jpw_elig") or [active]
        idx  = (ctx.user_data.get("jpw_idx", 0) + 1) % len(elig)
        ctx.user_data["jpw_idx"] = idx
        active = elig[idx]; ctx.user_data["jpw_active"] = active
        await _show_card(query, active, "🔀 Switched", ctx=ctx); return WO_MENU
    if data == "act:install":
        await _show_card(query, active, "🔧 *Installation*", install_menu(), ctx); return WO_MENU
    if data == "act:hold":
        await _show_card(query, active, "⏸ *Hold Reason*", hold_menu(), ctx); return WO_MENU
    if data == "ins:cons":
        await _show_card(query, active, "🧰 *Cable Cut*", consumables_menu(), ctx); return WO_MENU

    # ── REACHED ──────────────────────────────────────────────────────────────
    if data == "act:reached":
        await query.edit_message_text("⚡ Fetching relay token…")

        # Try relay token first
        relay_tokens = await asyncio.to_thread(get_relay_tokens)
        relay_label  = ""
        if relay_tokens and relay_tokens.get("ready"):
            relay_label = "✅ Hook token injected"
            await query.edit_message_text("⚡ Relay token ✅ — Marking Reached…")
        else:
            relay_label = "⚠️ No relay token"
            await query.edit_message_text("⚡ No relay token — trying direct…")

        try:
            result = await _run(run_wo_steps, client, username, wos, active, relay_tokens)
        except Exception as e:
            await _show_card(query, active, f"❌ {e}", relay_status=relay_label, ctx=ctx)
            return WO_MENU

        act = result.get("action_taken")
        relay_used = "🔑 Relay" if result.get("relay_used") else "🔓 Direct"
        if act == "marked_reached":
            active["StatusDesc"]  = "In Progress"
            active["ActionCode"]  = "ZA26"
            ctx.user_data["jpw_active"] = active
            await _show_card(query, active, f"✅ *REACHED!*  {relay_used}", ctx=ctx)
        elif act == "skipped_already_reached":
            await _show_card(query, active, "ℹ️ Already reached.", ctx=ctx)
        elif act in ("update_failed", "begin_journey_failed"):
            err = result.get("error") or "Verification Failed"
            msg = _GATED if "Verification" in err else f"❌ {err}"
            await _show_card(query, active, msg, relay_status=relay_label, ctx=ctx)
        else:
            await _show_card(query, active, f"ℹ️ {result.get('error') or act}", ctx=ctx)
        return WO_MENU

    # ── REFRESH ───────────────────────────────────────────────────────────────
    if data == "act:refresh":
        try:
            wos = await _run(client.list_work_orders, username)
        except Exception as e:
            await _show_card(query, active, f"❌ Refresh: {e}", ctx=ctx); return WO_MENU
        elig = eligible_wos(wos)
        ctx.user_data.update({"jpw_wos": wos, "jpw_elig": elig, "jpw_idx": 0})
        active = elig[0] if elig else active
        ctx.user_data["jpw_active"] = active
        relay = await asyncio.to_thread(get_relay_tokens)
        relay_label = "✅ Token fresh" if (relay and relay.get("ready")) else "⚠️ No token"
        await _show_card(query, active, "🔄 Refreshed", relay_status=relay_label, ctx=ctx)
        return WO_MENU

    # ── HOLD ──────────────────────────────────────────────────────────────────
    if data.startswith("hold:"):
        code = data.split(":", 1)[1]
        reason = _reason_label(code)
        try:
            r = await _run(client.hold, username, wo_id, reason, lat, lon)
        except Exception as e:
            r = {"IsSuccessful": False, "ErrorInfo": {"UserMessage": str(e)}}
        if r.get("IsSuccessful"):
            await _finish(ctx, chat_id, f"⏸ *HOLD*\nWO: `{wo_id}`\nReason: {reason}")
            return ASK_CREDS
        await _show_card(query, active, f"⏸ {reason}\n{_msg(r)}", hold_menu(), ctx); return WO_MENU

    # ── COMPLETE ──────────────────────────────────────────────────────────────
    if data == "ins:complete":
        await query.edit_message_text("⚡ Completing…")
        try:
            r = await _run(client.complete, username, wo_id, lat, lon)
        except Exception as e:
            r = {"IsSuccessful": False, "ErrorInfo": {"UserMessage": str(e)}}
        if r.get("IsSuccessful"):
            await _finish(ctx, chat_id, f"✔️ *COMPLETE*\nWO: `{wo_id}`\nTech: `{username}`")
            return ASK_CREDS
        await _show_card(query, active, f"✔️ Complete\n{_msg(r)}", ctx=ctx); return WO_MENU

    # ── CONSUMABLES ───────────────────────────────────────────────────────────
    if data.startswith("cons:"):
        meters = int(data.split(":", 1)[1])
        try:
            r = await _run(client.add_consumables, username, wo_id, meters)
        except Exception as e:
            r = {"IsSuccessful": False, "ErrorInfo": {"UserMessage": str(e)}}
        await _show_card(query, active, f"🧰 Cable {meters}m: {_msg(r)}", consumables_menu(), ctx)
        return WO_MENU

    await _show_card(query, active, ctx=ctx); return WO_MENU


# ── Main ──────────────────────────────────────────────────────────────────────

def build_app():
    treq = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30, pool_timeout=10)
    app  = Application.builder().token(BOT_TOKEN).request(treq).get_updates_request(treq).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", cmd_start)],
        states={
            ACCESS_GATE : [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_access)],
            ASK_CREDS   : [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_credentials)],
            WO_MENU     : [CallbackQueryHandler(on_wo_action, pattern="^(act|ins|cons|hold):")],
            SCAN_INPUT  : [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u,c: WO_MENU),
                           CallbackQueryHandler(on_wo_action, pattern="^(act|ins|cons|hold):")],
        },
        fallbacks=[CommandHandler("cancel", cmd_cancel), CommandHandler("start", cmd_start)],
        per_message=False,
    )
    app.add_handler(conv)
    return app

def main():
    if not BOT_TOKEN:
        raise SystemExit("❌ BOT_TOKEN not set in .env")
    log.info("JPW Auto-Reach Pro v4 starting…")
    asyncio.run(_main())

async def _main():
    app = build_app()
    await app.initialize()
    await app.start()
    await app.updater.start_polling(drop_pending_updates=True)
    log.info("✅ Bot polling started")
    stop = asyncio.Event()
    try: await stop.wait()
    except (KeyboardInterrupt, asyncio.CancelledError): pass
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: log.info("Bye")
