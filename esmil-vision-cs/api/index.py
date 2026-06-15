from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import firebase_admin
from firebase_admin import credentials, firestore
import os, json
from datetime import datetime, timedelta, date
from typing import Optional
from jose import jwt, JWTError
try:
    from firebase_admin import messaging as fcm_messaging
    FCM_AVAILABLE = True
except ImportError:
    FCM_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────
JWT_SECRET       = os.environ.get("JWT_SECRET", "esmil-vision-cs-2024")
JWT_ALGO         = "HS256"
JWT_EXPIRE_DAYS  = 30

project_root  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
static_folder = os.path.join(project_root, "static")

# ── Accounts & permissions ────────────────────────────────────────────
# Roles: admin | engineer | technician
# admin      → write, edit_today, edit_past, delete
# engineer   → write, edit_today
# technician → write, edit_today
import time

# Default accounts (used when the Firestore "accounts" collection is empty/unavailable).
# To change passwords WITHOUT redeploying: edit the "accounts" collection in Firebase Console.
DEFAULT_ACCOUNTS = {
    "esmil": {"password": "esmilvision1234!", "role": "admin",      "display": "ESMIL"},
    "cs":    {"password": "1",                "role": "cs",         "display": "CS"},
    "nsys":  {"password": "nsys",             "role": "cs",         "display": "NSYS"},
    "tech":  {"password": "1",                "role": "technician", "display": "Technician"},
}
ROLE_PERMS = {
    "admin":      ["write", "edit_today", "edit_past", "delete"],
    "cs":         ["write", "edit_today"],
    "technician": ["write", "edit_today"],
}

# Small cache so we don't hit Firestore on every auth check.
_acct_cache = {"data": None, "ts": 0.0}
ACCT_TTL = 30  # seconds; password changes in Firestore take effect within this window

def accounts_map():
    """Return {username: {password, role, display}}.
    If the Firestore 'accounts' collection has any docs, it is the source of truth;
    otherwise fall back to DEFAULT_ACCOUNTS."""
    now = time.time()
    if _acct_cache["data"] is not None and (now - _acct_cache["ts"]) < ACCT_TTL:
        return _acct_cache["data"]
    result = None
    try:
        ensure_db()
        fs = {}
        for doc in db.collection("accounts").stream():
            d = doc.to_dict() or {}
            fs[doc.id.strip().lower()] = {
                "password": str(d.get("password", "")),
                "role":     d.get("role", "cs"),
                "display":  d.get("display", doc.id.upper()),
            }
        if fs:
            result = fs
    except Exception as e:
        print(f"[accounts] Firestore read failed, using defaults: {e}")
    if result is None:
        result = {k: dict(v) for k, v in DEFAULT_ACCOUNTS.items()}
    _acct_cache["data"] = result
    _acct_cache["ts"] = now
    return result

# ── FastAPI ────────────────────────────────────────────────────────────
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)
if os.path.isdir(static_folder):
    app.mount("/static", StaticFiles(directory=static_folder), name="static")

# ── Firebase ───────────────────────────────────────────────────────────
db = None

def init_firebase():
    global db
    if not firebase_admin._apps:
        cred_str = os.environ.get("FIREBASE_CREDENTIALS")
        if cred_str:
            cred = credentials.Certificate(json.loads(cred_str))
        else:
            path = os.environ.get("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")
            if not os.path.exists(path):
                raise Exception("Firebase credentials not found. Set FIREBASE_CREDENTIALS env var.")
            cred = credentials.Certificate(path)
        firebase_admin.initialize_app(cred)
    db = firestore.client()

try:
    init_firebase()
except Exception as e:
    print(f"[Warning] Firebase init: {e}")

def ensure_db():
    global db
    if db is None:
        init_firebase()

# ── Auth helpers ───────────────────────────────────────────────────────
security = HTTPBearer(auto_error=False)

def make_token(username: str) -> str:
    exp = datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode({"sub": username, "exp": exp}, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token: str) -> Optional[str]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO]).get("sub")
    except JWTError:
        return None

def current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    u = decode_token(creds.credentials)
    if not u or u not in accounts_map():
        raise HTTPException(401, "Invalid or expired token")
    return u

def require(username: str, perm: str):
    role = accounts_map().get(username, {}).get("role", "")
    if perm not in ROLE_PERMS.get(role, []):
        raise HTTPException(403, f"Your account does not have '{perm}' permission")

def is_today(date_str: str) -> bool:
    return date_str == date.today().isoformat()

def serialize(obj):
    if isinstance(obj, dict):  return {k: serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [serialize(i) for i in obj]
    if hasattr(obj, "isoformat"): return obj.isoformat()
    return obj

# ════════════════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/login")
async def login(payload: dict):
    u = payload.get("username", "").strip().lower()
    p = payload.get("password", "").strip()
    accts = accounts_map()
    if u not in accts or accts[u]["password"] != p:
        raise HTTPException(401, "Invalid username or password")
    acc = accts[u]
    return JSONResponse({
        "token":       make_token(u),
        "username":    u,
        "display":     acc["display"],
        "role":        acc["role"],
        "permissions": ROLE_PERMS.get(acc["role"], []),
    })

@app.get("/api/auth/me")
async def me(u: str = Depends(current_user)):
    acc = accounts_map().get(u)
    if not acc:
        raise HTTPException(401, "Invalid or expired token")
    return JSONResponse({
        "username":    u,
        "display":     acc["display"],
        "role":        acc["role"],
        "permissions": ROLE_PERMS.get(acc["role"], []),
    })

# ════════════════════════════════════════════════════════════════════════
# ENTRIES
# ════════════════════════════════════════════════════════════════════════

@app.get("/api/entries")
async def get_entries(
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
    u: str = Depends(current_user)
):
    ensure_db()
    try:
        q = db.collection("entries")
        # Use only date_from on Firestore (single inequality filter = no composite index needed)
        if date_from:
            q = q.where("date", ">=", date_from)
        docs = list(q.stream())
        entries = []
        for d in docs:
            try:
                e = serialize({**d.to_dict(), "id": d.id})
                entries.append(e)
            except Exception:
                continue
        # Filter date_to in Python
        if date_to:
            entries = [e for e in entries if str(e.get("date","")) <= date_to]
        entries.sort(key=lambda x: str(x.get("date","")), reverse=True)
        return JSONResponse({"entries": entries})
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.get("/api/entries/{entry_id}")
async def get_entry(entry_id: str, u: str = Depends(current_user)):
    ensure_db()
    doc = db.collection("entries").document(entry_id).get()
    if not doc.exists:
        raise HTTPException(404, "Entry not found")
    return JSONResponse({"entry": serialize({**doc.to_dict(), "id": doc.id})})

@app.post("/api/entries")
async def create_entry(payload: dict, u: str = Depends(current_user)):
    require(u, "write")
    ensure_db()
    entry = {k: v for k, v in payload.items() if k != "id"}
    entry.update({"createdBy": u, "createdAt": firestore.SERVER_TIMESTAMP})
    ref = db.collection("entries").document()
    ref.set(entry)
    # Send push notification to esmil + technician accounts
    proc_label = entry.get("proc", "")
    ca_label   = "Cathode" if entry.get("ca") == "C" else "Anode"
    line       = entry.get("line", "")
    vision     = entry.get("vision", "")
    action     = entry.get("action", "")
    reviewer   = entry.get("reviewer", u)
    lot        = entry.get("lot", "")
    title = f"🔔 {proc_label} {ca_label} L{line} — New Entry"
    body_parts = [f"{vision} · {action}", f"by {reviewer}"]
    if lot:
        body_parts.append(f"Lot: {lot}")
    body = "  |  ".join(body_parts)
    # Send push BEFORE returning so it actually fires on serverless (no fire-and-forget)
    try:
        await send_push_to_roles(title, body, {"entryId": ref.id})
    except Exception as e:
        print(f"[FCM] push send failed: {e}")
    return JSONResponse({"id": ref.id, "success": True})

@app.put("/api/entries/{entry_id}")
async def update_entry(entry_id: str, payload: dict, u: str = Depends(current_user)):
    ensure_db()
    doc = db.collection("entries").document(entry_id).get()
    if not doc.exists:
        raise HTTPException(404, "Entry not found")
    entry_date = doc.to_dict().get("date", "")
    perm = "edit_today" if is_today(entry_date) else "edit_past"
    require(u, perm)
    data = {k: v for k, v in payload.items() if k != "id"}
    data.update({"updatedBy": u, "updatedAt": firestore.SERVER_TIMESTAMP})
    db.collection("entries").document(entry_id).update(data)
    return JSONResponse({"success": True})

@app.delete("/api/entries/{entry_id}")
async def delete_entry(entry_id: str, u: str = Depends(current_user)):
    require(u, "delete")
    ensure_db()
    db.collection("entries").document(entry_id).delete()
    return JSONResponse({"success": True})

# ════════════════════════════════════════════════════════════════════════
# HEALTH / STATIC
# ════════════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════════════
# FCM PUSH NOTIFICATIONS
# ════════════════════════════════════════════════════════════════════════

# Notify these roles when a new entry is created
NOTIFY_ROLES = {"admin", "technician"}

async def send_push_to_roles(title: str, body: str, data: dict = None):
    """Send push notification to all registered tokens for NOTIFY_ROLES."""
    if not FCM_AVAILABLE:
        return
    ensure_db()
    try:
        # Get all FCM tokens for notify roles
        docs = db.collection("fcm_tokens").stream()
        tokens = []
        for doc in docs:
            d = doc.to_dict()
            if d.get("role") in NOTIFY_ROLES:
                tokens.append(d.get("token"))
        tokens = [t for t in tokens if t]
        if not tokens:
            return
        # Data-only message: the web service worker builds the notification.
        # (Single notification on web; works on Android Chrome and iOS PWA.)
        payload_data = {"title": title, "body": body}
        for k, v in (data or {}).items():
            payload_data[k] = str(v)
        msg = fcm_messaging.MulticastMessage(
            data=payload_data,
            tokens=tokens,
            webpush=fcm_messaging.WebpushConfig(
                headers={"Urgency": "high", "TTL": "86400"},
                fcm_options=fcm_messaging.WebpushFCMOptions(
                    link="https://esmil-vision-cs.vercel.app/"
                ),
            ),
        )
        resp = fcm_messaging.send_each_for_multicast(msg)
        print(f"[FCM] Sent {resp.success_count}/{len(tokens)} notifications")
    except Exception as e:
        print(f"[FCM] Push error: {e}")

@app.post("/api/fcm/register")
async def register_fcm_token(payload: dict, u: str = Depends(current_user)):
    """Save FCM token for this user."""
    ensure_db()
    token = payload.get("token")
    role  = payload.get("role") or accounts_map().get(u, {}).get("role", "cs")
    if not token:
        raise HTTPException(400, "Token required")
    # Store with username as doc ID (one token per user)
    db.collection("fcm_tokens").document(u).set({
        "token": token,
        "role": role,
        "username": u,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })
    return JSONResponse({"success": True})

@app.delete("/api/fcm/unregister")
async def unregister_fcm_token(u: str = Depends(current_user)):
    """Remove FCM token on logout."""
    ensure_db()
    db.collection("fcm_tokens").document(u).delete()
    return JSONResponse({"success": True})

@app.post("/api/entries/bulk")
async def bulk_create(payload: dict, u: str = Depends(current_user)):
    """Bulk insert entries (admin only). Used for Excel data seeding."""
    require(u, "delete")  # admin only
    ensure_db()
    entries = payload.get("entries", [])
    if not entries:
        raise HTTPException(400, "No entries provided")
    
    batch = db.batch()
    count = 0
    for entry in entries[:500]:  # max 500 per call
        entry_clean = {k: v for k, v in entry.items() if k != "id"}
        entry_clean["createdBy"] = u
        entry_clean["seedImport"] = True
        ref = db.collection("entries").document()
        batch.set(ref, entry_clean)
        count += 1
        if count % 499 == 0:
            batch.commit()
            batch = db.batch()
    batch.commit()
    return JSONResponse({"success": True, "imported": count})

@app.get("/api/health")
async def health():
    return JSONResponse({"status": "ok"})

@app.get("/")
async def index():
    p = os.path.join(static_folder, "index.html")
    return FileResponse(p) if os.path.exists(p) else JSONResponse({"error": "Not found"}, status_code=404)

@app.get("/{path:path}")
async def serve_static(path: str):
    if path.startswith("api/"):
        raise HTTPException(404)
    p = os.path.join(static_folder, path)
    if os.path.exists(p) and os.path.isfile(p):
        return FileResponse(p)
    raise HTTPException(404)
