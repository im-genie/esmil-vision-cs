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
ACCOUNTS = {
    "esmil":       {"password": "Esmil2024!",  "role": "admin",       "display": "ESMIL"},
    "cs":          {"password": "Cs2024!",      "role": "cs",          "display": "CS"},
    "nsys":        {"password": "Nsys2024!",   "role": "cs",          "display": "NSYS"},
    "technician":  {"password": "Tech2024!",   "role": "technician",  "display": "Technician"},
}
ROLE_PERMS = {
    "admin":      ["write", "edit_today", "edit_past", "delete"],
    "cs":         ["write", "edit_today"],
    "technician": ["write", "edit_today"],
}

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
    if not u or u not in ACCOUNTS:
        raise HTTPException(401, "Invalid or expired token")
    return u

def require(username: str, perm: str):
    role = ACCOUNTS[username]["role"]
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
    if u not in ACCOUNTS or ACCOUNTS[u]["password"] != p:
        raise HTTPException(401, "Invalid username or password")
    acc = ACCOUNTS[u]
    return JSONResponse({
        "token":       make_token(u),
        "username":    u,
        "display":     acc["display"],
        "role":        acc["role"],
        "permissions": ROLE_PERMS[acc["role"]],
    })

@app.get("/api/auth/me")
async def me(u: str = Depends(current_user)):
    acc = ACCOUNTS[u]
    return JSONResponse({
        "username":    u,
        "display":     acc["display"],
        "role":        acc["role"],
        "permissions": ROLE_PERMS[acc["role"]],
    })

# ════════════════════════════════════════════════════════════════════════
# ENTRIES
# ════════════════════════════════════════════════════════════════════════

@app.get("/api/entries")
async def get_entries(u: str = Depends(current_user)):
    ensure_db()
    docs = (db.collection("entries")
              .order_by("date", direction=firestore.Query.DESCENDING)
              .stream())
    return JSONResponse({"entries": [serialize({**d.to_dict(), "id": d.id}) for d in docs]})

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
    # Send push in background (non-blocking)
    import asyncio
    try:
        asyncio.ensure_future(send_push_to_roles(title, body, {"entryId": ref.id}))
    except Exception:
        pass
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
        # Send multicast
        msg = fcm_messaging.MulticastMessage(
            notification=fcm_messaging.Notification(title=title, body=body),
            data={k: str(v) for k, v in (data or {}).items()},
            tokens=tokens,
            android=fcm_messaging.AndroidConfig(priority="high"),
            apns=fcm_messaging.APNSConfig(
                payload=fcm_messaging.APNSPayload(
                    aps=fcm_messaging.Aps(sound="default", badge=1)
                )
            ),
            webpush=fcm_messaging.WebpushConfig(
                notification=fcm_messaging.WebpushNotification(
                    title=title, body=body,
                    icon="/static/icon-192.png",
                    vibrate=[200, 100, 200],
                )
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
    role  = payload.get("role") or ACCOUNTS[u]["role"]
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
