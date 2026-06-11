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
    "esmil":       {"password": "Esmil2024!",  "role": "admin",      "display": "ESMIL Admin"},
    "kwonnamtech": {"password": "Knt2024!",    "role": "engineer",   "display": "권남테크"},
    "nsys":        {"password": "Nsys2024!",   "role": "engineer",   "display": "NSYS"},
    "technician":  {"password": "Tech2024!",   "role": "technician", "display": "Technician"},
}
ROLE_PERMS = {
    "admin":      ["write", "edit_today", "edit_past", "delete"],
    "engineer":   ["write", "edit_today"],
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
