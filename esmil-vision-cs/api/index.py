from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import firebase_admin
from firebase_admin import credentials, firestore, storage as fb_storage
import os, json
from datetime import datetime, timedelta, date
from typing import Optional
from jose import jwt, JWTError
import time
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
# Roles: admin | cs | technician
# admin      → write, edit_today, edit_past, delete, manage_tasks, manage_manual, upload_teamfiles
# cs         → write, edit_today, edit_2days, upload_teamfiles
# technician → write, edit_today, edit_2days, upload_teamfiles

DEFAULT_ACCOUNTS = {
    "esmil": {"password": "esmilvision1234!", "role": "admin",      "display": "ESMIL"},
    "cs":    {"password": "1",                "role": "cs",         "display": "CS"},
    "nsys":  {"password": "nsys",             "role": "cs",         "display": "NSYS"},
    "tech":  {"password": "1",                "role": "technician", "display": "Technician"},
}

ROLE_PERMS = {
    "admin":      ["write", "edit_today", "edit_past", "delete", "manage_tasks", "manage_manual", "upload_teamfiles", "delete_teamfiles"],
    "cs":         ["write", "edit_today", "edit_2days", "upload_teamfiles"],
    "technician": ["write", "edit_today", "edit_2days", "upload_teamfiles"],
}

# Small cache so we don't hit Firestore on every auth check.
_acct_cache = {"data": None, "ts": 0.0}
ACCT_TTL = 30  # seconds

def accounts_map():
    """Return {username: {password, role, display}}."""
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
bucket = None

def init_firebase():
    global db, bucket
    if not firebase_admin._apps:
        cred_str = os.environ.get("FIREBASE_CREDENTIALS")
        if cred_str:
            cred = credentials.Certificate(json.loads(cred_str))
        else:
            path = os.environ.get("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")
            if not os.path.exists(path):
                raise Exception("Firebase credentials not found. Set FIREBASE_CREDENTIALS env var.")
            cred = credentials.Certificate(path)
        firebase_admin.initialize_app(cred, {
            'storageBucket': 'esmil-vision-cs.appspot.com'
        })
    db = firestore.client()
    bucket = fb_storage.bucket()

try:
    init_firebase()
except Exception as e:
    print(f"[Warning] Firebase init: {e}")

def ensure_db():
    global db, bucket
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

def days_ago(days: int) -> str:
    """Return date string from N days ago."""
    return (date.today() - timedelta(days=days)).isoformat()

def can_edit_entry(username: str, entry_date: str) -> bool:
    """Check if user can edit an entry based on date and role."""
    role = accounts_map().get(username, {}).get("role", "")
    today = date.today().isoformat()
    
    # admin can always edit
    if "edit_past" in ROLE_PERMS.get(role, []):
        return True
    
    # cs/technician can edit today and yesterday (edit_2days)
    if entry_date == today or entry_date == days_ago(1):
        return "edit_2days" in ROLE_PERMS.get(role, []) or "edit_today" in ROLE_PERMS.get(role, [])
    
    return False

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
    action_type: Optional[str] = None,
    u: str = Depends(current_user)
):
    ensure_db()
    try:
        q = db.collection("entries")
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
        # Filter by action_type if provided
        if action_type:
            entries = [e for e in entries if str(e.get("action","")).strip().lower() == action_type.lower()]
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
    
    # Send push notification
    proc_short = "RP" if entry.get("proc") == "RollPress" else entry.get("proc", "")
    ca_short   = entry.get("ca", "")
    line       = entry.get("line", "")
    vision     = entry.get("vision", "")
    action     = entry.get("action", "")
    reviewer   = entry.get("reviewer", u)
    lot        = entry.get("lot", "")
    status_txt = entry.get("status_ko") or entry.get("status") or ""
    act_txt    = entry.get("act_ko") or entry.get("act") or ""
    title = f"\U0001F514 {proc_short} · {ca_short}#{line}"
    body_lines = [f"{vision} · {action}"]
    if status_txt:
        body_lines.append(f"Status: {status_txt}")
    if act_txt:
        body_lines.append(f"Action: {act_txt}")
    tail = f"\uC791\uC131\uC790: {reviewer}"
    if lot:
        tail += f" · Lot {lot}"
    body_lines.append(tail)
    body = "\n".join(body_lines)
    
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
    
    # Check if user can edit this entry
    if not can_edit_entry(u, entry_date):
        raise HTTPException(403, "You can only edit entries from today or yesterday")
    
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
# TASKS
# ════════════════════════════════════════════════════════════════════════

@app.get("/api/tasks")
async def get_tasks(u: str = Depends(current_user)):
    """Get all tasks for the team."""
    ensure_db()
    try:
        docs = list(db.collection("tasks").order_by("createdAt", direction=firestore.Query.DESCENDING).stream())
        tasks = []
        for d in docs:
            tasks.append(serialize({**d.to_dict(), "id": d.id}))
        return JSONResponse({"tasks": tasks})
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.post("/api/tasks")
async def create_task(payload: dict, u: str = Depends(current_user)):
    """Create a new task (admin only)."""
    require(u, "manage_tasks")
    ensure_db()
    task = {
        "title": payload.get("title", ""),
        "description": payload.get("description", ""),
        "assignee": payload.get("assignee", ""),
        "priority": payload.get("priority", "normal"),  # low, normal, high
        "status": payload.get("status", "todo"),  # todo, in_progress, done
        "dueDate": payload.get("dueDate", ""),
        "createdBy": u,
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    }
    ref = db.collection("tasks").document()
    ref.set(task)
    return JSONResponse({"id": ref.id, "success": True})

@app.put("/api/tasks/{task_id}")
async def update_task(task_id: str, payload: dict, u: str = Depends(current_user)):
    """Update a task (admin only)."""
    require(u, "manage_tasks")
    ensure_db()
    doc = db.collection("tasks").document(task_id).get()
    if not doc.exists:
        raise HTTPException(404, "Task not found")
    
    data = {k: v for k, v in payload.items() if k != "id"}
    data["updatedBy"] = u
    data["updatedAt"] = firestore.SERVER_TIMESTAMP
    db.collection("tasks").document(task_id).update(data)
    return JSONResponse({"success": True})

@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, u: str = Depends(current_user)):
    """Delete a task (admin only)."""
    require(u, "manage_tasks")
    ensure_db()
    db.collection("tasks").document(task_id).delete()
    return JSONResponse({"success": True})

# ════════════════════════════════════════════════════════════════════════
# TEAM FILES (Tasks 탭 내 팀 파일 섹션)
# ════════════════════════════════════════════════════════════════════════

@app.get("/api/team-files")
async def get_team_files(u: str = Depends(current_user)):
    """Get all team files."""
    ensure_db()
    try:
        docs = list(db.collection("team_files").order_by("createdAt", direction=firestore.Query.DESCENDING).stream())
        files = []
        for d in docs:
            f = d.to_dict()
            f["id"] = d.id
            files.append(serialize(f))
        return JSONResponse({"files": files})
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.post("/api/team-files/upload")
async def upload_team_file(
    file: UploadFile = File(...),
    fileName: str = Form(""),
    description: str = Form(""),
    u: str = Depends(current_user)
):
    """Upload a team file (cs/technician can also upload)."""
    require(u, "upload_teamfiles")
    ensure_db()
    
    try:
        # Save to Firebase Storage
        blob_path = f"team_files/{datetime.now().isoformat()}_{file.filename}"
        blob = bucket.blob(blob_path)
        blob.upload_from_string(await file.read(), content_type=file.content_type)
        
        # Save metadata to Firestore
        team_file = {
            "fileName": fileName or file.filename,
            "originalFileName": file.filename,
            "description": description or "",
            "filePath": blob_path,
            "fileSize": blob.size,
            "uploadedBy": u,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }
        ref = db.collection("team_files").document()
        ref.set(team_file)
        
        return JSONResponse({
            "id": ref.id,
            "success": True,
            "fileName": file.filename,
            "filePath": blob_path
        })
    except Exception as ex:
        raise HTTPException(500, f"Upload failed: {str(ex)}")

@app.get("/api/team-files/{file_id}/download")
async def download_team_file(file_id: str, u: str = Depends(current_user)):
    """Download a team file (all can download)."""
    ensure_db()
    doc = db.collection("team_files").document(file_id).get()
    if not doc.exists:
        raise HTTPException(404, "File not found")
    
    team_file = doc.to_dict()
    file_path = team_file.get("filePath", "")
    
    if not file_path:
        raise HTTPException(404, "File not found")
    
    try:
        blob = bucket.blob(file_path)
        if not blob.exists():
            raise HTTPException(404, "File not found in storage")
        
        file_data = blob.download_as_bytes()
        return FileResponse(
            path=file_data,
            filename=team_file.get("originalFileName", "download"),
            media_type=blob.content_type
        )
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.delete("/api/team-files/{file_id}")
async def delete_team_file(file_id: str, u: str = Depends(current_user)):
    """Delete a team file (admin only)."""
    require(u, "delete_teamfiles")
    ensure_db()
    
    doc = db.collection("team_files").document(file_id).get()
    if not doc.exists:
        raise HTTPException(404, "File not found")
    
    team_file = doc.to_dict()
    file_path = team_file.get("filePath", "")
    
    # Delete from Storage
    if file_path:
        try:
            bucket.blob(file_path).delete()
        except Exception as e:
            print(f"[TeamFiles] Storage delete failed: {e}")
    
    # Delete from Firestore
    db.collection("team_files").document(file_id).delete()
    return JSONResponse({"success": True})

# ════════════════════════════════════════════════════════════════════════
# MANUALS
# ════════════════════════════════════════════════════════════════════════

@app.get("/api/manuals")
async def get_manuals(u: str = Depends(current_user)):
    """Get all manual documents."""
    ensure_db()
    try:
        docs = list(db.collection("manuals").order_by("createdAt", direction=firestore.Query.DESCENDING).stream())
        manuals = []
        for d in docs:
            m = d.to_dict()
            m["id"] = d.id
            manuals.append(serialize(m))
        return JSONResponse({"manuals": manuals})
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.post("/api/manuals/upload")
async def upload_manual(
    file: UploadFile = File(...),
    title: str = Form(""),
    category: str = Form(""),
    u: str = Depends(current_user)
):
    """Upload a manual document."""
    require(u, "manage_manual")
    ensure_db()
    
    try:
        # Save to Firebase Storage
        blob_path = f"manuals/{datetime.now().isoformat()}_{file.filename}"
        blob = bucket.blob(blob_path)
        blob.upload_from_string(await file.read(), content_type=file.content_type)
        
        # Save metadata to Firestore
        manual = {
            "title": title or file.filename,
            "category": category or "기타",
            "fileName": file.filename,
            "filePath": blob_path,
            "fileSize": blob.size,
            "uploadedBy": u,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }
        ref = db.collection("manuals").document()
        ref.set(manual)
        
        return JSONResponse({
            "id": ref.id,
            "success": True,
            "fileName": file.filename,
            "filePath": blob_path
        })
    except Exception as ex:
        raise HTTPException(500, f"Upload failed: {str(ex)}")

@app.get("/api/manuals/{manual_id}/download")
async def download_manual(manual_id: str, u: str = Depends(current_user)):
    """Download a manual document."""
    ensure_db()
    doc = db.collection("manuals").document(manual_id).get()
    if not doc.exists:
        raise HTTPException(404, "Manual not found")
    
    manual = doc.to_dict()
    file_path = manual.get("filePath", "")
    
    if not file_path:
        raise HTTPException(404, "File not found")
    
    try:
        blob = bucket.blob(file_path)
        if not blob.exists():
            raise HTTPException(404, "File not found in storage")
        
        file_data = blob.download_as_bytes()
        return FileResponse(
            path=file_data,
            filename=manual.get("fileName", "download"),
            media_type=blob.content_type
        )
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.delete("/api/manuals/{manual_id}")
async def delete_manual(manual_id: str, u: str = Depends(current_user)):
    """Delete a manual document."""
    require(u, "manage_manual")
    ensure_db()
    
    doc = db.collection("manuals").document(manual_id).get()
    if not doc.exists:
        raise HTTPException(404, "Manual not found")
    
    manual = doc.to_dict()
    file_path = manual.get("filePath", "")
    
    # Delete from Storage
    if file_path:
        try:
            bucket.blob(file_path).delete()
        except Exception as e:
            print(f"[Manual] Storage delete failed: {e}")
    
    # Delete from Firestore
    db.collection("manuals").document(manual_id).delete()
    return JSONResponse({"success": True})

# ════════════════════════════════════════════════════════════════════════
# FCM PUSH NOTIFICATIONS
# ════════════════════════════════════════════════════════════════════════

NOTIFY_ROLES = {"admin", "technician"}

async def send_push_to_roles(title: str, body: str, data: dict = None):
    """Send push notification to all registered tokens for NOTIFY_ROLES."""
    if not FCM_AVAILABLE:
        return
    ensure_db()
    try:
        pairs = []
        seen = set()
        for doc in db.collection("fcm_tokens").stream():
            d = doc.to_dict() or {}
            tok = d.get("token")
            if d.get("role") in NOTIFY_ROLES and tok and tok not in seen:
                seen.add(tok)
                pairs.append((doc.id, tok))
        if not pairs:
            return
        tokens = [t for _, t in pairs]
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
        try:
            for i, r in enumerate(resp.responses):
                if r.success:
                    continue
                emsg = (str(getattr(r, "exception", "")) or "").lower()
                if ("not-registered" in emsg or "unregistered" in emsg
                        or "not found" in emsg or "invalid-registration" in emsg
                        or "invalid argument" in emsg):
                    db.collection("fcm_tokens").document(pairs[i][0]).delete()
        except Exception as ce:
            print(f"[FCM] cleanup skip: {ce}")
    except Exception as e:
        print(f"[FCM] Push error: {e}")

@app.post("/api/fcm/register")
async def register_fcm_token(payload: dict, u: str = Depends(current_user)):
    """Save FCM token for THIS device."""
    ensure_db()
    token = payload.get("token")
    role  = payload.get("role") or accounts_map().get(u, {}).get("role", "cs")
    device = (payload.get("deviceId") or "").strip()
    if not token:
        raise HTTPException(400, "Token required")
    doc_id = device or token
    db.collection("fcm_tokens").document(doc_id).set({
        "token": token,
        "role": role,
        "username": u,
        "deviceId": device,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })
    return JSONResponse({"success": True})

@app.delete("/api/fcm/unregister")
async def unregister_fcm_token(deviceId: str = "", u: str = Depends(current_user)):
    """Remove this device's token on logout."""
    ensure_db()
    try:
        if deviceId:
            db.collection("fcm_tokens").document(deviceId).delete()
        db.collection("fcm_tokens").document(u).delete()
    except Exception:
        pass
    return JSONResponse({"success": True})

@app.post("/api/entries/bulk")
async def bulk_create(payload: dict, u: str = Depends(current_user)):
    """Bulk insert entries (admin only)."""
    require(u, "delete")
    ensure_db()
    entries = payload.get("entries", [])
    if not entries:
        raise HTTPException(400, "No entries provided")
    
    batch = db.batch()
    count = 0
    for entry in entries[:500]:
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
