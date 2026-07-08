from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Body
from fastapi.responses import JSONResponse, FileResponse, Response
from urllib.parse import quote
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import firebase_admin
from firebase_admin import credentials, firestore, storage as fb_storage
import os, json, hashlib, hmac
from datetime import datetime, timedelta, date
from zoneinfo import ZoneInfo
from typing import Optional
from jose import jwt, JWTError
import time
try:
    from firebase_admin import messaging as fcm_messaging
    FCM_AVAILABLE = True
except ImportError:
    FCM_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────
def _derive_jwt_secret() -> str:
    """JWT 서명 키: 환경변수 우선, 없으면 Firebase 서비스 계정 키에서 파생.
    코드(저장소)에 시크릿이 남지 않도록 하드코딩 폴백을 제거했다."""
    env = os.environ.get("JWT_SECRET")
    if env:
        return env
    cred_str = os.environ.get("FIREBASE_CREDENTIALS")
    if not cred_str:
        path = os.environ.get("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                cred_str = f.read()
    if cred_str:
        return hashlib.sha256(("esmil-jwt-v2|" + cred_str).encode()).hexdigest()
    # 자격증명이 전혀 없는 환경(로컬 개발 등): 프로세스 수명 동안만 유효한 임의 키
    return os.urandom(32).hex()

JWT_SECRET       = _derive_jwt_secret()
JWT_ALGO         = "HS256"
JWT_EXPIRE_DAYS  = 30

project_root  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
static_folder = os.path.join(project_root, "static")

# ── Accounts & permissions ────────────────────────────────────────────
# Roles: admin | cs | technician
# admin      → write, edit_today, edit_past, delete, manage_tasks, manage_manual, upload_teamfiles
# cs         → write, edit_today, edit_2days, upload_teamfiles
# technician → write, edit_today, edit_2days, upload_teamfiles

# 계정은 Firestore 'accounts' 컬렉션에서 관리한다 (비밀번호는 pbkdf2 해시 저장).
# 보안상 하드코딩된 비밀번호는 제거됨 — Firestore를 읽을 수 없으면 로그인 불가.
DEFAULT_ACCOUNTS = {}

def hash_pw(pw: str) -> str:
    """pbkdf2-sha256 해시 (표준 라이브러리만 사용)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"pbkdf2$200000${salt.hex()}${dk.hex()}"

def verify_pw(pw: str, stored: str) -> bool:
    """해시(pbkdf2$...) 및 예전 평문 저장 계정 모두 검증."""
    stored = str(stored or "")
    if not pw or not stored:
        return False
    if stored.startswith("pbkdf2$"):
        try:
            _, iters, salt_hex, hash_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), int(iters))
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False
    return hmac.compare_digest(stored, pw)

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
            'storageBucket': 'esmil-vision-cs.firebasestorage.app'
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

# ── 근무일(Work day): 08:00 → 다음날 08:00, 공장 현지시간(Michigan) 기준 ──
try:
    PLANT_TZ = ZoneInfo("America/Detroit")
except Exception:  # tzdata 미설치 환경 대비 (고정 오프셋 폴백)
    from datetime import timezone as _tz
    PLANT_TZ = _tz(timedelta(hours=-5))
OP_DAY_START_HOUR = 8

def op_today() -> date:
    """Current work day (8am boundary, plant local time)."""
    now = datetime.now(PLANT_TZ) - timedelta(hours=OP_DAY_START_HOUR)
    return now.date()

def can_edit_entry(username: str, entry_date: str) -> bool:
    """Admin: any entry. cs/technician: entries from the current or previous work day."""
    role = accounts_map().get(username, {}).get("role", "")
    perms = ROLE_PERMS.get(role, [])

    # admin can always edit
    if "edit_past" in perms:
        return True

    if "edit_2days" not in perms and "edit_today" not in perms:
        return False

    cutoff = (op_today() - timedelta(days=1)).isoformat()
    return bool(entry_date) and entry_date >= cutoff

def serialize(obj):
    if isinstance(obj, dict):  return {k: serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [serialize(i) for i in obj]
    if hasattr(obj, "isoformat"): return obj.isoformat()
    return obj

# ── 감사 로그 & 관리자 확인 ──────────────────────────────────────────
AUDIT_RETENTION_DAYS = 7

def audit_log(actor: str, action: str, target: str = "", detail: str = ""):
    """감사 로그 기록. 실패해도 본 동작에는 영향 주지 않는다."""
    try:
        ensure_db()
        db.collection("audit").add({
            "user": actor, "action": action, "target": target, "detail": detail,
            "at": firestore.SERVER_TIMESTAMP,
        })
    except Exception as e:
        print(f"[audit] skip: {e}")

def require_admin(username: str):
    if accounts_map().get(username, {}).get("role") != "admin":
        raise HTTPException(403, "Admin only")

# ════════════════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/login")
async def login(payload: dict):
    u = payload.get("username", "").strip().lower()
    p = payload.get("password", "").strip()
    accts = accounts_map()
    if u not in accts or not verify_pw(p, accts[u]["password"]):
        audit_log(u or "?", "login_fail")
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
# ADMIN: 계정 관리 & 감사 로그 (esmil 전용)
# ════════════════════════════════════════════════════════════════════════

@app.get("/api/accounts")
async def list_accounts(u: str = Depends(current_user)):
    require_admin(u)
    out = [{"username": name, "role": a.get("role"), "display": a.get("display")}
           for name, a in sorted(accounts_map().items())]
    return JSONResponse({"accounts": out})

@app.post("/api/accounts")
async def upsert_account(payload: dict, u: str = Depends(current_user)):
    require_admin(u)
    ensure_db()
    username = str(payload.get("username", "")).strip().lower()
    if not username or not username.isalnum():
        raise HTTPException(400, "Invalid username (letters/numbers only)")
    role = payload.get("role", "cs")
    if role not in ROLE_PERMS:
        raise HTTPException(400, "Invalid role")
    display = str(payload.get("display", "")).strip() or username.upper()
    password = str(payload.get("password", ""))

    ref = db.collection("accounts").document(username)
    existing = ref.get()
    if not existing.exists and not password:
        raise HTTPException(400, "Password required for new account")

    # 마지막 admin 강등 방지
    if existing.exists and (existing.to_dict() or {}).get("role") == "admin" and role != "admin":
        admins = [n for n, a in accounts_map().items() if a.get("role") == "admin"]
        if admins == [username]:
            raise HTTPException(400, "Cannot demote the last admin account")

    data = {"role": role, "display": display}
    if password:
        data["password"] = hash_pw(password)
    ref.set(data, merge=True)
    _acct_cache["data"] = None  # 캐시 즉시 무효화
    audit_log(u, "account_update" if existing.exists else "account_create", username,
              f"role={role}" + (" (비밀번호 변경)" if password and existing.exists else ""))
    return JSONResponse({"success": True})

@app.delete("/api/accounts/{username}")
async def delete_account(username: str, u: str = Depends(current_user)):
    require_admin(u)
    ensure_db()
    username = username.strip().lower()
    if username == u:
        raise HTTPException(400, "Cannot delete your own account")
    tgt = accounts_map().get(username)
    if not tgt:
        raise HTTPException(404, "Account not found")
    if tgt.get("role") == "admin":
        admins = [n for n, a in accounts_map().items() if a.get("role") == "admin"]
        if len(admins) <= 1:
            raise HTTPException(400, "Cannot delete the last admin account")
    db.collection("accounts").document(username).delete()
    _acct_cache["data"] = None
    audit_log(u, "account_delete", username)
    return JSONResponse({"success": True})

@app.get("/api/audit")
async def get_audit(limit: int = 300, u: str = Depends(current_user)):
    require_admin(u)
    ensure_db()
    try:
        # 90일 지난 로그 지연 삭제
        try:
            cutoff = datetime.now(PLANT_TZ) - timedelta(days=AUDIT_RETENTION_DAYS)
            for d in db.collection("audit").where("at", "<", cutoff).stream():
                d.reference.delete()
        except Exception as pe:
            print(f"[audit] purge skip: {pe}")
        docs = db.collection("audit").order_by(
            "at", direction=firestore.Query.DESCENDING).limit(max(1, min(int(limit), 1000))).stream()
        logs = [serialize({**(d.to_dict() or {}), "id": d.id}) for d in docs]
        return JSONResponse({"logs": logs})
    except Exception as ex:
        raise HTTPException(500, str(ex))

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

    audit_log(u, "entry_create", ref.id, f"{entry.get('date','')} {proc_short}{ca_short}#{line} {action}")
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
        raise HTTPException(403, "You can only edit entries from the current or previous work day (8am-8am)")
    
    data = {k: v for k, v in payload.items() if k != "id"}
    data.update({"updatedBy": u, "updatedAt": firestore.SERVER_TIMESTAMP})
    db.collection("entries").document(entry_id).update(data)
    audit_log(u, "entry_edit", entry_id, entry_date)
    return JSONResponse({"success": True})

@app.delete("/api/entries/{entry_id}")
async def delete_entry(entry_id: str, u: str = Depends(current_user)):
    """Admin: any entry. cs/technician: only entries within the current/previous work day."""
    ensure_db()
    doc = db.collection("entries").document(entry_id).get()
    if not doc.exists:
        raise HTTPException(404, "Entry not found")
    e = doc.to_dict() or {}
    role = accounts_map().get(u, {}).get("role", "")
    if "delete" not in ROLE_PERMS.get(role, []):
        if not can_edit_entry(u, e.get("date", "")):
            raise HTTPException(403, "You can only delete entries from the current or previous work day (8am-8am)")
    db.collection("entries").document(entry_id).delete()
    audit_log(u, "entry_delete", entry_id,
              f"{e.get('date','')} {e.get('proc','')} {e.get('vision','')} {e.get('action','')}")
    return JSONResponse({"success": True})

# ════════════════════════════════════════════════════════════════════════
# TASKS
# ════════════════════════════════════════════════════════════════════════

TASK_RETENTION_DAYS = 30  # 과거 할일 보관 기간 (지나면 영구 삭제)

@app.get("/api/tasks")
async def get_tasks(u: str = Depends(current_user)):
    """Get all tasks for the team. Tasks older than TASK_RETENTION_DAYS are purged."""
    ensure_db()
    try:
        cutoff = (date.today() - timedelta(days=TASK_RETENTION_DAYS)).isoformat()
        docs = list(db.collection("tasks").order_by("createdAt", direction=firestore.Query.DESCENDING).stream())
        tasks = []
        for d in docs:
            t = d.to_dict() or {}
            # createdDate 없는 예전 데이터는 createdAt으로 보정
            cd = t.get("createdDate")
            if not cd:
                ts = t.get("createdAt")
                cd = ts.date().isoformat() if hasattr(ts, "date") else date.today().isoformat()
                t["createdDate"] = cd
            if cd < cutoff:
                d.reference.delete()
                continue
            tasks.append(serialize({**t, "id": d.id}))
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
        "completed": bool(payload.get("completed", False)),
        "createdDate": payload.get("createdDate") or date.today().isoformat(),
        "createdBy": u,
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    }
    ref = db.collection("tasks").document()
    ref.set(task)
    # 새 할일 등록 알림 → 현장 계정(technician/cs)으로 푸시
    await send_push_to_roles(
        "📋 새 할일",
        f"'{task['title']}' 할일이 등록되었습니다.",
        {"type": "task_created", "taskId": ref.id},
        roles={"technician", "cs"},
    )
    audit_log(u, "task_create", ref.id, task["title"])
    return JSONResponse({"id": ref.id, "success": True})

@app.put("/api/tasks/{task_id}")
async def update_task(task_id: str, payload: dict, u: str = Depends(current_user)):
    """Update a task. Admins can edit everything; cs/technician can only check/uncheck (completed)."""
    ensure_db()
    acct = accounts_map().get(u, {})
    role = acct.get("role", "")
    is_admin = "manage_tasks" in ROLE_PERMS.get(role, [])

    data = {k: v for k, v in payload.items() if k != "id"}
    if not is_admin:
        # Non-admins may only toggle completion
        if not data or set(data.keys()) - {"completed"}:
            raise HTTPException(403, "Only task completion can be changed by your account")

    doc = db.collection("tasks").document(task_id).get()
    if not doc.exists:
        raise HTTPException(404, "Task not found")

    # 체크/해제 시 누가 언제 완료했는지 기록
    if "completed" in data:
        if data["completed"]:
            data["completedBy"] = acct.get("display", u)
            data["completedAt"] = datetime.utcnow().isoformat() + "Z"
        else:
            data["completedBy"] = firestore.DELETE_FIELD
            data["completedAt"] = firestore.DELETE_FIELD

    data["updatedBy"] = u
    data["updatedAt"] = firestore.SERVER_TIMESTAMP
    db.collection("tasks").document(task_id).update(data)

    # Alarm admins (esmil) whenever a non-admin checks off a to-do
    task_title = (doc.to_dict() or {}).get("title", "")
    if data.get("completed") is True and not is_admin:
        display = acct.get("display", u)
        await send_push_to_roles(
            "✅ 할일 완료",
            f"{display}님이 '{task_title}' 항목을 완료했습니다.",
            {"type": "task_completed", "taskId": task_id},
            roles={"admin"},
        )
    if "title" in data:
        audit_log(u, "task_edit", task_id, str(data.get("title", "")))
    elif "completed" in data:
        audit_log(u, "task_check" if data["completed"] else "task_uncheck", task_id, task_title)
    return JSONResponse({"success": True})

@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, u: str = Depends(current_user)):
    """Delete a task (admin only)."""
    require(u, "manage_tasks")
    ensure_db()
    doc = db.collection("tasks").document(task_id).get()
    title = (doc.to_dict() or {}).get("title", "") if doc.exists else ""
    db.collection("tasks").document(task_id).delete()
    audit_log(u, "task_delete", task_id, title)
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

        audit_log(u, "teamfile_upload", ref.id, file.filename)
        return JSONResponse({
            "id": ref.id,
            "success": True,
            "fileName": file.filename,
            "filePath": blob_path
        })
    except Exception as ex:
        raise HTTPException(500, f"Upload failed: {str(ex)}")

# ── 대용량 파일 직접 업로드 ─────────────────────────────────────────────
# Vercel 서버리스 함수는 요청 본문이 4.5MB로 제한되어 그 이상은 413이 난다.
# 브라우저가 서명 URL로 Firebase Storage에 직접 올린 뒤 메타데이터만 등록한다.

def _make_upload_url(prefix: str, file_name: str, content_type: str):
    blob_path = f"{prefix}/{datetime.now().isoformat()}_{file_name}"
    blob = bucket.blob(blob_path)
    url = blob.generate_signed_url(
        version="v4",
        expiration=timedelta(minutes=30),
        method="PUT",
        content_type=content_type or "application/octet-stream",
    )
    return url, blob_path

def _uploaded_blob(prefix: str, blob_path: str):
    """직접 업로드된 blob을 검증하고 메타데이터가 채워진 상태로 반환."""
    if not blob_path.startswith(prefix + "/") or ".." in blob_path:
        raise HTTPException(400, "Invalid blobPath")
    blob = bucket.get_blob(blob_path)
    if blob is None:
        raise HTTPException(400, "File not found in storage. Upload it first.")
    return blob

def _blob_original_name(blob) -> str:
    """'prefix/타임스탬프_원본명' 경로에서 원본 파일명 추출 (폴백용)."""
    return blob.name.split("/", 1)[-1].split("_", 1)[-1]

@app.post("/api/team-files/upload-url")
async def team_file_upload_url(payload: dict = Body(...), u: str = Depends(current_user)):
    """팀 파일 직접 업로드용 서명 URL 발급."""
    require(u, "upload_teamfiles")
    ensure_db()
    file_name = str(payload.get("fileName") or "").strip()
    if not file_name:
        raise HTTPException(400, "fileName is required")
    try:
        url, blob_path = _make_upload_url("team_files", file_name, str(payload.get("contentType") or ""))
        return JSONResponse({"uploadUrl": url, "blobPath": blob_path})
    except Exception as ex:
        raise HTTPException(500, f"Signed URL failed: {ex}")

@app.post("/api/team-files/register")
async def register_team_file(payload: dict = Body(...), u: str = Depends(current_user)):
    """직접 업로드 완료 후 팀 파일 메타데이터 등록."""
    require(u, "upload_teamfiles")
    ensure_db()
    blob = _uploaded_blob("team_files", str(payload.get("blobPath") or ""))
    original = str(payload.get("originalFileName") or "").strip() or _blob_original_name(blob)
    team_file = {
        "fileName": str(payload.get("fileName") or "").strip() or original,
        "originalFileName": original,
        "description": str(payload.get("description") or ""),
        "filePath": blob.name,
        "fileSize": blob.size,
        "uploadedBy": u,
        "createdAt": firestore.SERVER_TIMESTAMP,
    }
    ref = db.collection("team_files").document()
    ref.set(team_file)
    audit_log(u, "teamfile_upload", ref.id, original)
    return JSONResponse({"id": ref.id, "success": True, "fileName": original, "filePath": blob.name})

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
        # originalFileName이 확장자가 포함된 원본명 (fileName은 표시용 제목)
        fname = team_file.get("originalFileName") or team_file.get("fileName") or "download"
        return Response(
            content=file_data,
            media_type=blob.content_type or "application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fname)}"},
        )
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(500, str(ex))

def _signed_preview_url(blob) -> str:
    """Microsoft Office 뷰어가 파일을 읽을 수 있도록 15분짜리 서명 URL 발급."""
    return blob.generate_signed_url(version="v4", expiration=timedelta(minutes=15), method="GET")

@app.get("/api/team-files/{file_id}/preview-url")
async def team_file_preview_url(file_id: str, u: str = Depends(current_user)):
    """Office 문서 미리보기용 임시 서명 URL (로그인 필요)."""
    ensure_db()
    doc = db.collection("team_files").document(file_id).get()
    if not doc.exists:
        raise HTTPException(404, "File not found")
    fp = (doc.to_dict() or {}).get("filePath", "")
    if not fp:
        raise HTTPException(404, "File not found")
    blob = bucket.blob(fp)
    if not blob.exists():
        raise HTTPException(404, "File not found in storage")
    try:
        return JSONResponse({"url": _signed_preview_url(blob)})
    except Exception as ex:
        raise HTTPException(500, f"Signed URL failed: {ex}")

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
    audit_log(u, "teamfile_delete", file_id, team_file.get("fileName", ""))
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
    subcategory: str = Form(""),
    u: str = Depends(current_user)
):
    """Upload a manual document. All logged-in roles can upload; only admin can delete."""
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
            "subcategory": subcategory,
            "fileName": file.filename,
            "filePath": blob_path,
            "fileSize": blob.size,
            "uploadedBy": u,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }
        ref = db.collection("manuals").document()
        ref.set(manual)

        audit_log(u, "manual_upload", ref.id, f"{category}/{subcategory} · {file.filename}")
        return JSONResponse({
            "id": ref.id,
            "success": True,
            "fileName": file.filename,
            "filePath": blob_path
        })
    except Exception as ex:
        raise HTTPException(500, f"Upload failed: {str(ex)}")

@app.post("/api/manuals/upload-url")
async def manual_upload_url(payload: dict = Body(...), u: str = Depends(current_user)):
    """메뉴얼 직접 업로드용 서명 URL 발급 (모든 로그인 계정 가능)."""
    ensure_db()
    file_name = str(payload.get("fileName") or "").strip()
    if not file_name:
        raise HTTPException(400, "fileName is required")
    try:
        url, blob_path = _make_upload_url("manuals", file_name, str(payload.get("contentType") or ""))
        return JSONResponse({"uploadUrl": url, "blobPath": blob_path})
    except Exception as ex:
        raise HTTPException(500, f"Signed URL failed: {ex}")

@app.post("/api/manuals/register")
async def register_manual(payload: dict = Body(...), u: str = Depends(current_user)):
    """직접 업로드 완료 후 메뉴얼 메타데이터 등록."""
    ensure_db()
    blob = _uploaded_blob("manuals", str(payload.get("blobPath") or ""))
    file_name = str(payload.get("originalFileName") or "").strip() or _blob_original_name(blob)
    category = str(payload.get("category") or "기타")
    subcategory = str(payload.get("subcategory") or "")
    manual = {
        "title": str(payload.get("title") or "").strip() or file_name,
        "category": category,
        "subcategory": subcategory,
        "fileName": file_name,
        "filePath": blob.name,
        "fileSize": blob.size,
        "uploadedBy": u,
        "createdAt": firestore.SERVER_TIMESTAMP,
    }
    ref = db.collection("manuals").document()
    ref.set(manual)
    audit_log(u, "manual_upload", ref.id, f"{category}/{subcategory} · {file_name}")
    return JSONResponse({"id": ref.id, "success": True, "fileName": file_name, "filePath": blob.name})

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
        fname = manual.get("fileName") or "download"
        return Response(
            content=file_data,
            media_type=blob.content_type or "application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fname)}"},
        )
    except HTTPException:
        raise
    except Exception as ex:
        raise HTTPException(500, str(ex))

@app.get("/api/manuals/{manual_id}/preview-url")
async def manual_preview_url(manual_id: str, u: str = Depends(current_user)):
    """Office 문서 미리보기용 임시 서명 URL (로그인 필요)."""
    ensure_db()
    doc = db.collection("manuals").document(manual_id).get()
    if not doc.exists:
        raise HTTPException(404, "Manual not found")
    fp = (doc.to_dict() or {}).get("filePath", "")
    if not fp:
        raise HTTPException(404, "File not found")
    blob = bucket.blob(fp)
    if not blob.exists():
        raise HTTPException(404, "File not found in storage")
    try:
        return JSONResponse({"url": _signed_preview_url(blob)})
    except Exception as ex:
        raise HTTPException(500, f"Signed URL failed: {ex}")

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
    audit_log(u, "manual_delete", manual_id, manual.get("title", ""))
    return JSONResponse({"success": True})

# ════════════════════════════════════════════════════════════════════════
# FCM PUSH NOTIFICATIONS
# ════════════════════════════════════════════════════════════════════════

NOTIFY_ROLES = {"admin", "technician"}

async def send_push_to_roles(title: str, body: str, data: dict = None, roles: set = None):
    """Send push notification to all registered tokens for the given roles (default NOTIFY_ROLES)."""
    if not FCM_AVAILABLE:
        return
    ensure_db()
    target_roles = roles or NOTIFY_ROLES
    try:
        pairs = []
        seen = set()
        for doc in db.collection("fcm_tokens").stream():
            d = doc.to_dict() or {}
            tok = d.get("token")
            if d.get("role") in target_roles and tok and tok not in seen:
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
