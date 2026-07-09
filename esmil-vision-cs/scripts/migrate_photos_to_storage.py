# 기존 entries의 base64 사진을 Firebase Storage로 이전 (1회 실행)
#
# 목적: 사진 바이트가 Firestore 문서/API 응답(Vercel 트래픽)에 실리지 않게 한다.
#   photos: ["data:image/jpeg;base64,..."]  →  photoPaths: ["entry_photos/<id>/<uuid>.jpg"]
#
# 실행 전 전체 entries를 backups/에 gzip JSON으로 백업한다. 재실행 안전
# (photos에 base64가 남아있는 문서만 처리).
#
# 사용법: python scripts/migrate_photos_to_storage.py
import os, sys, io, json, gzip, base64, uuid
from datetime import datetime, timezone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)

import firebase_admin
from firebase_admin import credentials, firestore, storage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUP_DIR = os.path.join(os.path.dirname(ROOT), "backups")
PHOTO_PREFIX = "entry_photos"

cred = credentials.Certificate(os.path.join(ROOT, "firebase-credentials.json"))
firebase_admin.initialize_app(cred, {"storageBucket": "esmil-vision-cs.firebasestorage.app"})
db = firestore.client()
bucket = storage.bucket()

def default(o):
    return o.isoformat() if hasattr(o, "isoformat") else str(o)

# 1) 전체 백업
os.makedirs(BACKUP_DIR, exist_ok=True)
docs = list(db.collection("entries").stream())
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup_path = os.path.join(BACKUP_DIR, f"entries_backup_{stamp}.json.gz")
with gzip.open(backup_path, "wt", encoding="utf-8") as f:
    json.dump({d.id: d.to_dict() for d in docs}, f, ensure_ascii=False, default=default)
print(f"backup: {backup_path} ({os.path.getsize(backup_path)/1024/1024:.1f}MB, {len(docs)} docs)")

# 2) base64 사진 → Storage
migrated = photos_moved = skipped = 0
for i, d in enumerate(docs):
    e = d.to_dict() or {}
    photos = e.get("photos") or []
    b64s = [p for p in photos if str(p).startswith("data:")]
    if not b64s:
        skipped += 1
        continue
    paths = list(e.get("photoPaths") or [])
    for p in b64s:
        try:
            header, b64 = str(p).split(",", 1)
            ct = header.split(":", 1)[1].split(";")[0] or "image/jpeg"
            ext = "png" if "png" in ct else "jpg"
            blob_path = f"{PHOTO_PREFIX}/{d.id}/{uuid.uuid4().hex}.{ext}"
            bucket.blob(blob_path).upload_from_string(base64.b64decode(b64), content_type=ct)
            paths.append(blob_path)
            photos_moved += 1
        except Exception as ex:
            print(f"  ! {d.id}: photo upload failed: {ex}")
            raise SystemExit(1)  # 사진 유실 방지: 실패 시 문서를 건드리지 않고 중단
    d.reference.update({"photoPaths": paths, "photos": firestore.DELETE_FIELD})
    migrated += 1
    if migrated % 50 == 0:
        print(f"  {migrated} docs migrated ({photos_moved} photos)...")

print(f"DONE: {migrated} docs migrated, {photos_moved} photos moved to Storage, {skipped} docs unchanged")
