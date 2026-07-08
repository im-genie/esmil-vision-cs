# NSYS Pending List 엑셀 → Firestore(pending_issues) 1회 임포트
#
# 사용법:  python scripts/import_pending_from_excel.py "<엑셀 경로>" [--replace]
#   --replace : 기존 pending_issues 문서를 모두 지우고 다시 임포트
import os, sys, io
from datetime import datetime, timezone

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import openpyxl
import firebase_admin
from firebase_admin import credentials, firestore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHEET = "★JF2 N-SYS"

def norm_date(v):
    if isinstance(v, datetime):
        return v.date().isoformat()
    s = str(v or "").strip()
    return s[:10] if s else ""

def norm_text(v):
    return str(v).strip() if v is not None else ""

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    xlsx = sys.argv[1]
    replace = "--replace" in sys.argv

    cred = credentials.Certificate(os.path.join(ROOT, "firebase-credentials.json"))
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    col = db.collection("pending_issues")

    existing = list(col.limit(500).stream())
    if existing and not replace:
        print(f"pending_issues에 이미 {len(existing)}건이 있습니다. 다시 임포트하려면 --replace를 붙이세요.")
        sys.exit(1)
    if existing and replace:
        for d in existing:
            d.reference.delete()
        print(f"기존 {len(existing)}건 삭제")

    ws = openpyxl.load_workbook(xlsx, read_only=True, data_only=True)[SHEET]
    batch = db.batch()
    n = 0
    for row in ws.iter_rows(min_row=7, values_only=True):
        no, issue_dt = row[1], row[2]
        desc, details = norm_text(row[7]), norm_text(row[8])
        if no is None or (not desc and not issue_dt):
            continue
        status = norm_text(row[11]).lower() or "ongoing"
        if status not in ("ongoing", "monitoring", "completed"):
            status = "ongoing"
        remark = norm_text(row[12])
        if remark:
            details = (details + "\n\n[Remark] " + remark).strip()
        issue_date = norm_date(issue_dt)
        due_date = norm_date(row[10])
        # 정렬용 타임스탬프는 이슈 발행일 기준으로 세팅
        base_dt = datetime.fromisoformat(issue_date).replace(tzinfo=timezone.utc) \
            if issue_date else datetime.now(timezone.utc)
        upd_dt = datetime.fromisoformat(due_date).replace(tzinfo=timezone.utc) \
            if due_date else base_dt

        issue = {
            "issueNo": int(no),
            "issueDate": issue_date,
            "category": norm_text(row[3]) or "SW",
            "process": norm_text(row[4]) or "공통",
            "polarity": norm_text(row[5]) or "공통",
            "vision": " ".join(norm_text(row[6]).split()),  # 개행 → 공백
            "description": desc,
            "details": details,
            "assignee": norm_text(row[9]),
            "dueDate": due_date,
            "status": status,
            "attachments": [],
            "createdBy": "excel-import",
            "updatedBy": "excel-import",
            "createdAt": base_dt,
            "updatedAt": upd_dt,
        }
        if status == "completed":
            issue["completedAt"] = upd_dt.isoformat().replace("+00:00", "Z")
        batch.set(col.document(), issue)
        n += 1
        if n % 400 == 0:
            batch.commit(); batch = db.batch()
    batch.commit()
    print(f"임포트 완료: {n}건")

if __name__ == "__main__":
    main()
