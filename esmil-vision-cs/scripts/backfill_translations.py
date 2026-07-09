# 기존 데이터의 한국어 내용을 영어로 일괄 번역해 Firestore에 저장 (백필)
#
#   entries        : status → status_en, act → act_en
#   pending_issues : description → description_en, details → details_en
#
# 렌더러(EN 모드)가 *_en 필드를 우선 사용하므로, 백필 후에는 실시간 번역 없이
# 즉시 영어로 표시된다. 재실행 안전(이미 _en 있는 문서는 건너뜀), 번역 결과는
# 로컬 캐시 파일에 저장되어 중단 후 재실행 시 이어서 진행된다.
#
# 사용법: python scripts/backfill_translations.py
import os, re, sys, io, json, time, tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from deep_translator import GoogleTranslator
import firebase_admin
from firebase_admin import credentials, firestore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(tempfile.gettempdir(), "esmil_tr_cache.json")
KO = re.compile(r"[가-힣]")

cred = credentials.Certificate(os.path.join(ROOT, "firebase-credentials.json"))
firebase_admin.initialize_app(cred)
db = firestore.client()

cache = {}
if os.path.exists(CACHE):
    try:
        cache = json.load(open(CACHE, encoding="utf-8"))
    except Exception:
        cache = {}

translator = GoogleTranslator(source="ko", target="en")

def tr(text):
    text = text.strip()
    if not text or not KO.search(text):
        return None
    if text in cache:
        return cache[text]
    try:
        out = translator.translate(text[:4500]) or ""
    except Exception as ex:
        print(f"  ! translate failed: {ex}")
        time.sleep(3)
        return None
    cache[text] = out
    if len(cache) % 20 == 0:
        json.dump(cache, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False)
    time.sleep(0.15)  # 예의상 스로틀
    return out

def backfill(coll, fields):
    """fields: {원본필드: 번역필드}"""
    done = skipped = 0
    docs = list(db.collection(coll).stream())
    print(f"[{coll}] {len(docs)} docs")
    for i, d in enumerate(docs):
        e = d.to_dict() or {}
        upd = {}
        for src, dst in fields.items():
            v = str(e.get(src) or "")
            if not v or e.get(dst) or not KO.search(v):
                continue
            out = tr(v)
            if out and out != v:
                upd[dst] = out
        if upd:
            d.reference.update(upd)
            done += 1
        else:
            skipped += 1
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(docs)} processed ({done} updated)")
    print(f"[{coll}] updated {done}, skipped {skipped}")

backfill("entries", {"status": "status_en", "act": "act_en"})
backfill("pending_issues", {"description": "description_en", "details": "details_en"})
json.dump(cache, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False)
print("DONE")
