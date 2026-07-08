# Firebase Storage 버킷 CORS 설정 (1회 실행용)
#
# 브라우저가 서명 URL로 버킷에 직접 PUT 업로드하려면 (api/index.py의
# /upload-url + /register 흐름) 버킷에 CORS가 열려 있어야 한다.
# 실행: python scripts/set_bucket_cors.py  (프로젝트 루트에서)
import os, sys

import firebase_admin
from firebase_admin import credentials, storage

BUCKET = "esmil-vision-cs.firebasestorage.app"
CRED_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "firebase-credentials.json")

cred = credentials.Certificate(CRED_PATH)
firebase_admin.initialize_app(cred, {"storageBucket": BUCKET})
bucket = storage.bucket()

bucket.cors = [{
    # 서명 URL 자체가 인증 수단이므로 origin은 넓게 열어도 안전하다
    "origin": ["*"],
    "method": ["GET", "PUT", "HEAD"],
    "responseHeader": ["Content-Type"],
    "maxAgeSeconds": 3600,
}]
bucket.patch()

print(f"CORS set on {BUCKET}:")
for rule in bucket.cors:
    print(" ", rule)
