# LG ESMIL Vision CS Working Sheet

FastAPI + Firebase + Vercel 기반 비전 검사 CS 이슈 관리 웹앱.

---

## 계정 및 초기 비밀번호

| 계정 | 초기 비밀번호 | 권한 |
|---|---|---|
| `esmil` | `Esmil2024!` | 전체 (작성/수정/삭제) |
| `kwonnamtech` | `Knt2024!` | 작성 + 오늘 수정 |
| `nsys` | `Nsys2024!` | 작성 + 오늘 수정 |
| `technician` | `Tech2024!` | 작성 + 오늘 수정 |

> 비밀번호 변경: `api/index.py` 의 `ACCOUNTS` 딕셔너리에서 수정

---

## 권한 정리

| 기능 | esmil | kwonnamtech / nsys | technician |
|---|---|---|---|
| 새 항목 작성 | ✓ | ✓ | ✓ |
| 오늘 항목 수정 | ✓ | ✓ | ✓ |
| 과거 항목 수정 | ✓ | ✗ | ✗ |
| 항목 삭제 | ✓ | ✗ | ✗ |

---

## 배포 순서

### 1단계 — Firebase 프로젝트 만들기

1. https://console.firebase.google.com 접속
2. **Add project** 클릭 → 프로젝트 이름: `esmil-vision-cs`
3. Google Analytics: 꺼도 됨 → **Create project**
4. 좌측 메뉴 **Firestore Database** → **Create database**
   - Start in **production mode** → Next → 리전: `asia-northeast3 (Seoul)` → **Enable**
5. 좌측 상단 ⚙️ **Project settings** → **Service accounts** 탭
6. **Generate new private key** 버튼 클릭 → JSON 파일 다운로드
7. 다운로드된 JSON 파일을 열어서 내용 전체를 복사해 둠

### 2단계 — GitHub에 올리기

1. https://github.com/new 에서 새 레포 생성
   - 이름: `esmil-vision-cs`
   - Private 권장
2. 이 폴더 전체를 업로드하거나 git push

### 3단계 — Vercel 배포

1. https://vercel.com 가입 (GitHub 계정으로 로그인)
2. **Add New Project** → GitHub 레포 선택 → **Import**
3. Framework: **Other** → **Deploy** 클릭 (첫 배포는 실패해도 됨)
4. 배포된 프로젝트 → **Settings** → **Environment Variables** 에 추가:
   - `FIREBASE_CREDENTIALS` = (1단계에서 복사한 JSON 내용 전체)
   - `JWT_SECRET` = (임의의 긴 문자열, 예: `esmil-vision-2024-xK9mP3qR`)
5. **Redeploy** 클릭

배포 완료 후 `https://esmil-vision-cs.vercel.app` 으로 접속 가능.

---

## 로컬 테스트

```bash
pip install -r requirements.txt
export FIREBASE_CREDENTIALS_PATH=firebase-credentials.json
uvicorn api.index:app --reload
# → http://localhost:8000
```

---

## 프로젝트 구조

```
esmil-vision-cs/
├── api/
│   └── index.py          # FastAPI 백엔드 (인증 + CRUD)
├── static/
│   └── index.html        # 프론트엔드 (로그인 + 전체 UI)
├── requirements.txt
├── vercel.json
└── README.md
```
