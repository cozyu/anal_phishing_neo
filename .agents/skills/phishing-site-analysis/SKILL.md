# Phishing / Scam Site Analysis (PhishGuard Standard)

PhishGuard 프로젝트에서 피싱/스캠 사이트를 분석하고 표준 보고서를 생성하기 위한 종합 스킬. 사용자(cozyu)와 2026-04 ~ 2026-05에 합의한 규칙·메모리·산출 형식을 한 곳에 모아둔다.

## 언제 사용하는가

- 사용자가 "URL이 피싱사이트인 것 같다 / 분석해줘 / 분석 보고서 만들어줘" 라고 요청할 때
- 새 도메인에 대해 WHOIS·VT·urlscan·Playwright·CT 등을 종합한 분석이 필요할 때
- 기존 보고서를 갱신·보강할 때 (스크린샷·타임라인·JS 행위 등 챕터 추가)

## 메모리와의 연결 (반드시 함께 따라야 할 영구 규칙)

다음 메모리 파일이 본 스킬의 정책 근거다. 충돌 시 메모리가 우선한다.

- [feedback_report_no_commit.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/feedback_report_no_commit.md) — `report/`, `.playwright-mcp/`는 git 커밋 제외
- [reference_report_layout.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/reference_report_layout.md) — 폴더 구조, 파일명 규칙, URL Full 표기 규칙, PDF 빌드 명령
- [feedback_report_include_screenshot.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/feedback_report_include_screenshot.md) — 본문 발췌(crop) + 부록 풀캡처
- [feedback_report_timeline_chapter.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/feedback_report_timeline_chapter.md) — 공격자 활동 타임라인 (8개 인사이트 항목)
- [feedback_report_pii_capture.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/feedback_report_pii_capture.md) — 개인정보·금융정보 입력 화면 캡처
- [reference_js_behavior_analysis.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/reference_js_behavior_analysis.md) — JS 행위 분석 6개 카테고리 체크리스트
- [feedback_screenshot_path.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/feedback_screenshot_path.md) — Playwright 스크린샷은 기본적으로 `.playwright-mcp/` 아래(분석 산출물은 `report/[도메인]/`로 직접 저장)
- [user_git_identity.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/user_git_identity.md) — git 커밋 메시지에 AI 메타데이터 금지

## 산출 구조

```
report/[도메인]/                                  (.gitignore 등재됨, 커밋 제외)
├── report.html                                  # 작업용 (이 이름 유지)
├── [도메인]_YYMMDD_HHMMSS.pdf                    # 최종 산출
├── mobile.html / desktop.html / detail.html …   # 다운로드한 사이트 자료
├── *.js                                         # 분석 대상 JS 번들
├── screenshot-*.png                             # 풀 페이지 캡처
├── crop-*.png                                   # 본문 발췌 캡처
├── network-*.txt                                # Playwright 네트워크 캡처
├── crop_screenshots.py                          # 발췌 생성 스크립트
└── scan_*.py                                    # 분석 보조 스크립트
```

## 표준 분석 워크플로 (체크리스트)

각 단계는 [references/workflow.md](references/workflow.md)에 실행 명령·예제까지 포함되어 있다. 가능한 만큼 모두 수행한다.

1. **사전 준비**: 도메인을 받아 `mkdir -p report/[도메인]` + 절대경로 변수 설정
2. **WHOIS / DNS / HTTP**: 등록일, 등록기관, 네임서버, 등록자 국가, A/AAAA, 호스팅 헤더 (모바일/데스크탑 UA 다중)
3. **VirusTotal / urlscan.io**: URL·도메인 분석, 자매 사이트 검색 (같은 인프라 호스트로 역검색)
4. **콘텐츠 다운로드**: `curl -sk --compressed -A "iPhone Mobile"` + 데스크탑 UA 동시. base64 해제, 압축 풀기
5. **클로킹 관찰**: 모바일/데스크탑/봇 UA 응답 차이, JS 측 분기(`navigator.userAgent`, `searchParams.get('token')`), 봇 차단 게이트키퍼 정규식
6. **JS 행위 분석** (→ [references/js-checklist.md](references/js-checklist.md)): 외부 호출, postMessage, fingerprint, 안티분석, 광고 픽셀, 자체 통계
7. **결제·로그인 흐름 진입**: Playwright 모바일 뷰포트 + UA로 "구매/로그인" 진입 → PII 입력 폼 캡처. **본 분석자는 더미 데이터만, 실제 PII 절대 입력 금지**
8. **Certificate Transparency**: `crt.sh?q=DOMAIN&output=json` → 인증서 발급 시각, SAN에 묶인 자매 도메인 식별
9. **자매 도메인 추적**: 인증서 SAN, 공유 백엔드(`api.*`), 공유 CDN, ASN으로 묶기. 각자 WHOIS·urlscan 비교
10. **운영자 시간대 추론**: 모든 이벤트를 UTC ↔ KST ↔ 추정 현지 시간으로 환산 (예: CST = UTC+8 중국 영업시간)
11. **MITRE ATT&CK 매핑**: T1583.001/004/008, T1588.004, T1566.002, T1102, T1027, 사기 캠페인 고유 TTP(Cold Pool 등)
12. **스크린샷 발췌**: PIL로 풀 페이지를 잘라 본문용 crop. 풀스크린샷은 부록 A
13. **보고서 작성**: [references/report-template.html](references/report-template.html) 복제 → 채워 넣기
14. **PDF 빌드**: chromium 헤드리스 + 파일명 규칙 적용 (→ [references/pdf-build.md](references/pdf-build.md))
15. **검증**: pypdf로 페이지 수·텍스트 추출 확인. 한글 깨짐 / 빈 페이지 점검

## 표준 보고서 챕터 구조

```
1. 사기 패턴 발췌 (모바일 라이브 캡처)            # crop 2-5장
2. 핵심 요약                                     # 항목 표
3. 공유 인프라 = 동일 운영자 네트워크              # 자매 사이트 클러스터
4. 공격자 활동 타임라인                          # 5개 서브챕터:
   4.1 자매 인프라 일괄 등록 패턴
   4.2 운영자 활동 시간대 분석 (OPSEC 단서)
   4.3 인프라 라이프사이클 (만료 예측)
   4.4 MITRE ATT&CK 매핑
   4.5 핵심 인사이트 요약
5. 운영자 식별                                   # 국가/조직/등록기관 패턴
6. 사이트 시스템 식별자                          # SaaS shopId, userId 등
7. 광고/추적 픽셀                                # Google/Facebook/TikTok/Criteo + 자체
8. 개인정보·금융정보 수집 분석                    # 4개 서브챕터:
   8.1 수취인/로그인 등 PII 입력 발췌
   8.2 결제수단 선택 발췌
   8.3 카드/계좌 입력 발췌 + 안티봇 노출
   8.4 데이터 송신 엔드포인트 표
9. JavaScript 행위 분석                          # 4개 서브챕터:
   9.1 로드되는 JS 모듈
   9.2 자체 통계 추적 페이로드 (Full JSON)
   9.3 행위 매트릭스 (위험도 태그)
   9.4 핵심 인사이트
10. 콘텐츠 위장 패턴                             # SEO 키워드 폭탄, 가짜 후기 등
11. 추정 공격 시나리오                           # ① ~ ⑥
12. 인프라 IOC                                   # 도메인/IP/픽셀ID/식별자
13. 위험성 평가
14. 권고 조치 (효과 순)
15. 분석 산출물
부록 A. 전체 페이지 캡처 (풀 사이즈)
```

> 분석 대상에 따라 챕터는 가감 가능하지만 4(타임라인) / 8(PII) / 9(JS) / 부록 A(풀캡처)는 가능한 항상 포함한다.

## 작성 규칙 요점

- **URL은 항상 풀 텍스트로**: `gclid=...` 같은 중간 생략 금지. 길면 `<pre style="font-size:8.5pt; …">…</pre>` 블록으로 분리.
- **스크린샷 본문 = crop, 부록 = full**. 본문에 풀 페이지(4000px+)를 그대로 임베드하면 인쇄 시 식별 불가.
- **HTML→PDF**: snap chromium은 `/tmp/` 접근 차단 → 반드시 사용자 홈 이하 경로(예: `/home/cozyu/git/.../report/[도메인]/`) 안에서 빌드.
- **임시 빌드 → 파일명 규칙으로 rename**:
  ```bash
  chromium --headless --disable-gpu --no-sandbox --print-to-pdf="$D/_tmp_report.pdf" \
    --no-pdf-header-footer file://$D/report.html
  ts=$(stat -c "%y" "$D/_tmp_report.pdf")
  mv "$D/_tmp_report.pdf" "$D/[도메인]_$(date -d "$ts" +%y%m%d_%H%M%S).pdf"
  ```
- **민감정보**: 분석자가 결제 흐름 등에 더미값을 넣은 경우 캡처 전 지우거나 마스킹.
- **연구 단계**: 사용자가 "코드 수정 금지"로 요청한 경우 PhishGuard 모듈을 건드리지 않고 보고서만 생성한다.

## 자주 쓰는 스니펫

### 환경 변수 / 가상환경
```bash
D=/home/cozyu/git/anal_phishing_neo/report/[도메인]
mkdir -p "$D"
source /home/cozyu/git/anal_phishing_neo/.venv/bin/activate
export $(grep -E '^(VT_API_KEY|URLSCAN_API_KEY|CRIMINALIP_KEY|GEMINI_API_KEY)' /home/cozyu/git/anal_phishing_neo/.env | xargs)
```

### WHOIS
```bash
python -c "import whois; print(whois.whois('[도메인]'))"
```

### Certificate Transparency
```bash
curl -s "https://crt.sh/?q=[도메인]&output=json" -m 15 | python3 -c "
import sys, json
for r in sorted(json.load(sys.stdin), key=lambda x: x.get('entry_timestamp','')):
    print(r.get('entry_timestamp'), '|', r.get('not_before'), '|', r.get('name_value','')[:80])"
```

### 모바일 UA로 HTML 다운로드 (압축 해제)
```bash
curl -sk --compressed -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) AppleWebKit/605.1.15 Mobile/15E148" "$URL" -o "$D/mobile.html"
```

### VT + urlscan 일괄 조회
[references/data-collection.md](references/data-collection.md) 참조.

### 자매 사이트 검색 (공유 인프라 호스트로 역검색)
```bash
# urlscan에서 같은 API 백엔드를 호출하는 사이트 검색
python - <<PY
import os, requests
us = os.environ["URLSCAN_API_KEY"]
for q in ['domain:api.btrbdf.com','domain:resource5-cdn.ocolt.com']:
    r = requests.get("https://urlscan.io/api/v1/search/", params={"q":q,"size":30}, headers={"API-Key":us})
    print(q, '->', r.json().get('total'))
PY
```

### 스크린샷 발췌 (PIL)
[references/crop_screenshots_template.py](references/crop_screenshots_template.py) 참조.

### PDF 빌드 + 파일명
[references/pdf-build.md](references/pdf-build.md) 참조.

## 분석 도구 (이 프로젝트에서 검증된 도구만)

| 용도 | 도구 |
|---|---|
| WHOIS | `python-whois` (`.venv` 안에 설치됨) |
| VirusTotal | API v3 (`VT_API_KEY`) |
| urlscan.io | API + Pro Structure Search (`URLSCAN_API_KEY`) |
| Certificate Transparency | `crt.sh` (무료) |
| 라이브 크롤·결제흐름 | Playwright MCP (`mcp__playwright__*`) |
| 정적 HTML/JS | `curl --compressed` + grep / Python |
| 스크린샷 발췌 | PIL (Pillow) |
| PDF 변환 | `chromium --headless --print-to-pdf` |
| 한글 폰트 | Noto Sans CJK KR (시스템 설치됨) |
| 도메인·시각대 변환 | `date -d` (Bash), `datetime` (Python) |

## 같은 운영자 그룹 식별 신호 (체크포인트)

이전 분석에서 확인된 4개 운영자 그룹의 특징을 패턴으로 활용:

1. **Spaceship + Vercel + Supabase 그룹** (`ekazikcaepevecwqbgii.supabase.co` 사용)
   - 한국 표적: naverpay-order.com (중고나라 사칭), first-futures1.com (해외선물 대여계좌), daeshin-gagu.com (가구)
   - 식별 단서: Spaceship 등록기관, LAUNCH1/2.SPACESHIP.NET, Vercel 호스팅, 동일 Supabase 프로젝트 ID

2. **Tucows + Cloudflare 그룹** (IDN 홈오그래프 + 텔레그램 사칭)
   - 도메인 예: `xn--c1avbb.org` (`пого.org`)
   - 식별 단서: 키릴 IDN, 모바일 클로킹, red.js 봇 게이트키퍼, postMessage origin 미검증

3. **중국 Easymall SaaS 그룹** (가짜 쇼핑몰 9,000+ 사이트)
   - 식별 단서: `api.btrbdf.com`, `resource5-cdn.ocolt.com`, `cdn3.hsrdkt.com`, `media.dpdvx.com`
   - 자체 트래킹에 `isEasymall: true`, `isCloak: "1"`, 中文 `timezoneOffset: "东9区"` 노출
   - Airwallex 결제 + Sardine.ai/Forter/Zendesk(`hanguo-service`)로 차지백 회피

새 분석에서 위 시그니처가 보이면 해당 그룹의 자매 사이트로 분류하고 [report/](file:///home/cozyu/git/anal_phishing_neo/report/) 아래 기존 보고서를 참조 인용한다.

## 자주 막히는 부분 / 우회

- **snap chromium이 `/tmp/` 못 읽음**: 사용자 홈 이하 경로 사용. `/home/cozyu/git/.../report/[도메인]/`로 HTML/이미지 모두 옮긴 뒤 빌드.
- **Streamlit 백그라운드 데몬 차단**: 분석 흐름과 무관하므로 보고서 빌드 시 띄울 필요 없음. PhishGuard 본체는 사용자가 직접 띄움.
- **VT/urlscan 신규 도메인 미탐지**: 신규 등록 + 클로킹 + 봇 차단의 합작이므로 0/35는 정상. 보고서에 "VT/urlscan 미탐지 = 0-day window" 명시.
- **응답이 `application/octet-stream`로 와서 바이너리로 보임**: `curl --compressed` 누락. 다시 받기.
- **Playwright 데스크탑 UA로 모바일 클로킹 우회 안 됨**: 뷰포트만 변경해선 부족. UA 정규식이 `/Mobile/`를 매치해야 하면 라이브 우회 어려움 → curl로 받은 정적 분석 + 자매 사이트 참고.

## 참고 (references/)

- [workflow.md](references/workflow.md) — 단계별 실행 명령 모음
- [data-collection.md](references/data-collection.md) — WHOIS·VT·urlscan·CT 일괄 조회 스니펫
- [report-template.html](references/report-template.html) — 보고서 HTML 시작 템플릿
- [crop_screenshots_template.py](references/crop_screenshots_template.py) — PIL 발췌 스크립트
- [js-checklist.md](references/js-checklist.md) — JS 행위 분석 체크리스트
- [pdf-build.md](references/pdf-build.md) — chromium 빌드 + 파일명 규칙
- [chapter-skeletons.md](references/chapter-skeletons.md) — 각 챕터의 HTML 빈 골격
