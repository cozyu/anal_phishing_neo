# 표준 분석 워크플로 — 단계별 실행 명령

각 단계는 `report/[report_slug]/`을 작업 디렉토리로 사용한다. 먼저 대상 URL을 정규화하고 `$DOMAIN`, `$URL`, `$REPORT_SLUG`, `$D`를 설정한다.

```bash
TARGET='https://example.com/path?keep=full-query'
eval "$(python3 .agents/skills/codex-phishing-site-analysis/scripts/normalize_target.py "$TARGET" --shell)"
D=/home/cozyu/git/anal_phishing_neo/report/$REPORT_SLUG
mkdir -p "$D"
source /home/cozyu/git/anal_phishing_neo/.venv/bin/activate
```

API 키가 필요한 단계에서만 `.env`를 로드한다. 값에 공백/특수문자가 있을 수 있으므로 `export $(grep ... | xargs)`를 기본값으로 쓰지 않는다.

```bash
set -a
. /home/cozyu/git/anal_phishing_neo/.env
set +a
```

## 0. 안전한 분석 환경

라이브 사이트는 hostile target으로 취급한다.

- 개인 브라우저 세션, 저장된 쿠키, 실제 계정, 실제 PII, 실제 결제정보를 사용하지 않는다.
- Playwright는 새 context/profile로 열고, 카메라/마이크/위치/알림/클립보드 권한을 허용하지 않는다.
- 다운로드가 필요한 경우를 제외하고 자동 다운로드를 피한다. 다운로드 파일은 실행하지 않는다.
- 폼은 구조 관찰과 캡처까지만 진행한다. 최종 제출/결제/인증 요청 직전 중단한다.
- 더미값 입력이 불가피하면 캡처 전 삭제하거나 마스킹하고, 송신 요청을 발생시키지 않는다.
- 관찰에 사용한 User-Agent, viewport, URL, 수집 시각을 증거 매니페스트나 보고서에 남긴다.

## 1. WHOIS

```bash
python -c "import whois; print(whois.whois('$DOMAIN'))"
```

확인할 필드: `creation_date`, `updated_date` (list 가능), `expiration_date`, `registrar`, `name_servers`, `country/state`, `name/org` (PRIVACY REDACTED 여부).

## 2. DNS / HTTP (모바일·데스크탑 UA 모두)

```bash
# DNS
for h in $DOMAIN www.$DOMAIN; do echo "--- $h ---"; getent hosts "$h"; done

# 모바일 응답
curl -sIL -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148" "$URL/" | head -30
# 데스크탑 응답
curl -sIL -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36" "$URL/" | head -30

# HTML 다운로드 (압축 해제 필수)
curl -sk --compressed -A "Mozilla/5.0 (iPhone) Mobile/15E148" "$URL/" -o "$D/mobile.html"
curl -sk --compressed -A "Mozilla/5.0 (Windows NT 10.0) Chrome/124"   "$URL/" -o "$D/desktop.html"
cmp -s "$D/mobile.html" "$D/desktop.html" && echo IDENTICAL || echo DIFFERENT
```

## 3. VirusTotal + urlscan.io + 보조 인텔

[data-collection.md](data-collection.md)의 "외부 위협 인텔리전스 일괄 조회"와 "보조 위협 인텔리전스 (무료 소스)" 블록을 차례로 실행. URLhaus·PhishTank는 키 없이 동작하며 OTX·Safe Browsing은 `.env`에 키가 있으면 자동 활성화된다.

## 3-2. Wayback / archive.org 패시브 룩업

도메인 생애주기 확인. [data-collection.md](data-collection.md) "Wayback Machine / archive.org 패시브 룩업" 블록 실행. 캡처가 0건이면 cold pool / 신규 등록, 과거 캡처가 전혀 다른 콘텐츠면 도메인 재활용.

## 4. Certificate Transparency

```bash
curl -s "https://crt.sh/?q=$DOMAIN&output=json" -m 15 | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'Total certificates: {len(data)}')
seen=set()
for r in sorted(data, key=lambda x: x.get('entry_timestamp','')):
    if r.get('id') in seen: continue
    seen.add(r['id'])
    print(f\"  {r.get('entry_timestamp','')}\\n     issuer={r.get('issuer_name','')[:50]}\\n     not_before={r.get('not_before')} not_after={r.get('not_after')}\\n     name_value={r.get('name_value','')[:80]}\")"
```

## 5. 자매 도메인 (공유 인프라 역검색)

```bash
python - <<'PY'
import os, requests
us = os.environ["URLSCAN_API_KEY"]
# HTML/JS에서 추출한 외부 호스트 목록을 INFRA에 채워라
INFRA = ['api.btrbdf.com','resource5-cdn.ocolt.com','cdn3.hsrdkt.com','media.dpdvx.com']
for q in INFRA:
    r = requests.get("https://urlscan.io/api/v1/search/", params={"q": f'domain:{q}', "size": 30}, headers={"API-Key": us}, timeout=20)
    j = r.json()
    print(f"\n=== domain:{q} total={j.get('total')} ===")
    seen = set()
    for res in j.get("results", [])[:15]:
        p = res.get("page",{}); t = res.get("task",{})
        d = p.get("domain","")
        if d in seen: continue
        seen.add(d)
        print(f"  {t.get('time')} | {d} | {p.get('title','')!r}")
PY
```

## 6. 자매 도메인 WHOIS·인증서 일괄

```bash
python - <<'PY'
import whois
DOMAINS = ['ocolt.com','dvpwjkl.com','vfdasd.com','btrbdf.com']  # ← 채워 넣기
for d in DOMAINS:
    try:
        w = whois.whois(d)
        cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        print(f"  {d:24s} created={cd}  registrar={w.registrar}")
    except Exception as e:
        print(f"  {d:24s} ERR {e}")
PY
```

## 7. 외부 호스트 / 스크립트 / API 엔드포인트 추출

```bash
echo "=== external hosts ==="
grep -oE "https?://[a-z0-9.-]+\.(com|net|org|io|ai|cn|me|ms|top|shop)" "$D/mobile.html" | sort -u

echo "=== scripts ==="
grep -oE '<script[^>]*src="[^"]+"' "$D/mobile.html" | head -30

echo "=== meta og ==="
grep -oE '<meta property="og:[^"]+" content="[^"]+"' "$D/mobile.html"

echo "=== inline JS endpoints ==="
grep -oE "(fetch|axios|XMLHttpRequest|sendBeacon)\s*\.?\(?\s*['\"][^'\"]{2,80}" "$D/mobile.html" | head -20
```

## 8. JS 번들 다운로드

```bash
# mobile.html에서 발견한 모든 .js URL을 받는다. 예시:
for u in \
  "https://cdn3.hsrdkt.com/assets/checkout.CAIBvs6g.js" \
  "https://cdn3.hsrdkt.com/assets/js/account.2ca9b7a535b0.js" \
  "https://cdn3.hsrdkt.com/assets/js/cart.2ca9b7a535b0.js" \
  "https://api.btrbdf.com/shopapi/one-cookie.js"; do
  fn=$(basename "$u")
  curl -sk --compressed -A "iPhone" "$u" -o "$D/$fn"
  printf "  %-50s %s bytes\n" "$fn" "$(wc -c < "$D/$fn")"
done
```

## 7-2. 단계별 동적 엔드포인트 헌팅

정적 HTML이 비어 보이거나 모든 버튼이 `javascript:void(null);`이면 **반드시** [dynamic-endpoints.md](dynamic-endpoints.md)의 절차를 실행한다. 사기 사이트는 흔히 `Case1.php → Case2.php → Case3.php`처럼 시리즈 페이지로 데이터 캡처 흐름을 펼친다 — 메인 페이지에는 노출되지 않으며 직접 URL 프로브로만 발견된다.

```bash
# 빠른 시작: 시리즈 경로 일괄 프로브
for P in Case1.php Case2.php Case3.php step1.php step2.php login.php do_login.php submit.php api.php api/login.php save.php verify.php result.php; do
  s=$(curl -sk -A "Mozilla/5.0 (iPhone) Mobile/15E148" -o /dev/null -w "%{http_code} %{size_download}b" "$URL/$P" -m 8)
  echo "$s" | grep -qE "^(404|403)" || printf "  %-25s %s\n" "$P" "$s"
done
```

발견된 경로는 다운로드해 폼 `action` 체인을 추적하고, 더미 데이터로 POST 시뮬레이션 후 GET 대비 sha256·size 차이를 비교한다(상세 절차는 dynamic-endpoints.md).

## 8-2. Cloaking 응답 매트릭스

여러 UA / referer / 토큰 조건으로 같은 URL을 요청해 응답 차이를 비교한다. [cloaking-checklist.md](cloaking-checklist.md)의 1~7단계 실행. 산출물은 `$D/cloak/`에 저장되며 evidence_manifest가 자동 수집한다.

## 8-3. IDN 호모그래프 검사 (도메인이 IDN이거나 한글-라틴 혼합 의심 시)

```bash
python3 .agents/skills/codex-phishing-site-analysis/scripts/idn_homograph.py "$DOMAIN"
# 보고서 챕터 10.2에 임베드할 HTML 출력
python3 .agents/skills/codex-phishing-site-analysis/scripts/idn_homograph.py "$DOMAIN" --html
```

## 9. Playwright 라이브 캡처 (결제·로그인 흐름)

mcp__playwright__* 도구로:

1. `browser_resize(390, 844)` — iPhone 13 mini 뷰포트
2. `browser_navigate(URL)` — 메인 진입
3. `browser_take_screenshot(filename=..., fullPage=true)` — 풀 페이지
4. `browser_snapshot()` — DOM 트리, ref 확보
5. `browser_click(target=...)` — "바로 구매하기", "로그인" 등 진입
6. `browser_network_requests(static=false, filename=...)` — 네트워크 트레이스 저장

⚠️ **실제 PII는 절대 입력하지 않는다.** 입력 폼 구조만 캡처하고 송신 직전에 중단.

## 10. 스크린샷 발췌

[crop_screenshots_template.py](crop_screenshots_template.py) 복제해서 사용. 풀 페이지 png에서 사기 식별 요소 영역만 잘라낸다.

## 11. 보고서 작성

[report-template.html](report-template.html)을 `report/[도메인]/report.html`로 복제. [chapter-skeletons.md](chapter-skeletons.md)에 챕터 1~15 + 부록A의 빈 골격이 있으니 도메인 정보로 채운다.

## 11-2. 보고서 완전성 사전 검증 (PDF 빌드 전)

```bash
python3 .agents/skills/codex-phishing-site-analysis/scripts/check_report.py "$D/report.html"
```

체크 항목: 챕터 1~15 + 부록 A 존재, 템플릿 플레이스홀더(`__DOMAIN__` 등) 잔존 여부, verdict 블록, 참조된 모든 `<img>`의 로컬 파일 존재. 에러가 있으면 PDF 빌드 전에 보강한다.

## 12. PDF 빌드

[pdf-build.md](pdf-build.md) 참조.

## 13. 검증

```bash
python3 - <<PY
from pypdf import PdfReader
import glob, os
pdfs = sorted(glob.glob("$D/${REPORT_SLUG}_*.pdf"), key=os.path.getmtime)
assert pdfs, "final PDF not found"
r = PdfReader(pdfs[-1])
print("pages:", len(r.pages))
print("p1[0:200]:", r.pages[0].extract_text()[:200])
PY
```

한글이 깨지지 않고 페이지 수가 합리적인지 확인. 깨지면 Noto CJK 폰트 시스템 설치 여부 확인 (`fc-list :lang=ko`).

## 14. 증거 매니페스트

주요 산출물 수집 후, 그리고 최종 PDF 생성 후 다시 실행한다.

```bash
python3 .agents/skills/codex-phishing-site-analysis/scripts/evidence_manifest.py \
  "$D" \
  --target-url "$URL" \
  --domain "$DOMAIN" \
  --notes "mobile+desktop UA, passive intel, Playwright screenshots if available"
```

`evidence_manifest.json`에는 파일 경로, 크기, mtime, sha256, 생성 시각, 기본 환경 정보가 들어간다. 보고서의 "분석 산출물" 챕터에서 이 파일을 언급한다.
