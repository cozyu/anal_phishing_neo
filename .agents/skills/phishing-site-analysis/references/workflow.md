# 표준 분석 워크플로 — 단계별 실행 명령

각 단계는 `report/[도메인]/`을 작업 디렉토리로 사용한다. `$D`, `$URL` 변수를 우선 설정한다.

```bash
DOMAIN=krbysyhb.com           # ← 분석 대상으로 교체
URL=https://$DOMAIN
D=/home/cozyu/git/anal_phishing_neo/report/$DOMAIN
mkdir -p "$D"
source /home/cozyu/git/anal_phishing_neo/.venv/bin/activate
export $(grep -E '^(VT_API_KEY|URLSCAN_API_KEY|CRIMINALIP_KEY|GEMINI_API_KEY)' /home/cozyu/git/anal_phishing_neo/.env | xargs)
```

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

## 3. VirusTotal + urlscan.io

[data-collection.md](data-collection.md) 참조 (한 번에 돌리는 Python 블록).

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

[report-template.html](report-template.html)을 `report/[도메인]/report.html`로 복제. [chapter-skeletons.md](chapter-skeletons.md)에 각 챕터 빈 골격이 있으니 도메인 정보로 채운다.

## 12. PDF 빌드

[pdf-build.md](pdf-build.md) 참조.

## 13. 검증

```bash
python -c "
from pypdf import PdfReader
r = PdfReader('$D/_tmp_report.pdf')
print('pages:', len(r.pages))
print('p1[0:200]:', r.pages[0].extract_text()[:200])"
```

한글이 깨지지 않고 페이지 수가 합리적인지 확인. 깨지면 Noto CJK 폰트 시스템 설치 여부 확인 (`fc-list :lang=ko`).
