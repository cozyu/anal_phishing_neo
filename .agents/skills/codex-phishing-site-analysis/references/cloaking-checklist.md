# Cloaking 탐지 체크리스트

사기 사이트가 분석자/봇과 실사용자에게 다른 콘텐츠를 보여주는지 확인. 같은 URL을 **여러 조건으로** 요청해 응답 차이를 비교한다.

## 사전 준비

```bash
# 작업 변수 (workflow.md 1단계와 동일)
TARGET='https://example.com/path?ad_id=abc'
eval "$(python3 .agents/skills/codex-phishing-site-analysis/scripts/normalize_target.py "$TARGET" --shell)"
D=/home/cozyu/git/anal_phishing_neo/report/$REPORT_SLUG
mkdir -p "$D/cloak"
```

샘플 결과는 모두 `$D/cloak/`에 저장하고 매니페스트에 포함시킨다.

## 1. User-Agent 클로킹

```bash
declare -A UA=(
  [mobile_ios]="Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
  [mobile_android]="Mozilla/5.0 (Linux; Android 14; SM-S921N) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36"
  [desktop]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
  [googlebot]="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  [bingbot]="Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
  [curl]="curl/8.0.0"
  [python]="python-requests/2.31.0"
  [headless]="Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/124.0.0.0 Safari/537.36"
)

for k in "${!UA[@]}"; do
  curl -sk --compressed -A "${UA[$k]}" -o "$D/cloak/ua_${k}.html" -w "%{http_code} %{size_download}\n" "$URL/" \
    | awk -v k="$k" '{printf "  %-16s status=%s size=%s\n", k, $1, $2}'
done

# 차이 요약: 크기 + sha256
for f in "$D"/cloak/ua_*.html; do
  printf "  %-30s %10s bytes  sha256=%s\n" "$(basename "$f")" "$(wc -c < "$f")" "$(sha256sum "$f" | awk '{print substr($1,1,16)}')"
done
```

체크포인트:
- 봇 UA에 빈 페이지/302 리다이렉트/`noindex` HTML이 응답되면 cloaking 강한 신호
- 데스크탑에 정상적인 쇼핑몰, 모바일에만 사기 UI가 나타나면 모바일 타깃팅
- HeadlessChrome 응답이 모바일 UA와 다르면 분석 회피 시도

## 2. Referer 클로킹

광고/스미싱 referer를 가진 사용자에게만 활성화되는 사이트.

```bash
declare -A REF=(
  [direct]=""
  [google_search]="https://www.google.com/"
  [google_ad]="https://googleads.g.doubleclick.net/"
  [facebook_ad]="https://l.facebook.com/"
  [tiktok_ad]="https://www.tiktok.com/"
  [naver_search]="https://search.naver.com/"
  [kakao_chat]="https://kakao.com/"
)

UA_IPHONE="Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148"
for k in "${!REF[@]}"; do
  if [ -z "${REF[$k]}" ]; then
    curl -sk --compressed -A "$UA_IPHONE"                         -o "$D/cloak/ref_${k}.html" "$URL/"
  else
    curl -sk --compressed -A "$UA_IPHONE" -e "${REF[$k]}"          -o "$D/cloak/ref_${k}.html" "$URL/"
  fi
  printf "  %-16s %10s bytes\n" "$k" "$(wc -c < "$D/cloak/ref_${k}.html")"
done
```

## 3. Geo / Accept-Language 클로킹

```bash
declare -A LANG=(
  [ko_KR]="ko-KR,ko;q=0.9,en;q=0.7"
  [en_US]="en-US,en;q=0.9"
  [zh_CN]="zh-CN,zh;q=0.9,en;q=0.7"
  [ja_JP]="ja-JP,ja;q=0.9"
)
for k in "${!LANG[@]}"; do
  curl -sk --compressed -A "$UA_IPHONE" -H "Accept-Language: ${LANG[$k]}" -o "$D/cloak/lang_${k}.html" "$URL/"
  printf "  %-10s %10s bytes\n" "$k" "$(wc -c < "$D/cloak/lang_${k}.html")"
done
```

Geo IP 클로킹은 출구 IP 자체가 바뀌어야 정확히 잡힌다. 가능한 방법:
- 다른 인터넷 회선 / 모바일 데이터 / 회사 vs 집 회선에서 같은 URL 비교
- 합법적 보유 권한이 있는 다국적 VPN exit 사용 시 `--resolve` 또는 `socks5` 옵션
- urlscan.io의 다른 country 옵션으로 재스캔 (`country=us`, `country=de` 등)

## 4. 광고/세션 토큰 게이트

URL의 `?ad_id=`, `?utm_source=`, `?token=` 등을 떼어내고 같은 페이지를 받아본다.

```bash
BASE_URL="${URL%%\?*}"   # 쿼리 제거
curl -sk --compressed -A "$UA_IPHONE" -o "$D/cloak/noquery.html" "$BASE_URL/"
curl -sk --compressed -A "$UA_IPHONE" -o "$D/cloak/withquery.html" "$URL/"
diff -q "$D/cloak/noquery.html" "$D/cloak/withquery.html" || echo "→ 토큰 게이트 가능성"
```

체크포인트:
- 토큰 없으면 빈 페이지 / 다른 쇼핑몰 / 정상 SaaS 데모로 응답
- 토큰 있으면 사기 UI 활성화
- JS 측에서 `searchParams.get('ad_id')` 등으로 게이트 확인 ([js-checklist.md](js-checklist.md) B.5)

## 5. 시간 기반 게이트

분석은 KST 새벽에 하면 사이트가 비활성일 수 있다. 운영자 활동 시간대(주로 CST/UTC+8)와 다른 시각에 동일 요청을 반복.

```bash
date -u
curl -sk --compressed -A "$UA_IPHONE" -o "$D/cloak/time_$(date -u +%H%M).html" "$URL/"
wc -c "$D"/cloak/time_*.html
```

24시간 사이의 응답 크기 변화 + JS 활성 시점을 [data-collection.md](data-collection.md) "운영자 활동 시간대 환산표"로 매칭.

## 6. Headless / Webdriver 탐지 (Playwright 분석 직전)

[js-checklist.md](js-checklist.md) B.3·B.4 항목으로 정적 스캔한 뒤, Playwright 실행 시 다음 확인:

```javascript
// Playwright 콘솔에서 직접 평가
({
  webdriver: navigator.webdriver,
  chrome: !!window.chrome,
  permissions: navigator.permissions && (await navigator.permissions.query({name:'notifications'})).state,
  plugins: navigator.plugins.length,
  languages: navigator.languages,
  hardwareConcurrency: navigator.hardwareConcurrency,
  webgl_renderer: (() => { try { const c = document.createElement('canvas').getContext('webgl'); const d = c.getExtension('WEBGL_debug_renderer_info'); return c.getParameter(d.UNMASKED_RENDERER_WEBGL); } catch(e) { return null; } })(),
})
```

`webdriver=true`거나 plugins=0이면 사이트가 봇으로 판단하고 다른 응답을 줄 수 있음. 필요하면 `--disable-blink-features=AutomationControlled` + 페이지 진입 전 `Object.defineProperty(navigator,'webdriver',{get:()=>undefined})` 같은 우회를 **분석 목적에 한해** 사용. 우회 사용 사실은 보고서에 명시.

## 7. 비교 요약 표 (보고서 본문 임베드용)

```html
<h3>X.Y. Cloaking 응답 매트릭스</h3>
<table>
  <tr><th>요청 조건</th><th>HTTP</th><th>응답 크기</th><th>관찰 내용</th></tr>
  <tr><td>iPhone UA + 광고 referer</td><td>200</td><td>...</td><td>사기 UI 활성</td></tr>
  <tr><td>Desktop UA + direct</td><td>200</td><td>...</td><td>정상 쇼핑몰 (위장)</td></tr>
  <tr><td>Googlebot UA</td><td>200</td><td>0</td><td>빈 페이지 (cloaking 강함)</td></tr>
  <tr><td>광고 토큰 제거</td><td>302</td><td>—</td><td>다른 도메인으로 리다이렉트</td></tr>
</table>
```

## 산출물 정리

- `cloak/ua_*.html`, `cloak/ref_*.html`, `cloak/lang_*.html`, `cloak/noquery.html`, `cloak/withquery.html`
- `evidence_manifest.json`에 자동 포함 (`scripts/evidence_manifest.py`가 하위 디렉토리 스캔)
- 보고서 챕터 10 (콘텐츠 위장 패턴) 또는 챕터 9 (JS 행위 분석)의 안티-분석 섹션에서 인용
