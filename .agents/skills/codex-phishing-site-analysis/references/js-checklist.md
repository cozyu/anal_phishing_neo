# JavaScript 행위 분석 체크리스트

[reference_js_behavior_analysis.md](file:///home/cozyu/.claude/projects/-home-cozyu-git-anal-phishing-neo/memory/reference_js_behavior_analysis.md)의 작업용 압축본. 보고서 9장에 채워야 할 표 골격까지 포함.

## A. 정적 분석 (소스만으로)

`$JSFILE`에 분석 대상 JS를 지정하고 실행:

```bash
JSFILE=$D/checkout.CAIBvs6g.js

echo "=== A.1 외부 호스트 호출 ==="
grep -oE "https?://[a-z0-9.-]+\.[a-z]+" "$JSFILE" | sort -u

echo "=== A.2 API 엔드포인트 ==="
grep -oE "['\"]\/api\/v?[0-9]?\/[a-zA-Z_/-]{3,50}['\"]" "$JSFILE" | sort -u

echo "=== A.3 fetch / axios / XHR ==="
grep -oiE "(axios|fetch|XMLHttpRequest|sendBeacon)\s*\.?\(?\s*['\"][^'\"]{4,80}" "$JSFILE" | sort -u

echo "=== A.4 form 필드명 ==="
grep -oE "['\"](consigneeName|consigneePhone|consigneeAddress|consigneeEmail|cellphone|phone|email|address|cardNumber|cvc|cvv|expDate|password)['\"]" "$JSFILE" | sort | uniq -c

echo "=== A.5 postMessage (origin 검증 없는지 함께 확인) ==="
grep -oE "addEventListener\([\"']message[\"']" "$JSFILE" | head
grep -oE "postMessage\(" "$JSFILE" | wc -l

echo "=== A.6 localStorage / sessionStorage ==="
grep -oE "(localStorage|sessionStorage)\.(setItem|getItem|removeItem)" "$JSFILE" | sort | uniq -c

echo "=== A.7 클립보드 / 키 입력 후킹 ==="
grep -oE "(navigator\.clipboard|document\.execCommand\(['\"]copy)" "$JSFILE"
grep -oE "addEventListener\([\"'](keydown|keypress|input)" "$JSFILE"

echo "=== A.8 암호화 / 인코딩 ==="
grep -oiE "(CryptoJS|AES|HmacSHA|md5\(|sha1\(|btoa\(|atob\()" "$JSFILE" | sort | uniq -c

echo "=== A.9 외부 스크립트 동적 로드 ==="
grep -oE "document\.createElement\([\"']script[\"']" "$JSFILE" | wc -l

echo "=== A.10 결제 게이트웨이 / 사기방지 SaaS ==="
grep -oiE "(airwallex|stripe|paypal|toss|kakaopay|naverpay|sardine|forter|fingerprintjs|recaptcha)" "$JSFILE" | sort | uniq -c
```

## A-2. 번들·난독화 보강

grep 결과가 적거나 minified bundle인 경우 추가로 수행한다.

```bash
echo "=== sourcemap / bundler markers ==="
grep -oiE "(sourceMappingURL|webpackJsonp|__webpack_require__|vite|rollup|dynamic import|import\\()" "$JSFILE" | sort | uniq -c

echo "=== relative endpoints, not only /api ==="
grep -oE "['\"][./]?[a-zA-Z0-9_/-]{2,80}(api|order|pay|checkout|login|user|cart|statistics|track|pixel|beacon)[a-zA-Z0-9_/?=&.-]{0,120}['\"]" "$JSFILE" | sort -u | head -100

echo "=== encoded strings / unicode escapes ==="
grep -oE "(\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2})" "$JSFILE" | head -50

echo "=== dynamic import / lazy chunks ==="
grep -oE "import\\(['\"][^'\"]+['\"]\\)|['\"][^'\"]+\\.js['\"]" "$JSFILE" | sort -u | head -100
```

가능하면 pretty-print 후 재검색한다.

```bash
python - <<'PY'
from pathlib import Path
import re, sys
p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("$JSFILE")
text = p.read_text(errors="ignore")
text = re.sub(r"([{};])", r"\1\n", text)
(p.with_suffix(p.suffix + ".pretty.js")).write_text(text)
print(p.with_suffix(p.suffix + ".pretty.js"))
PY "$JSFILE"
```

`//# sourceMappingURL=`이 있으면 sourcemap URL도 받아 원본 파일명, API 경로, 모듈명을 확인한다. 단, sourcemap 다운로드도 라이브 대상 접속이므로 User-Agent와 수집 시각을 증거에 남긴다.

## B. 안티 분석 / 우회 기법

```bash
echo "=== B.1 User-Agent 클로킹 ==="
grep -oE "navigator\.userAgent\.(match|test|indexOf)" "$JSFILE" | head

echo "=== B.2 봇 차단 게이트키퍼 패턴 ==="
# red.js 같은 거대 봇 정규식 (수백 종 봇 UA를 / / .test()로 매칭)
grep -oE "Googlebot|bingbot|Slurp|Scrapy|HeadlessChrome|PhantomJS|wget|curl|python-requests|axios" "$JSFILE" | sort -u | head -20

echo "=== B.3 Headless 탐지 ==="
grep -oE "navigator\.webdriver|window\.chrome|Notification\.permission" "$JSFILE" | head

echo "=== B.4 Devtools 탐지 ==="
grep -oE "outerWidth.*innerWidth|debugger|Function\.prototype\.toString" "$JSFILE" | head

echo "=== B.5 URL 토큰 게이트 ==="
grep -oE "searchParams\.get\([\"'][a-z_]+[\"']\)" "$JSFILE" | sort -u

echo "=== B.6 난독화 신호 ==="
grep -oE "(eval\(|new Function\(|atob\(|String\.fromCharCode)" "$JSFILE" | sort | uniq -c
```

## C. 핑거프린팅 · 트래커

```bash
echo "=== C.1 navigator 핑거프린팅 ==="
grep -oE "navigator\.(userAgent|webdriver|platform|language|languages|product|hardwareConcurrency|deviceMemory|connection|cookieEnabled|onLine|maxTouchPoints)" "$JSFILE" | sort | uniq -c

echo "=== C.2 Canvas / WebGL ==="
grep -oE "(canvas\.toDataURL|WebGL[A-Za-z]+)" "$JSFILE" | head

echo "=== C.3 광고 픽셀 ==="
grep -oiE "(gtag\(|fbq\(|ttq\.|criteo|clarity\(|hj\()" "$JSFILE" | sort | uniq -c

echo "=== C.4 RUM / APM ==="
grep -oiE "(arms-retcode|aliyuncs|sentry|newrelic|datadog|honeycomb)" "$JSFILE" | sort | uniq -c
```

## D. 보고서 9장에 들어갈 행위 매트릭스 (HTML)

채워야 할 빈 골격 (보고서 9.3 챕터):

```html
<h3>9.3. 행위 매트릭스</h3>
<table>
  <tr><th>행위</th><th>모듈/위치</th><th>외부 호스트</th><th>데이터 종류</th><th>위험도</th></tr>
  <tr><td>주문/PII 송신</td><td>account.js (<code>/api/v1/order/create</code>)</td><td>$DOMAIN</td><td>이름·전화·주소·결제수단</td><td><span class="tag">매우 높음</span></td></tr>
  <tr><td>카드 정보 수집</td><td>Airwallex iframe</td><td>checkout.airwallex.com</td><td>PAN, CVV, expiry</td><td><span class="tag">매우 높음</span></td></tr>
  <tr><td>자체 통계 / 핑거프린팅</td><td>statistics.js</td><td>$DOMAIN/statistics/md.gif</td><td>navigator + 페이지 ID</td><td><span class="tag warn">중간</span></td></tr>
  <tr><td>광고 컨버전 픽셀</td><td>pixel*.js</td><td>google-analytics, tiktok, criteo</td><td>구매 이벤트</td><td><span class="tag warn">중간</span></td></tr>
  <tr><td>세션 리플레이</td><td>인라인</td><td>clarity.ms</td><td>클릭·스크롤</td><td><span class="tag warn">중간</span></td></tr>
  <tr><td>사기방지(역방향)</td><td>cart.js</td><td>api.sardine.ai, cdn0.forter.com</td><td>디바이스 핑거</td><td><span class="tag warn">중간</span></td></tr>
  <tr><td>봇 차단 게이트키퍼</td><td>red.js (예시)</td><td>(인라인)</td><td>—</td><td>안티 분석</td></tr>
  <tr><td>postMessage 세션 인젝션</td><td>index.html 인라인</td><td>(any origin)</td><td>localStorage 전체</td><td><span class="tag">매우 높음</span></td></tr>
</table>
```

## D-2. 모바일 2차 페이로드 (APK / 딥링크 / 스미싱)

한국 스미싱은 1차 페이지에서 **APK 다운로드 또는 메신저 외부 앱 인텐트**로 유도하는 경우가 흔하다.

```bash
echo "=== D-2.1 APK / 다운로드 ==="
grep -oE "href=\"[^\"]*\.apk(\?[^\"]*)?\"" "$D"/*.html 2>/dev/null
grep -oE "https?://[^\"' )<>]+\.apk(\?[^\"' )<>]*)?" "$D"/*.html "$D"/*.js 2>/dev/null
grep -oE "(googleusercontent\.com|firebaseio\.com|amazonaws\.com)[^\"' )]+\.apk" "$D"/*.html 2>/dev/null

echo "=== D-2.2 안드로이드 패키지 ID 단서 ==="
grep -oE "(com|kr|net)\.[a-z0-9_]{2,20}(\.[a-z0-9_]{2,20}){1,4}" "$D"/*.html "$D"/*.js 2>/dev/null \
  | grep -vE "(com\.google|com\.facebook|com\.apple|com\.microsoft|com\.adobe|kr\.co\.|net\.daum\.|com\.kakao\.)" \
  | sort -u | head -50

echo "=== D-2.3 외부 앱 인텐트 / 딥링크 ==="
grep -oE "intent://[^\"' ]+#Intent;[^\"' ]+" "$D"/*.html "$D"/*.js 2>/dev/null | head
grep -oE "(market|kakaotalk|nidlogin|kakaolink|line|whatsapp|tg|sms|tel|mailto)://[^\"' )]+" "$D"/*.html "$D"/*.js 2>/dev/null | sort -u | head

echo "=== D-2.4 카톡/문자 자동 발송 트리거 ==="
grep -oE "(Kakao\.Link|kakaoLink|navigator\.share|window\.location\s*=\s*['\"]sms:)" "$D"/*.html "$D"/*.js 2>/dev/null

echo "=== D-2.5 푸시/원격 제어 SDK ==="
grep -oiE "(firebase\.initializeApp|FCM_|onesignal|airbridge|adjust|appsflyer)" "$D"/*.html "$D"/*.js 2>/dev/null | sort | uniq -c

echo "=== D-2.6 모바일 권한 요청 (PWA 클로킹) ==="
grep -oE "navigator\.(geolocation|mediaDevices|permissions|wakeLock|bluetooth)" "$D"/*.js 2>/dev/null | sort | uniq -c
```

체크포인트:
- `.apk` 다운로드 → 즉시 hash 계산 + VT 업로드 (`POST /api/v3/files`). 분석가 디바이스에서 절대 설치하지 않는다.
- `intent://` URI는 안드로이드 chrome에서 외부 앱을 강제 실행. 보고서 본문에 풀 URI를 인용 (체이닝 단서).
- 카톡/SMS 인텐트가 사용자 친구로 사기 메시지를 전파하는 자기복제(self-propagation)에 쓰이는지 확인.

## E. 동적 분석 (Playwright)

라이브 사이트인 경우 `browser_network_requests(static=false, filename=...)`로 결제·로그인 흐름 중 발생한 모든 XHR·fetch를 캡처해 `$D/network-*.txt`에 저장. 그 안에서 `POST` 행만 추출해 송신 페이로드 분석.

```bash
grep -iE "POST " "$D/network-checkout.txt" | head -20
```
