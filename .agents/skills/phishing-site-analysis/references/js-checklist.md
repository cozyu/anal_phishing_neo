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

## E. 동적 분석 (Playwright)

라이브 사이트인 경우 `browser_network_requests(static=false, filename=...)`로 결제·로그인 흐름 중 발생한 모든 XHR·fetch를 캡처해 `$D/network-*.txt`에 저장. 그 안에서 `POST` 행만 추출해 송신 페이로드 분석.

```bash
grep -iE "POST " "$D/network-checkout.txt" | head -20
```
