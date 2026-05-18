# 보고서 챕터 빈 골격 (HTML)

[report-template.html](report-template.html)의 헤더·verdict·결론을 채운 뒤, 아래 챕터들을 그대로 복사해 도메인 정보로 교체한다. 모든 챕터는 `<h2>n. ...</h2>` 형식.

---

## 1. 사기 패턴 발췌 (모바일 라이브 캡처)

```html
<h2>1. 사기 패턴 발췌 (모바일 라이브 캡처)</h2>
<p>전체 페이지는 매우 길어 본문에는 사기 식별에 중요한 부분만 발췌하고, 풀 페이지 캡처는 <strong>부록 A</strong>에 별도 수록합니다.</p>

<figure class="crop">
  <img src="crop-main-header.png" alt="메인 페이지 상단">
  <figcaption>[발췌 1] ... 미끼 배너 설명</figcaption>
</figure>

<figure class="crop">
  <img src="crop-detail-title.png" alt="상품 디테일">
  <figcaption>[발췌 2] ... 가짜 사회적 증명 + 묶음 결제 유도</figcaption>
</figure>
```

## 2. 핵심 요약

```html
<h2>2. 핵심 요약</h2>
<table>
  <tr><th style="width:25%">항목</th><th>내용</th></tr>
  <tr><td>위장 업종</td><td>...</td></tr>
  <tr><td>대표 상품/사칭 대상</td><td>...</td></tr>
  <tr><td>도메인 등록일</td><td>YYYY-MM-DD (운영 X개월)</td></tr>
  <tr><td>등록기관</td><td>...</td></tr>
  <tr><td>등록자 국가</td><td>...</td></tr>
  <tr><td>네임서버</td><td>...</td></tr>
  <tr><td>호스팅 CDN</td><td>...</td></tr>
  <tr><td>유입 채널</td><td>...</td></tr>
  <tr><td>VirusTotal</td><td>X/Y 탐지</td></tr>
  <tr><td>urlscan.io 이력</td><td>N건</td></tr>
</table>
```

## 3. 공유 인프라 (있는 경우)

```html
<h2>3. 공유 인프라 = 동일 운영자의 네트워크</h2>
<table>
  <tr><th>공유 인프라 호스트</th><th>역할</th><th>urlscan 등록 사이트 수</th></tr>
  <tr><td><code>api.example.com</code></td><td>...</td><td>...</td></tr>
</table>
<div class="callout danger">자매 사이트 클러스터 요약</div>

<h3>3.1. 자매 사이트 예시</h3>
<ul>
  <li><code>...</code> &mdash; "..."</li>
</ul>

<h3>3.2. 동일 운영자 판단 신뢰도</h3>
<table>
  <tr><th>신뢰도</th><th>근거</th><th>해석</th></tr>
  <tr><td><span class="tag">높음</span></td><td>동일 백엔드 + 동일 shop/user 식별자 + 동일 결제/추적 픽셀 + 근접 등록 시각</td><td>동일 운영자 또는 동일 운영 패널 가능성이 큼</td></tr>
  <tr><td><span class="tag warn">중간</span></td><td>동일 SaaS/CDN + 유사 템플릿 + 일부 공유 픽셀</td><td>같은 범죄형 SaaS 생태계일 수 있으나 운영자 단정은 보류</td></tr>
  <tr><td>낮음</td><td>공유 CDN/호스팅만 일치</td><td>클러스터 단서로만 사용</td></tr>
</table>
```

## 4. 공격자 활동 타임라인

```html
<h2>4. 공격자 활동 타임라인</h2>
<p>WHOIS, Certificate Transparency(crt.sh), urlscan.io, HTTP 응답 헤더 등을 종합 (시각 모두 UTC).</p>
<div class="timeline">
  <div class="row"><span class="date">YYYY-MM-DD HH:MM:SS</span>도메인 등록</div>
  <div class="interval">↓ 인터벌 X일 — 해설</div>
  <div class="row"><span class="date">YYYY-MM-DD HH:MM:SS</span>TLS 인증서 발급</div>
  <div class="row"><span class="date">YYYY-MM-DD HH:MM:SS</span>urlscan 첫 캡처 (광고 활성?)</div>
  <div class="row"><span class="date">YYYY-MM-DD HH:MM:SS</span>현재 분석 시점</div>
</div>

<h3>4.1. 자매 인프라 일괄 등록 패턴 (자동화 OPSEC)</h3>
<table>
  <tr><th>등록 시각 (UTC)</th><th>도메인</th><th>역할</th><th>등록기관</th></tr>
  <!-- 1초~5분 인터벌의 일괄 등록 그룹을 한 행으로 묶기 -->
</table>

<h3>4.2. 운영자 활동 시간대 분석 (OPSEC 단서)</h3>
<table>
  <tr><th>이벤트</th><th>UTC</th><th>KST (UTC+9)</th><th>추정 운영자 현지</th></tr>
</table>

<h3>4.3. 인프라 라이프사이클 (만료 예측)</h3>
<table>
  <tr><th>자원</th><th>시작</th><th>만료</th><th>잔여 / 상태</th></tr>
</table>

<h3>4.4. MITRE ATT&amp;CK 매핑</h3>
<table>
  <tr><th>Tactic</th><th>Technique</th><th>관찰 증거</th></tr>
  <tr><td>Resource Development</td><td><code>T1583.001</code> Acquire Infrastructure: Domains</td><td>...</td></tr>
  <tr><td>Resource Development</td><td><code>T1588.004</code> Obtain Capabilities: Digital Certificates</td><td>...</td></tr>
  <tr><td>Resource Development</td><td><code>T1583.008</code> Malvertising</td><td>...</td></tr>
  <tr><td>Initial Access</td><td><code>T1566.002</code> Phishing: Spearphishing Link (광고 변형)</td><td>...</td></tr>
  <tr><td>Defense Evasion</td><td><code>T1102</code> Web Service (정상 SaaS 악용)</td><td>...</td></tr>
  <tr><td>Defense Evasion</td><td><code>T1027</code> Obfuscated/Compressed Content</td><td>...</td></tr>
  <tr><td>Defense Evasion (사기 캠페인)</td><td><strong>Cold Pool / Dormant Domain</strong></td><td>...</td></tr>
</table>

<h3>4.5. 핵심 인사이트 요약</h3>
<ul>
  <li><strong>자동화 수준</strong>: ...</li>
  <li><strong>운영자 국가 단서</strong>: ...</li>
  <li><strong>다음 모니터링 포인트</strong>: 인증서 만료 시점 ...</li>
</ul>
```

## 5. 운영자 식별 신호 (caveated)

```html
<h2>5. 운영자 식별 신호</h2>
<p>아래 신호들은 단일로는 동일 운영자를 단정할 수 없으며, <strong>둘 이상이 동시에 일치할 때만</strong> 중간 이상의 신뢰도를 부여한다.</p>

<h3>5.1. 인프라 신호</h3>
<table>
  <tr><th>신호</th><th>관찰값</th><th>판단 가중치</th></tr>
  <tr><td>공유 백엔드 API 호스트</td><td><code>...</code></td><td>높음</td></tr>
  <tr><td>공유 CDN/origin IP</td><td>...</td><td>중간</td></tr>
  <tr><td>네임서버 그룹</td><td>...</td><td>중간</td></tr>
  <tr><td>registrar + WHOIS 등록국가</td><td>...</td><td>낮음 (대량 SaaS)</td></tr>
</table>

<h3>5.2. 코드 신호</h3>
<table>
  <tr><th>신호</th><th>관찰값</th><th>판단 가중치</th></tr>
  <tr><td>shopId / userId / marketId 등 SaaS 식별자</td><td>...</td><td>높음</td></tr>
  <tr><td>동일 광고/추적 픽셀 ID</td><td>GA: ..., TikTok: ..., FB: ...</td><td>높음</td></tr>
  <tr><td>JS 번들 sha256 (난독화 시드 동일)</td><td>...</td><td>매우 높음</td></tr>
  <tr><td>API 응답 헤더 시그니처</td><td><code>Server</code>, <code>X-Powered-By</code></td><td>중간</td></tr>
</table>

<h3>5.3. 행동 신호</h3>
<table>
  <tr><th>신호</th><th>관찰값</th><th>판단 가중치</th></tr>
  <tr><td>도메인 일괄 등록 시각 (수 초~수 분 간격)</td><td>...</td><td>높음</td></tr>
  <tr><td>인증서 발급 시각 패턴</td><td>...</td><td>중간</td></tr>
  <tr><td>운영자 활동 시간대 (KST/CST 정합)</td><td>...</td><td>낮음 (보조)</td></tr>
</table>

<div class="callout">
  <strong>주의:</strong> "동일 운영자"가 아닌 "동일 SaaS 패널을 사용하는 별개 운영자"일 가능성도 항상 명시한다.
</div>
```

## 6. 사이트/시스템 식별자

```html
<h2>6. 사이트/시스템 식별자</h2>
<p>HTML/JS/네트워크 트레이스에서 추출한 SaaS 백엔드 식별자. 자매 사이트 클러스터링과 신고/차단 대응의 핵심 키.</p>

<table>
  <tr><th>식별자 종류</th><th>위치</th><th>값</th><th>의미</th></tr>
  <tr><td><code>shopId</code></td><td>inline script / API 응답</td><td>...</td><td>SaaS 어드민의 가게 ID</td></tr>
  <tr><td><code>userId</code> / <code>merchantId</code></td><td>API 헤더/payload</td><td>...</td><td>운영 계정 ID</td></tr>
  <tr><td><code>marketId</code> / <code>regionId</code></td><td>cookie / URL</td><td>...</td><td>타겟 지역 라벨 (KR=...)</td></tr>
  <tr><td><code>templateId</code> / <code>themeId</code></td><td>CSS / inline</td><td>...</td><td>가게 템플릿 (동일 템플릿이면 자매 가능성)</td></tr>
  <tr><td>광고 추적 ID</td><td>URL <code>?ad_id=</code></td><td>...</td><td>광고 캠페인 식별 (게이트 토큰 역할 종종)</td></tr>
  <tr><td>세션/주문 ID 규칙</td><td>API 응답</td><td>예: <code>ORD-CN-YYYYMMDD-...</code></td><td>운영자 국가 단서</td></tr>
</table>

<h3>6.1. 식별자 추출 출처 (Evidence)</h3>
<pre>
file: mobile.html  line: ...  snippet: window.__SHOP__ = {shopId: "...", ...}
file: account.js   line: ...  snippet: const MARKET_ID = "kr_001";
network: POST /api/v1/order  request body: {"merchantId": "...", ...}
</pre>
```

## 7. 광고/추적 픽셀

```html
<h2>7. 광고/추적 픽셀</h2>
<p>유입 채널과 동일 운영자 클러스터링에 중요. 픽셀 ID 자체가 운영자/광고주 식별자다.</p>

<table>
  <tr><th>플랫폼</th><th>탐지 방법</th><th>관찰된 ID</th><th>비고</th></tr>
  <tr><td>Google Ads / GA4</td><td><code>gtag('config', 'G-...'|'AW-...')</code></td><td>...</td><td>전환 추적</td></tr>
  <tr><td>Facebook / Meta Pixel</td><td><code>fbq('init', '...')</code></td><td>...</td><td>리타게팅</td></tr>
  <tr><td>TikTok Pixel</td><td><code>ttq.load('...')</code></td><td>...</td><td>젊은층 광고</td></tr>
  <tr><td>Criteo</td><td><code>gum.criteo.com/...</code></td><td>account=...</td><td>제휴 광고</td></tr>
  <tr><td>Microsoft Clarity</td><td><code>clarity("set", ...)</code> 또는 <code>clarity.ms/tag/...</code></td><td>...</td><td>세션 리플레이</td></tr>
  <tr><td>Hotjar / 기타</td><td><code>hj(</code> / <code>_hjSettings</code></td><td>...</td><td>UX 추적</td></tr>
  <tr><td>네이버/카카오</td><td><code>wcs_do</code> / <code>kakaoPixel</code></td><td>...</td><td>한국 광고 채널 확인</td></tr>
</table>

<h3>7.1. 픽셀 신고 채널</h3>
<ul>
  <li>Google: <code>safebrowsing@google.com</code> / Google Ads 정책 위반 신고</li>
  <li>Meta: Business Help Center &rarr; Report ad / fraud</li>
  <li>TikTok Ads: 광고 위반 신고</li>
  <li>Criteo: <code>abuse@criteo.com</code></li>
</ul>
```

## 8. 개인정보·금융정보 수집 분석 (라이브 사이트만)

```html
<h2>8. 개인정보·금융정보 수집 분석 (체크아웃 흐름)</h2>

<h3>8.1. 수취인 정보 입력란 <span class="tag">개인정보</span></h3>
<figure class="crop">
  <img src="crop-checkout-recipient.png">
  <figcaption>[발췌 N] ...</figcaption>
</figure>
<table>
  <tr><th>필드</th><th>placeholder/예시</th><th>수집 데이터</th></tr>
</table>

<h3>8.2. 결제수단 선택 <span class="tag">금융정보</span></h3>
<figure class="crop">
  <img src="crop-checkout-payment.png">
  <figcaption>[발췌 N] ...</figcaption>
</figure>

<h3>8.3. 카드/계좌 입력 폼 <span class="tag">금융정보</span></h3>
<figure class="crop">
  <img src="crop-checkout-card-antibot.png">
  <figcaption>[발췌 N] 카드번호 / 유효기간 / CVC + 안티봇 캡차</figcaption>
</figure>
<div class="callout danger">중요 단서 (예: 농협 카드 배제, 중국어 콤마, 거짓 약속 등)</div>

<h3>8.4. 데이터 송신 엔드포인트 (관찰됨)</h3>
<table>
  <tr><th>엔드포인트</th><th>역할</th><th>송신 데이터 종류</th></tr>
</table>
```

## 9. JavaScript 행위 분석

```html
<h2>9. JavaScript 행위 분석 (악성 행위 추론)</h2>

<h3>9.1. 로드되는 주요 JS 모듈</h3>
<table>
  <tr><th>모듈</th><th>역할</th></tr>
</table>

<h3>9.2. 자체 통계 추적 페이로드 (Full JSON)</h3>
<pre>{
  ...풀 JSON 페이로드 (URL 인코딩 해제)...
}</pre>

<h3>9.3. 행위 매트릭스</h3>
<!-- js-checklist.md의 표 골격 사용 -->

<h3>9.4. 핵심 인사이트</h3>
<ul>
</ul>
```

## 10. 콘텐츠 위장 패턴

```html
<h2>10. 콘텐츠 위장 패턴</h2>

<h3>10.1. 도메인/브랜드 위장</h3>
<table>
  <tr><th>위장 기법</th><th>관찰 사례</th><th>탐지 단서</th></tr>
  <tr><td>타이포스쿼팅</td><td><code>nav3r.com</code> vs <code>naver.com</code></td><td>Levenshtein ≤ 2</td></tr>
  <tr><td>IDN 호모그래프</td><td>키릴 <code>а</code> / 그리스 <code>ο</code> 혼용</td><td>Punycode 변환 시 <code>xn--</code> 등장</td></tr>
  <tr><td>서브도메인 사칭</td><td><code>naver.com.evil.io</code></td><td>실제 ETLD+1은 <code>evil.io</code></td></tr>
  <tr><td>경로 사칭</td><td><code>evil.com/naver/login</code></td><td>호스트는 정상 브랜드와 무관</td></tr>
  <tr><td>유사 로고/CI</td><td>...</td><td>이미지 hash 매칭</td></tr>
</table>

<h3>10.2. 문자 코드포인트 분석</h3>
<div class="charbox">
도메인: <span class="cyrillic">а</span>pple.com (U+0430 키릴 a + ascii pple.com)
&rarr; Punycode: xn--pple-43d.com
</div>
<p>도메인의 각 문자를 Unicode 블록 단위로 분해해 ASCII 외 코드포인트를 강조한다. <code>scripts/idn_homograph.py</code> 출력 임베드.</p>

<h3>10.3. 가짜 사회적 증명</h3>
<ul>
  <li>실시간 구매 알림 토스트 ("3분 전 김** 구매") — 클라이언트 사이드 랜덤 생성 여부 확인</li>
  <li>리뷰 수/별점 — 백엔드에서 받지 않고 하드코딩</li>
  <li>잔여 수량 카운트다운 — JS 타이머만 사용</li>
  <li>"인증마크" 이미지 — 클릭 불가, 실제 인증기관 도메인 미연결</li>
</ul>

<h3>10.4. 결제/약관 거짓 안내</h3>
<ul>
  <li>"100% 환불 보장" 문구 + 실제 환불 경로 없음</li>
  <li>"무료 배송" + 강제 배송비 추가 단계</li>
  <li>특정 카드사 배제 (예: 농협 카드 결제 불가) — 차지백 회피 의도</li>
  <li>약관/개인정보처리방침 페이지가 lorem ipsum 또는 다른 브랜드 텍스트 복붙</li>
</ul>

<h3>10.5. 한국어 자연스러움 검사</h3>
<table>
  <tr><th>의심 신호</th><th>예시</th></tr>
  <tr><td>중국어 콤마 <code>，</code> / 마침표 <code>。</code></td><td>...</td></tr>
  <tr><td>일본식 띄어쓰기 / 가타카나 잔재</td><td>...</td></tr>
  <tr><td>기계 번역 어색한 어순</td><td>...</td></tr>
  <tr><td>혼합 폰트 (한자/간체)</td><td>...</td></tr>
</table>
```

## 11. 추정 공격 시나리오

```html
<h2>11. 추정 공격 시나리오</h2>
<ol>
  <li>운영자가 SaaS 어드민에서 신규 사이트 발급 ...</li>
  <li>광고/스미싱으로 한국 사용자 유입 ...</li>
  <li>피해자가 모바일에서 클릭 → 한국어 UI 노출</li>
  <li>PII / 결제 정보 입력 → 운영자 백엔드로 송신</li>
  <li>결과: 미배송 / 짝퉁 / 카드 도용 / 세션 탈취 ...</li>
  <li>차단 시 SaaS에서 새 도메인 발급해 회전</li>
</ol>
```

## 12. 인프라 IOC

```html
<h2>12. 인프라 IOC</h2>
<table>
  <tr><th>유형</th><th>값</th></tr>
  <tr><td>대상 도메인</td><td><code>...</code></td></tr>
  <tr><td>관찰된 진입 URL (Full)</td><td><pre>...풀 URL...</pre></td></tr>
  <tr><td>오리진 IP</td><td>...</td></tr>
  <tr><td>공유 백엔드 / CDN</td><td>...</td></tr>
  <tr><td>광고 픽셀 ID</td><td>Google ... · TikTok ... · Criteo ... · MS Clarity ...</td></tr>
  <tr><td>SaaS 식별자</td><td>shopId=..., userId=..., marketId=...</td></tr>
  <tr><td>관찰된 광고 ID</td><td>ad_id=..., campaign_id=..., gclid=...</td></tr>
</table>
```

## 13. 위험성 평가

```html
<h2>13. 위험성 평가</h2>

<h3>13.1. 스코어링 (가중 합산)</h3>
<table>
  <tr><th>지표</th><th>관찰값</th><th>가중치</th><th>점수</th></tr>
  <tr><td>PII 수집 (이름·전화·주소)</td><td>예/아니오</td><td>2</td><td>0~2</td></tr>
  <tr><td>금융정보 수집 (카드번호·CVC)</td><td>예/아니오</td><td>3</td><td>0~3</td></tr>
  <tr><td>자격증명 수집 (계정 ID/PW)</td><td>예/아니오</td><td>3</td><td>0~3</td></tr>
  <tr><td>도메인 운영기간 &lt; 90일</td><td>일수</td><td>2</td><td>0~2</td></tr>
  <tr><td>VT 악성 탐지 ≥ 3 vendor</td><td>탐지 수</td><td>2</td><td>0~2</td></tr>
  <tr><td>자매 도메인 ≥ 3개 (공유 인프라)</td><td>개수</td><td>2</td><td>0~2</td></tr>
  <tr><td>안티-분석/봇 차단 코드 존재</td><td>예/아니오</td><td>1</td><td>0~1</td></tr>
  <tr><td>광고 유입 (유료 광고 referer)</td><td>예/아니오</td><td>1</td><td>0~1</td></tr>
  <tr><td><strong>합계</strong></td><td></td><td>최대 16</td><td><strong>X / 16</strong></td></tr>
</table>

<h3>13.2. 등급 환산</h3>
<table>
  <tr><th>점수</th><th>등급</th><th>설명</th></tr>
  <tr><td>13–16</td><td><span class="tag">매우 높음</span></td><td>능동 사기 운영 + 광범위 피해 우려, 즉시 차단·신고 대상</td></tr>
  <tr><td>9–12</td><td><span class="tag warn">높음</span></td><td>적극 사기 의심, 모니터링 + 차단 권고</td></tr>
  <tr><td>5–8</td><td><span class="tag warn">중간</span></td><td>사기 가능성, 추가 증거 수집 필요</td></tr>
  <tr><td>0–4</td><td><span class="tag ok">낮음</span></td><td>의심 단서 부족, 클러스터 관찰 대상</td></tr>
</table>

<h3>13.3. 피해 시나리오</h3>
<ul>
  <li><strong>금전 피해</strong>: 결제 후 미배송 / 짝퉁 / 카드 도용 (추정 1인당 손실 ...)</li>
  <li><strong>개인정보 유출</strong>: 수취인 정보 → 보이스피싱 2차 표적화</li>
  <li><strong>2차 캠페인</strong>: 동일 SaaS의 자매 사이트로 재유입</li>
</ul>
```

## 14. 권고 조치

```html
<h2>14. 권고 조치 (효과 순)</h2>
<ol>
  <li><span class="tag">최우선</span> 공유 백엔드 차단 요청 (Alibaba / AWS / Cloudflare Abuse)</li>
  <li><span class="tag">즉시</span> Google Ads / Facebook / TikTok / Criteo 광고 정책 위반 신고</li>
  <li><span class="tag">긴급</span> KISA 보호나라(118 / boho.or.kr)</li>
  <li>경찰청 사이버수사대 — SaaS 식별자·자매 IOC 일괄 제공</li>
  <li>네이버/카카오 / 한국소비자원 사기 사이트 등재</li>
</ol>
```

## 15. 분석 산출물

```html
<h2>15. 분석 산출물</h2>
<p>본 분석의 모든 원자료는 <code>report/__DOMAIN__/</code> 폴더에 보존되며, sha256 해시는 <code>evidence_manifest.json</code>에 기록된다.</p>

<table>
  <tr><th>분류</th><th>파일</th><th>설명</th></tr>
  <tr><td>본 보고서</td><td><code>report.html</code> + <code>__SLUG___YYMMDD_HHMMSS.pdf</code></td><td>이 문서</td></tr>
  <tr><td>증거 매니페스트</td><td><code>evidence_manifest.json</code></td><td>전 파일 sha256, 수집 환경</td></tr>
  <tr><td>HTML 스냅샷</td><td><code>mobile.html</code>, <code>desktop.html</code></td><td>mobile/desktop UA 응답</td></tr>
  <tr><td>JS 번들</td><td><code>*.js</code></td><td>운영 모듈 원본</td></tr>
  <tr><td>풀 스크린샷</td><td><code>screenshot-*-mobile.png</code></td><td>Playwright fullPage</td></tr>
  <tr><td>발췌 스크린샷</td><td><code>crop-*.png</code></td><td>본문 임베드용</td></tr>
  <tr><td>네트워크 트레이스</td><td><code>network-*.txt</code></td><td>XHR/fetch 캡처</td></tr>
  <tr><td>분석 스크립트</td><td><code>crop_screenshots.py</code>, <code>scan_*.py</code></td><td>재현용</td></tr>
</table>

<h3>15.1. 재현 절차</h3>
<ol>
  <li><code>evidence_manifest.json</code>의 <code>target_url</code>·<code>domain</code> 확인</li>
  <li>동일 UA / viewport (manifest <code>analyst_notes</code> 참조)로 재수집</li>
  <li>각 파일 sha256 비교 — 사이트가 동적 콘텐츠라면 차이를 기록</li>
  <li>본 보고서의 챕터별 인용 위치를 원본 파일과 대조</li>
</ol>
```

## 부록 A. 전체 페이지 캡처

```html
<hr>
<h2>부록 A. 전체 페이지 캡처 (풀 사이즈)</h2>
<figure class="appendix">
  <img src="screenshot-main-mobile.png">
  <figcaption>[부록 A-1] 메인 페이지 전체 (모바일)</figcaption>
</figure>
<figure class="appendix">
  <img src="screenshot-detail-mobile.png">
  <figcaption>[부록 A-2] 상품 디테일 전체</figcaption>
</figure>
<figure class="appendix">
  <img src="screenshot-checkout-mobile.png">
  <figcaption>[부록 A-3] 결제 페이지 전체</figcaption>
</figure>
```
