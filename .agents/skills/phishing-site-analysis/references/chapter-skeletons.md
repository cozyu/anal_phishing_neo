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
