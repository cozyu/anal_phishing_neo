# 단계별 동적 엔드포인트 헌팅 체크리스트

정적 HTML 분석만으로는 사기 캠페인의 진짜 데이터 수집 흐름을 놓칠 수 있다. 운영자는 흔히 **번호가 매겨진 시리즈 페이지**(Case1.php → Case2.php → Case3.php, step1.html → step2.html, 등)와 **JS 동적 라우팅**으로 보이스피싱/신원도용 시나리오를 단계적으로 펼친다. 이 체크리스트는 분석가가 "사이트가 비어 있다"고 판단하기 전에 반드시 확인해야 하는 추가 절차다.

## 언제 적용하는가

다음 신호 중 **둘 이상**이 동시에 보이면 즉시 적용:

- 정적 HTML 분석에서 모든 메인 버튼/링크가 `javascript:void(null);`, `href="#"`, `onclick=""`만 갖고 있음
- 회원가입·로그인 폼은 노출되어 있으나 form `action` 속성이 비어 있거나 더미
- 정부/금융 사칭 사이트인데 분석가가 직접 데이터를 제출해보기 전엔 데이터 송신 endpoint가 식별되지 않음
- HTML 메인 페이지의 last-modified가 도메인 등록 시각보다 한참 앞섬 (사전 빌드 키트)
- 사용자가 "더미값을 넣었더니 다른 페이지가 나왔다"고 보고

## 절차

### 1. 시리즈 경로 자동 프로브

운영자가 흔히 쓰는 번호·단계 명명 규칙을 사전에 일괄 시도. 워크플로의 작업 변수(`$URL`)가 설정된 상태에서:

```bash
declare -a CANDS=(
  # 대검찰청·KICS·경찰 사칭 보이스피싱 키트의 표준 (실제 관측)
  Case1.php Case2.php Case3.php Case4.php Case5.php Case6.php Case7.php Case8.php Case9.php Case10.php Case11.php Case12.php
  case1.php case2.php case3.php

  # step / page / sub 시리즈
  step1.php step2.php step3.php step4.php step5.php
  step1.html step2.html step3.html
  page1.html page2.html page3.html
  sub1.php sub2.php sub3.php

  # 흐름 키워드
  notice.php warrant.php payment.php pay.php transfer.php verify.php
  result.php done.php complete.php finish.php end.php fin.php
  contact.php call.php phone.php

  # 인증 / 로그인 / 폼
  login.php do_login.php login_check.php signin.php signin_check.php
  api.php api/login.php api/submit.php submit.php save.php upload.php
  cert.php npki.php nidp.php pwc.php

  # 관리자·운영자
  admin.php admin/ manage.php manage/ config.php
  bbs/login_check.php wp-admin/ wp-login.php

  # PWA / 메타
  manifest.json manifest.webmanifest sw.js robots.txt sitemap.xml
  .well-known/security.txt .well-known/apple-app-site-association
  .well-known/assetlinks.json
)
for P in "${CANDS[@]}"; do
  s=$(curl -sk -A "Mozilla/5.0 (iPhone) Mobile/15E148" -o /dev/null \
    -w "%{http_code} %{size_download}b ct=%{content_type}" "$URL/$P" -m 8)
  if ! echo "$s" | grep -qE "^(404|403)"; then
    printf "  %-32s %s\n" "$P" "$s"
  fi
done
```

`404`·`403`이 아닌 모든 응답을 별도 파일로 다운로드해 분석한다.

### 2. 발견 시리즈에 대한 단계 추적

`Case1.php`가 발견되면 즉시 `Case2.php`, `Case3.php`, ... 로 확장 — 통상 3~10개 단계 페이지로 구성된다. 각 단계의:

```bash
for P in Case1.php Case2.php Case3.php Case4.php Case5.php; do
  curl -sk -A "Mozilla/5.0 (iPhone) Mobile/15E148" "$URL/$P" \
    -o "$D/page_${P}.html" \
    -w "  %-12s status=%{http_code} size=%{size_download}b\n" -m 15
done
```

각 페이지의 `<form>` `action` 속성을 그대로 따라가면 운영자가 의도한 다음 단계가 노출된다 (Case1 → Case2 → Case3 식의 체인).

### 3. 폼 송신 시뮬레이션 (안전 더미 데이터)

⚠️ **실제 PII / 주민번호 / 카드번호 / 인증서 절대 사용 금지.** 모두 명백한 가짜값으로 채운다.

```bash
# Case1.php의 hidden input 추출
grep -ohE '<input[^>]+(name|value)="[^"]+"' "$D/page_Case1.php.html" \
  | grep -ohE 'name="[^"]+"' | sort -u

# 안전 더미값으로 POST 후 응답 저장
curl -sk -A "Mozilla/5.0 (iPhone)" -X POST \
  -d "nm=홍길동&rrno1=000000&rrno2=0000000&sttWrdsQueryVal=test" \
  "$URL/Case1.php" -o "$D/page_Case1_POST_dummy.html" \
  -w "  status=%{http_code} size=%{size_download}b\n" -m 15
```

### 4. GET vs POST 차이 분석 (반사 입력 탐지)

POST가 GET과 동일한 응답인지, 입력값이 HTML에 반사되는지, 새 다음-단계 URL이 노출되는지 확인:

```bash
# 빈 POST와 더미 POST 둘 다 시도해 차이 비교
curl -sk -A "Mozilla/5.0 (iPhone)" -X POST -d "" \
  "$URL/Case1.php" -o "$D/page_Case1_POST_empty.html" -m 15

# sha256 차이로 반사 입력 감지
sha256sum "$D/page_Case1.php.html" "$D/page_Case1_POST_empty.html" "$D/page_Case1_POST_dummy.html"

# 바이트 diff로 어디가 다른지 확인
diff <(python3 -c "import re; print(re.sub(r'\\s+',' ',open('$D/page_Case1.php.html').read()))" | tr ' ' '\n') \
     <(python3 -c "import re; print(re.sub(r'\\s+',' ',open('$D/page_Case1_POST_dummy.html').read()))" | tr ' ' '\n') | head -30
```

체크포인트:
- POST(dummy) sha256이 GET과 다르고 size가 더크다면 → **입력값이 HTML에 반사됨** = 서버가 로깅하거나 다음 페이지에 PII를 표시
- POST(empty)와 GET이 동일하다면 → 폼 검증이 클라이언트만 또는 빈 POST는 무시
- 응답에 새로운 URL이나 JS 리다이렉트가 등장하면 → 다음 단계 추적

### 5. 단계별 시나리오 라벨링

운영자의 단계별 메시지 톤이 캠페인 유형을 알려준다. 정부 사칭 보이스피싱 키트의 표준 3~5단계:

| 단계 | 일반 라벨 | 한국형 보이스피싱 키트 관측 사례 |
|---|---|---|
| 1 | 미끼 / 협박 통지 | "사건번호 ‥‥, 명의도용·자금세탁 혐의" + 본인확인 강요 |
| 2 | 가짜 영장 / 처분 | "구속영장 발부", "지급정지" + 패닉 유도 + 계좌 노출 |
| 3 | 가짜 조회 결과 | "거래내역 조회표", "지급정지 계좌" 시각화 |
| 4 | 통화 연결 / 안전계좌 | "수사관과 통화하세요" / "안전계좌로 송금하세요" |
| 5 | 종료 / 재유입 | "협조 완료" 메시지 + 다음 캠페인 SMS |

보고서 챕터 11(공격 시나리오)에 단계별 흐름을 그대로 인용한다.

### 6. 시각 증거 캡처 (Playwright)

각 Case 페이지에 직접 진입해 풀스크린샷을 부록 A에 포함:

```python
# Playwright 인터랙션 예
1. browser_navigate(URL + "/index2.html")
2. browser_take_screenshot(filename="screenshot-step0-index2.png", fullPage=True)
3. browser_evaluate({() => document.forms[0].action})  # 다음 URL 확인
4. browser_navigate(URL + "/Case1.php")
5. browser_take_screenshot(filename="screenshot-step1-Case1.png", fullPage=True)
6. browser_navigate(URL + "/Case2.php")
7. browser_take_screenshot(filename="screenshot-step2-Case2.png", fullPage=True)
# 폼 제출은 URL을 직접 갈아 끼우는 방식이 안전 — 더미 데이터를 페이지에 타이핑해 클릭하지 말 것
```

### 7. 도용 인물·기관·문서 식별

각 단계 페이지의 **서명·발신자·문서번호**를 그대로 인용해 IOC에 등재:

- 가짜 사건번호 (예: `2025 고합 8785호`)
- 가짜 영장번호 (예: `2025형제 316호`)
- 가짜 계좌번호 (예: `우리은행 1002-200-59***8`) — 일부 마스킹이라도 그대로 인용
- 도용된 실명 (예: 검찰총장·기관장) — **현직자 인물 확인 시 명예훼손 신고 가능**
- 발신자 직위 (예: 대검찰청 특수부, 서울중앙지검 수사과)

### 8. 보고서 반영

- 챕터 8(개인정보·금융정보 수집): 각 Case 페이지가 수집하는 필드 명시
- 챕터 9.3(행위 매트릭스): 단계별 행위 / 외부 호스트 / 데이터 종류
- 챕터 11(공격 시나리오): 단계 1~N의 시나리오 그대로 인용
- 챕터 12(IOC): 가짜 사건번호·영장번호·계좌·도용 인물·각 Case 페이지의 sha256
- 부록 A: 단계별 스크린샷

## 분석 안전 수칙

- **실제 주민등록번호·이름·계좌·인증서·OTP 절대 입력 금지**. 모두 명백한 가짜값(000000-0000000, "홍길동", "test")으로 채운다.
- 더미값도 가능한 한 적게 입력 — 운영자 측 로그에 분석 흔적이 남을 수 있다.
- 폼 제출은 **분석가 IP**를 노출시키므로, 본격적인 시뮬레이션은 분석 전용 VPS/VPN 환경 권장.
- 분석가 IP가 노출돼도 무방하다면 IP·UA·수집 시각을 증거 매니페스트에 기록.
- 동적 POST 시뮬레이션 결과 파일은 별도 접미사(`_POST_empty`, `_POST_dummy`)로 구분해 저장.
- 분석 후 운영자가 분석가 IP를 차단할 가능성이 있으니, 차단 시 재현 절차에 명시.
