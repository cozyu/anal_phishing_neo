# PDF 빌드 + 파일명 규칙

## 빌드 명령

```bash
D=/home/cozyu/git/anal_phishing_neo/report/$DOMAIN

# 1) 임시 파일로 빌드 (HTML과 같은 디렉토리에 두기 — snap chromium은 /tmp 못 읽음)
chromium --headless --disable-gpu --no-sandbox \
  --print-to-pdf="$D/_tmp_report.pdf" \
  --no-pdf-header-footer \
  "file://$D/report.html"

# 2) mtime을 KST 시각으로 환산해 파일명 규칙 적용
ts=$(stat -c "%y" "$D/_tmp_report.pdf")
yy=$(date -d "$ts" +%y%m%d)
hms=$(date -d "$ts" +%H%M%S)
mv -v "$D/_tmp_report.pdf" "$D/${DOMAIN}_${yy}_${hms}.pdf"
```

## 검증

```bash
python - <<PY
from pypdf import PdfReader
import re
pdf = f"$D/${DOMAIN}_${yy}_${hms}.pdf"
r = PdfReader(pdf)
print(f"pages: {len(r.pages)}")
# 각 페이지에서 챕터 헤딩 추출
for i, p in enumerate(r.pages):
    txt = p.extract_text() or ''
    heads = re.findall(r'\n([0-9]+(?:\.[0-9]+)?\.\s+[^\n]{4,60})', txt)
    appx  = re.findall(r'(부록 [A-Z]\.[^\n]{0,40})', txt)
    if heads or appx:
        print(f'  p{i+1:2d}: heads={heads[:2]} appx={appx[:1]}')
PY
```

체크포인트:
- 페이지 수가 챕터 수에 비례하는가? (대개 15-30페이지)
- 한글이 깨지지 않았는가? (`r.pages[0].extract_text()[:200]`이 정상)
- 부록 A 페이지가 끝부분에 있는가?
- 첫 페이지에 verdict + 발췌 캡처가 있는가?

## 자주 막히는 문제

| 증상 | 원인 | 해결 |
|---|---|---|
| "Your file couldn't be accessed" PDF | snap chromium이 `/tmp/` 접근 차단 | HTML/이미지를 사용자 홈 이하 경로(`/home/cozyu/git/anal_phishing_neo/report/[도메인]/`)로 이동 후 빌드 |
| `exit 144` | 컨테이너 정책으로 백그라운드 데몬 차단 (Streamlit 등). chromium 빌드 자체는 보통 정상 | 빌드는 foreground로 실행 |
| 한글 ?? 깨짐 | Noto CJK 폰트 누락 | `fc-list :lang=ko`로 확인. Ubuntu에서는 `apt install fonts-noto-cjk` |
| 이미지가 PDF에 안 나옴 | `<img src="...">` 상대경로가 HTML과 같은 폴더에 없음 | 모든 png·jpg를 `report/[도메인]/`로 옮기고 빌드 |
| PDF가 너무 큼(>50MB) | 풀스크린샷이 4000px 이상이라 부록 페이지가 많음 | 풀스크린샷은 50% max-width로 축소 (기존 CSS 적용됨), 또는 jpeg로 변환 |

## 파일명 규칙 (재확인)

`[도메인]_YYMMDD_HHMMSS.pdf`
- YYMMDD: 2자리 연도 + 월 + 일 (예: 260515)
- HHMMSS: 24시간제 시·분·초 (KST 기준)
- 시각: 보고서 PDF 빌드 시점 = 분석 완료 시점의 mtime
- IDN은 Punycode 도메인 그대로 사용 (예: `xn--c1avbb.org_260514_165450.pdf`)
- 콜론·슬래시 등 OS 호환성 이슈 문자 금지
- 재분석 시 새 파일명으로 생성 (이전 PDF는 보존 또는 사용자 지시에 따라 정리)
