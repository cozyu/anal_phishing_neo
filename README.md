# PhishGuard - 피싱 사이트 분석 플랫폼

피싱 사이트 비교 분석, 도메인 모니터링, 유사 사이트 검색을 위한 웹 기반 플랫폼.

## 주요 기능

### 1. 피싱 사이트 비교 분석 (비교분석)
- urlscan.io에서 다운로드한 2개의 피싱 사이트 메타데이터(JSON)를 업로드하여 유사점 비교 분석
- **파일 업로드 모드**: JSON 파일 직접 업로드 (드래그 앤 드롭 지원, 파일 확장자 제한 없음)
- **URL 입력 모드**: 2개의 URL을 입력하면 urlscan.io API로 스캔 후 자동 비교 (Enter 키로 즉시 실행)
- **규칙 기반 비교** (4열 테이블: 항목 | 결과 | 사이트1 | 사이트2):
  - 도메인, IP(IPv4만), ASN, 서버, 국가, 페이지 제목, URL 경로, 공유 리소스 해시, 기술 스택
  - 인증서 상세: 발급자, 무료 인증서 여부, 유효기간 패턴, TLS 설정, SAN 목록
  - 유사도 점수 산출 (높음/중간/낮음 색상 구분)
  - 스캔 시각 (KST 변환) 표시
- **Gemini AI 심층 분석**: 인프라 연관성, 피싱 킷 유사성, 공격자 프로파일링, 타겟 분석, 위험도 평가, 향후 탐지 전략
  - 사용된 Gemini 모델명 표시
  - 모델 폴백: gemini-3.0-flash → gemini-2.5-flash → gemini-3.1-flash-lite → gemini-2.5-flash-lite
- AI 프롬프트는 `prompt_config.yaml`에서 별도 관리 (분석 항목 추가/수정 가능)
- **백그라운드 실행**: 분석 중 페이지 이동 가능, 작업 큐 지원 (다중 분석 순차 처리)
- **작업 취소**: 진행 중인 작업과 대기 중인 작업 개별 취소 가능
- **이력 구분**: [파일] / [URL] 태그로 분석 방법 구분
- **IPv6 제외**: 모든 분석에서 IPv4만 사용

### 2. 도메인 등록 모니터링 (도메인모니터링)
- 키워드를 입력하면 최근 N일간 해당 키워드를 포함한 신규 등록 도메인 조회 (Enter 키로 즉시 검색)
- **VirusTotal Intelligence Search API**: 와일드카드 도메인 검색 (`*keyword*`) + 등록일(`creation_date`) 기준 필터링
  - 기본 조회 기간: 30일
  - 최대 3페이지(300개) 페이지네이션
- **python-whois** (공개 WHOIS 서버, 무료): 각 도메인 상세 정보 조회 (등록일, 만료일, 등록기관, 국가)
- 완전한 도메인(예: fsd-i.com) 입력 시 TLD 자동 제거 + VirusTotal에 없으면 직접 WHOIS 조회로 폴백
- 등록일 기준 내림차순 정렬
- 테이블 형태 결과 표시 (20건 단위 페이지네이션)
- **백그라운드 실행**: 검색 중 페이지 이동 가능, 작업 큐 지원
- **작업 취소**: 진행 중 WHOIS 조회 루프에서 즉시 취소 가능

### 3. 유사 사이트 검색 (유사사이트검색)
- URL을 입력하면 urlscan.io **Structure Search API** (Pro)로 구조적으로 유사한 사이트를 검색
- **워크플로우**: URL 스캔 제출 → UUID 획득 → Structure Search API 호출
- **API 엔드포인트**: `GET /api/v1/pro/result/{uuid}/similar/`
  - `threshold`: 유사도 기준 (`"75%"` 형식 문자열, 1~100% 키보드 입력)
  - `q`: ElasticSearch 쿼리 (날짜 필터 `date:>YYYY-MM-DD` 등)
  - `size`: 결과 수 제한
- **유사도 기준**: 기본값 75%, 1~100% 범위에서 직접 입력 가능
- **조회 기간**: 기본값 30일, 1~365일 범위에서 조정 가능
- **결과 표시**: 3열 카드 레이아웃 (스크린샷, 도메인, URL, IP, 국가, 서버, ASN, 스캔시각)
- **링크**: 각 결과에서 pro.urlscan.io 결과 페이지로 이동
- 12건 단위 페이지네이션
- **백그라운드 실행**: 검색 중 페이지 이동 가능, 작업 큐 + 취소 지원
- 이력 자동 저장 (`[유사검색]` 태그)

### 4. 분석 이력 (분석이력)
- 비교 분석/도메인 모니터링/유사 사이트 검색 결과가 Supabase에 자동 저장
- API 재호출 없이 이전 결과 재확인 가능
- 카테고리 전환 (라디오 버튼): 비교 분석 / 도메인 모니터링 / 유사 사이트 검색
- 이력 목록 (10건 단위 페이지네이션) + 상세 보기 + 삭제 기능
- 카테고리 전환 시 상세 보기 자동 초기화 (목록으로 복귀)
- 모든 시간은 KST(UTC+9)로 표시, DB 저장은 UTC

## 기술 스택

- **프레임워크**: Streamlit (Python 풀스택)
- **테마**: 다크 테마 (`.streamlit/config.toml`)
- **AI 분석**: Google Gemini API (`google-genai` 패키지)
- **도메인 검색**: VirusTotal Intelligence Search API
- **도메인 상세 조회**: python-whois (공개 WHOIS 서버, 무료)
- **URL 스캔/유사검색**: urlscan.io API + Structure Search Pro API
- **이력 저장**: Supabase (PostgreSQL)
- **설정 관리**: `.env` (로컬) / Streamlit Secrets (클라우드)
- **비동기 처리**: `@st.fragment(run_every="1s")` + `threading` 기반 작업 큐
- **API 로깅**: `logs/api_YYYY-MM-DD.log` (일별 로테이션)
- **가상환경**: Python venv (.venv)

## 프로젝트 구조

```
anal_phishing_neo/
├── .env                        # 환경변수 (API 키, 설정값)
├── .gitignore
├── .streamlit/
│   └── config.toml             # Streamlit 테마 설정 (다크 테마)
├── README.md
├── requirements.txt            # Python 의존성
├── supabase_setup.sql          # Supabase 테이블 생성 SQL
├── prompt_config.yaml          # Gemini AI 프롬프트 설정 (분석 항목, 출력 형식)
│
├── app.py                      # Streamlit 메인 (st.navigation으로 페이지 라우팅)
├── pages/
│   ├── 0_home.py               # 홈 (기능 소개, Supabase 연결 상태)
│   ├── 1_비교분석.py            # 비교 분석 (파일 업로드 / URL 입력, 작업 큐)
│   ├── 2_도메인모니터링.py      # 도메인 모니터링 (VT 검색 + WHOIS 조회, 작업 큐)
│   ├── 4_유사사이트검색.py      # 유사 사이트 검색 (urlscan Structure Search Pro)
│   └── 3_분석이력.py            # 분석 이력 (Supabase 조회/삭제, 상세 보기)
│
├── analyzer.py                 # 비교 분석 엔진 (규칙 비교 + Gemini AI 호출)
├── domain_monitor.py           # 도메인 모니터링 (VT Intelligence Search + python-whois)
├── urlscan_client.py           # urlscan.io API 클라이언트 (스캔 + Structure Search)
├── db.py                       # Supabase CRUD (이력 저장/조회/삭제)
├── config.py                   # 설정 로더 (Streamlit Secrets → .env 폴백)
├── background.py               # 백그라운드 작업 큐 (BackgroundTask, TaskQueue)
├── api_logger.py               # API 호출 로깅 (일별 로그 파일)
│
└── logs/                       # API 로그 디렉토리 (자동 생성, gitignore)
    └── api_2026-03-24.log
```

## 환경변수 (.env)

| 변수명 | 설명 | 필수 |
|--------|------|------|
| `GEMINI_API_KEY` | Google Gemini API 키 | O |
| `VT_API_KEY` | VirusTotal API 키 (도메인 모니터링용) | O |
| `URLSCAN_API_KEY` | urlscan.io API 키 (URL 비교 분석 + 유사 사이트 검색, Pro 필요) | O |
| `SUPABASE_URL` | Supabase 프로젝트 URL | O |
| `SUPABASE_KEY` | Supabase anon/service_role 키 | O |
| `WHOISXML_API_KEY` | WhoisXML API 키 (현재 미사용, 레거시) | X |
| `DOMAIN_LOOKUP_DAYS` | 도메인 조회 기간 일수 (기본: 30) | X |

## 설치 및 실행

```bash
# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# .env 파일에 API 키 설정
# GEMINI_API_KEY, VT_API_KEY, URLSCAN_API_KEY, SUPABASE_URL, SUPABASE_KEY

# Supabase 테이블 생성 (Dashboard > SQL Editor에서 실행)
# supabase_setup.sql 참조

# 서버 실행
streamlit run app.py
# http://localhost:8501 접속
```

## Supabase 설정

1. [supabase.com](https://supabase.com)에서 프로젝트 생성
2. SQL Editor에서 `supabase_setup.sql` 실행
3. Settings > API에서 Project URL과 anon 키 복사
4. `.env`에 `SUPABASE_URL`, `SUPABASE_KEY` 입력

## Streamlit Cloud 배포

1. GitHub에 push
2. [share.streamlit.io](https://share.streamlit.io)에서 연결
3. Secrets에 `.env`와 동일한 키-값 설정 (TOML 형식)

## 설계 결정 사항

### 플랫폼
- **Streamlit 선택 이유**: Python만으로 풀스택 구현, 무료 배포(Streamlit Cloud), API 키를 Secrets로 관리
- **Flask → Streamlit 전환**: 무료 배포가 쉬운 클라이언트 사이드 플랫폼 요구사항 반영

### API 선택
- **VirusTotal > WhoisXML**: 도메인 검색에 `creation_date` 기반 필터링 지원, 와일드카드 검색(`*keyword*`)으로 부분 매칭 가능. WhoisXML의 `sinceDate`는 WHOIS 업데이트 기준이라 등록일 기준 필터링 불가
- **python-whois 유지**: WHOIS 상세 조회는 무료 공개 서버 사용. Streamlit Cloud에서 `whois` 명령어 동작 여부는 미확인 (동작 안 하면 대안 검토 필요)
- **google-genai 패키지**: `google-generativeai`는 deprecated, `google-genai`로 전환

### 비동기 처리
- **`@st.fragment(run_every="1s")`**: 작업 진행 상황을 1초마다 자동 갱신하면서 버튼 인터랙션 유지. `time.sleep` + `st.rerun()` 패턴은 버튼 클릭을 블로킹하여 폐기
- **BackgroundTask + TaskQueue**: `threading` 기반, 작업 큐로 다중 요청 순차 처리, 개별 취소 지원
- **취소 메커니즘**: `task.cancelled` 플래그를 WHOIS/스캔 루프에서 체크하여 조기 종료

### UI/UX
- **비교 결과 4열 테이블**: `항목 | 결과 | 사이트1 | 사이트2` 형태로 차이점 한눈에 비교
- **폰트 축소**: 분석 보고서 0.85rem, 버튼 0.65~0.7rem으로 정보 밀도 향상
- **테이블 이스케이프**: `|`, 줄바꿈 문자를 치환하여 마크다운 테이블 깨짐 방지
- **페이지 진입 시 결과 초기화**: 다른 페이지에서 돌아오면 이전 결과 자동 초기화 (같은 페이지 rerun에서는 유지)
- **이력 상세 보기**: 카테고리 전환 시 `on_change` 콜백으로 자동 초기화
- **시간 표시**: DB 저장은 UTC, 표시는 모두 KST(UTC+9) 변환
- **홈 페이지**: 2x2 카드형 레이아웃 (CSS border/padding/border-radius로 구분)

### 데이터
- **Supabase**: 이력 저장 (history 테이블, JSONB 데이터 컬럼)
- **API 로깅**: `api_logger.py`로 모든 외부 API 호출을 `logs/` 디렉토리에 일별 파일로 기록 (요청/응답/오류, 긴 데이터 2000자 truncate, API 키 미포함)
- **IPv6 제외**: urlscan.io 결과에서 IPv6 IP 필터링, 메인 IP가 IPv6인 경우 IPv4 목록에서 대체

## 변경 이력

- 2026-03-24: 초기 프로젝트 생성 (Flask 기반 비교 분석 기능)
- 2026-03-24: Streamlit으로 플랫폼 전환 + Supabase 이력 저장
- 2026-03-24: google-genai 패키지 전환
- 2026-03-24: Gemini AI 자동 분석 + 이력 자동 저장
- 2026-03-24: 인증서 분석 확대 (발급자, 무료 여부, 유효기간, TLS, SAN)
- 2026-03-24: 비교 결과 4열 테이블 (사이트별 컬럼 분리)
- 2026-03-24: 도메인 검색 WhoisXML → VirusTotal 전환 (등록일 기준 필터링)
- 2026-03-24: 백그라운드 작업 큐 + 취소 기능
- 2026-03-24: st.fragment 비동기 폴링 전환 (time.sleep 패턴 폐기)
- 2026-03-24: API 호출 로깅 (api_logger.py)
- 2026-03-24: 이력 페이지 카테고리 전환 시 상세 초기화
- 2026-03-24: 분석 모드 구분 ([파일]/[URL]), 스캔 시각 KST 표시
- 2026-03-24: st.form으로 Enter 키 즉시 검색 지원
- 2026-03-25: 유사 사이트 검색 기능 추가 (urlscan Structure Search Pro API)
- 2026-03-25: 홈 페이지 2x2 카드형 UI 개선
