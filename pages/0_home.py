"""PhishGuard 홈"""

import streamlit as st
st.session_state["_current_page"] = "home"
from config import get_config

st.title("\U0001F6E1\uFE0F PhishGuard")
st.subheader("피싱 사이트 분석 플랫폼")

st.markdown("""
<style>
    .feature-card {
        background: #1e1e2e; border: 1px solid #333; border-radius: 10px;
        padding: 1.2rem 1.4rem; height: 100%; min-height: 180px;
    }
    .feature-card h4 { margin: 0 0 0.6rem 0; font-size: 1.1rem; }
    .feature-card p { font-size: 0.85rem; color: #ccc; margin-bottom: 0.5rem; }
    .feature-card ul { font-size: 0.8rem; color: #aaa; padding-left: 1.2rem; margin: 0; }
</style>
""", unsafe_allow_html=True)

col1, col2 = st.columns(2, gap="medium")

with col1:
    st.markdown("""<div class="feature-card">
        <h4>\U0001F310 도메인 검색 및 모니터링(URL)</h4>
        <p>키워드를 입력하면 최근 신규 등록된 의심 도메인을 조회합니다.</p>
        <ul><li>VirusTotal 도메인 검색</li><li>WHOIS 상세 정보</li></ul>
    </div>""", unsafe_allow_html=True)

with col2:
    st.markdown("""<div class="feature-card">
        <h4>\U0001F511 도메인 검색 및 모니터링(Title)</h4>
        <p>웹사이트 제목 키워드를 등록하면 urlscan.io + VirusTotal에서 동일 키워드 사이트를 검색합니다.</p>
        <ul><li>URLScan / VirusTotal 개별 검색</li><li>URL 목록 복사</li></ul>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

col3, col4 = st.columns(2, gap="medium")

with col3:
    st.markdown("""<div class="feature-card">
        <h4>\U0001F3AF 피싱사이트 분석(AI분석)</h4>
        <p>URL 하나를 입력하면 VirusTotal + CriminalIP + URLScan.io 3개 소스로 종합 분석합니다.</p>
        <ul><li>위협 점수 산출 (0-100)</li><li>IOC 추출 + 연관 사이트 발견</li><li>Gemini AI 보고서</li></ul>
    </div>""", unsafe_allow_html=True)

with col4:
    st.markdown("""<div class="feature-card">
        <h4>\U0001F4E6 피싱사이트 일괄분석</h4>
        <p>URL 목록을 입력하면 urlscan.io 스캔 이력 확인 후 미등록 URL만 스캔 제출합니다.</p>
        <ul><li>기존 이력 자동 확인</li><li>최대 100건 일괄 처리</li></ul>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

col5, col6 = st.columns(2, gap="medium")

with col5:
    st.markdown("""<div class="feature-card">
        <h4>\U0001F50D 피싱사이트 비교분석</h4>
        <p>urlscan.io 메타데이터(JSON)를 업로드하거나 URL을 입력하여 두 피싱 사이트를 비교 분석합니다.</p>
        <ul><li>규칙 기반 유사도 점수</li><li>Gemini AI 심층 분석</li></ul>
    </div>""", unsafe_allow_html=True)

with col6:
    st.markdown("""<div class="feature-card">
        <h4>\U0001F50E 유사사이트검색(DOM기반)</h4>
        <p>URL을 입력하면 urlscan.io Structure Search로 구조적으로 유사한 사이트를 검색합니다.</p>
        <ul><li>유사도 기준 조정 가능</li><li>스크린샷 미리보기</li></ul>
    </div>""", unsafe_allow_html=True)

st.markdown("---")

supabase_url = get_config("SUPABASE_URL")
if supabase_url:
    st.sidebar.success("Supabase 연결됨")
else:
    st.sidebar.warning("Supabase 미설정 (이력 저장 불가)")

st.sidebar.markdown("---")
