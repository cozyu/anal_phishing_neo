"""PhishGuard 홈"""

import streamlit as st
st.session_state["_current_page"] = "home"
from config import get_config

st.title("\U0001F6E1\uFE0F PhishGuard")
st.subheader("피싱 사이트 분석 플랫폼")

st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("### \U0001F50D 비교 분석")
    st.markdown(
        "urlscan.io 메타데이터(JSON)를 업로드하거나 "
        "URL을 입력하여 두 피싱 사이트를 비교 분석합니다."
    )
    st.markdown("- 규칙 기반 유사도 점수")
    st.markdown("- Gemini AI 심층 분석")

with col2:
    st.markdown("### \U0001F310 도메인 모니터링")
    st.markdown(
        "키워드를 입력하면 최근 신규 등록된 "
        "의심 도메인을 조회합니다."
    )
    st.markdown("- WhoisXML Reverse WHOIS")
    st.markdown("- WHOIS 상세 정보")

with col3:
    st.markdown("### \U0001F4CB 분석 이력")
    st.markdown(
        "이전 분석 결과를 다시 확인하거나 "
        "삭제할 수 있습니다."
    )
    st.markdown("- Supabase 저장")
    st.markdown("- API 재호출 불필요")

st.markdown("---")

supabase_url = get_config("SUPABASE_URL")
if supabase_url:
    st.sidebar.success("Supabase 연결됨")
else:
    st.sidebar.warning("Supabase 미설정 (이력 저장 불가)")

st.sidebar.markdown("---")
