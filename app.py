"""PhishGuard - 피싱 사이트 분석 플랫폼 (Streamlit)"""

import streamlit as st

st.set_page_config(
    page_title="PhishGuard",
    page_icon="\U0001F6E1\uFE0F",
    layout="wide",
    initial_sidebar_state="expanded",
)

pg = st.navigation([
    st.Page("pages/0_home.py", title="PhishGuard", icon="\U0001F6E1\uFE0F", default=True),
    st.Page("pages/1_비교분석.py", title="비교분석", icon="\U0001F50D"),
    st.Page("pages/2_도메인모니터링.py", title="도메인모니터링", icon="\U0001F310"),
    st.Page("pages/4_유사사이트검색.py", title="유사사이트검색", icon="\U0001F50E"),
    st.Page("pages/5_키워드모니터링.py", title="키워드모니터링", icon="\U0001F511"),
    st.Page("pages/3_분석이력.py", title="분석이력", icon="\U0001F4CB"),
])

pg.run()
