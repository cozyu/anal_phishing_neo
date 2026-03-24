"""설정 관리 - Streamlit Secrets 또는 .env에서 로드"""

import os


def get_config(key, default=None):
    """Streamlit secrets → 환경변수 → 기본값 순서로 설정값 조회"""
    try:
        import streamlit as st
        return st.secrets[key]
    except Exception:
        pass
    from dotenv import load_dotenv
    load_dotenv()
    return os.getenv(key, default)
