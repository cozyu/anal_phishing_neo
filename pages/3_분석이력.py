"""분석 이력 페이지"""

from datetime import datetime, timezone, timedelta

import streamlit as st
from db import get_history_list, get_history_detail, delete_history
from config import get_config

KST = timezone(timedelta(hours=9))

st.title("\U0001F4CB 분석 이력")

st.markdown("""
<style>
    .history-table { font-size: 0.85rem; }
    .history-table td, .history-table th { white-space: nowrap; }
    .report-section { font-size: 0.85rem; line-height: 1.5; }
    .report-section h1 { font-size: 1.3rem; }
    .report-section h2 { font-size: 1.15rem; }
    .report-section h3 { font-size: 1.0rem; }
    .report-section p, .report-section li, .report-section td { font-size: 0.85rem; }
    /* 목록 컴팩트화 */
    [data-testid="stVerticalBlock"] > [data-testid="stHorizontalBlock"] {
        gap: 0 !important;
    }
    [data-testid="stHorizontalBlock"] { margin-bottom: -0.8rem !important; }
    button[data-testid="stBaseButton-secondary"] {
        font-size: 0.65rem !important;
        padding: 0.1rem 0.4rem !important;
        min-height: 0 !important;
        height: 1.4rem !important;
        line-height: 1 !important;
        border-radius: 0.6rem !important;
    }
    p { margin-bottom: 0 !important; font-size: 0.85rem !important; }
</style>
""", unsafe_allow_html=True)


def _to_kst(dt_str):
    if not dt_str:
        return ""
    try:
        dt_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return dt_str[:16].replace("T", " ")


def _esc(val):
    return str(val).replace("|", "/").replace("\n", " ").replace("\r", "")


# Supabase 미설정 시 안내
if not get_config("SUPABASE_URL"):
    st.warning("Supabase가 설정되지 않아 이력 기능을 사용할 수 없습니다.")
    st.stop()


st.session_state["_current_page"] = "history"


def _render_detail(category):
    """상세 보기 렌더링. 표시했으면 True 반환."""
    view_key = f"view_{category}_id"
    if view_key not in st.session_state:
        return False

    if st.button("\u25C0 목록으로 돌아가기", key=f"back_{category}"):
        st.session_state.pop(view_key, None)
        st.rerun()

    detail = get_history_detail(category, st.session_state[view_key])
    if not detail:
        st.error("이력을 찾을 수 없습니다.")
        return True

    st.subheader(detail["title"])
    st.caption(f"저장 시각: {_to_kst(detail.get('created_at', ''))}")
    data = detail["data"]

    if category == "compare":
        score = data.get("score", 0)
        meta1 = data.get("meta1", {})
        meta2 = data.get("meta2", {})
        mode = data.get("mode", "file")
        mode_label = "\U0001F4C1 파일 업로드" if mode == "file" else "\U0001F310 URL 스캔"

        st.markdown(
            f"<div class='report-section'>"
            f"<b>유사도 점수: {score}%</b> &nbsp; <span style='color:#888'>({mode_label})</span></div>",
            unsafe_allow_html=True,
        )

        scan1 = _to_kst(meta1.get("scan_time", "")) or "N/A"
        scan2 = _to_kst(meta2.get("scan_time", "")) or "N/A"

        table_md = f"| 항목 | 결과 | {_esc(meta1.get('domain', '사이트1'))} | {_esc(meta2.get('domain', '사이트2'))} |\n"
        table_md += "|---|---|---|---|\n"
        table_md += f"| 스캔 시각 | - | {_esc(scan1)} | {_esc(scan2)} |\n"
        for comp in data.get("comparisons", []):
            status_icon = ""
            if "일치" in comp["status"] and "불" not in comp["status"]:
                status_icon = "\u2705"
            elif "불일치" in comp["status"] or "없음" in comp["status"]:
                status_icon = "\u274C"
            else:
                status_icon = "\U0001F7E1"
            s1 = _esc(comp.get("site1", comp.get("detail", "")))
            s2 = _esc(comp.get("site2", ""))
            table_md += f"| {_esc(comp['name'])} | {status_icon} {_esc(comp['status'])} | {s1} | {s2} |\n"

        st.markdown(f"<div class='report-section'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)

        ai = data.get("ai_analysis", "")
        if ai:
            ai_model = data.get("ai_model", "N/A")
            st.caption(f"AI 모델: {ai_model}")
            st.markdown(f"<div class='report-section'>\n\n{ai}\n\n</div>", unsafe_allow_html=True)

    elif category == "domains":
        st.markdown(f"**키워드**: {data.get('keyword', 'N/A')}")

        domain_results = data.get("results", [])
        if domain_results:
            table_md = "| # | 도메인 | 등록일 | 만료일 | 등록기관 | 국가 |\n"
            table_md += "|---|--------|--------|--------|----------|------|\n"

            for i, d in enumerate(domain_results):
                if d.get("status") == "error":
                    table_md += f"| {i+1} | {_esc(d['domain'])} | - | - | 조회 실패 | - |\n"
                    continue

                table_md += (
                    f"| {i+1} "
                    f"| {_esc(d['domain'])} "
                    f"| {_esc(d.get('creation_date', 'N/A')[:10])} "
                    f"| {_esc(d.get('expiration_date', 'N/A')[:10])} "
                    f"| {_esc(d.get('registrar', 'N/A')[:40])} "
                    f"| {_esc(d.get('country', 'N/A'))} |\n"
                )

            st.markdown(f"<div class='history-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)
        else:
            st.info("도메인 결과가 없습니다.")

    return True


PAGE_SIZE = 10


def _render_list(category):
    """이력 목록 렌더링 (페이지네이션)"""
    view_key = f"view_{category}_id"
    page_key = f"history_page_{category}"
    history_list = get_history_list(category)

    if not history_list:
        st.info("저장된 이력이 없습니다.")
        return

    total_pages = max(1, (len(history_list) + PAGE_SIZE - 1) // PAGE_SIZE)
    current_page = st.session_state.get(page_key, 0)
    start = current_page * PAGE_SIZE
    end = min(start + PAGE_SIZE, len(history_list))

    st.markdown(f"**총 {len(history_list)}건**")

    for item in history_list[start:end]:
        col_title, col_date, col_actions = st.columns([4, 2, 2])
        with col_title:
            st.markdown(f"**{item['title']}**")
        with col_date:
            st.text(_to_kst(item.get("created_at", "")))
        with col_actions:
            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                if st.button("\U0001F50D 상세", key=f"view_{item['id']}"):
                    st.session_state[view_key] = item["id"]
                    st.rerun()
            with btn_col2:
                if st.button("\U0001F5D1 삭제", key=f"del_{item['id']}"):
                    delete_history(category, item["id"])
                    st.rerun()

    if total_pages > 1:
        st.caption(f"페이지 {current_page + 1} / {total_pages}")
        col_prev, _, col_next = st.columns([1, 3, 1])
        with col_prev:
            if st.button("\u25C0 이전", disabled=current_page <= 0, key=f"prev_{category}"):
                st.session_state[page_key] = current_page - 1
                st.rerun()
        with col_next:
            if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key=f"next_{category}"):
                st.session_state[page_key] = current_page + 1
                st.rerun()


# --- 카테고리 선택 ---
def _on_tab_change():
    """탭 전환 시 상세 보기 초기화"""
    for _k in ["view_compare_id", "view_domains_id"]:
        st.session_state.pop(_k, None)


selected = st.radio(
    "카테고리",
    options=["compare", "domains"],
    format_func=lambda x: "비교 분석" if x == "compare" else "도메인 모니터링",
    horizontal=True,
    key="history_tab",
    on_change=_on_tab_change,
    label_visibility="collapsed",
)

if not _render_detail(selected):
    _render_list(selected)
