"""도메인 등록 모니터링 페이지"""

import streamlit as st
from config import get_config
from domain_monitor import search_domains, get_domain_detail, sort_by_creation_date
from db import save_history
from background import BackgroundTask, TaskQueue

st.session_state["_current_page"] = "domains"
st.title("\U0001F310 도메인 등록 모니터링")

st.markdown("""
<style>
    .domain-table { font-size: 0.85rem; }
    .domain-table td, .domain-table th { padding: 0.3rem 0.5rem; white-space: nowrap; }
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown(
        "<div style='font-size:0.8rem'>"
        "검색 엔진: <b>VirusTotal</b><br>"
        "<a href='https://www.virustotal.com/gui/my-apikey' target='_blank'>API 쿼터 확인</a>"
        "</div>",
        unsafe_allow_html=True,
    )

if "domain_queue" not in st.session_state:
    st.session_state["domain_queue"] = TaskQueue()

queue = st.session_state["domain_queue"]

# 다른 페이지에서 진입 시 이전 결과 초기화
if st.session_state.get("_current_page") != "domains" and not queue.is_busy:
    for key in ["domain_results", "domain_keyword", "domain_total", "domain_page", "domain_saved"]:
        st.session_state.pop(key, None)


def _domain_search_bg(keyword, days, task=None):
    """백그라운드 도메인 검색"""
    if task:
        task.set_progress("VirusTotal 검색 중...")
    domains = search_domains(keyword, days=days)

    if not domains:
        return {"results": [], "total": 0, "saved": False, "keyword": keyword}

    details = []
    for i, domain in enumerate(domains):
        if task and task.cancelled:
            return None
        detail = get_domain_detail(domain)
        details.append(detail)
        if task:
            task.set_progress(f"WHOIS 조회 중... {i + 1}/{len(domains)}")

    if task and task.cancelled:
        return None

    filtered = sort_by_creation_date(details)

    if task:
        task.set_progress("이력 저장 중...")
    save_data = [
        {k: v for k, v in d.items() if k != "_creation_dt"} for d in filtered
    ]
    title = f"도메인 모니터링: {keyword}"
    history_id = save_history("domains", title, {"keyword": keyword, "days": days, "results": save_data})

    return {
        "results": filtered,
        "total": len(domains),
        "saved": history_id is not None,
        "keyword": keyword,
    }


def _esc(val):
    return str(val).replace("|", "/").replace("\n", " ").replace("\r", "")


# 검색 폼
with st.form("search_form"):
    col1, col2 = st.columns([3, 1])
    with col1:
        keyword = st.text_input("검색 키워드", placeholder="예: samsung, naver, paypal")
    with col2:
        days = st.number_input(
            "등록일 기준 (일)",
            min_value=1,
            max_value=365,
            value=int(get_config("DOMAIN_LOOKUP_DAYS", "30")),
        )
    submitted = st.form_submit_button("검색")

PAGE_SIZE = 20

if submitted and keyword:
    name = f"도메인 검색: {keyword} ({days}일)"
    task = BackgroundTask(name=name, target=_domain_search_bg, args=(keyword, days))
    queue.add(task)
    st.rerun()


# --- 비동기 작업 상태 표시 (fragment) ---
@st.fragment(run_every="1s")
def _queue_status():
    # 완료된 작업 처리
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"검색 오류: {last.error}")
        elif last.result:
            st.session_state["domain_results"] = last.result["results"]
            st.session_state["domain_total"] = last.result["total"]
            st.session_state["domain_saved"] = last.result["saved"]
            st.session_state["domain_keyword"] = last.result["keyword"]
            st.session_state["domain_page"] = 0
        if len(completed) > 1:
            st.success(f"{len(completed)}건의 검색이 완료되었습니다.")
        st.rerun(scope="app")
        return

    current = queue.current
    pending = queue.pending

    if not current or current.done:
        return

    st.markdown("---")
    st.markdown("### 작업 진행 상황")
    col_info, col_cancel = st.columns([8, 1])
    with col_info:
        st.info(f"\U0001F504 **진행 중**: {current.name}\n\n{current.progress or '준비 중...'}")
    with col_cancel:
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        if st.button("취소", key="cancel_current_domain", type="primary"):
            queue.cancel_current()

    if pending:
        st.markdown(f"**대기 중 ({len(pending)}건)**")
        for i, p in enumerate(pending):
            col_name, col_del = st.columns([8, 1])
            with col_name:
                st.caption(f"  {i + 1}. {p.name}")
            with col_del:
                if st.button("취소", key=f"rm_domain_{i}"):
                    queue.remove_pending(i)


_queue_status()


# --- 결과 표시 ---
if "domain_results" in st.session_state:
    results = st.session_state["domain_results"]
    keyword_display = st.session_state.get("domain_keyword", "")
    current_page = st.session_state.get("domain_page", 0)

    st.markdown("---")
    st.markdown(f"**검색 결과: '{keyword_display}'** - **{len(results)}개**")

    if st.session_state.get("domain_saved"):
        st.caption("\u2705 이력이 자동 저장되었습니다.")
    else:
        st.caption("\u26A0\uFE0F Supabase 미설정 - 이력이 저장되지 않았습니다.")

    if not results:
        st.info("조회 기간 내 등록된 도메인이 없습니다.")
    else:
        total_pages = max(1, (len(results) + PAGE_SIZE - 1) // PAGE_SIZE)
        start = current_page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(results))
        page_results = results[start:end]

        table_md = "| # | 도메인 | 등록일 | 만료일 | 등록기관 | 국가 |\n"
        table_md += "|---|--------|--------|--------|----------|------|\n"

        for i, d in enumerate(page_results):
            idx = start + i + 1
            if d.get("status") == "error":
                table_md += f"| {idx} | {_esc(d['domain'])} | - | - | 조회 실패 | - |\n"
                continue
            table_md += (
                f"| {idx} "
                f"| {_esc(d['domain'])} "
                f"| {_esc(d.get('creation_date', 'N/A')[:10])} "
                f"| {_esc(d.get('expiration_date', 'N/A')[:10])} "
                f"| {_esc(d.get('registrar', 'N/A')[:40])} "
                f"| {_esc(d.get('country', 'N/A'))} |\n"
            )

        st.markdown(f"<div class='domain-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)

        if total_pages > 1:
            st.caption(f"페이지 {current_page + 1} / {total_pages} (총 {len(results)}건)")
            col_prev, _, col_next = st.columns([1, 2, 1])
            with col_prev:
                if st.button("\u25C0 이전", disabled=current_page <= 0, key="btn_prev"):
                    st.session_state["domain_page"] = current_page - 1
                    st.rerun()
            with col_next:
                if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key="btn_next"):
                    st.session_state["domain_page"] = current_page + 1
                    st.rerun()
