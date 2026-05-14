"""도메인 등록 모니터링 페이지 (URL 기반)"""

import time
import streamlit as st
from datetime import datetime, timezone, timedelta

from config import get_config
from domain_monitor import search_domains, get_domain_detail, sort_by_creation_date
from db import (
    save_history,
    add_keyword, get_keywords, delete_keyword,
    save_keyword_results, get_latest_keyword_results, get_seen_domains,
)
from background import BackgroundTask, TaskQueue

DOMAIN_SOURCE = "vt_domain"
KEYWORD_PURPOSE = "url"

st.session_state["_current_page"] = "domains"
st.title("\U0001F310 도메인 검색 및 모니터링(URL)")

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


# ── 유틸리티 ──

def _to_kst(dt_str):
    if not dt_str:
        return "-"
    try:
        dt_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return dt_str[:16] if len(dt_str) >= 16 else dt_str


def _esc(val):
    return str(val).replace("|", "/").replace("\n", " ").replace("\r", "")


def _strip_save_data(details):
    """_creation_dt 같은 내부 키 제거"""
    return [{k: v for k, v in d.items() if k != "_creation_dt"} for d in details]


# ── 백그라운드 작업 함수 ──

def _domain_search_bg(keyword, days, task=None):
    """단건 도메인 검색 (history 저장)"""
    if task:
        task.set_progress("VirusTotal 검색 중...")
    domains = search_domains(keyword, days=days)

    if not domains:
        return {"results": [], "total": 0, "saved": False, "keyword": keyword, "adhoc": True}

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
    save_data = _strip_save_data(filtered)
    title = f"도메인 모니터링: {keyword}"
    history_id = save_history("domains", title, {"keyword": keyword, "days": days, "results": save_data})

    return {
        "results": filtered,
        "total": len(domains),
        "saved": history_id is not None,
        "keyword": keyword,
        "adhoc": True,
    }


def _monitor_search_bg(keywords_list, days, incremental=False, task=None):
    """등록 키워드 재검색 (keyword_results + history 저장)"""
    all_results = {}
    for i, kw in enumerate(keywords_list):
        if task and task.cancelled:
            return None
        mode_label = "신규" if incremental else f"{days}일"
        if task:
            task.set_progress(
                f"[{mode_label}] '{kw['keyword']}' VirusTotal 검색 중... ({i+1}/{len(keywords_list)})"
            )
        try:
            # 신규 모드에서도 일단 충분히 긴 기간으로 조회 후 도메인 차집합 적용
            search_days = 365 if incremental else days
            domains = search_domains(kw["keyword"], days=search_days)

            details = []
            for j, domain in enumerate(domains):
                if task and task.cancelled:
                    return None
                detail = get_domain_detail(domain)
                details.append(detail)
                if task:
                    task.set_progress(
                        f"[{mode_label}] '{kw['keyword']}' WHOIS 조회 중... {j + 1}/{len(domains)}"
                    )

            filtered = sort_by_creation_date(details)
            save_data = _strip_save_data(filtered)

            if incremental:
                seen = get_seen_domains(kw["id"], DOMAIN_SOURCE)
                new_data = [d for d in save_data if d.get("domain") not in seen]
            else:
                new_data = save_data

            save_keyword_results(kw["id"], kw["keyword"], DOMAIN_SOURCE, len(new_data), new_data[:200])
            all_results[kw["id"]] = {
                "keyword": kw["keyword"],
                "total": len(new_data),
                "results": new_data,
            }
        except Exception as e:
            all_results[kw["id"]] = {
                "keyword": kw["keyword"], "total": 0, "results": [], "error": str(e),
            }
        if i < len(keywords_list) - 1:
            time.sleep(1)
    return {"adhoc": False, "data": all_results, "mode": "신규" if incremental else f"{days}일"}


def _save_monitor_history(result):
    """모니터링 재검색 결과를 history(domains)에도 저장"""
    data = result.get("data", {})
    mode = result.get("mode", "")
    keywords_str = ", ".join(v["keyword"] for v in data.values())
    total_found = sum(v.get("total", 0) for v in data.values())
    title = f"[모니터링/{mode}] {keywords_str} ({total_found}건)"
    save_history("domains", title, {
        "monitor": True,
        "mode": mode,
        "results_by_keyword": {
            v["keyword"]: v.get("results", []) for v in data.values()
        },
    })


# ══════════════════════════════════════════════════════════════
# 섹션 A: 즉시 검색
# ══════════════════════════════════════════════════════════════

st.markdown("### 즉시 검색")

with st.form("search_form"):
    col1, col2 = st.columns([3, 1])
    with col1:
        keyword = st.text_input("키워드", placeholder="도메인 검색 키워드 입력 (예: fsec, fsi 등)")
    with col2:
        days = st.number_input(
            "등록일 기준 (일)",
            min_value=1,
            max_value=365,
            value=int(get_config("DOMAIN_LOOKUP_DAYS", "30")),
        )
    submitted = st.form_submit_button("검색 중..." if queue.is_busy else "검색", disabled=queue.is_busy)

PAGE_SIZE = 20

if submitted and keyword and not queue.is_busy:
    name = f"[검색] '{keyword}' ({days}일)"
    task = BackgroundTask(name=name, target=_domain_search_bg, args=(keyword, days))
    queue.add(task)
    st.rerun()


# ── 결과 테이블 렌더링 헬퍼 ──

def _render_domain_table(results, page_key="domain_page", show_bulk=True):
    if not results:
        st.info("조회 기간 내 등록된 도메인이 없습니다.")
        return

    current_page = st.session_state.get(page_key, 0)
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
            f"| {_esc((d.get('creation_date') or 'N/A')[:10])} "
            f"| {_esc((d.get('expiration_date') or 'N/A')[:10])} "
            f"| {_esc((d.get('registrar') or 'N/A')[:40])} "
            f"| {_esc(d.get('country') or 'N/A')} |\n"
        )

    st.markdown(f"<div class='domain-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)

    if show_bulk:
        domain_urls = [
            f"https://{d['domain']}" for d in results
            if d.get("domain") and d.get("status") != "error"
        ]
        if domain_urls:
            if st.button(f"일괄분석 ({len(domain_urls)}건)", key=f"{page_key}_bulk"):
                st.session_state["bulk_scan_urls"] = "\n".join(domain_urls)
                st.switch_page("pages/7_일괄스캔.py")

    if total_pages > 1:
        st.caption(f"페이지 {current_page + 1} / {total_pages} (총 {len(results)}건)")
        col_prev, _, col_next = st.columns([1, 2, 1])
        with col_prev:
            if st.button("◀ 이전", disabled=current_page <= 0, key=f"{page_key}_prev"):
                st.session_state[page_key] = current_page - 1
                st.rerun()
        with col_next:
            if st.button("다음 ▶", disabled=current_page >= total_pages - 1, key=f"{page_key}_next"):
                st.session_state[page_key] = current_page + 1
                st.rerun()


# 즉시 검색 결과 표시
if "domain_results" in st.session_state:
    results = st.session_state["domain_results"]
    keyword_display = st.session_state.get("domain_keyword", "")

    st.markdown(f"#### 검색 결과: '{keyword_display}' - **{len(results)}개**")

    if st.session_state.get("domain_saved"):
        st.caption("✅ 이력이 자동 저장되었습니다.")
    else:
        st.caption("⚠️ Supabase 미설정 - 이력이 저장되지 않았습니다.")

    _render_domain_table(results, page_key="domain_page")

    # 모니터링 등록 버튼
    if keyword_display:
        all_keywords = get_keywords(active_only=True, purpose=KEYWORD_PURPOSE)
        existing_kw = next((kw for kw in all_keywords if kw["keyword"] == keyword_display), None)
        if existing_kw:
            last_searched = _to_kst(existing_kw.get("last_searched_at"))
            st.caption(f"'{keyword_display}'는 이미 URL 모니터링에 등록되어 있습니다. (최종 검색: {last_searched})")
        else:
            if st.button(f"'{keyword_display}' URL 모니터링에 등록", type="primary", key="btn_register_kw"):
                add_keyword(keyword_display, purpose=KEYWORD_PURPOSE)
                st.success(f"'{keyword_display}' URL 모니터링 등록 완료")
                st.rerun()


# ══════════════════════════════════════════════════════════════
# 작업 큐 상태 (fragment)
# ══════════════════════════════════════════════════════════════

@st.fragment(run_every="1s")
def _queue_status():
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"검색 오류: {last.error}")
        elif last.result:
            if last.result.get("adhoc"):
                st.session_state["domain_results"] = last.result["results"]
                st.session_state["domain_total"] = last.result["total"]
                st.session_state["domain_saved"] = last.result["saved"]
                st.session_state["domain_keyword"] = last.result["keyword"]
                st.session_state["domain_page"] = 0
            else:
                st.session_state["monitor_last_result"] = last.result
                _save_monitor_history(last.result)
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


# ══════════════════════════════════════════════════════════════
# 섹션 B: 모니터링 키워드 (등록 + 주기 재검색)
# ══════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 모니터링 키워드")

monitor_keywords = get_keywords(active_only=True, purpose=KEYWORD_PURPOSE)

if monitor_keywords:
    for i, kw in enumerate(monitor_keywords):
        col_num, col_kw, col_date, col_last, col_del = st.columns([0.5, 3, 2, 2, 1])
        with col_num:
            st.caption(f"{i+1}")
        with col_kw:
            st.markdown(f"**{kw['keyword']}**")
        with col_date:
            st.caption(f"등록: {_to_kst(kw.get('created_at'))}")
        with col_last:
            st.caption(f"최종 검색: {_to_kst(kw.get('last_searched_at'))}")
        with col_del:
            if st.button("삭제", key=f"del_dk_{kw['id']}", type="primary"):
                delete_keyword(kw["id"])
                st.rerun()

    # 재검색 폼
    st.markdown("#### 재검색")
    with st.form("monitor_research_form"):
        kw_names = [kw["keyword"] for kw in monitor_keywords]
        selected_kws = st.multiselect("검색할 키워드 선택", options=kw_names)
        col_mode, col_days = st.columns([2, 1])
        with col_mode:
            research_mode = st.radio(
                "검색 모드",
                ["특정 기간 내 등록 도메인", "신규만 (이전 검색 이후)"],
                horizontal=True,
                key="domain_research_mode",
            )
        with col_days:
            research_days = st.number_input(
                "조회 기간(일)", min_value=1, max_value=365, value=14,
                key="domain_research_days",
                help="신규 모드에서는 무시됩니다 (이전 검색 이후 신규 도메인만 표시)",
            )
        research_submitted = st.form_submit_button(
            "검색 중..." if queue.is_busy else "재검색",
            disabled=queue.is_busy,
        )

    if queue.is_busy:
        st.info("\U0001F504 검색 중입니다. 잠시 기다려주세요...")

    if research_submitted and selected_kws and not queue.is_busy:
        selected_objs = [kw for kw in monitor_keywords if kw["keyword"] in selected_kws]
        incremental = research_mode.startswith("신규만")
        mode_label = "신규" if incremental else f"{research_days}일"
        task = BackgroundTask(
            name=f"[모니터링/{mode_label}] {len(selected_objs)}건",
            target=_monitor_search_bg,
            args=(selected_objs, research_days, incremental),
        )
        queue.add(task)
        st.rerun()

    # ── 모니터링 재검색 결과 보기 ──
    st.markdown("---")
    st.markdown("### 모니터링 검색 결과")

    kw_options = {kw["keyword"]: kw["id"] for kw in monitor_keywords}
    selected_view = st.selectbox(
        "키워드 선택", options=list(kw_options.keys()), key="dk_view_select",
    )

    if selected_view:
        view_data = get_latest_keyword_results(kw_options[selected_view], DOMAIN_SOURCE)
        if view_data and view_data.get("results"):
            st.caption(
                f"검색 시각: {_to_kst(view_data.get('searched_at'))} "
                f"| 결과: {view_data.get('total_found', 0)}건"
            )
            _render_domain_table(view_data["results"], page_key="dk_view_page")
        else:
            st.info("아직 모니터링 검색 결과가 없습니다. 위에서 재검색을 실행하세요.")

else:
    st.info(
        "등록된 모니터링 키워드가 없습니다. 위 즉시 검색에서 키워드 검색 후 "
        "**'모니터링에 등록'** 버튼을 눌러 등록하세요."
    )
