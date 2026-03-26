"""유사 사이트 검색 (urlscan Structure Search) 페이지"""

import streamlit as st
from urlscan_client import scan_and_structure_search, structure_search
from db import save_history
from background import BackgroundTask, TaskQueue

st.session_state["_current_page"] = "similar"
st.title("\U0001F50E 유사 사이트 검색")

st.markdown("""
<style>
    .similar-card {
        border: 1px solid #444; border-radius: 8px; padding: 0.8rem;
        margin-bottom: 0.8rem; font-size: 0.85rem;
    }
    .similar-card img { border-radius: 4px; width: 100%; }
    .similar-card a { color: #4da6ff; text-decoration: none; }
    .similar-card a:hover { text-decoration: underline; }
    .similar-meta { color: #aaa; font-size: 0.75rem; margin-top: 0.3rem; }
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
</style>
""", unsafe_allow_html=True)

if "similar_queue" not in st.session_state:
    st.session_state["similar_queue"] = TaskQueue()

queue = st.session_state["similar_queue"]

# 다른 페이지에서 진입 시 이전 결과 초기화
if st.session_state.get("_current_page") != "similar" and not queue.is_busy:
    for key in ["similar_results", "similar_url", "similar_page", "similar_saved"]:
        st.session_state.pop(key, None)


def _to_kst(dt_str):
    if not dt_str:
        return "N/A"
    try:
        from datetime import datetime, timezone, timedelta
        dt_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return dt_str[:19] if len(dt_str) >= 19 else dt_str


def _search_bg(url, threshold, days=30, task=None):
    """백그라운드 유사 사이트 검색"""
    from datetime import datetime, timedelta
    date_from = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    q = f"date:>{date_from}"
    results = scan_and_structure_search(
        url, threshold=threshold, size=100, q=q,
        progress_callback=lambda msg: task.set_progress(msg) if task else None,
    )

    if task and task.cancelled:
        return None

    if task:
        task.set_progress("이력 저장 중...")
    total = results.get("total", 0)
    items = results.get("results", [])
    save_data = {
        "url": url,
        "threshold": threshold,
        "scan_uuid": results.get("scan_uuid"),
        "total": total,
        "results": items[:100],
    }
    title = f"[유사검색] {url} (유사도≥{threshold}%)"
    history_id = save_history("similar", title, save_data)

    return {
        "items": items,
        "total": total,
        "scan_uuid": results.get("scan_uuid"),
        "saved": history_id is not None,
        "url": url,
        "threshold": threshold,
    }


# 검색 폼
with st.form("similar_form"):
    url = st.text_input("대상 URL", placeholder="https://example.com")
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        threshold = st.number_input(
            "유사도 기준 (%)",
            min_value=1,
            max_value=100,
            value=75,
        )
    with col2:
        days = st.number_input(
            "조회 기간 (일)",
            min_value=1,
            max_value=365,
            value=10,
        )
    submitted = st.form_submit_button("검색")

if submitted and url:
    name = f"유사 검색: {url} ({threshold}%, {days}일)"
    task = BackgroundTask(name=name, target=_search_bg, args=(url, threshold, days))
    queue.add(task)
    st.rerun()


# --- 비동기 작업 상태 표시 (fragment) ---
@st.fragment(run_every="1s")
def _queue_status():
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"검색 오류: {last.error}")
        elif last.result:
            st.session_state["similar_results"] = last.result
            st.session_state["similar_page"] = 0
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
        if st.button("취소", key="cancel_current_similar", type="primary"):
            queue.cancel_current()

    if pending:
        st.markdown(f"**대기 중 ({len(pending)}건)**")
        for i, p in enumerate(pending):
            col_name, col_del = st.columns([8, 1])
            with col_name:
                st.caption(f"  {i + 1}. {p.name}")
            with col_del:
                if st.button("취소", key=f"rm_similar_{i}"):
                    queue.remove_pending(i)


_queue_status()

PAGE_SIZE = 12

# --- 결과 표시 ---
if "similar_results" in st.session_state:
    data = st.session_state["similar_results"]
    items = data["items"]
    total = data["total"]
    current_page = st.session_state.get("similar_page", 0)

    st.markdown("---")
    st.markdown(f"**대상**: `{data['url']}` | **유사도 기준**: {data['threshold']}% | **검색 결과**: {total}건")

    if data.get("saved"):
        st.caption("\u2705 이력이 자동 저장되었습니다.")
    else:
        st.caption("\u26A0\uFE0F Supabase 미설정 - 이력이 저장되지 않았습니다.")

    if not items:
        st.info("유사한 사이트를 찾지 못했습니다.")
    else:
        total_pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
        start = current_page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(items))
        page_items = items[start:end]

        # 카드형 3열 레이아웃
        for row_start in range(0, len(page_items), 3):
            cols = st.columns(3)
            for col_idx, col in enumerate(cols):
                item_idx = row_start + col_idx
                if item_idx >= len(page_items):
                    break
                item = page_items[item_idx]
                task_info = item.get("task", {})
                page_info = item.get("page", {})
                scan_uuid = item.get("_id", "")
                screenshot_url = f"https://urlscan.io/screenshots/{scan_uuid}.png" if scan_uuid else ""
                page_url = page_info.get("url", "N/A")
                domain = page_info.get("domain", "N/A")
                scan_time = _to_kst(task_info.get("time", ""))
                country = page_info.get("country", "N/A")
                server = page_info.get("server", "N/A")
                ip = page_info.get("ip", "N/A")
                asn = page_info.get("asnname", "N/A")
                urlscan_link = f"https://pro.urlscan.io/result/{scan_uuid}/" if scan_uuid else "#"

                with col:
                    card_html = f"""<div class="similar-card">"""
                    if screenshot_url:
                        card_html += f"""<img src="{screenshot_url}" alt="screenshot" loading="lazy">"""
                    card_html += f"""
                        <div style="margin-top:0.4rem;">
                            <strong>{domain}</strong><br>
                            <a href="{page_url}" target="_blank">{page_url[:80]}{'...' if len(page_url) > 80 else ''}</a>
                        </div>
                        <div class="similar-meta">
                            IP: {ip} | 국가: {country}<br>
                            서버: {server} | ASN: {asn[:40]}<br>
                            스캔: {scan_time}<br>
                            <a href="{urlscan_link}" target="_blank">urlscan.io에서 보기</a>
                        </div>
                    </div>"""
                    st.markdown(card_html, unsafe_allow_html=True)

        # 페이지네이션
        if total_pages > 1:
            st.caption(f"페이지 {current_page + 1} / {total_pages} (표시 {len(items)}건 / 전체 {total}건)")
            col_prev, _, col_next = st.columns([1, 2, 1])
            with col_prev:
                if st.button("\u25C0 이전", disabled=current_page <= 0, key="btn_prev_similar"):
                    st.session_state["similar_page"] = current_page - 1
                    st.rerun()
            with col_next:
                if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key="btn_next_similar"):
                    st.session_state["similar_page"] = current_page + 1
                    st.rerun()
