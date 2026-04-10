"""일괄 URL 스캔 페이지 - URL 목록의 urlscan.io 이력 확인 후 미등록 URL 스캔 제출"""

import time
import streamlit as st
from urlscan_client import _normalize_url, _extract_domain, search_existing_scan_by_url, submit_scan
from db import save_history
from background import BackgroundTask, TaskQueue

st.session_state["_current_page"] = "bulk_scan"
st.title("📦 피싱사이트 분석(URLScan)")

st.markdown("""
<style>
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
    .bulk-table { font-size: 0.85rem; }
    .bulk-table td, .bulk-table th { white-space: nowrap; }
</style>
""", unsafe_allow_html=True)

if "bulk_scan_queue" not in st.session_state:
    st.session_state["bulk_scan_queue"] = TaskQueue()

queue = st.session_state["bulk_scan_queue"]

# 다른 페이지에서 진입 시 이전 결과 초기화
if st.session_state.get("_current_page") != "bulk_scan" and not queue.is_busy:
    for key in ["bulk_scan_results"]:
        st.session_state.pop(key, None)


def _bulk_scan_bg(urls, task=None):
    """백그라운드 일괄 스캔 처리"""
    # 중복 제거 (순서 유지)
    seen = set()
    unique_urls = []
    for url in urls:
        normalized = _normalize_url(url)
        if normalized not in seen:
            seen.add(normalized)
            unique_urls.append(normalized)

    results = []
    total = len(unique_urls)

    for i, url in enumerate(unique_urls):
        if task and task.cancelled:
            return None

        if task:
            task.set_progress(f"처리 중... ({i + 1}/{total}) - {url}")

        domain = _extract_domain(url)
        result_item = {
            "url": url,
            "domain": domain,
            "status": "",
            "uuid": None,
            "error": None,
            "urlscan_link": "",
        }

        try:
            existing_uuid = search_existing_scan_by_url(url)
            if existing_uuid:
                result_item["status"] = "이력있음"
                result_item["uuid"] = existing_uuid
                result_item["urlscan_link"] = f"https://pro.urlscan.io/result/{existing_uuid}/"
            else:
                scan_result = submit_scan(url)
                if scan_result and scan_result.get("uuid"):
                    result_item["status"] = "스캔제출"
                    result_item["uuid"] = scan_result["uuid"]
                    result_item["urlscan_link"] = f"https://pro.urlscan.io/result/{scan_result['uuid']}/"
                else:
                    result_item["status"] = "실패"
                    result_item["error"] = "스캔 제출 실패"
        except Exception as e:
            result_item["status"] = "실패"
            result_item["error"] = str(e)

        results.append(result_item)
        time.sleep(0.5)

    # 이력 저장
    if task:
        task.set_progress("이력 저장 중...")

    submitted = sum(1 for r in results if r["status"] == "스캔제출")
    skipped = sum(1 for r in results if r["status"] == "이력있음")
    failed = sum(1 for r in results if r["status"] == "실패")

    save_data = {
        "total": len(results),
        "submitted": submitted,
        "skipped": skipped,
        "failed": failed,
        "results": results,
    }
    title = f"[일괄스캔] {len(results)}건 (제출:{submitted}, 이력:{skipped}, 실패:{failed})"
    history_id = save_history("bulk_scan", title, save_data)

    save_data["saved"] = history_id is not None
    return save_data


# 입력 폼
with st.form("bulk_scan_form"):
    url_text = st.text_area(
        "URL 목록 (한 줄에 하나씩)",
        placeholder="https://example1.com\nhttps://example2.com\nexample3.com",
        height=200,
    )
    submitted = st.form_submit_button("스캔 시작")

if submitted and url_text.strip():
    raw_lines = url_text.strip().splitlines()
    urls = [line.strip() for line in raw_lines if line.strip()]
    if not urls:
        st.warning("URL을 입력해주세요.")
    elif len(urls) > 100:
        st.warning("한 번에 최대 100개까지 처리할 수 있습니다.")
    else:
        name = f"일괄 스캔 ({len(urls)}건)"
        task = BackgroundTask(name=name, target=_bulk_scan_bg, args=(urls,))
        if queue.add(task):
            st.rerun()
        else:
            st.warning("이미 동일한 작업이 진행 중입니다.")


# --- 비동기 작업 상태 표시 (fragment) ---
@st.fragment(run_every="1s")
def _queue_status():
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"스캔 오류: {last.error}")
        elif last.result:
            st.session_state["bulk_scan_results"] = last.result
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
        st.info(f"🔄 **진행 중**: {current.name}\n\n{current.progress or '준비 중...'}")
    with col_cancel:
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        if st.button("취소", key="cancel_current_bulk", type="primary"):
            queue.cancel_current()

    if pending:
        st.markdown(f"**대기 중 ({len(pending)}건)**")
        for i, p in enumerate(pending):
            col_name, col_del = st.columns([8, 1])
            with col_name:
                st.caption(f"  {i + 1}. {p.name}")
            with col_del:
                if st.button("취소", key=f"rm_bulk_{i}"):
                    queue.remove_pending(i)


_queue_status()

# --- 결과 표시 ---
if "bulk_scan_results" in st.session_state:
    data = st.session_state["bulk_scan_results"]
    results = data["results"]

    st.markdown("---")
    st.markdown("### 스캔 결과")

    # 요약 메트릭
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("전체", data["total"])
    col2.metric("스캔 제출", data["submitted"])
    col3.metric("이력 있음", data["skipped"])
    col4.metric("실패", data["failed"])

    if data.get("saved"):
        st.caption("✅ 이력이 자동 저장되었습니다.")
    else:
        st.caption("⚠️ Supabase 미설정 - 이력이 저장되지 않았습니다.")

    if results:
        status_icons = {"스캔제출": "🟢", "이력있음": "🔵", "실패": "🔴"}

        table_md = "| # | URL | 상태 | UUID | 링크 |\n"
        table_md += "|---|-----|------|------|------|\n"
        for i, r in enumerate(results, 1):
            icon = status_icons.get(r["status"], "")
            url_display = r["url"]
            if len(url_display) > 60:
                url_display = url_display[:57] + "..."
            uuid_display = r["uuid"][:12] + "..." if r["uuid"] and len(r["uuid"]) > 12 else (r.get("error") or "-")
            link = f"[보기]({r['urlscan_link']})" if r.get("urlscan_link") else "-"
            table_md += f"| {i} | {url_display} | {icon} {r['status']} | {uuid_display} | {link} |\n"

        st.markdown(f"<div class='bulk-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)
