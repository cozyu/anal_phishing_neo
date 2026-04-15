"""피싱 사이트 비교 분석 페이지"""

import json
import streamlit as st
from analyzer import extract_metadata, compare_sites, analyze_with_gemini
from urlscan_client import scan_and_get_result, search_existing_scan, get_scan_result
from db import save_history
from background import BackgroundTask, TaskQueue

st.session_state["_current_page"] = "compare"
st.title("\U0001F50D 피싱사이트 비교분석")

st.markdown("""
<style>
    .report-section { font-size: 0.85rem; line-height: 1.5; }
    .report-section h1 { font-size: 1.3rem; }
    .report-section h2 { font-size: 1.15rem; }
    .report-section h3 { font-size: 1.0rem; }
    .report-section p, .report-section li, .report-section td { font-size: 0.85rem; }
    .compare-row { font-size: 0.85rem; padding: 0.2rem 0; }
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
</style>
""", unsafe_allow_html=True)

if "compare_queue" not in st.session_state:
    st.session_state["compare_queue"] = TaskQueue()

queue = st.session_state["compare_queue"]

# 다른 페이지에서 진입 시 이전 결과 초기화
if st.session_state.get("_current_page") != "compare" and not queue.is_busy:
    for key in ["compare_result", "compare_meta", "ai_analysis", "history_saved"]:
        st.session_state.pop(key, None)


def _analysis_bg(meta1, meta2, mode="file", task=None):
    if task and task.cancelled:
        return None
    if task:
        task.set_progress("규칙 기반 비교 분석 중...")
    result = compare_sites(meta1, meta2)

    if task and task.cancelled:
        return None
    if task:
        task.set_progress("Gemini AI 심층 분석 중...")
    ai_text, ai_model = analyze_with_gemini(
        meta1, meta2, result,
        progress_callback=lambda msg: task.set_progress(msg) if task else None,
    )

    if task and task.cancelled:
        return None
    if task:
        task.set_progress("이력 저장 중...")
    mode_tag = "[파일]" if mode == "file" else "[URL]"
    title = f"{mode_tag} {meta1['domain']} vs {meta2['domain']}"
    save_data = {
        "mode": mode,
        "comparisons": result["comparisons"],
        "score": result["score"],
        "meta1": meta1,
        "meta2": meta2,
        "ai_analysis": ai_text,
        "ai_model": ai_model,
    }
    history_id = save_history("compare", title, save_data)

    return {
        "result": result,
        "meta": (meta1, meta2),
        "ai_analysis": ai_text,
        "ai_model": ai_model,
        "saved": history_id is not None,
    }


def _url_scan_and_analysis_bg(url1, url2, task=None):
    if task:
        task.set_progress(f"사이트 1 스캔 중: {url1}")
    data1 = scan_and_get_result(url1, progress_callback=lambda msg: task.set_progress(msg) if task else None)

    if task and task.cancelled:
        return None

    if task:
        task.set_progress(f"사이트 2 스캔 중: {url2}")
    data2 = scan_and_get_result(url2, progress_callback=lambda msg: task.set_progress(msg) if task else None)

    if task and task.cancelled:
        return None

    meta1 = extract_metadata(data1)
    meta2 = extract_metadata(data2)

    # IP 정보 누락 체크
    no_ip_sites = []
    if not meta1.get("ip"):
        no_ip_sites.append({"url": url1, "domain": meta1.get("domain", url1)})
    if not meta2.get("ip"):
        no_ip_sites.append({"url": url2, "domain": meta2.get("domain", url2)})

    if no_ip_sites:
        return {
            "type": "no_ip",
            "no_ip_sites": no_ip_sites,
            "url1": url1,
            "url2": url2,
            "meta1": meta1,
            "meta2": meta2,
        }

    return _analysis_bg(meta1, meta2, mode="url", task=task)


def _retry_with_existing_bg(url1, url2, meta1, meta2, task=None):
    """기존 urlscan 데이터로 재분석"""
    from urlscan_client import _extract_domain

    if not meta1.get("ip"):
        domain = meta1.get("domain") or _extract_domain(url1)
        if task:
            task.set_progress(f"기존 스캔 결과 검색 중: {domain}")
        scan_id = search_existing_scan(domain)
        if not scan_id:
            raise Exception(f"{domain}의 기존 스캔 결과를 찾을 수 없습니다.")
        if task:
            task.set_progress(f"기존 스캔 데이터 로드 중: {scan_id[:8]}...")
        data = get_scan_result(scan_id)
        meta1 = extract_metadata(data)
        if not meta1.get("ip"):
            raise Exception(f"{domain}의 기존 스캔 결과에도 IP 정보가 없습니다.")

    if task and task.cancelled:
        return None

    if not meta2.get("ip"):
        domain = meta2.get("domain") or _extract_domain(url2)
        if task:
            task.set_progress(f"기존 스캔 결과 검색 중: {domain}")
        scan_id = search_existing_scan(domain)
        if not scan_id:
            raise Exception(f"{domain}의 기존 스캔 결과를 찾을 수 없습니다.")
        if task:
            task.set_progress(f"기존 스캔 데이터 로드 중: {scan_id[:8]}...")
        data = get_scan_result(scan_id)
        meta2 = extract_metadata(data)
        if not meta2.get("ip"):
            raise Exception(f"{domain}의 기존 스캔 결과에도 IP 정보가 없습니다.")

    if task and task.cancelled:
        return None

    return _analysis_bg(meta1, meta2, mode="url", task=task)


tab_url, tab_file = st.tabs(["URL 입력", "파일 업로드"])

with tab_file:
    st.markdown("urlscan.io에서 다운로드한 JSON 파일 2개를 업로드하세요.")
    col1, col2 = st.columns(2)
    with col1:
        file1 = st.file_uploader("사이트 1 JSON", type=None, key="file1")
    with col2:
        file2 = st.file_uploader("사이트 2 JSON", type=None, key="file2")

    if st.button("분석 시작", key="btn_file", disabled=not (file1 and file2)):
        try:
            data1 = json.loads(file1.read().decode("utf-8"))  # type: ignore[union-attr]
            data2 = json.loads(file2.read().decode("utf-8"))  # type: ignore[union-attr]
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            st.error(f"JSON 파싱 오류: {e}")
            st.stop()

        meta1 = extract_metadata(data1)
        meta2 = extract_metadata(data2)
        name = f"{meta1['domain']} vs {meta2['domain']}"
        task = BackgroundTask(name=name, target=_analysis_bg, args=(meta1, meta2))
        queue.add(task)
        st.rerun()

with tab_url:
    st.markdown("2개의 URL을 입력하면 urlscan.io로 스캔 후 자동 비교합니다.")
    with st.form("url_form"):
        col1, col2 = st.columns(2)
        with col1:
            url1 = st.text_input("사이트 1 URL", placeholder="https://example-phishing1.com")
        with col2:
            url2 = st.text_input("사이트 2 URL", placeholder="https://example-phishing2.com")
        url_submitted = st.form_submit_button("스캔 및 분석")

    if url_submitted and url1 and url2:
        name = f"{url1} vs {url2}"
        task = BackgroundTask(name=name, target=_url_scan_and_analysis_bg, args=(url1, url2))
        queue.add(task)
        st.rerun()


# --- 비동기 작업 상태 표시 (fragment) ---
@st.fragment(run_every="1s")
def _queue_status():
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"분석 오류: {last.error}")
        elif last.result and last.result.get("type") == "no_ip":
            st.session_state["compare_no_ip"] = last.result
        elif last.result:
            st.session_state.pop("compare_no_ip", None)
            st.session_state["compare_result"] = last.result["result"]
            st.session_state["compare_meta"] = last.result["meta"]
            st.session_state["ai_analysis"] = last.result["ai_analysis"]
            st.session_state["ai_model"] = last.result.get("ai_model")
            st.session_state["history_saved"] = last.result["saved"]
        if len(completed) > 1:
            st.success(f"{len(completed)}건의 분석이 완료되었습니다.")
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
        if st.button("취소", key="cancel_current_compare", type="primary"):
            queue.cancel_current()

    if pending:
        st.markdown(f"**대기 중 ({len(pending)}건)**")
        for i, p in enumerate(pending):
            col_name, col_del = st.columns([8, 1])
            with col_name:
                st.caption(f"  {i + 1}. {p.name}")
            with col_del:
                if st.button("취소", key=f"rm_compare_{i}"):
                    queue.remove_pending(i)


_queue_status()


# --- IP 없음 알림 및 재분석 제안 ---
if "compare_no_ip" in st.session_state:
    no_ip_data = st.session_state["compare_no_ip"]
    no_ip_sites = no_ip_data["no_ip_sites"]

    st.markdown("---")
    for site in no_ip_sites:
        st.warning(f"⚠️ **{site['domain']}** - IP 정보가 없어 사이트에 접근할 수 없습니다.")

    st.info("urlscan.io에 기존 저장된 스캔 데이터로 분석할 수 있습니다.")
    col_retry, col_cancel = st.columns([1, 3])
    with col_retry:
        if st.button("기존 데이터로 분석", type="primary", key="btn_retry_existing"):
            name = f"[재분석] {no_ip_data['url1']} vs {no_ip_data['url2']}"
            task = BackgroundTask(
                name=name,
                target=_retry_with_existing_bg,
                args=(no_ip_data["url1"], no_ip_data["url2"],
                      no_ip_data["meta1"], no_ip_data["meta2"]),
            )
            queue.add(task)
            st.session_state.pop("compare_no_ip", None)
            st.rerun()
    with col_cancel:
        if st.button("취소", key="btn_cancel_no_ip"):
            st.session_state.pop("compare_no_ip", None)
            st.rerun()


# --- 결과 표시 ---
if "compare_result" in st.session_state:
    result = st.session_state["compare_result"]
    meta1, meta2 = st.session_state["compare_meta"]

    st.markdown("---")

    score = result["score"]
    if score >= 70:
        score_color = "red"
        score_label = "높은 유사도"
    elif score >= 40:
        score_color = "orange"
        score_label = "중간 유사도"
    else:
        score_color = "green"
        score_label = "낮은 유사도"

    st.markdown(
        f"<div class='compare-row'><strong>유사도 점수: "
        f"<span style='color:{score_color};font-size:1.1rem'>{score}%</span></strong> "
        f"({score_label})</div>",
        unsafe_allow_html=True,
    )

    def _esc(v):
        return str(v).replace("|", "/").replace("\n", " ").replace("\r", "")

    def _to_kst(dt_str):
        if not dt_str:
            return "N/A"
        try:
            from datetime import datetime as _dt, timezone as _tz, timedelta as _td
            dt_str = dt_str.replace("Z", "+00:00")
            dt = _dt.fromisoformat(dt_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_tz.utc)
            return dt.astimezone(_tz(_td(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt_str[:19]

    scan1 = _to_kst(meta1.get("scan_time", ""))
    scan2 = _to_kst(meta2.get("scan_time", ""))

    table_md = f"| 항목 | 결과 | {_esc(meta1['domain'])} | {_esc(meta2['domain'])} |\n"
    table_md += "|---|---|---|---|\n"
    table_md += f"| 스캔 시각 | - | {_esc(scan1)} | {_esc(scan2)} |\n"
    for comp in result["comparisons"]:
        status_icon = ""
        if "일치" in comp["status"] and "불" not in comp["status"]:
            status_icon = "\u2705"
        elif "불일치" in comp["status"] or "없음" in comp["status"]:
            status_icon = "\u274C"
        else:
            status_icon = "\U0001F7E1"
        s1 = _esc(comp.get("site1", comp.get("detail", "")))
        s2 = _esc(comp.get("site2", ""))
        table_md += f"| {comp['name']} | {status_icon} {_esc(comp['status'])} | {s1} | {s2} |\n"

    st.markdown(f"<div class='report-section'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)

    if st.session_state.get("history_saved"):
        st.caption("\u2705 이력이 자동 저장되었습니다.")
    else:
        st.caption("\u26A0\uFE0F Supabase 미설정 - 이력이 저장되지 않았습니다.")

    if "ai_analysis" in st.session_state:
        st.markdown("---")
        ai_model = st.session_state.get("ai_model", "N/A")
        st.caption(f"AI 모델: {ai_model}")
        st.markdown(
            f"<div class='report-section'>\n\n{st.session_state['ai_analysis']}\n\n</div>",
            unsafe_allow_html=True,
        )
