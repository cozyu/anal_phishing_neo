"""도메인 검색 및 모니터링(Title) - 키워드 검색 → 모니터링 등록 → 재검색"""

import time
import streamlit as st
from datetime import datetime, timezone, timedelta

from db import (
    add_keyword, get_keywords, delete_keyword,
    save_keyword_results, get_latest_keyword_results, get_seen_urls,
    save_history,
)
from urlscan_client import search_by_title
from domain_monitor import search_urls_by_title as vt_search_urls_by_title
from background import BackgroundTask, TaskQueue

st.session_state["_current_page"] = "keyword"
st.title("\U0001F511 도메인 검색 및 모니터링(Title)")

st.markdown("""
<style>
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
    .kw-table th, .kw-table td {
        font-size: 0.85rem; padding: 0.3rem 0.6rem;
    }
    table td:nth-child(2) { white-space: normal !important; word-break: break-all !important; max-width: 320px !important; }
    table td:nth-child(3), table td:nth-child(4) { white-space: normal !important; word-break: break-word !important; max-width: 200px !important; }
    table td:nth-child(6), table td:nth-child(7) { white-space: nowrap !important; }
</style>
""", unsafe_allow_html=True)

if "keyword_queue" not in st.session_state:
    st.session_state["keyword_queue"] = TaskQueue()

queue = st.session_state["keyword_queue"]


# ── 유틸리티 함수 ──


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


def _strip_url(url):
    return url.rstrip("/")


def _get_since_date(kw_id, source):
    prev = get_latest_keyword_results(kw_id, source)
    if prev and prev.get("searched_at"):
        try:
            dt_str = prev["searched_at"].replace("Z", "+00:00")
            dt = datetime.fromisoformat(dt_str)
            return (dt - timedelta(days=1)).strftime("%Y-%m-%d")
        except Exception:
            pass
    return None


def _resolve_ip_countries(results_list, ip_key_fn):
    import requests as _req
    ip_set = set()
    for r in results_list:
        ip = ip_key_fn(r)
        if ip and ip != "N/A":
            ip_set.add(ip)
    if not ip_set:
        return
    ip_country = {}
    ip_list = list(ip_set)
    for batch_start in range(0, len(ip_list), 100):
        batch = ip_list[batch_start:batch_start + 100]
        try:
            resp = _req.post(
                "http://ip-api.com/batch?fields=query,countryCode",
                json=[{"query": ip} for ip in batch],
                timeout=10,
            )
            if resp.ok:
                for item in resp.json():
                    ip_country[item["query"]] = item.get("countryCode") or "N/A"
        except Exception:
            pass
    for r in results_list:
        ip = ip_key_fn(r)
        if ip and ip in ip_country:
            if "page" in r:
                r["page"]["country"] = ip_country[ip]
            else:
                r["country"] = ip_country.get(ip, "N/A")


def _resolve_domain_creation_dates(results_list, domain_key_fn, task=None, label=""):
    import whois as _whois
    from concurrent.futures import ThreadPoolExecutor, as_completed
    domain_set = set()
    for r in results_list:
        domain = domain_key_fn(r)
        if domain and domain != "N/A":
            domain_set.add(domain)
    if not domain_set:
        return

    def _lookup_one(domain):
        try:
            w = _whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                return domain, str(creation_date)[:10]
            else:
                return domain, "N/A"
        except Exception:
            return domain, "N/A"

    domain_dates = {}
    workers = min(10, len(domain_set))
    done_count = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_lookup_one, d): d for d in domain_set}
        for future in as_completed(futures):
            if task and task.cancelled:
                executor.shutdown(wait=False, cancel_futures=True)
                return
            domain, date_str = future.result()
            domain_dates[domain] = date_str
            done_count += 1
            if task and label:
                task.set_progress(f"{label} 도메인 등록일 조회 중... ({done_count}/{len(domain_set)})")

    for r in results_list:
        domain = domain_key_fn(r)
        if domain and domain in domain_dates:
            if "page" in r:
                r["page"]["creation_date"] = domain_dates[domain]
            else:
                r["creation_date"] = domain_dates.get(domain, "N/A")


# ── 결과 테이블 렌더링 헬퍼 ──

PAGE_SIZE = 20


def _render_urlscan_results(results, searched_at=None, page_key="kw_us_page"):
    """URLScan 결과 테이블 렌더링"""
    results.sort(key=lambda x: x.get("task", {}).get("time", ""), reverse=True)
    total = len(results)
    if searched_at:
        st.caption(f"검색 시각: {searched_at} | 결과: {total}건")

    current_page = st.session_state.get(page_key, 0)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    start = current_page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)

    header = "| # | URL | 도메인 | 페이지 제목 | IP | 국가 | 등록일 | 스캔일시 |\n|---|-----|--------|------------|----|----|------|--------|\n"
    rows = ""
    for idx, item in enumerate(results[start:end], start=start + 1):
        page_info = item.get("page", {})
        task_info = item.get("task", {})
        url = page_info.get("url", "N/A")
        domain = page_info.get("domain", "N/A")
        title = (page_info.get("title") or "N/A").replace("|", "\\|")[:50]
        ip = page_info.get("ip", "N/A")
        country = page_info.get("country", "N/A")
        creation_date = page_info.get("creation_date", "N/A")
        scan_time = _to_kst(task_info.get("time", ""))
        rows += f"| {idx} | {url[:60]} | {domain} | {title} | {ip} | {country} | {creation_date} | {scan_time} |\n"
    st.markdown(header + rows)

    if total_pages > 1:
        st.caption(f"페이지 {current_page + 1} / {total_pages}")
        col_prev, _, col_next = st.columns([1, 2, 1])
        with col_prev:
            if st.button("\u25C0 이전", disabled=current_page <= 0, key=f"{page_key}_prev"):
                st.session_state[page_key] = current_page - 1
                st.rerun()
        with col_next:
            if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key=f"{page_key}_next"):
                st.session_state[page_key] = current_page + 1
                st.rerun()

    _render_url_copy(results, lambda item: item.get("page", {}).get("url", ""),
                     lambda item: item.get("page", {}).get("country", ""), page_key)


def _render_vt_results(results, searched_at=None, page_key="kw_vt_page"):
    """VirusTotal 결과 테이블 렌더링"""
    results.sort(
        key=lambda x: x.get("last_analysis_date", "") if x.get("last_analysis_date", "") not in ("N/A", "") else "",
        reverse=True,
    )
    total = len(results)
    if searched_at:
        st.caption(f"검색 시각: {searched_at} | 결과: {total}건")

    current_page = st.session_state.get(page_key, 0)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    start = current_page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)

    header = "| # | URL | 페이지 제목 | IP | 국가 | 등록일 | 최종 분석일 |\n|---|-----|-----------|----|----|------|----------|\n"
    rows = ""
    for idx, item in enumerate(results[start:end], start=start + 1):
        url = (item.get("url") or "N/A").replace("|", "\\|")
        title = (item.get("title") or "N/A").replace("|", "\\|")[:50]
        ip = item.get("ip", "N/A")
        country = item.get("country", "N/A")
        creation_date = item.get("creation_date", "N/A")
        analysis_date = item.get("last_analysis_date", "N/A")
        rows += f"| {idx} | {url[:80]} | {title} | {ip} | {country} | {creation_date} | {analysis_date} |\n"
    st.markdown(header + rows)

    if total_pages > 1:
        st.caption(f"페이지 {current_page + 1} / {total_pages}")
        col_prev, _, col_next = st.columns([1, 2, 1])
        with col_prev:
            if st.button("\u25C0 이전", disabled=current_page <= 0, key=f"{page_key}_prev"):
                st.session_state[page_key] = current_page - 1
                st.rerun()
        with col_next:
            if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key=f"{page_key}_next"):
                st.session_state[page_key] = current_page + 1
                st.rerun()

    _render_url_copy(results, lambda item: item.get("url", ""),
                     lambda item: item.get("country", ""), page_key)


def _render_url_copy(results, url_fn, country_fn, key_prefix):
    """URL 목록 복사 expander"""
    with st.expander("URL 목록 복사"):
        seen_copy = set()
        all_list, no_kr_list = [], []
        for item in results:
            raw = url_fn(item)
            if not raw:
                continue
            stripped = _strip_url(raw)
            if stripped in seen_copy:
                continue
            seen_copy.add(stripped)
            all_list.append(stripped)
            if (country_fn(item) or "").upper() != "KR":
                no_kr_list.append(stripped)
        if all_list:
            st.markdown(f"**전체** ({len(all_list)}건)")
            st.code("\n".join(all_list), language=None)
        if no_kr_list and len(no_kr_list) != len(all_list):
            st.markdown(f"**한국 IP 제외** ({len(no_kr_list)}건)")
            st.code("\n".join(no_kr_list), language=None)


# ── 백그라운드 검색 함수 ──


def _adhoc_urlscan_bg(keyword, days, task=None):
    """단건 키워드 URLScan 검색 (DB 미저장)"""
    if task:
        task.set_progress(f"[URLScan] '{keyword}' 검색 중...")
    data = search_by_title(keyword, size=100, days=days)
    results = data.get("results", [])
    if task:
        task.set_progress(f"[URLScan] '{keyword}' 국가 정보 조회 중...")
    _resolve_ip_countries(results, lambda r: r.get("page", {}).get("ip"))
    _resolve_domain_creation_dates(
        results, lambda r: r.get("page", {}).get("domain"),
        task=task, label=f"[URLScan] '{keyword}'",
    )
    return {"source": "urlscan", "adhoc": True,
            "data": {"_adhoc": {"keyword": keyword, "total": len(results), "results": results}}}


def _adhoc_vt_bg(keyword, days, exact_match=True, task=None):
    """단건 키워드 VirusTotal 검색 (DB 미저장)"""
    if task:
        task.set_progress(f"[VirusTotal] '{keyword}' 타이틀 검색 중...")
    results = vt_search_urls_by_title(keyword, days=days, exact_match=exact_match)
    from urllib.parse import urlparse as _urlparse

    def _vt_domain(r):
        try:
            return _urlparse(r.get("url", "")).hostname or "N/A"
        except Exception:
            return "N/A"
    _resolve_domain_creation_dates(
        results, _vt_domain,
        task=task, label=f"[VirusTotal] '{keyword}'",
    )
    return {"source": "virustotal", "adhoc": True,
            "data": {"_adhoc": {"keyword": keyword, "total": len(results), "results": results}}}


def _urlscan_search_bg(keywords_list, days, incremental=True, task=None):
    """등록 키워드 URLScan 검색 (DB 저장)"""
    all_results = {}
    for i, kw in enumerate(keywords_list):
        if task and task.cancelled:
            return None
        mode_label = "신규" if incremental else "전체"
        if task:
            task.set_progress(f"[URLScan/{mode_label}] '{kw['keyword']}' 검색 중... ({i+1}/{len(keywords_list)})")
        try:
            since = _get_since_date(kw["id"], "urlscan") if incremental else None
            data = search_by_title(kw["keyword"], size=100, days=days, since_date=since)
            raw_results = data.get("results", [])
            if incremental:
                seen = get_seen_urls(kw["id"], "urlscan")
                new_results = [r for r in raw_results if r.get("page", {}).get("url", "") not in seen]
            else:
                new_results = raw_results
            if task:
                task.set_progress(f"[URLScan/{mode_label}] '{kw['keyword']}' 국가 정보 조회 중...")
            _resolve_ip_countries(new_results, lambda r: r.get("page", {}).get("ip"))
            _resolve_domain_creation_dates(
                new_results, lambda r: r.get("page", {}).get("domain"),
                task=task, label=f"[URLScan/{mode_label}] '{kw['keyword']}'",
            )
            save_keyword_results(kw["id"], kw["keyword"], "urlscan", len(new_results), new_results[:100])
            all_results[kw["id"]] = {"keyword": kw["keyword"], "total": len(new_results), "results": new_results}
        except Exception as e:
            all_results[kw["id"]] = {"keyword": kw["keyword"], "total": 0, "results": [], "error": str(e)}
        if i < len(keywords_list) - 1:
            time.sleep(1)
    return {"source": "urlscan", "data": all_results}


def _vt_search_bg(keywords_list, days, incremental=True, exact_match=True, task=None):
    """등록 키워드 VirusTotal 검색 (DB 저장)"""
    all_results = {}
    for i, kw in enumerate(keywords_list):
        if task and task.cancelled:
            return None
        mode_label = "신규" if incremental else "전체"
        if task:
            task.set_progress(f"[VirusTotal/{mode_label}] '{kw['keyword']}' 타이틀 검색 중... ({i+1}/{len(keywords_list)})")
        try:
            since = _get_since_date(kw["id"], "virustotal") if incremental else None
            results = vt_search_urls_by_title(kw["keyword"], days=days, since_date=since, exact_match=exact_match)
            if task and task.cancelled:
                return None
            if incremental:
                seen = get_seen_urls(kw["id"], "virustotal")
                new_results = [r for r in results if r.get("url", "") not in seen]
            else:
                new_results = results
            from urllib.parse import urlparse as _urlparse

            def _vt_domain(r):
                try:
                    return _urlparse(r.get("url", "")).hostname or "N/A"
                except Exception:
                    return "N/A"
            _resolve_domain_creation_dates(
                new_results, _vt_domain,
                task=task, label=f"[VirusTotal/{mode_label}] '{kw['keyword']}'",
            )
            save_keyword_results(kw["id"], kw["keyword"], "virustotal", len(new_results), new_results)
            all_results[kw["id"]] = {"keyword": kw["keyword"], "total": len(new_results), "results": new_results}
        except Exception as e:
            all_results[kw["id"]] = {"keyword": kw["keyword"], "total": 0, "results": [], "error": str(e)}
        if i < len(keywords_list) - 1:
            time.sleep(1)
    return {"source": "virustotal", "data": all_results}


def _save_keyword_history(result):
    source = result.get("source", "")
    data = result.get("data", {})
    source_label = "URLScan" if source == "urlscan" else "VirusTotal"
    keywords_str = ", ".join(v["keyword"] for v in data.values())
    total_found = sum(v.get("total", 0) for v in data.values())
    title = f"[키워드/{source_label}] {keywords_str} ({total_found}건)"
    save_history("keyword_monitor", title, result)


# ══════════════════════════════════════════════════════════════
# 섹션 A: 키워드 검색 (검색 먼저 → 등록은 나중에)
# ══════════════════════════════════════════════════════════════

st.markdown("### 키워드 검색")

with st.form("adhoc_search_form"):
    col_kw, col_days = st.columns([3, 1])
    with col_kw:
        adhoc_keyword = st.text_input("키워드", placeholder="검색할 웹사이트 제목 키워드 입력")
    with col_days:
        adhoc_days = st.number_input("조회 기간(일)", min_value=1, max_value=365, value=7)
    col_src, col_match = st.columns([2, 1])
    with col_src:
        adhoc_source = st.radio("검색 소스", ["VirusTotal", "URLScan"], horizontal=True, key="adhoc_src")
    with col_match:
        adhoc_exact = st.checkbox("제목 정확 일치 (VT)", value=True, key="adhoc_exact")
    adhoc_submitted = st.form_submit_button("검색", disabled=queue.is_busy)

if adhoc_submitted and adhoc_keyword.strip():
    st.session_state.pop("adhoc_result", None)
    st.session_state["adhoc_keyword"] = adhoc_keyword.strip()
    kw = adhoc_keyword.strip()
    if adhoc_source == "URLScan":
        task = BackgroundTask(name=f"[검색] URLScan '{kw}'", target=_adhoc_urlscan_bg, args=(kw, adhoc_days))
    else:
        task = BackgroundTask(name=f"[검색] VirusTotal '{kw}'", target=_adhoc_vt_bg, args=(kw, adhoc_days, adhoc_exact))
    queue.add(task)
    st.rerun()

# 검색 결과 표시
if "adhoc_result" in st.session_state:
    result = st.session_state["adhoc_result"]
    adhoc_data = result.get("data", {}).get("_adhoc", {})
    kw_text = adhoc_data.get("keyword", "")
    kw_results = adhoc_data.get("results", [])
    total = adhoc_data.get("total", 0)

    st.markdown(f"#### 검색 결과: {kw_text} ({total}건)")

    if kw_results:
        if result["source"] == "urlscan":
            _render_urlscan_results(kw_results, page_key="adhoc_us_page")
        else:
            _render_vt_results(kw_results, page_key="adhoc_vt_page")

        # 모니터링 등록 버튼
        all_keywords = get_keywords(active_only=True)
        existing_kw = next((kw for kw in all_keywords if kw["keyword"] == kw_text), None)
        if existing_kw:
            last_searched = _to_kst(existing_kw.get("last_searched_at"))
            st.caption(f"'{kw_text}'는 이미 모니터링에 등록되어 있습니다. (최종 검색: {last_searched})")
        else:
            if st.button(f"'{kw_text}' 모니터링에 등록", type="primary"):
                add_keyword(kw_text)
                st.success(f"'{kw_text}' 모니터링 등록 완료")
                st.rerun()
    else:
        st.info("검색 결과가 없습니다.")


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
                st.session_state["adhoc_result"] = last.result
            else:
                st.session_state["kw_last_result"] = last.result
                _save_keyword_history(last.result)
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
        if st.button("취소", key="cancel_current_kw", type="primary"):
            queue.cancel_current()

    if pending:
        st.markdown(f"**대기 중 ({len(pending)}건)**")
        for i, p in enumerate(pending):
            col_name, col_del = st.columns([8, 1])
            with col_name:
                st.caption(f"  {i + 1}. {p.name}")
            with col_del:
                if st.button("취소", key=f"rm_kw_{i}"):
                    queue.remove_pending(i)


_queue_status()


# ══════════════════════════════════════════════════════════════
# 섹션 B: 등록된 키워드 관리 + 재검색
# ══════════════════════════════════════════════════════════════

keywords = get_keywords(active_only=True)

if keywords:
    st.markdown("---")
    st.markdown("### 등록된 키워드")

    for i, kw in enumerate(keywords):
        col_num, col_kw, col_date, col_last, col_del = st.columns([0.5, 3, 2, 2, 1])
        with col_num:
            st.caption(f"{i+1}")
        with col_kw:
            st.markdown(f"**{kw['keyword']}**")
        with col_date:
            st.caption(f"등록: {_to_kst(kw.get('created_at'))}")
        with col_last:
            st.caption(f"검색: {_to_kst(kw.get('last_searched_at'))}")
        with col_del:
            if st.button("삭제", key=f"del_kw_{kw['id']}", type="primary"):
                delete_keyword(kw["id"])
                st.rerun()

    # 재검색 폼
    st.markdown("#### 재검색")
    with st.form("research_form"):
        kw_names = [kw["keyword"] for kw in keywords]
        selected_kws = st.multiselect(
            "검색할 키워드 선택", options=kw_names, default=kw_names,
        )
        col_mode, col_days = st.columns([2, 1])
        with col_mode:
            research_mode = st.radio(
                "검색 모드",
                ["최근 N일 기준", "이전 검색 이후(증분)"],
                horizontal=True,
                key="research_mode",
            )
        with col_days:
            research_days = st.number_input(
                "조회 기간(일)", min_value=1, max_value=365, value=7,
                key="research_days",
                help="증분 모드에서는 무시됩니다",
            )
        col_src, col_match = st.columns([2, 1])
        with col_src:
            research_source = st.radio(
                "검색 소스", ["VirusTotal", "URLScan"],
                horizontal=True, key="research_src",
            )
        with col_match:
            research_exact = st.checkbox("제목 정확 일치 (VT)", value=True, key="research_exact")
        research_submitted = st.form_submit_button("재검색", disabled=queue.is_busy)

    if research_submitted and selected_kws and not queue.is_busy:
        selected_kw_objs = [kw for kw in keywords if kw["keyword"] in selected_kws]
        incremental = research_mode.startswith("이전")
        mode_label = "증분" if incremental else f"{research_days}일"
        days = 365 if incremental else research_days

        if research_source == "URLScan":
            task = BackgroundTask(
                name=f"[재검색] URLScan {mode_label} ({len(selected_kw_objs)}건)",
                target=_urlscan_search_bg,
                args=(selected_kw_objs, days, incremental),
            )
        else:
            task = BackgroundTask(
                name=f"[재검색] VirusTotal {mode_label} ({len(selected_kw_objs)}건)",
                target=_vt_search_bg,
                args=(selected_kw_objs, days, incremental, research_exact),
            )
        queue.add(task)
        st.rerun()

    # ══════════════════════════════════════════════════════════
    # 섹션 C: 등록 키워드 검색 결과 보기
    # ══════════════════════════════════════════════════════════

    st.markdown("---")
    st.markdown("### 검색 결과")

    kw_options = {kw["keyword"]: kw["id"] for kw in keywords}
    selected_kw = st.selectbox("키워드 선택", options=list(kw_options.keys()), key="kw_select")

    if selected_kw:
        selected_id = kw_options[selected_kw]
        tab_urlscan, tab_vt = st.tabs(["\U0001F50D URLScan 결과", "\U0001F310 VirusTotal 결과"])

        with tab_urlscan:
            urlscan_data = get_latest_keyword_results(selected_id, "urlscan")
            if urlscan_data and urlscan_data.get("results"):
                _render_urlscan_results(
                    urlscan_data["results"],
                    searched_at=_to_kst(urlscan_data.get("searched_at")),
                    page_key="kw_us_page",
                )
            else:
                st.info("URLScan 검색 결과가 없습니다.")

        with tab_vt:
            vt_data = get_latest_keyword_results(selected_id, "virustotal")
            if vt_data and vt_data.get("results"):
                _render_vt_results(
                    vt_data["results"],
                    searched_at=_to_kst(vt_data.get("searched_at")),
                    page_key="kw_vt_page",
                )
            else:
                st.info("VirusTotal 검색 결과가 없습니다.")

else:
    st.markdown("---")
    st.info("등록된 모니터링 키워드가 없습니다. 위에서 키워드를 검색한 후 등록하세요.")
