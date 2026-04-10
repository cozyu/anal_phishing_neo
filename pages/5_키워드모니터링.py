"""키워드 모니터링 (urlscan.io 타이틀 검색 + VirusTotal 도메인 검색) 페이지"""

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
st.title("\U0001F511 도메인 모니터링(URL)")

st.markdown("""
<style>
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
    .kw-table th, .kw-table td {
        font-size: 0.85rem; padding: 0.3rem 0.6rem;
    }
</style>
""", unsafe_allow_html=True)

if "keyword_queue" not in st.session_state:
    st.session_state["keyword_queue"] = TaskQueue()

queue = st.session_state["keyword_queue"]


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
    """URL 후행 / 제거"""
    return url.rstrip("/")


# ── 백그라운드 검색 함수 ──


def _get_since_date(kw_id, source):
    """이전 검색 기록이 있으면 마지막 검색일 -1일을 YYYY-MM-DD 형식으로 반환.
    URLScan은 date:> (초과)이므로 하루 빼서 당일 포함 처리."""
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
    """결과 목록에서 IP를 추출하여 ip-api.com 배치 API로 국가 조회 후 매핑"""
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
            # urlscan 결과는 page 하위에 country를 저장
            if "page" in r:
                r["page"]["country"] = ip_country[ip]
            else:
                r["country"] = ip_country.get(ip, "N/A")


def _resolve_domain_creation_dates(results_list, domain_key_fn, task=None, label=""):
    """결과 목록에서 도메인을 추출하여 python-whois로 등록일 조회 후 매핑"""
    import whois as _whois
    domain_set = set()
    for r in results_list:
        domain = domain_key_fn(r)
        if domain and domain != "N/A":
            domain_set.add(domain)
    if not domain_set:
        return
    domain_dates = {}
    for i, domain in enumerate(domain_set):
        if task and task.cancelled:
            return
        if task and label:
            task.set_progress(f"{label} 도메인 등록일 조회 중... ({i+1}/{len(domain_set)})")
        try:
            w = _whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                domain_dates[domain] = str(creation_date)[:10]
            else:
                domain_dates[domain] = "N/A"
        except Exception:
            domain_dates[domain] = "N/A"
        time.sleep(0.3)
    for r in results_list:
        domain = domain_key_fn(r)
        if domain and domain in domain_dates:
            if "page" in r:
                r["page"]["creation_date"] = domain_dates[domain]
            else:
                r["creation_date"] = domain_dates.get(domain, "N/A")


def _urlscan_search_bg(keywords_list, days, incremental=True, task=None):
    """URLScan 키워드 검색. incremental=True이면 마지막 검색 이후 신규만."""
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
            # IP → 국가 조회
            if task:
                task.set_progress(f"[URLScan/{mode_label}] '{kw['keyword']}' 국가 정보 조회 중...")
            _resolve_ip_countries(new_results, lambda r: r.get("page", {}).get("ip"))
            # 도메인 등록일 조회
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
    """VirusTotal 키워드 타이틀 검색. incremental=True이면 마지막 검색 이후 신규만."""
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
            # 도메인 등록일 조회
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


# ── 섹션 1: 키워드 등록 ──

with st.form("keyword_form"):
    new_kw = st.text_input("키워드 등록", placeholder="웹사이트 제목 키워드 입력")
    submitted = st.form_submit_button("등록")

if submitted and new_kw:
    result = add_keyword(new_kw.strip())
    if result:
        st.success(f"키워드 '{new_kw.strip()}' 등록 완료")
        st.rerun()
    else:
        st.error("키워드 등록 실패 (Supabase 미설정)")

# ── 섹션 2: 등록된 키워드 목록 + 검색 ──

keywords = get_keywords(active_only=True)

if keywords:
    st.markdown("---")
    st.markdown("### 등록된 키워드")

    # 키워드 테이블
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

    # 검색 폼 (st.form으로 중복 호출 방지)
    with st.form("kw_search_form"):
        col_mode, col_days = st.columns([2, 1])
        with col_mode:
            search_mode = st.radio(
                "검색 모드",
                ["신규만 (마지막 검색 이후)", "전체 (기간 지정)"],
                horizontal=True,
                key="kw_mode",
            )
        with col_days:
            days = st.number_input(
                "조회 기간 (일)", min_value=1, max_value=365, value=14,
                key="kw_days",
            )

        col_source, col_match = st.columns([2, 1])
        with col_source:
            search_source = st.radio(
                "검색 소스",
                ["URLScan", "VirusTotal"],
                horizontal=True,
                key="kw_source",
            )
        with col_match:
            exact_match = st.checkbox(
                "제목 정확 일치 (VT)",
                value=True,
                key="kw_exact_match",
            )
        search_submitted = st.form_submit_button(
            "검색", disabled=queue.is_busy,
        )

    if search_submitted and not queue.is_busy and not queue.pending:
        incremental = search_mode.startswith("신규")
        mode_label = "신규" if incremental else "전체"
        if search_source == "URLScan":
            task = BackgroundTask(
                name=f"URLScan {mode_label} 검색 ({len(keywords)}건)",
                target=_urlscan_search_bg,
                args=(keywords, days, incremental),
            )
        else:
            task = BackgroundTask(
                name=f"VirusTotal {mode_label} 검색 ({len(keywords)}건)",
                target=_vt_search_bg,
                args=(keywords, days, incremental, exact_match),
            )
        queue.add(task)
        st.rerun()
else:
    st.info("등록된 키워드가 없습니다. 위에서 키워드를 등록하세요.")


def _save_keyword_history(result):
    """키워드 검색 결과를 분석이력에 저장"""
    source = result.get("source", "")
    data = result.get("data", {})
    source_label = "URLScan" if source == "urlscan" else "VirusTotal"
    keywords_str = ", ".join(v["keyword"] for v in data.values())
    total_found = sum(v.get("total", 0) for v in data.values())
    title = f"[키워드/{source_label}] {keywords_str} ({total_found}건)"
    save_history("keyword_monitor", title, result)


# ── 작업 큐 상태 (fragment) ──

@st.fragment(run_every="1s")
def _queue_status():
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"검색 오류: {last.error}")
        elif last.result:
            st.session_state["kw_last_result"] = last.result
            # 분석이력에 저장
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


# ── 섹션 3: 검색 결과 표시 ──

if keywords:
    st.markdown("---")
    st.markdown("### 검색 결과")

    kw_options = {kw["keyword"]: kw["id"] for kw in keywords}
    selected_kw = st.selectbox("키워드 선택", options=list(kw_options.keys()), key="kw_select")

    if selected_kw:
        selected_id = kw_options[selected_kw]

        tab_urlscan, tab_vt = st.tabs(["\U0001F50D URLScan 결과", "\U0001F310 VirusTotal 결과"])

        PAGE_SIZE = 20

        # ── URLScan 탭 ──
        with tab_urlscan:
            urlscan_data = get_latest_keyword_results(selected_id, "urlscan")
            if urlscan_data and urlscan_data.get("results"):
                results = urlscan_data["results"]
                # 스캔일 기준 내림차순 정렬
                results.sort(
                    key=lambda x: x.get("task", {}).get("time", ""),
                    reverse=True,
                )
                total = urlscan_data.get("total_found", len(results))
                searched_at = _to_kst(urlscan_data.get("searched_at"))
                st.caption(f"검색 시각: {searched_at} | 결과: {total}건 (표시: {len(results)}건)")

                # 페이지네이션
                current_page = st.session_state.get("kw_us_page", 0)
                total_pages = max(1, (len(results) + PAGE_SIZE - 1) // PAGE_SIZE)
                start = current_page * PAGE_SIZE
                end = min(start + PAGE_SIZE, len(results))
                page_items = results[start:end]

                # 테이블 헤더
                header = "| # | URL | 도메인 | 페이지 제목 | IP | 국가 | 등록일 | 스캔일시 |\n|---|-----|--------|------------|----|----|------|--------|\n"
                rows = ""
                for idx, item in enumerate(page_items, start=start + 1):
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

                # 페이지네이션 컨트롤
                if total_pages > 1:
                    st.caption(f"페이지 {current_page + 1} / {total_pages}")
                    col_prev, _, col_next = st.columns([1, 2, 1])
                    with col_prev:
                        if st.button("\u25C0 이전", disabled=current_page <= 0, key="us_prev"):
                            st.session_state["kw_us_page"] = current_page - 1
                            st.rerun()
                    with col_next:
                        if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key="us_next"):
                            st.session_state["kw_us_page"] = current_page + 1
                            st.rerun()

                # URL 목록 복사 (중복 제거)
                with st.expander("URL 목록 복사"):
                    seen_copy = set()
                    all_list, no_kr_list = [], []
                    for item in results:
                        raw = item.get("page", {}).get("url", "")
                        if not raw:
                            continue
                        stripped = _strip_url(raw)
                        if stripped in seen_copy:
                            continue
                        seen_copy.add(stripped)
                        all_list.append(stripped)
                        if item.get("page", {}).get("country", "").upper() != "KR":
                            no_kr_list.append(stripped)
                    if all_list:
                        st.markdown(f"**전체** ({len(all_list)}건)")
                        st.code("\n".join(all_list), language=None)
                    if no_kr_list and len(no_kr_list) != len(all_list):
                        st.markdown(f"**한국 IP 제외** ({len(no_kr_list)}건)")
                        st.code("\n".join(no_kr_list), language=None)
            else:
                st.info("URLScan 검색 결과가 없습니다. 'URLScan 전체 검색' 버튼을 눌러주세요.")

        # ── VirusTotal 탭 ──
        with tab_vt:
            vt_data = get_latest_keyword_results(selected_id, "virustotal")
            if vt_data and vt_data.get("results"):
                results = vt_data["results"]
                # 분석일 기준 내림차순 정렬
                results.sort(
                    key=lambda x: x.get("last_analysis_date", "") if x.get("last_analysis_date", "") != "N/A" else "",
                    reverse=True,
                )
                total = vt_data.get("total_found", len(results))
                searched_at = _to_kst(vt_data.get("searched_at"))
                st.caption(f"검색 시각: {searched_at} | 결과: {total}건")

                # 페이지네이션
                current_page = st.session_state.get("kw_vt_page", 0)
                total_pages = max(1, (len(results) + PAGE_SIZE - 1) // PAGE_SIZE)
                start = current_page * PAGE_SIZE
                end = min(start + PAGE_SIZE, len(results))
                page_items = results[start:end]

                # 테이블
                header = "| # | URL | 페이지 제목 | IP | 국가 | 등록일 | 최종 분석일 |\n|---|-----|-----------|----|----|------|----------|\n"
                rows = ""
                for idx, item in enumerate(page_items, start=start + 1):
                    url = (item.get("url") or "N/A").replace("|", "\\|")
                    title = (item.get("title") or "N/A").replace("|", "\\|")[:50]
                    ip = item.get("ip", "N/A")
                    country = item.get("country", "N/A")
                    creation_date = item.get("creation_date", "N/A")
                    analysis_date = item.get("last_analysis_date", "N/A")
                    rows += f"| {idx} | {url[:80]} | {title} | {ip} | {country} | {creation_date} | {analysis_date} |\n"
                st.markdown(header + rows)

                # 페이지네이션 컨트롤
                if total_pages > 1:
                    st.caption(f"페이지 {current_page + 1} / {total_pages}")
                    col_prev, _, col_next = st.columns([1, 2, 1])
                    with col_prev:
                        if st.button("\u25C0 이전", disabled=current_page <= 0, key="vt_prev"):
                            st.session_state["kw_vt_page"] = current_page - 1
                            st.rerun()
                    with col_next:
                        if st.button("다음 \u25B6", disabled=current_page >= total_pages - 1, key="vt_next"):
                            st.session_state["kw_vt_page"] = current_page + 1
                            st.rerun()

                # URL 목록 복사 (중복 제거)
                with st.expander("URL 목록 복사"):
                    seen_copy = set()
                    all_list, no_kr_list = [], []
                    for item in results:
                        raw = item.get("url", "")
                        if not raw:
                            continue
                        stripped = _strip_url(raw)
                        if stripped in seen_copy:
                            continue
                        seen_copy.add(stripped)
                        all_list.append(stripped)
                        if item.get("country", "").upper() != "KR":
                            no_kr_list.append(stripped)
                    if all_list:
                        st.markdown(f"**전체** ({len(all_list)}건)")
                        st.code("\n".join(all_list), language=None)
                    if no_kr_list and len(no_kr_list) != len(all_list):
                        st.markdown(f"**한국 IP 제외** ({len(no_kr_list)}건)")
                        st.code("\n".join(no_kr_list), language=None)
            else:
                st.info("VirusTotal 검색 결과가 없습니다. 'VirusTotal 전체 검색' 버튼을 눌러주세요.")
