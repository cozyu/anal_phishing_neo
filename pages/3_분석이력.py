"""분석 이력 페이지"""

from datetime import datetime, timezone, timedelta

import streamlit as st
from db import get_history_list, get_history_detail, delete_history
from config import get_config

KST = timezone(timedelta(hours=9))

st.title("\U0001F4CB 결과 다시보기")

st.markdown("""
<style>
    .history-table { font-size: 0.85rem; }
    .history-table td, .history-table th { white-space: nowrap; }
    .history-table td:nth-child(2) { white-space: normal; word-break: break-all; max-width: 320px; }
    .history-table td:nth-child(3), .history-table td:nth-child(4) { white-space: normal; word-break: break-word; max-width: 200px; }
    .history-table td:nth-child(6), .history-table td:nth-child(7) { white-space: nowrap; }
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

    elif category == "similar":
        st.markdown(f"**대상 URL**: `{data.get('url', 'N/A')}` | **유사도 기준**: {data.get('threshold', 'N/A')}% | **결과**: {data.get('total', 0)}건")

        similar_results = data.get("results", [])
        if similar_results:
            table_md = "| # | 도메인 | URL | IP | 국가 | 스캔시각 |\n"
            table_md += "|---|--------|-----|-----|------|--------|\n"
            for i, item in enumerate(similar_results):
                page_info = item.get("page", {})
                task_info = item.get("task", {})
                domain = _esc(page_info.get("domain", "N/A"))
                page_url = _esc(page_info.get("url", "N/A"))
                if len(page_url) > 60:
                    page_url = page_url[:57] + "..."
                ip = _esc(page_info.get("ip", "N/A"))
                country = _esc(page_info.get("country", "N/A"))
                scan_time = _to_kst(task_info.get("time", ""))
                table_md += f"| {i+1} | {domain} | {page_url} | {ip} | {country} | {scan_time} |\n"
            st.markdown(f"<div class='history-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)
        else:
            st.info("유사 사이트 결과가 없습니다.")

        return True

    elif category == "url_analysis":
        # 위협 판정 배지
        score = data.get("score", 0)
        verdict = data.get("verdict", "")
        reasons = data.get("verdict_reasons", [])
        if verdict == "malicious":
            icon, label, css_bg = "🔴", "악성", "#4a1010"
        elif verdict == "suspicious":
            icon, label, css_bg = "🟡", "의심", "#4a3800"
        else:
            icon, label, css_bg = "🟢", "안전", "#1a472a"
        reasons_html = "<br>".join(f"• {r}" for r in reasons[:5])
        st.markdown(
            f"<div style='background:{css_bg}; border-radius:8px; padding:1rem; margin-bottom:1rem;'>"
            f"<h3 style='margin:0'>{icon} {label} — 위협 점수: {score}/100</h3>"
            f"<p style='font-size:0.85rem; opacity:0.9; margin:0.5rem 0 0 0'>{reasons_html}</p></div>",
            unsafe_allow_html=True,
        )

        # 탭 구성
        tab_overview, tab_ioc, tab_related, tab_ai = st.tabs(["📋 개요", "🔍 IOC", "🔗 연관사이트", "📊 AI 보고서"])

        with tab_overview:
            collected = data.get("collected", {})
            cip = collected.get("criminalip", {})
            info = cip.get("main_domain_info", {}) if cip.get("status") == "ok" else {}
            whois_info = collected.get("whois", {}).get("data", {}) if collected.get("whois", {}).get("status") == "ok" else {}
            rows = [
                ("도메인", data.get("domain", "")),
                ("URL", data.get("url", "")),
                ("등록일", info.get("domain_created") or whois_info.get("creation_date", "N/A")),
                ("등록기관", info.get("domain_registrar") or whois_info.get("registrar", "N/A")),
            ]
            vt_url = collected.get("vt_url", {})
            if vt_url.get("status") == "ok":
                stats = vt_url.get("data", {}).get("data", {}).get("attributes", {}).get("stats", {})
                if stats:
                    rows.append(("VT 탐지", f"malicious={stats.get('malicious', 0)}, suspicious={stats.get('suspicious', 0)}"))
            md = "| 항목 | 값 |\n|------|-----|\n"
            for label_text, val in rows:
                md += f"| {label_text} | {_esc(val)} |\n"
            st.markdown(md)

            screenshot = data.get("screenshot_url")
            if screenshot:
                st.image(screenshot, width=400)

        with tab_ioc:
            iocs = data.get("iocs", {})
            domains_ioc = iocs.get("domains", [])
            if domains_ioc:
                st.markdown(f"**도메인 ({len(domains_ioc)}개)**")
                st.code("\n".join(sorted(set(domains_ioc))))
            ips_ioc = iocs.get("ips", [])
            if ips_ioc:
                st.markdown(f"**IP ({len(ips_ioc)}개)**")
                ip_md = "| IP | ASN | 국가 | 위험도 |\n|-----|-----|------|--------|\n"
                for ip in ips_ioc:
                    ip_md += f"| {ip.get('ip', '')} | {ip.get('asn', '')} | {ip.get('country', '')} | {ip.get('score', '')} |\n"
                st.markdown(ip_md)
            jarm = iocs.get("jarm")
            if jarm:
                st.markdown("**JARM**")
                st.code(jarm)
            san = iocs.get("ssl_san_domains", [])
            if san:
                with st.expander(f"SSL SAN 공유 도메인 ({len(san)}개)"):
                    st.code("\n".join(san))
            op = iocs.get("operator_params", {})
            if op:
                st.markdown("**운영자 파라미터**")
                op_md = "| 파라미터 | 값 |\n|---------|-----|\n"
                for k, v in op.items():
                    op_md += f"| {k} | `{v}` |\n"
                st.markdown(op_md)

        with tab_related:
            related = data.get("related_sites", {})
            confirmed = related.get("confirmed_malicious", [])
            if confirmed:
                st.markdown(f"**🔴 확인된 악성 ({len(confirmed)}개)**")
                for s in confirmed:
                    st.markdown(f"- **{s['domain']}** — {s['reason']}")
            needs = related.get("needs_investigation", [])
            if needs:
                st.markdown(f"**🟡 조사 필요 ({len(needs)}개)**")
                for s in needs:
                    st.markdown(f"- **{s['domain']}** — {s['reason']}")
            legit = related.get("legitimate", [])
            if legit:
                with st.expander(f"🟢 합법 서비스 ({len(legit)}개)"):
                    for s in legit:
                        st.markdown(f"- {s['domain']} — {s['reason']}")
            if not confirmed and not needs and not legit:
                st.info("연관 사이트 정보 없음")

        with tab_ai:
            ai_model = data.get("ai_model")
            if ai_model:
                st.caption(f"Gemini 모델: {ai_model}")
            ai_report = data.get("ai_report", "")
            if ai_report:
                st.markdown(f"<div class='report-section'>\n\n{ai_report}\n\n</div>", unsafe_allow_html=True)
            else:
                st.warning("AI 보고서 없음")

        return True

    elif category == "bulk_scan":
        st.markdown(
            f"**전체**: {data.get('total', 0)}건 | "
            f"**스캔 제출**: {data.get('submitted', 0)}건 | "
            f"**이력 있음**: {data.get('skipped', 0)}건 | "
            f"**실패**: {data.get('failed', 0)}건"
        )
        bulk_results = data.get("results", [])
        if bulk_results:
            table_md = "| # | URL | 상태 | 링크 |\n"
            table_md += "|---|-----|------|------|\n"
            for i, r in enumerate(bulk_results, 1):
                url_display = _esc(r.get("url", ""))
                if len(url_display) > 60:
                    url_display = url_display[:57] + "..."
                uuid = r.get("uuid")
                link = f"[보기](https://pro.urlscan.io/result/{uuid}/)" if uuid else _esc(r.get("error") or "-")
                table_md += f"| {i} | {url_display} | {_esc(r.get('status', ''))} | {link} |\n"
            st.markdown(f"<div class='history-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)
        else:
            st.info("결과가 없습니다.")
        return True

    elif category == "keyword_monitor":
        source = data.get("source", "")
        source_label = "URLScan" if source == "urlscan" else "VirusTotal"
        kw_data = data.get("data", {})
        total_found = sum(v.get("total", 0) for v in kw_data.values())
        st.markdown(f"**검색 소스**: {source_label} | **총 결과**: {total_found}건")

        for kw_id, kw_info in kw_data.items():
            keyword = kw_info.get("keyword", "N/A")
            kw_total = kw_info.get("total", 0)
            kw_results = kw_info.get("results", [])
            error = kw_info.get("error")

            st.markdown(f"#### {keyword} ({kw_total}건)")
            if error:
                st.error(f"오류: {error}")
                continue
            if not kw_results:
                st.info("결과 없음")
                continue

            # 최종분석일/스캔일 기준 내림차순 정렬
            if source == "urlscan":
                kw_results.sort(
                    key=lambda x: x.get("task", {}).get("time", ""),
                    reverse=True,
                )
            else:
                kw_results.sort(
                    key=lambda x: x.get("last_analysis_date", "") if x.get("last_analysis_date", "") not in ("N/A", "") else "",
                    reverse=True,
                )

            if source == "urlscan":
                table_md = "| # | URL | 도메인 | 페이지 제목 | IP | 국가 | 등록일 | 스캔일시 |\n"
                table_md += "|---|-----|--------|------------|----|----|------|--------|\n"
                for idx, item in enumerate(kw_results, 1):
                    page_info = item.get("page", {})
                    task_info = item.get("task", {})
                    url = _esc(page_info.get("url", "N/A"))[:60]
                    domain = _esc(page_info.get("domain", "N/A"))
                    title_text = _esc((page_info.get("title") or "N/A")[:50])
                    ip = _esc(page_info.get("ip", "N/A"))
                    country = _esc(page_info.get("country", "N/A"))
                    creation_date = _esc(page_info.get("creation_date", "N/A"))
                    scan_time = _to_kst(task_info.get("time", ""))
                    table_md += f"| {idx} | {url} | {domain} | {title_text} | {ip} | {country} | {creation_date} | {scan_time} |\n"
            else:
                table_md = "| # | URL | 페이지 제목 | IP | 국가 | 등록일 | 최종 분석일 |\n"
                table_md += "|---|-----|-----------|----|----|------|----------|\n"
                for idx, item in enumerate(kw_results, 1):
                    url = _esc((item.get("url") or "N/A"))[:80]
                    title_text = _esc((item.get("title") or "N/A")[:50])
                    ip = _esc(item.get("ip", "N/A"))
                    country = _esc(item.get("country", "N/A"))
                    creation_date = _esc(item.get("creation_date", "N/A"))
                    analysis_date = _esc(item.get("last_analysis_date", "N/A"))
                    table_md += f"| {idx} | {url} | {title_text} | {ip} | {country} | {creation_date} | {analysis_date} |\n"

            st.markdown(f"<div class='history-table'>\n\n{table_md}\n\n</div>", unsafe_allow_html=True)

        return True

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
        seq = item.get("seq", "")
        col_num, col_title, col_date, col_actions = st.columns([0.5, 4, 2, 2])
        with col_num:
            st.text(f"#{seq}" if seq else "-")
        with col_title:
            title_text = item['title']
            if len(title_text) > 60:
                title_text = title_text[:57] + "..."
            st.markdown(f"**{title_text}**")
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
    for _k in ["view_compare_id", "view_domains_id", "view_similar_id", "view_url_analysis_id", "view_bulk_scan_id", "view_keyword_monitor_id"]:
        st.session_state.pop(_k, None)


_CATEGORY_LABELS = {
    "domains": "도메인 검색 및 모니터링(URL)",
    "keyword_monitor": "도메인 검색 및 모니터링(Title)",
    "similar": "유사 사이트 검색(DOM기반)",
    "url_analysis": "피싱사이트 분석(자동분석)",
    "compare": "피싱사이트 분석(수동분석)",
    "bulk_scan": "피싱사이트 분석(URLScan)",
}

selected = st.radio(
    "카테고리",
    options=list(_CATEGORY_LABELS.keys()),
    format_func=lambda x: _CATEGORY_LABELS[x],
    horizontal=True,
    key="history_tab",
    on_change=_on_tab_change,
    label_visibility="collapsed",
)

if not _render_detail(selected):
    _render_list(selected)
