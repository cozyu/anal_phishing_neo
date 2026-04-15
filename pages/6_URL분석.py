"""URL 종합 분석 페이지 — VirusTotal + CriminalIP + URLScan.io"""

import streamlit as st
from url_analyzer import analyze_url
from db import save_history
from background import BackgroundTask, TaskQueue

st.session_state["_current_page"] = "url_analysis"
st.title("🎯 피싱사이트 분석(AI분석)")

st.markdown("""
<style>
    .report-section { font-size: 0.85rem; line-height: 1.5; }
    .report-section h1 { font-size: 1.3rem; }
    .report-section h2 { font-size: 1.15rem; }
    .report-section h3 { font-size: 1.0rem; }
    .report-section p, .report-section li, .report-section td { font-size: 0.85rem; }
    button[data-testid="stBaseButton-primary"] {
        font-size: 0.7rem !important; padding: 0.2rem 0.6rem !important;
    }
    button[data-testid="stBaseButton-secondary"] {
        font-size: 0.65rem !important; padding: 0.15rem 0.5rem !important;
    }
    .verdict-safe { background: #1a472a; border: 1px solid #2d6a4f; border-radius: 8px; padding: 1rem; }
    .verdict-suspicious { background: #4a3800; border: 1px solid #7a6200; border-radius: 8px; padding: 1rem; }
    .verdict-malicious { background: #4a1010; border: 1px solid #7a2020; border-radius: 8px; padding: 1rem; }
    .ioc-block { background: #1e1e2e; border: 1px solid #333; border-radius: 6px; padding: 0.8rem; font-size: 0.8rem; }
</style>
""", unsafe_allow_html=True)

if "url_analysis_queue" not in st.session_state:
    st.session_state["url_analysis_queue"] = TaskQueue()
queue = st.session_state["url_analysis_queue"]


# ---------- 백그라운드 태스크 ----------

def _analyze_bg(url, auto_investigate, task=None):
    """백그라운드 분석 실행"""
    if task and task.cancelled:
        return None
    result = analyze_url(url, auto_investigate=auto_investigate, task=task)
    if result is None:
        return None

    # 이력 저장
    if task:
        task.set_progress("이력 저장 중...")
    verdict_map = {"safe": "안전", "suspicious": "의심", "malicious": "악성"}
    verdict_kr = verdict_map.get(result["verdict"], result["verdict"])
    title = f"[{verdict_kr}] {result['domain']} ({result['score']}점)"
    save_history("url_analysis", title, result)

    return result


# ---------- 입력 폼 ----------

with st.form("url_analysis_form"):
    url_input = st.text_input(
        "분석할 URL",
        placeholder="https://example.com 또는 example.com",
    )
    auto_investigate = st.checkbox("자동 심층 조사 (악성/의심 판정 시)", value=True)
    submitted = st.form_submit_button("🔍 분석 시작", type="primary")

if submitted and url_input:
    name = f"URL 분석: {url_input}"
    task = BackgroundTask(name=name, target=_analyze_bg, args=(url_input, auto_investigate))
    if queue.add(task):
        st.rerun()
    else:
        st.warning("이미 동일한 분석이 진행 중입니다.")


# ---------- 진행 상태 표시 ----------

@st.fragment(run_every="1s")
def _queue_status():
    completed = queue.pop_completed()
    if completed:
        last = completed[-1]
        if last.error:
            st.error(f"분석 오류: {last.error}")
        elif last.result:
            st.session_state["url_analysis_result"] = last.result
        st.rerun(scope="app")
        return

    current = queue.current
    if not current or current.done:
        return

    col_info, col_cancel = st.columns([8, 1])
    with col_info:
        st.info(f"**{current.name}**\n\n{current.progress or '준비 중...'}")
    with col_cancel:
        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        if st.button("취소", key="cancel_analysis", type="primary"):
            queue.cancel_current()

    for i, p in enumerate(queue.pending):
        col_name, col_del = st.columns([8, 1])
        with col_name:
            st.caption(f"⏳ {i + 1}. {p.name}")
        with col_del:
            if st.button("×", key=f"rm_pending_{i}"):
                queue.remove_pending(i)

_queue_status()


# ---------- 결과 렌더링 ----------

def _render_verdict(result):
    """위협 판정 배지 표시"""
    score = result["score"]
    verdict = result["verdict"]
    reasons = result.get("verdict_reasons", [])

    if verdict == "malicious":
        icon, label, css = "🔴", "악성", "verdict-malicious"
    elif verdict == "suspicious":
        icon, label, css = "🟡", "의심", "verdict-suspicious"
    else:
        icon, label, css = "🟢", "안전", "verdict-safe"

    reasons_html = "<br>".join(f"• {r}" for r in reasons[:5])
    st.markdown(f"""
    <div class="{css}">
        <h2 style="margin:0">{icon} {label} — 위협 점수: {score}/100</h2>
        <p style="margin:0.5rem 0 0 0; font-size:0.85rem; opacity:0.9">{reasons_html}</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("")


def _render_overview(result):
    """개요 탭"""
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("#### 도메인 정보")
        cip = result["collected"].get("criminalip", {})
        info = cip.get("main_domain_info", {}) if cip.get("status") == "ok" else {}
        whois_data = result["collected"].get("whois", {})
        whois_info = whois_data.get("data", {}) if whois_data.get("status") == "ok" else {}

        rows = [
            ("도메인", result["domain"]),
            ("URL", result["url"]),
            ("등록일", info.get("domain_created") or whois_info.get("creation_date", "N/A")),
            ("등록기관", info.get("domain_registrar") or whois_info.get("registrar", "N/A")),
            ("페이지 제목", info.get("title", "N/A")),
            ("DGA 점수", str(cip.get("classification", {}).get("dga_score", "N/A")) if cip.get("status") == "ok" else "N/A"),
            ("JARM", f"`{result['iocs'].get('jarm', 'N/A')}`"),
        ]

        # VT 탐지
        vt_url = result["collected"].get("vt_url", {})
        if vt_url.get("status") == "ok":
            stats = vt_url.get("data", {}).get("data", {}).get("attributes", {}).get("stats", {})
            if stats:
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                harm = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = mal + sus + harm + undetected
                rows.append(("VT 탐지", f"🔴 {mal} malicious / 🟡 {sus} suspicious / {total} total"))

        # VT 도메인 평판
        vt_dom = result["collected"].get("vt_domain", {})
        if vt_dom.get("status") == "ok":
            rep = vt_dom.get("reputation")
            dom_stats = vt_dom.get("last_analysis_stats", {})
            if dom_stats:
                rows.append(("VT 도메인 평판", f"점수: {rep}, malicious: {dom_stats.get('malicious', 0)}"))

        md = "| 항목 | 값 |\n|------|-----|\n"
        for label, val in rows:
            md += f"| {label} | {val} |\n"
        st.markdown(md)

    with col2:
        screenshot = result.get("screenshot_url")
        if screenshot:
            st.markdown("#### 스크린샷")
            st.image(screenshot, use_container_width=True)


def _render_infrastructure(result):
    """인프라 탭"""
    cip = result["collected"].get("criminalip", {})
    if cip.get("status") != "ok":
        st.warning("CriminalIP 데이터 없음")
        return

    # DNS
    st.markdown("#### DNS 레코드")
    dns = cip.get("dns_record", {})

    # A 레코드
    a_records = dns.get("dns_record_type_a", {}).get("ipv4", [])
    if a_records:
        md = "**A 레코드 (IPv4)**\n\n| IP | 위험도 |\n|-----|--------|\n"
        for r in a_records:
            md += f"| {r.get('ip', '')} | {r.get('score', '')} |\n"
        st.markdown(md)

    # NS
    ns = dns.get("dns_record_type_ns", [])
    if ns:
        st.markdown(f"**NS**: {', '.join(ns)}")

    # MX
    mx = dns.get("dns_record_type_mx", [])
    if mx:
        mx_flat = [m if isinstance(m, str) else ", ".join(m) for m in mx]
        st.markdown(f"**MX**: {', '.join(mx_flat)}")

    # SSL 인증서
    st.markdown("#### SSL 인증서")
    main_cert = cip.get("main_certificate", {})
    if main_cert:
        md = "| 항목 | 값 |\n|------|-----|\n"
        md += f"| 발급자 | {main_cert.get('issuer', '')} |\n"
        md += f"| 유효기간 | {main_cert.get('startdate', '')} ~ {main_cert.get('enddate', '')} |\n"
        md += f"| 알고리즘 | {main_cert.get('signed_algorithm', '')} |\n"
        st.markdown(md)

    # SSL SAN
    san = result["collected"].get("ssl_san", [])
    if san:
        with st.expander(f"SSL SAN 도메인 ({len(san)}개)"):
            st.code("\n".join(san))

    # 보안 헤더
    st.markdown("#### 보안 헤더")
    headers = cip.get("security_headers", [])
    if headers:
        for h in headers:
            st.markdown(f"- {h}")
    else:
        st.warning("보안 헤더 없음 (HSTS, CSP, X-Frame-Options 등 미설정)")

    # Mapped IP
    mapped = cip.get("mapped_ip", [])
    if mapped:
        st.markdown("#### 매핑된 IP")
        md = "| IP | ASN | 국가 | 위험도 |\n|-----|-----|------|--------|\n"
        for ip in mapped:
            md += f"| {ip.get('ip', '')} | {ip.get('as_name', '')} | {ip.get('country', '')} | {ip.get('score', '')} |\n"
        st.markdown(md)


def _render_phishing_indicators(result):
    """피싱 지표 탭"""
    cip = result["collected"].get("criminalip", {})
    if cip.get("status") != "ok":
        st.warning("CriminalIP 데이터 없음")
        return

    summary = cip.get("summary", {})
    classification = cip.get("classification", {})

    indicators = [
        ("DGA 점수", classification.get("dga_score", "N/A"), "≥5 고위험"),
        ("Google Safe Browsing", classification.get("google_safe_browsing", []) or "없음", "탐지 시 위험"),
        ("파비콘 외부 도메인", summary.get("diff_domain_favicon", "N/A"), "Dangerous=위험"),
        ("난독화 JS", summary.get("js_obfuscated", 0), "≥3 고위험"),
        ("의심 요소", summary.get("suspicious_element", 0), "≥3 고위험"),
        ("SPF", summary.get("spf1", "N/A"), "Fail=위험"),
        ("페이지 경고", summary.get("page_warning", False), "true=경고"),
        ("자격증명 입력", summary.get("cred_input", "N/A"), "Dangerous=위험"),
        ("메일 서버", summary.get("mail_server", False), "true 시 확인 필요"),
        ("숨겨진 요소", summary.get("hidden_element", 0), ">0 의심"),
        ("숨겨진 iframe", summary.get("hidden_iframe", 0), ">0 위험"),
        ("URL 피싱 확률", summary.get("url_phishing_prob", "N/A"), ">0.5 위험"),
        ("피싱 기록", summary.get("phishing_record", 0), ">0 위험"),
        ("리다이렉션 도메인 변경", summary.get("redirection_diff_domain", 0), ">0 의심"),
        ("퓨니코드", summary.get("punycode", False), "true=위험"),
    ]

    md = "| 지표 | 값 | 기준 |\n|------|-----|------|\n"
    for label, val, criteria in indicators:
        val_str = str(val)
        is_danger = False
        if isinstance(val, (int, float)) and val >= 3:
            is_danger = True
        elif val in ("Dangerous", "Fail", True) or (isinstance(val, list) and val):
            is_danger = True
        display = f"**{val_str}**" if is_danger else val_str
        md += f"| {label} | {display} | {criteria} |\n"
    st.markdown(md)


def _render_network(result):
    """네트워크 탭"""
    cip = result["collected"].get("criminalip", {})
    if cip.get("status") != "ok":
        st.warning("CriminalIP 데이터 없음")
        return

    # 연결 국가 / 트래픽
    pni = cip.get("page_networking_info", {})
    if pni:
        col1, col2, col3 = st.columns(3)
        col1.metric("연결 국가", pni.get("connected_countries", "N/A"))
        col2.metric("HTTPS 비율", f"{pni.get('https_percent', 0)}%")
        col3.metric("트래픽", pni.get("transfer_traffic", "N/A"))

    # 연결 도메인/서브도메인
    st.markdown("#### 연결 도메인")
    connected = cip.get("connected_domain_subdomain", [])
    if connected:
        md = "| 메인 도메인 | 서브도메인 |\n|------------|----------|\n"
        for cd in connected:
            main = cd.get("main_domain", {}).get("domain", "")
            subs = ", ".join(s.get("domain", "") for s in cd.get("subdomains", []))
            md += f"| {main} | {subs or '-'} |\n"
        st.markdown(md)

    # 쿠키
    cookies = cip.get("cookies", [])
    if cookies:
        st.markdown("#### 쿠키")
        md = "| 이름 | 도메인 | 만료 | HTTP Only |\n|------|--------|------|----------|\n"
        for c in cookies:
            md += f"| {c.get('name', '')} | {c.get('domain', '')} | {c.get('expires', '')} | {c.get('http_only', '')} |\n"
        st.markdown(md)

    # 추적 픽셀 파라미터
    op = result["iocs"].get("operator_params", {})
    if op:
        st.markdown("#### 추적 픽셀 운영자 파라미터")
        md = "| 파라미터 | 값 |\n|---------|-----|\n"
        for k, v in op.items():
            md += f"| {k} | `{v}` |\n"
        st.markdown(md)


def _render_iocs(result):
    """IOC 탭"""
    iocs = result["iocs"]

    # 도메인
    domains = iocs.get("domains", [])
    if domains:
        st.markdown(f"#### 도메인 ({len(domains)}개)")
        st.code("\n".join(sorted(set(domains))))

    # IP
    ips = iocs.get("ips", [])
    if ips:
        st.markdown(f"#### IP ({len(ips)}개)")
        md = "| IP | ASN | 국가 | 위험도 |\n|-----|-----|------|--------|\n"
        for ip in ips:
            md += f"| {ip.get('ip', '')} | {ip.get('asn', '')} | {ip.get('country', '')} | {ip.get('score', '')} |\n"
        st.markdown(md)

    # JARM
    jarm = iocs.get("jarm")
    if jarm:
        st.markdown("#### JARM 핑거프린트")
        st.code(jarm)

    # SSL SAN
    san = iocs.get("ssl_san_domains", [])
    if san:
        with st.expander(f"SSL SAN 공유 도메인 ({len(san)}개)"):
            st.code("\n".join(san))

    # 쿠키 패턴
    cookies = iocs.get("cookies", [])
    if cookies:
        st.markdown("#### 쿠키 패턴")
        md = "| 이름 | 도메인 |\n|------|--------|\n"
        for c in cookies:
            md += f"| {c.get('name', '')} | {c.get('domain', '')} |\n"
        st.markdown(md)

    # URL 패턴
    patterns = iocs.get("url_patterns", [])
    if patterns:
        st.markdown("#### URL 패턴")
        for p in patterns[:5]:
            st.code(p, language=None)

    # 운영자 파라미터
    op = iocs.get("operator_params", {})
    if op:
        st.markdown("#### 운영자 식별 파라미터")
        md = "| 파라미터 | 값 |\n|---------|-----|\n"
        for k, v in op.items():
            md += f"| {k} | `{v}` |\n"
        st.markdown(md)

    # 전체 복사
    all_iocs = []
    all_iocs.extend(sorted(set(domains)))
    all_iocs.extend([ip.get("ip", "") for ip in ips])
    if jarm:
        all_iocs.append(jarm)
    all_iocs.extend(san)
    if all_iocs:
        st.markdown("---")
        ioc_text = "\n".join(all_iocs)
        st.text_area("전체 IOC (복사용)", ioc_text, height=150)


def _render_related_sites(result):
    """연관사이트 탭"""
    related = result.get("related_sites", {})

    # 확인된 악성
    confirmed = related.get("confirmed_malicious", [])
    if confirmed:
        st.markdown(f"#### 🔴 확인된 악성 사이트 ({len(confirmed)}개)")
        for i, site in enumerate(confirmed):
            col1, col2 = st.columns([6, 1])
            with col1:
                st.markdown(
                    f"**{site['domain']}** — {site['reason']} "
                    f"<span style='font-size:0.75rem; opacity:0.7'>({site.get('source', '')})</span>",
                    unsafe_allow_html=True,
                )
            with col2:
                if st.button("재분석", key=f"reanalyze_mal_{i}", type="secondary"):
                    _start_reanalysis(site["domain"])

    # 조사 필요
    needs = related.get("needs_investigation", [])
    if needs:
        st.markdown(f"#### 🟡 조사 필요 ({len(needs)}개)")
        for i, site in enumerate(needs):
            col1, col2 = st.columns([6, 1])
            with col1:
                st.markdown(
                    f"**{site['domain']}** — {site['reason']} "
                    f"<span style='font-size:0.75rem; opacity:0.7'>({site.get('source', '')})</span>",
                    unsafe_allow_html=True,
                )
            with col2:
                if st.button("재분석", key=f"reanalyze_inv_{i}", type="secondary"):
                    _start_reanalysis(site["domain"])

    # 합법 서비스
    legit = related.get("legitimate", [])
    if legit:
        with st.expander(f"🟢 합법 서비스 ({len(legit)}개)"):
            for site in legit:
                st.markdown(f"- **{site['domain']}** — {site['reason']}")

    if not confirmed and not needs and not legit:
        st.info("연관 사이트 정보 없음")


def _start_reanalysis(domain):
    """연관사이트 재분석 시작"""
    name = f"재분석: {domain}"
    task = BackgroundTask(name=name, target=_analyze_bg, args=(domain, True))
    if queue.add(task):
        st.rerun()
    else:
        st.toast(f"이미 분석 중: {domain}")


def _render_ai_report(result):
    """AI 보고서 탭"""
    report = result.get("ai_report", "")
    model = result.get("ai_model")

    if model:
        st.caption(f"Gemini 모델: {model}")

    if report:
        st.markdown(f'<div class="report-section">{report}</div>', unsafe_allow_html=True)
    else:
        st.warning("AI 보고서 없음")


# ---------- 메인 결과 표시 ----------

if "url_analysis_result" in st.session_state:
    result = st.session_state["url_analysis_result"]

    # 위협 판정 배지
    _render_verdict(result)

    # 탭 구성
    tab_overview, tab_infra, tab_phishing, tab_network, tab_ioc, tab_related, tab_ai = st.tabs([
        "📋 개요", "🏗️ 인프라", "⚠️ 피싱지표", "🌐 네트워크", "🔍 IOC", "🔗 연관사이트", "📊 AI 보고서"
    ])

    with tab_overview:
        _render_overview(result)
    with tab_infra:
        _render_infrastructure(result)
    with tab_phishing:
        _render_phishing_indicators(result)
    with tab_network:
        _render_network(result)
    with tab_ioc:
        _render_iocs(result)
    with tab_related:
        _render_related_sites(result)
    with tab_ai:
        _render_ai_report(result)
