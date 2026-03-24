"""피싱 사이트 비교 분석 엔진 + Gemini AI 호출"""

import json
from difflib import SequenceMatcher
from urllib.parse import urlparse

import yaml
from google import genai

from config import get_config
from api_logger import log_request, log_response, log_error

GEMINI_MODELS = [
    "gemini-3.0-flash",
    "gemini-2.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash-lite",
]


def load_prompt_config():
    with open("prompt_config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def extract_metadata(scan_data):
    """urlscan.io 결과에서 핵심 메타데이터 추출"""
    page = scan_data.get("page", {})
    task = scan_data.get("task", {})
    lists = scan_data.get("lists", {})

    # 인증서 상세 정보 추출
    certs = []
    seen_subjects = set()
    for req in scan_data.get("data", {}).get("requests", []):
        security = (
            req.get("response", {}).get("response", {}).get("securityDetails", {})
        )
        if security and security.get("issuer"):
            subject = security.get("subjectName", "")
            if subject in seen_subjects:
                continue
            seen_subjects.add(subject)

            # SAN 목록 추출
            san_list = security.get("sanList", [])

            cert = {
                "issuer": security.get("issuer", ""),
                "subject": subject,
                "protocol": security.get("protocol", ""),
                "validFrom": security.get("validFrom", 0),
                "validTo": security.get("validTo", 0),
                "keyExchange": security.get("keyExchange", ""),
                "keyExchangeGroup": security.get("keyExchangeGroup", ""),
                "cipher": security.get("cipher", ""),
                "signedCertificateTimestampList": security.get("signedCertificateTimestampList", []),
                "sanList": san_list,
            }
            certs.append(cert)

    # 기술 스택 추출
    techs = []
    wappa = scan_data.get("meta", {}).get("processors", {}).get("wappa", {})
    for t in wappa.get("data", []):
        techs.append({
            "app": t.get("app", ""),
            "categories": [c.get("name", "") for c in t.get("categories", [])],
        })

    # IPv4만 사용
    ipv4_list = [ip for ip in lists.get("ips", []) if ":" not in ip]
    main_ip = page.get("ip", "")
    if ":" in main_ip:  # 메인 IP가 IPv6이면 IPv4 목록에서 대체
        main_ip = ipv4_list[0] if ipv4_list else ""

    return {
        "url": task.get("url", ""),
        "scan_time": task.get("time", ""),
        "domain": page.get("domain", ""),
        "ip": main_ip,
        "country": page.get("country", ""),
        "server": page.get("server", ""),
        "title": page.get("title", ""),
        "asn": page.get("asn", ""),
        "asnname": page.get("asnname", ""),
        "ips": ipv4_list,
        "domains": lists.get("domains", []),
        "hashes": lists.get("hashes", []),
        "urls": lists.get("urls", []),
        "certificates": certs,
        "technologies": techs,
    }


def _format_cert_validity(cert):
    """인증서 유효기간 포맷"""
    from datetime import datetime, timezone
    try:
        valid_from = datetime.fromtimestamp(cert["validFrom"], tz=timezone.utc).strftime("%Y-%m-%d")
        valid_to = datetime.fromtimestamp(cert["validTo"], tz=timezone.utc).strftime("%Y-%m-%d")
        days = (datetime.fromtimestamp(cert["validTo"], tz=timezone.utc) -
                datetime.fromtimestamp(cert["validFrom"], tz=timezone.utc)).days
        return valid_from, valid_to, days
    except (ValueError, OSError):
        return "N/A", "N/A", 0


def _is_free_cert(issuer):
    """무료 인증서 여부 판별"""
    free_issuers = ["let's encrypt", "zerossl", "buypass", "ssl.com", "cloudflare"]
    return any(fi in issuer.lower() for fi in free_issuers)


def compare_sites(meta1, meta2):
    """규칙 기반 비교 분석"""
    results = []
    score = 0
    max_score = 0

    def add(name, status, site1, site2, points, max_pts):
        nonlocal score, max_score
        results.append({"name": name, "status": status, "site1": site1, "site2": site2, "points": points})
        score += points
        max_score += max_pts

    # 도메인
    if meta1["domain"] == meta2["domain"]:
        add("도메인", "일치", meta1["domain"], meta2["domain"], 10, 10)
    else:
        sim = SequenceMatcher(None, meta1["domain"], meta2["domain"]).ratio()
        add("도메인", f"유사도 {sim:.0%}", meta1["domain"], meta2["domain"], int(sim * 10), 10)

    # IP (IPv4만)
    if meta1["ip"] and meta2["ip"] and meta1["ip"] == meta2["ip"]:
        add("IP (IPv4)", "일치", meta1["ip"], meta2["ip"], 10, 10)
    else:
        shared = set(meta1["ips"]) & set(meta2["ips"])
        if shared:
            shared_str = ", ".join(list(shared)[:5])
            add("IP (IPv4)", "공유 IP 존재", f'{meta1.get("ip", "N/A")} (공유: {shared_str})', meta2.get("ip", "N/A"), 5, 10)
        else:
            add("IP (IPv4)", "불일치", meta1.get("ip", "N/A"), meta2.get("ip", "N/A"), 0, 10)

    # ASN
    asn1 = f'{meta1.get("asn", "N/A")} ({meta1.get("asnname", "")})' if meta1.get("asn") else "N/A"
    asn2 = f'{meta2.get("asn", "N/A")} ({meta2.get("asnname", "")})' if meta2.get("asn") else "N/A"
    if meta1["asn"] and meta2["asn"] and meta1["asn"] == meta2["asn"]:
        add("ASN", "일치", asn1, asn2, 10, 10)
    else:
        add("ASN", "불일치", asn1, asn2, 0, 10)

    # 서버
    if meta1["server"] and meta2["server"] and meta1["server"] == meta2["server"]:
        add("서버", "일치", meta1["server"], meta2["server"], 10, 10)
    else:
        add("서버", "불일치", meta1.get("server", "N/A"), meta2.get("server", "N/A"), 0, 10)

    # 국가
    if meta1["country"] and meta2["country"] and meta1["country"] == meta2["country"]:
        add("국가", "일치", meta1["country"], meta2["country"], 5, 5)
    else:
        add("국가", "불일치", meta1.get("country", "N/A"), meta2.get("country", "N/A"), 0, 5)

    # 페이지 제목
    if meta1["title"] and meta2["title"]:
        sim = SequenceMatcher(None, meta1["title"], meta2["title"]).ratio()
        add("페이지 제목", f"유사도 {sim:.0%}", meta1["title"], meta2["title"], int(sim * 10), 10)
    else:
        add("페이지 제목", "정보 없음", meta1.get("title", "N/A"), meta2.get("title", "N/A"), 0, 10)

    # URL 경로
    path1 = urlparse(meta1["url"]).path
    path2 = urlparse(meta2["url"]).path
    sim = SequenceMatcher(None, path1, path2).ratio()
    add("URL 경로", f"유사도 {sim:.0%}", path1 or "/", path2 or "/", int(sim * 10), 10)

    # 공유 리소스 해시
    h1, h2 = set(meta1["hashes"]), set(meta2["hashes"])
    shared_hashes = h1 & h2
    total = max(len(h1), len(h2), 1)
    if shared_hashes:
        ratio = len(shared_hashes) / total
        add("공유 리소스 해시", f"{len(shared_hashes)}개 일치", f"{len(h1)}개", f"{len(h2)}개 (공유 {ratio:.0%})", min(int(ratio * 15), 15), 15)
    else:
        add("공유 리소스 해시", "없음", f"{len(h1)}개", f"{len(h2)}개", 0, 15)

    # 기술 스택
    t1 = {t["app"] for t in meta1.get("technologies", []) if t.get("app")}
    t2 = {t["app"] for t in meta2.get("technologies", []) if t.get("app")}
    shared_techs = t1 & t2
    if shared_techs:
        ratio = len(shared_techs) / max(len(t1), len(t2), 1)
        add("기술 스택", f"{len(shared_techs)}개 일치", ", ".join(sorted(t1)), ", ".join(sorted(t2)), min(int(ratio * 10), 10), 10)
    else:
        add("기술 스택", "공유 없음", ", ".join(sorted(t1)) or "N/A", ", ".join(sorted(t2)) or "N/A", 0, 10)

    # 인증서 상세 비교
    c1_list = meta1.get("certificates", [])
    c2_list = meta2.get("certificates", [])
    if c1_list and c2_list:
        c1, c2 = c1_list[0], c2_list[0]

        # 발급자 비교
        if c1["issuer"] == c2["issuer"]:
            add("인증서 발급자", "일치", c1["issuer"], c2["issuer"], 5, 5)
        else:
            add("인증서 발급자", "불일치", c1["issuer"], c2["issuer"], 0, 5)

        # 무료 인증서 남용 여부
        free1 = _is_free_cert(c1["issuer"])
        free2 = _is_free_cert(c2["issuer"])
        f1_label = f'{c1["issuer"]} (무료)' if free1 else c1["issuer"]
        f2_label = f'{c2["issuer"]} (무료)' if free2 else c2["issuer"]
        if free1 and free2:
            add("무료 인증서", "양쪽 모두 무료", f1_label, f2_label, 3, 5)
        elif free1 or free2:
            which = "사이트1만 무료" if free1 else "사이트2만 무료"
            add("무료 인증서", which, f1_label, f2_label, 1, 5)
        else:
            add("무료 인증서", "해당 없음", f1_label, f2_label, 0, 5)

        # 유효기간 패턴 비교
        vf1, vt1, days1 = _format_cert_validity(c1)
        vf2, vt2, days2 = _format_cert_validity(c2)
        if days1 > 0 and days2 > 0:
            s1 = f"{days1}일 ({vf1}~{vt1})"
            s2 = f"{days2}일 ({vf2}~{vt2})"
            if days1 == days2:
                add("인증서 유효기간", "동일 기간", s1, s2, 3, 5)
            else:
                add("인증서 유효기간", "상이", s1, s2, 0, 5)

        # TLS 프로토콜/암호화 비교
        tls1 = f'{c1["protocol"]} / {c1.get("cipher", "N/A")}'
        tls2 = f'{c2["protocol"]} / {c2.get("cipher", "N/A")}'
        if c1["protocol"] == c2["protocol"] and c1.get("cipher") == c2.get("cipher"):
            add("TLS 설정", "일치", tls1, tls2, 3, 5)
        else:
            add("TLS 설정", "상이", tls1, tls2, 0, 5)

        # SAN 목록 비교
        san1 = set(c1.get("sanList", []))
        san2 = set(c2.get("sanList", []))
        shared_san = san1 & san2
        s1 = ", ".join(sorted(san1)[:3]) + (f" 외 {len(san1)-3}개" if len(san1) > 3 else "") if san1 else "N/A"
        s2 = ", ".join(sorted(san2)[:3]) + (f" 외 {len(san2)-3}개" if len(san2) > 3 else "") if san2 else "N/A"
        if shared_san:
            add("인증서 SAN", f"{len(shared_san)}개 공유", s1, s2, 4, 5)
        elif san1 or san2:
            add("인증서 SAN", "공유 없음", s1, s2, 0, 5)
    else:
        add("인증서", "정보 없음", "N/A", "N/A", 0, 25)

    total_score = int((score / max_score) * 100) if max_score > 0 else 0

    return {
        "comparisons": results,
        "score": total_score,
        "meta1": meta1,
        "meta2": meta2,
    }


def analyze_with_gemini(meta1, meta2, comparison_result):
    """Gemini AI 심층 분석"""
    config = load_prompt_config()
    api_key = get_config("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY가 설정되지 않았습니다."

    client = genai.Client(api_key=api_key)

    # 프롬프트 구성
    parts = [config["system_role"], "\n"]
    parts.append(f"## 사이트 1: {meta1['url']}\n```json\n{json.dumps(meta1, indent=2, ensure_ascii=False)}\n```\n\n")
    parts.append(f"## 사이트 2: {meta2['url']}\n```json\n{json.dumps(meta2, indent=2, ensure_ascii=False)}\n```\n\n")
    parts.append(f"## 규칙 기반 비교 결과 (유사도 점수: {comparison_result['score']}%)\n")

    for comp in comparison_result["comparisons"]:
        parts.append(f"- {comp['name']}: {comp['status']} (사이트1: {comp.get('site1', 'N/A')} / 사이트2: {comp.get('site2', 'N/A')})\n")

    parts.append("\n## 분석 항목\n")
    for section in config["analysis_sections"]:
        parts.append(f"### {section['title']}\n{section['description']}\n\n")

    parts.append(f"\n{config['output_format']}")

    prompt = "".join(parts)

    # 모델 폴백
    log_request("gemini", "POST", "generate_content", data={"prompt_length": len(prompt), "models": GEMINI_MODELS})
    last_error = None
    for model_name in GEMINI_MODELS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            log_response("gemini", 200, {"model": model_name, "response_length": len(response.text)})
            return response.text, model_name
        except Exception as e:
            log_error("gemini", f"model={model_name}, error={e}")
            last_error = e
            continue

    return f"모든 Gemini 모델 호출에 실패했습니다. 마지막 오류: {last_error}", None
