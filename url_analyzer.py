"""URL 종합 분석 엔진 — VirusTotal + CriminalIP + URLScan.io 통합"""

import json
import time
import subprocess
import yaml
import requests
import whois
from datetime import datetime, timedelta
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

from google import genai

from config import get_config
from api_logger import log_request, log_response, log_error
from criminalip_client import scan_and_get_report, get_ip_data
from urlscan_client import (
    scan_and_get_result,
    structure_search,
    search_hash_count,
    search_existing_scan,
)
from analyzer import extract_metadata, GEMINI_MODELS

VT_API_BASE = "https://www.virustotal.com/api/v3"

# ---------- 유틸 ----------

def _normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def _extract_domain(url):
    parsed = urlparse(_normalize_url(url))
    return parsed.hostname or url


def _load_analysis_prompt():
    with open("url_analysis_prompt.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------- Phase 1: 데이터 수집 ----------

def _collect_criminalip(domain, progress_cb):
    """CriminalIP 도메인 보고서 수집"""
    try:
        report = scan_and_get_report(domain, progress_callback=progress_cb)
        return {"status": "ok", "data": report}
    except Exception as e:
        log_error("url_analyzer.criminalip", str(e))
        return {"status": "error", "error": str(e)}


def _collect_urlscan(url, progress_cb):
    """URLScan.io 스캔 + 결과 수집"""
    try:
        def _progress(msg):
            if progress_cb:
                progress_cb(f"URLScan: {msg}")
        result = scan_and_get_result(url, progress_callback=_progress)
        meta = extract_metadata(result)
        return {"status": "ok", "data": result, "meta": meta}
    except Exception as e:
        log_error("url_analyzer.urlscan", str(e))
        # 기존 스캔 결과 폴백
        try:
            domain = _extract_domain(url)
            uuid = search_existing_scan(domain)
            if uuid:
                from urlscan_client import get_scan_result
                result = get_scan_result(uuid)
                meta = extract_metadata(result)
                return {"status": "ok", "data": result, "meta": meta, "fallback": True}
        except Exception:
            pass
        return {"status": "error", "error": str(e)}


def _collect_vt_url(url):
    """VirusTotal URL 분석 결과"""
    api_key = get_config("VT_API_KEY")
    if not api_key:
        return {"status": "error", "error": "VT_API_KEY 미설정"}
    headers = {"x-apikey": api_key}

    # URL 제출
    endpoint = f"{VT_API_BASE}/urls"
    data = {"url": _normalize_url(url)}
    log_request("vt.url_scan", "POST", endpoint)
    try:
        resp = requests.post(endpoint, headers=headers, data=data, timeout=30)
        log_response("vt.url_scan", resp.status_code)
        if not resp.ok:
            return {"status": "error", "error": f"VT URL 제출 실패: {resp.status_code}"}
        url_id = resp.json().get("data", {}).get("id", "")
    except Exception as e:
        log_error("vt.url_scan", str(e))
        return {"status": "error", "error": str(e)}

    # 결과 조회
    time.sleep(3)
    endpoint2 = f"{VT_API_BASE}/analyses/{url_id}"
    log_request("vt.url_result", "GET", endpoint2)
    try:
        resp2 = requests.get(endpoint2, headers=headers, timeout=30)
        log_response("vt.url_result", resp2.status_code)
        if resp2.ok:
            return {"status": "ok", "data": resp2.json()}
    except Exception as e:
        log_error("vt.url_result", str(e))

    return {"status": "error", "error": "VT 결과 조회 실패"}


def _collect_vt_domain(domain):
    """VirusTotal 도메인 정보"""
    api_key = get_config("VT_API_KEY")
    if not api_key:
        return {"status": "error", "error": "VT_API_KEY 미설정"}
    headers = {"x-apikey": api_key}
    endpoint = f"{VT_API_BASE}/domains/{domain}"
    log_request("vt.domain", "GET", endpoint)
    try:
        resp = requests.get(endpoint, headers=headers, timeout=30)
        log_response("vt.domain", resp.status_code)
        if resp.ok:
            return {"status": "ok", "data": resp.json()}
        return {"status": "error", "error": f"VT 도메인 조회 실패: {resp.status_code}"}
    except Exception as e:
        log_error("vt.domain", str(e))
        return {"status": "error", "error": str(e)}


def _collect_whois(domain):
    """python-whois로 WHOIS 조회"""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        return {
            "status": "ok",
            "data": {
                "registrar": w.registrar,
                "creation_date": str(creation) if creation else None,
                "expiration_date": str(expiration) if expiration else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "country": w.country,
                "registrant": w.org or w.name,
            },
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _collect_ssl_san(domain):
    """openssl로 SSL SAN 도메인 추출"""
    try:
        cmd = (
            f'echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null '
            f'| openssl x509 -noout -text 2>/dev/null'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout
        san_domains = []
        in_san = False
        for line in output.split('\n'):
            if 'Subject Alternative Name' in line:
                in_san = True
                continue
            if in_san:
                parts = line.strip().split(',')
                for part in parts:
                    part = part.strip()
                    if part.startswith('DNS:'):
                        d = part[4:].strip()
                        if not d.startswith('*.'):
                            san_domains.append(d)
                break
        return san_domains
    except Exception:
        return []


# ---------- 위협 점수 산출 ----------

def _calculate_threat_score(collected):
    """수집 데이터 기반 위협 점수 산출 (0-100)"""
    score = 0
    reasons = []

    # VT 탐지 (0-40)
    vt_url = collected.get("vt_url", {})
    if vt_url.get("status") == "ok":
        stats = (
            vt_url["data"]
            .get("data", {})
            .get("attributes", {})
            .get("stats", {})
        )
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total_bad = mal + sus
        if total_bad > 10:
            score += 40; reasons.append(f"VT 탐지: malicious={mal}, suspicious={sus}")
        elif total_bad > 5:
            score += 30; reasons.append(f"VT 탐지: malicious={mal}, suspicious={sus}")
        elif total_bad > 2:
            score += 20; reasons.append(f"VT 탐지: malicious={mal}, suspicious={sus}")
        elif total_bad > 0:
            score += 10; reasons.append(f"VT 탐지: malicious={mal}, suspicious={sus}")

    # CriminalIP 지표 (0-35)
    cip = collected.get("criminalip", {})
    if cip.get("status") == "ok":
        data = cip["data"]
        summary = data.get("summary", {})
        classification = data.get("classification", {})

        dga = classification.get("dga_score", 0)
        if dga >= 5:
            score += 10; reasons.append(f"DGA 점수 높음: {dga}")

        if summary.get("diff_domain_favicon") == "Dangerous":
            score += 5; reasons.append("파비콘 외부 도메인 위장")

        js_obf = summary.get("js_obfuscated", 0)
        if js_obf >= 3:
            score += 5; reasons.append(f"난독화 JS: {js_obf}개")

        sus_elem = summary.get("suspicious_element", 0)
        if sus_elem >= 3:
            score += 5; reasons.append(f"의심 요소: {sus_elem}개")

        if summary.get("spf1") == "Fail":
            score += 5; reasons.append("SPF 실패 (이메일 스푸핑 가능)")

        gsb = classification.get("google_safe_browsing", [])
        if gsb:
            score += 5; reasons.append(f"Google Safe Browsing: {gsb}")

    # 인프라 신호 (0-25)
    whois_data = collected.get("whois", {})
    if whois_data.get("status") == "ok":
        cd = whois_data["data"].get("creation_date")
        if cd:
            try:
                created = datetime.fromisoformat(cd.replace("Z", "+00:00"))
                age_days = (datetime.now() - created.replace(tzinfo=None)).days
                if age_days < 90:
                    score += 5; reasons.append(f"신생 도메인: {age_days}일")
            except (ValueError, TypeError):
                pass

    if cip.get("status") == "ok":
        data = cip["data"]
        if not data.get("security_headers"):
            score += 5; reasons.append("보안 헤더 없음")

        dns = data.get("dns_record", {})
        mx = dns.get("dns_record_type_mx", [])
        if mx:
            mx_flat = str(mx)
            if ".cn" in mx_flat or "global-mail" in mx_flat:
                score += 5; reasons.append(f"의심 MX: {mx}")

        mapped = data.get("mapped_ip", [])
        mod_ips = [ip for ip in mapped if ip.get("score") in ("moderate", "dangerous", "critical")]
        if mod_ips:
            score += 5; reasons.append(f"위험 IP: {len(mod_ips)}개")

        domain = data.get("main_domain_info", {}).get("main_domain", "")
        if domain and len(domain.split(".")[0]) >= 8 and domain.split(".")[0].isalpha():
            import re
            name = domain.split(".")[0]
            vowels = sum(1 for c in name if c in "aeiou")
            if vowels / len(name) < 0.3:
                score += 5; reasons.append(f"DGA 패턴 도메인명: {domain}")

    # 판정
    if score >= 51:
        verdict = "malicious"
    elif score >= 26:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return score, verdict, reasons


# ---------- IOC 추출 ----------

def _extract_iocs(collected):
    """수집 데이터에서 IOC 추출"""
    iocs = {
        "domains": [],
        "ips": [],
        "jarm": None,
        "cookies": [],
        "url_patterns": [],
        "operator_params": {},
        "ssl_san_domains": [],
        "hashes": [],
    }

    cip = collected.get("criminalip", {})
    if cip.get("status") == "ok":
        data = cip["data"]

        # 연결 도메인
        for cd in data.get("connected_domain_subdomain", []):
            main = cd.get("main_domain", {}).get("domain", "")
            if main:
                iocs["domains"].append(main)
            for sub in cd.get("subdomains", []):
                d = sub.get("domain", "")
                if d:
                    iocs["domains"].append(d)

        # IP
        for ip_info in data.get("connected_ip_info", []):
            iocs["ips"].append({
                "ip": ip_info.get("ip"),
                "asn": ip_info.get("as_name"),
                "country": ip_info.get("country"),
                "score": ip_info.get("score"),
                "domains": [d.get("domain") for d in ip_info.get("domain_list", [])],
            })

        # JARM
        jarm = data.get("main_domain_info", {}).get("jarm")
        if jarm:
            iocs["jarm"] = jarm

        # 쿠키
        for cookie in data.get("cookies", []):
            iocs["cookies"].append({
                "name": cookie.get("name"),
                "domain": cookie.get("domain"),
                "value": cookie.get("value", "")[:50],
            })

        # 네트워크 로그에서 추적 픽셀/URL 패턴 + 운영자 파라미터
        for entry in data.get("network_logs", {}).get("data", []):
            url = entry.get("url", "")
            if "statistics/" in url or "tracking" in url.lower() or "pixel" in url.lower():
                iocs["url_patterns"].append(url[:200])
                # 추적 파라미터 추출
                if "tracking_data=" in url:
                    try:
                        td_raw = url.split("tracking_data=")[1].split("&t=")[0]
                        td = json.loads(unquote(td_raw))
                        for key in ["shopId", "siteUserId", "collId", "marketId",
                                     "areaId", "currencyId", "serviceUid", "tplName"]:
                            if key in td:
                                iocs["operator_params"][key] = str(td[key])
                    except (json.JSONDecodeError, IndexError):
                        pass
            elif "shopapi" in url or "one-cookie" in url:
                iocs["url_patterns"].append(url[:200])

    # SSL SAN
    san_domains = collected.get("ssl_san", [])
    if san_domains:
        iocs["ssl_san_domains"] = san_domains

    # URLScan 해시
    urlscan = collected.get("urlscan", {})
    if urlscan.get("status") == "ok":
        meta = urlscan.get("meta", {})
        iocs["hashes"] = meta.get("hashes", [])[:20]

    return iocs


# ---------- 연관 사이트 분류 ----------

KNOWN_LEGITIMATE = {
    "tiktok.com", "analytics.tiktok.com", "tiktokw.us",
    "zendesk.com", "zdassets.com",
    "alicdn.com", "aliyuncs.com", "alibaba.com",
    "cloudflare.com", "amazonaws.com",
    "google.com", "googleapis.com", "gstatic.com",
    "facebook.com", "fbcdn.net",
    "jquery.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
}


def _is_legitimate(domain):
    for legit in KNOWN_LEGITIMATE:
        if domain == legit or domain.endswith(f".{legit}"):
            return True
    return False


def _is_dga_like(domain):
    name = domain.split(".")[0]
    if len(name) < 6:
        return False
    if not name.isalpha():
        return False
    vowels = sum(1 for c in name if c in "aeiou")
    return vowels / len(name) < 0.35


def _discover_related_sites(collected, iocs):
    """연관 사이트 분류: confirmed_malicious / needs_investigation / legitimate"""
    result = {
        "confirmed_malicious": [],
        "needs_investigation": [],
        "legitimate": [],
    }

    main_domain = ""
    cip = collected.get("criminalip", {})
    if cip.get("status") == "ok":
        main_domain = cip["data"].get("main_domain_info", {}).get("main_domain", "")

    # SSL SAN 도메인 분류
    for d in iocs.get("ssl_san_domains", []):
        if d == main_domain:
            continue
        if _is_dga_like(d):
            result["confirmed_malicious"].append({
                "domain": d, "reason": "SSL SAN 공유 + DGA 패턴",
                "source": "SSL SAN",
            })
        else:
            result["needs_investigation"].append({
                "domain": d, "reason": "SSL SAN 공유",
                "source": "SSL SAN",
            })

    # 연결 도메인 분류
    seen = {main_domain} | {e["domain"] for e in result["confirmed_malicious"]} | {e["domain"] for e in result["needs_investigation"]}
    for d in iocs.get("domains", []):
        base = d.split(".")[-2] + "." + d.split(".")[-1] if d.count(".") >= 1 else d
        if base in seen or d in seen:
            continue
        seen.add(base)
        seen.add(d)
        if _is_legitimate(d):
            result["legitimate"].append({
                "domain": d, "reason": "알려진 합법 서비스",
                "source": "CriminalIP 연결 도메인",
            })
        elif _is_dga_like(base):
            result["confirmed_malicious"].append({
                "domain": d, "reason": "DGA 패턴 + 리소스 연결",
                "source": "CriminalIP 연결 도메인",
            })
        else:
            result["needs_investigation"].append({
                "domain": d, "reason": "리소스 연결 확인",
                "source": "CriminalIP 연결 도메인",
            })

    # 구조적 유사 사이트 (Phase 2에서 추가)
    structure = collected.get("structure_search", {})
    if structure:
        for item in structure.get("results", [])[:20]:
            page = item.get("page", {})
            sd = page.get("domain", "")
            if sd and sd not in seen:
                seen.add(sd)
                sim = item.get("structureScore", 0)
                if sim >= 85:
                    result["confirmed_malicious"].append({
                        "domain": sd, "reason": f"구조적 유사도 {sim}%",
                        "source": "URLScan Structure Search",
                        "url": page.get("url", ""),
                    })
                elif sim >= 60:
                    result["needs_investigation"].append({
                        "domain": sd, "reason": f"구조적 유사도 {sim}%",
                        "source": "URLScan Structure Search",
                        "url": page.get("url", ""),
                    })

    return result


# ---------- Phase 2: IOC 심층 조사 ----------

def _run_investigation(collected, iocs, progress_cb, time_limit=300):
    """악성/의심 판정 시 추가 조사"""
    start = time.time()
    investigation = {}

    # 1. IP 인텔리전스 (최대 5개)
    unique_ips = []
    seen_ips = set()
    for ip_info in iocs.get("ips", []):
        ip = ip_info.get("ip")
        if ip and ip not in seen_ips and not ip.startswith("127."):
            seen_ips.add(ip)
            unique_ips.append(ip)
    unique_ips = unique_ips[:5]

    if unique_ips and time.time() - start < time_limit:
        if progress_cb:
            progress_cb(f"Phase 2: IP 인텔리전스 조회 중... ({len(unique_ips)}개)")
        ip_intel = {}
        for ip in unique_ips:
            if time.time() - start >= time_limit:
                break
            data = get_ip_data(ip)
            if data:
                ip_intel[ip] = {
                    "score": data.get("score", {}),
                    "tags": data.get("tags", {}),
                    "domain_count": data.get("domain", {}).get("count", 0),
                    "port_count": data.get("port", {}).get("count", 0),
                    "vuln_count": data.get("vulnerability", {}).get("count", 0),
                    "domains": [
                        d.get("domain") for d in
                        data.get("domain", {}).get("data", [])[:10]
                    ],
                }
            time.sleep(0.5)
        investigation["ip_intel"] = ip_intel

    # 2. 구조적 유사 사이트 (URLScan)
    urlscan = collected.get("urlscan", {})
    if urlscan.get("status") == "ok" and time.time() - start < time_limit:
        if progress_cb:
            progress_cb("Phase 2: 유사 사이트 검색 중...")
        scan_data = urlscan.get("data", {})
        uuid = scan_data.get("task", {}).get("uuid")
        if not uuid:
            uuid = search_existing_scan(_extract_domain(
                scan_data.get("task", {}).get("url", "")
            ))
        if uuid:
            try:
                similar = structure_search(uuid, threshold=60, size=30)
                collected["structure_search"] = similar
                investigation["structure_search_count"] = similar.get("total", 0)
            except Exception as e:
                log_error("url_analyzer.structure_search", str(e))

    # 3. VT IP 평판 (메인 IP)
    cip = collected.get("criminalip", {})
    if cip.get("status") == "ok" and time.time() - start < time_limit:
        mapped = cip["data"].get("mapped_ip", [])
        if mapped:
            main_ip = mapped[0].get("ip")
            if main_ip:
                if progress_cb:
                    progress_cb(f"Phase 2: VT IP 평판 조회 중... ({main_ip})")
                api_key = get_config("VT_API_KEY")
                if api_key:
                    endpoint = f"{VT_API_BASE}/ip_addresses/{main_ip}"
                    headers = {"x-apikey": api_key}
                    log_request("vt.ip", "GET", endpoint)
                    try:
                        resp = requests.get(endpoint, headers=headers, timeout=15)
                        log_response("vt.ip", resp.status_code)
                        if resp.ok:
                            investigation["vt_ip"] = resp.json()
                    except Exception as e:
                        log_error("vt.ip", str(e))

    # 4. 해시 출현 빈도 (상위 10개)
    hashes = iocs.get("hashes", [])[:10]
    if hashes and time.time() - start < time_limit:
        if progress_cb:
            progress_cb(f"Phase 2: 해시 출현 빈도 조회 중... ({len(hashes)}개)")
        hash_counts = {}
        for h in hashes:
            if time.time() - start >= time_limit:
                break
            hash_counts[h] = search_hash_count(h)
            time.sleep(0.3)
        investigation["hash_counts"] = hash_counts

    return investigation


# ---------- Phase 3: AI 보고서 ----------

def _generate_ai_report(collected, score, verdict, reasons, iocs, related, investigation, progress_cb):
    """Gemini AI로 분석 보고서 생성"""
    api_key = get_config("GEMINI_API_KEY")
    if not api_key:
        return "GEMINI_API_KEY가 설정되지 않았습니다.", None

    if progress_cb:
        progress_cb("Phase 3: AI 분석 보고서 생성 중...")

    prompt_config = _load_analysis_prompt()

    # 프롬프트 조합
    sections_text = "\n".join(
        f"### {s['title']}\n{s['description']}"
        for s in prompt_config["report_sections"]
    )

    # 데이터 요약 (토큰 절약)
    summary_data = {
        "url": collected.get("input_url", ""),
        "domain": collected.get("domain", ""),
        "threat_score": score,
        "verdict": verdict,
        "verdict_reasons": reasons,
    }

    # CriminalIP 핵심 데이터
    cip = collected.get("criminalip", {})
    if cip.get("status") == "ok":
        data = cip["data"]
        summary_data["criminalip"] = {
            "main_domain_info": data.get("main_domain_info"),
            "classification": data.get("classification"),
            "summary": data.get("summary"),
            "dns_record": data.get("dns_record"),
            "main_certificate": data.get("main_certificate"),
            "certificates": data.get("certificates", [])[:10],
            "connected_domain_subdomain": data.get("connected_domain_subdomain"),
            "connected_ip_info": data.get("connected_ip_info"),
            "cookies": data.get("cookies"),
            "security_headers": data.get("security_headers"),
            "mapped_ip": data.get("mapped_ip"),
            "page_networking_info": data.get("page_networking_info"),
            "screenshots": data.get("screenshots"),
        }

    # VT 데이터
    vt_url = collected.get("vt_url", {})
    if vt_url.get("status") == "ok":
        stats = vt_url["data"].get("data", {}).get("attributes", {}).get("stats", {})
        summary_data["virustotal_url"] = stats

    vt_domain = collected.get("vt_domain", {})
    if vt_domain.get("status") == "ok":
        attrs = vt_domain["data"].get("data", {}).get("attributes", {})
        summary_data["virustotal_domain"] = {
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "categories": attrs.get("categories"),
        }

    # WHOIS
    whois_data = collected.get("whois", {})
    if whois_data.get("status") == "ok":
        summary_data["whois"] = whois_data["data"]

    # IOC
    summary_data["iocs"] = {
        "domains": iocs.get("domains", [])[:30],
        "ips": iocs.get("ips", [])[:15],
        "jarm": iocs.get("jarm"),
        "cookies": iocs.get("cookies", [])[:10],
        "url_patterns": iocs.get("url_patterns", [])[:5],
        "operator_params": iocs.get("operator_params"),
        "ssl_san_domains": iocs.get("ssl_san_domains", [])[:50],
    }

    # 연관 사이트
    summary_data["related_sites"] = {
        "confirmed_malicious": related.get("confirmed_malicious", [])[:20],
        "needs_investigation": related.get("needs_investigation", [])[:20],
        "legitimate": related.get("legitimate", [])[:10],
    }

    # 심층 조사
    if investigation:
        summary_data["investigation"] = {
            k: v for k, v in investigation.items()
            if k != "hash_counts"  # 해시 카운트는 너무 길 수 있음
        }
        if "hash_counts" in investigation:
            summary_data["investigation"]["hash_counts_summary"] = {
                h: c for h, c in list(investigation["hash_counts"].items())[:10]
            }

    prompt = f"""{prompt_config['system_role']}

## 분석 대상
URL: {collected.get('input_url', '')}
도메인: {collected.get('domain', '')}

## 위협 판정
점수: {score}/100 | 판정: {verdict}
근거: {json.dumps(reasons, ensure_ascii=False)}

## 수집 데이터
```json
{json.dumps(summary_data, ensure_ascii=False, default=str)[:25000]}
```

## 보고서 섹션 구성
{sections_text}

## 출력 규칙
{prompt_config['output_format']}

위 데이터를 분석하여 체계적인 한국어 보고서를 작성하세요.
"""

    log_request("gemini.url_analysis", "POST", "generate_content",
                data={"prompt_length": len(prompt)})

    client = genai.Client(api_key=api_key)
    last_error = None
    for model_name in GEMINI_MODELS:
        try:
            response = client.models.generate_content(
                model=model_name, contents=prompt
            )
            log_response("gemini.url_analysis", 200, {"model": model_name})
            return response.text, model_name
        except Exception as e:
            log_error("gemini.url_analysis", f"model={model_name}, error={e}")
            last_error = e
            continue

    return f"모든 Gemini 모델 호출에 실패했습니다. 마지막 오류: {last_error}", None


# ---------- 메인 오케스트레이터 ----------

def analyze_url(url, auto_investigate=True, task=None):
    """URL 종합 분석 파이프라인

    Args:
        url: 분석 대상 URL
        auto_investigate: 악성/의심 판정 시 자동 심층 조사
        task: BackgroundTask 인스턴스 (취소 확인 + 진행 표시)

    Returns:
        dict: 전체 분석 결과
    """
    url = _normalize_url(url)
    domain = _extract_domain(url)

    def progress(msg):
        if task:
            task.set_progress(msg)

    collected = {"input_url": url, "domain": domain}

    # ========== Phase 1: 병렬 데이터 수집 ==========
    progress("Phase 1: 데이터 수집 시작...")

    futures = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures["criminalip"] = executor.submit(
            _collect_criminalip, domain, progress
        )
        futures["urlscan"] = executor.submit(
            _collect_urlscan, url, progress
        )
        futures["vt_url"] = executor.submit(_collect_vt_url, url)
        futures["vt_domain"] = executor.submit(_collect_vt_domain, domain)
        futures["whois"] = executor.submit(_collect_whois, domain)

        for name, future in futures.items():
            if task and task.cancelled:
                return None
            try:
                collected[name] = future.result(timeout=180)
                progress(f"Phase 1: {name} 완료")
            except Exception as e:
                collected[name] = {"status": "error", "error": str(e)}
                log_error(f"url_analyzer.{name}", str(e))

    if task and task.cancelled:
        return None

    # SSL SAN 수집
    progress("Phase 1: SSL SAN 도메인 수집 중...")
    collected["ssl_san"] = _collect_ssl_san(domain)

    # ========== 위협 점수 산출 ==========
    progress("위협 점수 산출 중...")
    score, verdict, reasons = _calculate_threat_score(collected)

    # ========== IOC 추출 ==========
    progress("IOC 추출 중...")
    iocs = _extract_iocs(collected)

    # ========== Phase 2: 심층 조사 (조건부) ==========
    investigation = {}
    if auto_investigate and verdict in ("malicious", "suspicious"):
        if task and task.cancelled:
            return None
        progress("Phase 2: 심층 조사 시작...")
        investigation = _run_investigation(collected, iocs, progress, time_limit=300)

        # 심층 조사 후 연관 사이트 재분류
        if task and task.cancelled:
            return None

    # ========== 연관 사이트 분류 ==========
    progress("연관 사이트 분류 중...")
    related = _discover_related_sites(collected, iocs)

    # ========== Phase 3: AI 보고서 ==========
    if task and task.cancelled:
        return None
    ai_report, ai_model = _generate_ai_report(
        collected, score, verdict, reasons, iocs, related, investigation, progress
    )

    # ========== 결과 조합 ==========
    progress("결과 정리 중...")

    # CriminalIP 스크린샷 URL
    screenshot_url = None
    cip = collected.get("criminalip", {})
    if cip.get("status") == "ok":
        screenshots = cip["data"].get("screenshots", [])
        if screenshots:
            screenshot_url = screenshots[0]

    result = {
        "url": url,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "score": score,
        "verdict": verdict,
        "verdict_reasons": reasons,
        "screenshot_url": screenshot_url,
        "iocs": iocs,
        "related_sites": related,
        "investigation": investigation,
        "ai_report": ai_report,
        "ai_model": ai_model,
        "collected": {
            "criminalip": _summarize_criminalip(collected.get("criminalip", {})),
            "urlscan": _summarize_urlscan(collected.get("urlscan", {})),
            "vt_url": collected.get("vt_url", {}),
            "vt_domain": _summarize_vt_domain(collected.get("vt_domain", {})),
            "whois": collected.get("whois", {}),
            "ssl_san": collected.get("ssl_san", []),
        },
    }

    progress("분석 완료!")
    return result


# ---------- 데이터 요약 (DB 저장 크기 절감) ----------

def _summarize_criminalip(cip):
    if cip.get("status") != "ok":
        return cip
    data = cip["data"]
    return {
        "status": "ok",
        "main_domain_info": data.get("main_domain_info"),
        "classification": data.get("classification"),
        "summary": data.get("summary"),
        "dns_record": data.get("dns_record"),
        "main_certificate": data.get("main_certificate"),
        "certificates": data.get("certificates", [])[:10],
        "connected_domain_subdomain": data.get("connected_domain_subdomain"),
        "connected_ip_info": data.get("connected_ip_info"),
        "cookies": data.get("cookies"),
        "security_headers": data.get("security_headers"),
        "mapped_ip": data.get("mapped_ip"),
        "page_networking_info": data.get("page_networking_info"),
        "screenshots": data.get("screenshots"),
        "network_logs_count": len(data.get("network_logs", {}).get("data", [])),
    }


def _summarize_urlscan(us):
    if us.get("status") != "ok":
        return us
    return {
        "status": "ok",
        "meta": us.get("meta", {}),
        "fallback": us.get("fallback", False),
    }


def _summarize_vt_domain(vt):
    if vt.get("status") != "ok":
        return vt
    attrs = vt.get("data", {}).get("data", {}).get("attributes", {})
    return {
        "status": "ok",
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": attrs.get("last_analysis_stats"),
        "registrar": attrs.get("registrar"),
        "categories": attrs.get("categories"),
    }
