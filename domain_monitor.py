"""도메인 등록 모니터링 (VirusTotal Intelligence Search + python-whois)"""

from datetime import datetime, timedelta

import requests
import whois

from config import get_config
from api_logger import log_request, log_response, log_error

VT_API_BASE = "https://www.virustotal.com/api/v3"


def search_domains(keyword, days=None):
    """VirusTotal Intelligence Search로 도메인 검색 (등록일 필터 지원)"""
    api_key = get_config("VT_API_KEY")
    if not api_key:
        raise Exception("VT_API_KEY가 설정되지 않았습니다.")

    if days is None:
        days = int(get_config("DOMAIN_LOOKUP_DAYS", "30"))

    # 완전한 도메인 입력 시 TLD 제거
    clean_keyword = keyword.split(".")[0] if "." in keyword else keyword

    # 등록일 기준 날짜
    since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    # VT Intelligence Search 쿼리: 도메인명 와일드카드 + 등록일 필터
    query = f"entity:domain domain:*{clean_keyword}* creation_date:{since_date}+"

    headers = {"x-apikey": api_key}
    domains = []
    url = f"{VT_API_BASE}/intelligence/search"
    params = {"query": query, "limit": 100}

    # 페이지네이션 (최대 3페이지 = 300개)
    for page in range(3):
        log_request("vt.search", "GET", url, params=params)
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        data = resp.json()
        log_response("vt.search", resp.status_code, {"page": page + 1, "count": len(data.get("data", []))})
        resp.raise_for_status()

        for item in data.get("data", []):
            domain_name = item.get("id", "")
            if domain_name:
                domains.append(domain_name)

        # 다음 페이지
        cursor = data.get("meta", {}).get("cursor")
        if not cursor or not data.get("data"):
            break
        params = {"query": query, "limit": 100, "cursor": cursor}

    # 완전한 도메인 입력인데 결과에 없으면 직접 WHOIS 조회로 폴백
    if "." in keyword and keyword.lower() not in [d.lower() for d in domains]:
        try:
            w = whois.whois(keyword)  # type: ignore[union-attr]
            if w and w.domain_name:  # type: ignore[union-attr]
                domains.insert(0, keyword)
        except Exception:
            pass

    return domains


def get_domain_detail(domain):
    """python-whois로 도메인 상세 정보 조회"""
    try:
        w = whois.whois(domain)  # type: ignore[union-attr]

        creation_date = w.creation_date  # type: ignore[union-attr]
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date  # type: ignore[union-attr]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        name_servers = w.name_servers or []  # type: ignore[union-attr]
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        name_servers = sorted(set(ns.lower() for ns in name_servers))

        return {
            "domain": domain,
            "registrar": w.registrar or "N/A",  # type: ignore[union-attr]
            "creation_date": str(creation_date) if creation_date else "N/A",
            "expiration_date": str(expiration_date) if expiration_date else "N/A",
            "country": getattr(w, "country", None) or "N/A",
            "name_servers": name_servers,
            "status": "success",
            "_creation_dt": creation_date,
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "error": str(e),
        }


def sort_by_creation_date(details_list):
    """등록일 기준 내림차순 정렬"""

    def sort_key(x):
        cdt = x.get("_creation_dt")
        if isinstance(cdt, datetime):
            return cdt.timestamp()
        return 0

    details_list.sort(key=sort_key, reverse=True)
    return details_list


def search_urls_by_title(keyword, days=30, since_date=None, exact_match=True):
    """VirusTotal Intelligence Search로 페이지 타이틀 기반 URL 검색.
    since_date가 주어지면 해당 날짜 이후만 검색 (YYYY-MM-DD 형식)."""
    api_key = get_config("VT_API_KEY")
    if not api_key:
        raise Exception("VT_API_KEY가 설정되지 않았습니다.")

    if since_date:
        query = f'entity:url title:"{keyword}" ls:{since_date}+'
    else:
        query = f'entity:url title:"{keyword}" ls:{days}d+'

    headers = {"x-apikey": api_key}
    results = []
    ip_set = set()
    url = f"{VT_API_BASE}/intelligence/search"
    params = {"query": query, "limit": 100, "relationships": "last_serving_ip_address"}

    for page in range(3):
        log_request("vt.title_search", "GET", url, params=params)
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        data = resp.json()
        log_response("vt.title_search", resp.status_code,
                     {"page": page + 1, "count": len(data.get("data", []))})
        resp.raise_for_status()

        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            item_url = attrs.get("url", item.get("id", ""))
            title = attrs.get("title", "")
            last_analysis = attrs.get("last_analysis_date", 0)
            if last_analysis:
                try:
                    analysis_dt = datetime.utcfromtimestamp(last_analysis)
                    last_analysis_str = analysis_dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    last_analysis_str = str(last_analysis)
            else:
                last_analysis_str = "N/A"

            # IP 추출 (relationship)
            ip = "N/A"
            rels = item.get("relationships", {})
            ip_data = rels.get("last_serving_ip_address", {}).get("data")
            if ip_data and isinstance(ip_data, dict):
                ip = ip_data.get("id", "N/A")
                if ip != "N/A":
                    ip_set.add(ip)

            results.append({
                "url": item_url,
                "title": title,
                "last_analysis_date": last_analysis_str,
                "ip": ip,
                "country": "",
                "status": "success",
            })

        cursor = data.get("meta", {}).get("cursor")
        if not cursor or not data.get("data"):
            break
        params = {"query": query, "limit": 100, "cursor": cursor,
                  "relationships": "last_serving_ip_address"}

    # 제목 필터링
    if exact_match:
        results = [r for r in results if r.get("title", "").strip() == keyword.strip()]
    else:
        kw_lower = keyword.strip().lower()
        results = [r for r in results if kw_lower in r.get("title", "").strip().lower()]
    ip_set = {r["ip"] for r in results if r.get("ip") and r["ip"] != "N/A"}

    # IP → 국가 일괄 조회 (ip-api.com 배치 API, 무료)
    ip_country = {}
    ip_list = list(ip_set)
    for batch_start in range(0, len(ip_list), 100):
        batch = ip_list[batch_start:batch_start + 100]
        try:
            batch_resp = requests.post(
                "http://ip-api.com/batch?fields=query,countryCode",
                json=[{"query": ip} for ip in batch],
                timeout=10,
            )
            if batch_resp.ok:
                for item in batch_resp.json():
                    ip_country[item["query"]] = item.get("countryCode") or "N/A"
        except Exception:
            pass

    for r in results:
        r["country"] = ip_country.get(r["ip"], "N/A")

    # 분석일 기준 내림차순 정렬
    results.sort(key=lambda x: x.get("last_analysis_date", ""), reverse=True)
    return results


def get_vt_quota():
    """VirusTotal API 사용량 조회"""
    api_key = get_config("VT_API_KEY")
    if not api_key:
        return None
    try:
        headers = {"x-apikey": api_key}
        resp = requests.get(
            f"{VT_API_BASE}/users/me",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            quotas = data.get("data", {}).get("attributes", {}).get("quotas", {})
            return quotas
    except Exception:
        pass
    return None
