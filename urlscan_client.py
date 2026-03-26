"""urlscan.io API 클라이언트"""

import time
import requests
from config import get_config
from api_logger import log_request, log_response, log_error

URLSCAN_API = "https://urlscan.io/api/v1"


def _normalize_url(url):
    """프로토콜이 없으면 https:// 자동 추가"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def search_existing_scan(domain):
    """urlscan.io Search API로 기존 스캔 결과 UUID 조회"""
    api_key = get_config("URLSCAN_API_KEY")
    headers = {"API-Key": api_key} if api_key else {}
    params = {"q": f"domain:{domain}", "size": 1}
    endpoint = f"{URLSCAN_API}/search/"

    log_request("urlscan.search", "GET", endpoint, params=params)
    resp = requests.get(endpoint, headers=headers, params=params, timeout=30)
    log_response("urlscan.search", resp.status_code,
                 {"total": resp.json().get("total", 0)} if resp.ok else resp.text)
    if resp.ok:
        data = resp.json()
        results = data.get("results", [])
        if results:
            return results[0].get("_id")
    return None


def get_scan_result(scan_id):
    """스캔 UUID로 결과 조회"""
    endpoint = f"{URLSCAN_API}/result/{scan_id}/"
    log_request("urlscan.result", "GET", endpoint)
    resp = requests.get(endpoint, timeout=15)
    log_response("urlscan.result", resp.status_code, {"scan_id": scan_id})
    resp.raise_for_status()
    return resp.json()


def submit_scan(url):
    """URL 스캔 제출"""
    api_key = get_config("URLSCAN_API_KEY")
    if not api_key:
        raise Exception("URLSCAN_API_KEY가 설정되지 않았습니다.")
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    url = _normalize_url(url)
    data = {"url": url, "visibility": "public"}
    endpoint = f"{URLSCAN_API}/scan/"

    log_request("urlscan.submit", "POST", endpoint, data=data)
    resp = requests.post(endpoint, headers=headers, json=data, timeout=30)
    log_response("urlscan.submit", resp.status_code, resp.json() if resp.ok else resp.text)
    resp.raise_for_status()
    return resp.json()


def search_hash_count(hash_value):
    """urlscan.io에서 해시를 포함하는 웹페이지 수 조회"""
    api_key = get_config("URLSCAN_API_KEY")
    headers = {"API-Key": api_key} if api_key else {}
    params = {"q": f"hash:{hash_value}", "size": 0}
    endpoint = f"{URLSCAN_API}/search/"

    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=15)
        if resp.ok:
            return resp.json().get("total", 0)
    except requests.RequestException:
        pass
    return -1


def search_hash_counts(hash_list, progress_callback=None):
    """여러 해시의 출현 횟수를 일괄 조회"""
    results = {}
    for i, h in enumerate(hash_list):
        if progress_callback:
            progress_callback(f"해시 출현 횟수 조회 중... ({i+1}/{len(hash_list)})")
        results[h] = search_hash_count(h)
        time.sleep(0.3)  # rate limit
    return results


def scan_and_get_result(url, progress_callback=None):
    """URL 스캔 제출 후 결과 대기"""
    submission = submit_scan(url)
    scan_id = submission.get("uuid")
    if not scan_id:
        raise Exception(f"스캔 제출 실패: {submission}")

    if progress_callback:
        progress_callback("스캔 처리 대기 중...")
    time.sleep(10)

    for i in range(22):  # ~110초 대기
        endpoint = f"{URLSCAN_API}/result/{scan_id}/"
        try:
            resp = requests.get(endpoint, timeout=15)
            if resp.status_code == 200:
                log_response("urlscan.result", resp.status_code, {"scan_id": scan_id, "keys": list(resp.json().keys())})
                return resp.json()
        except requests.RequestException as e:
            log_error("urlscan.result", f"scan_id={scan_id}, attempt={i+1}, error={e}")
        if progress_callback:
            progress_callback(f"결과 대기 중... ({(i + 1) * 5}초)")
        time.sleep(5)

    raise Exception(f"스캔 결과 대기 시간 초과 (ID: {scan_id})")


def structure_search(uuid, threshold=75, size=100, q=None):
    """Structure Search - 유사 사이트 검색 (Pro API)"""
    api_key = get_config("URLSCAN_API_KEY")
    if not api_key:
        raise Exception("URLSCAN_API_KEY가 설정되지 않았습니다.")
    headers = {"API-Key": api_key}
    params = {"threshold": f"{threshold}%", "size": size}
    if q:
        params["q"] = q
    endpoint = f"{URLSCAN_API}/pro/result/{uuid}/similar/"

    log_request("urlscan.structure_search", "GET", endpoint, params=params)
    resp = requests.get(endpoint, headers=headers, params=params, timeout=30)
    log_response("urlscan.structure_search", resp.status_code,
                 {"total": resp.json().get("total", 0)} if resp.ok else resp.text)
    resp.raise_for_status()
    return resp.json()


def _extract_domain(url):
    """URL에서 도메인 추출"""
    from urllib.parse import urlparse
    url = _normalize_url(url)
    parsed = urlparse(url)
    return parsed.hostname or url


def scan_and_structure_search(url, threshold=75, size=100, q=None, progress_callback=None):
    """URL 스캔 후 Structure Search 수행. 스캔 실패 시 기존 결과로 폴백."""
    scan_id = None

    # 1단계: 새로 스캔 시도
    try:
        if progress_callback:
            progress_callback(f"URL 스캔 제출 중: {url}")
        submission = submit_scan(url)
        scan_id = submission.get("uuid")
    except requests.HTTPError as e:
        if progress_callback:
            progress_callback("스캔 실패 - 기존 스캔 결과 검색 중...")
        log_error("urlscan.scan_and_structure_search", f"스캔 실패 ({e}), 기존 결과 검색 시도")

    # 2단계: 스캔 실패 시 기존 결과에서 UUID 검색
    if not scan_id:
        domain = _extract_domain(url)
        scan_id = search_existing_scan(domain)
        if not scan_id:
            raise Exception(f"스캔 제출 실패 및 기존 스캔 결과도 없습니다: {url}")
        if progress_callback:
            progress_callback(f"기존 스캔 결과 발견 (UUID: {scan_id[:8]}...)")
    else:
        # 새 스캔 결과 대기
        if progress_callback:
            progress_callback("스캔 처리 대기 중...")
        time.sleep(10)

        for i in range(22):
            endpoint = f"{URLSCAN_API}/result/{scan_id}/"
            try:
                resp = requests.get(endpoint, timeout=15)
                if resp.status_code == 200:
                    break
            except requests.RequestException:
                pass
            if progress_callback:
                progress_callback(f"스캔 결과 대기 중... ({(i + 1) * 5}초)")
            time.sleep(5)
        else:
            raise Exception(f"스캔 결과 대기 시간 초과 (ID: {scan_id})")

    if progress_callback:
        progress_callback("유사 사이트 검색 중...")
    results = structure_search(scan_id, threshold=threshold, size=size, q=q)
    results["scan_uuid"] = scan_id
    return results
