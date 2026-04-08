import time
import requests
from config import get_config
from api_logger import log_request, log_response, log_error

CRIMINALIP_API = "https://api.criminalip.io/v1"


def _get_headers():
    api_key = get_config("CRIMINALIP_KEY")
    if not api_key:
        raise Exception("CRIMINALIP_KEY가 설정되지 않았습니다.")
    return {"x-api-key": api_key}


def scan_domain(domain):
    """도메인 스캔 요청. scan_id 반환."""
    url = f"{CRIMINALIP_API}/domain/scan"
    headers = _get_headers()
    data = {"query": domain}
    log_request("criminalip.scan", "POST", url, data=data)
    resp = requests.post(url, headers=headers, data=data, timeout=30)
    log_response("criminalip.scan", resp.status_code, resp.json() if resp.ok else None)
    if resp.status_code == 400:
        body = resp.json()
        if "previous request" in body.get("message", "").lower():
            return None
    resp.raise_for_status()
    return resp.json()["data"]["scan_id"]


def get_scan_status(scan_id):
    """스캔 진행률 조회. 0~100 반환."""
    url = f"{CRIMINALIP_API}/domain/status/{scan_id}"
    headers = _get_headers()
    log_request("criminalip.status", "GET", url)
    resp = requests.get(url, headers=headers, timeout=15)
    log_response("criminalip.status", resp.status_code)
    resp.raise_for_status()
    return resp.json()["data"]["scan_percentage"]


def get_domain_report(scan_id):
    """스캔 ID로 도메인 보고서 조회."""
    url = f"{CRIMINALIP_API}/domain/report/{scan_id}"
    headers = _get_headers()
    log_request("criminalip.report", "GET", url)
    resp = requests.get(url, headers=headers, timeout=30)
    log_response("criminalip.report", resp.status_code)
    resp.raise_for_status()
    return resp.json()["data"]


def scan_and_get_report(domain, progress_callback=None, timeout=180):
    """도메인 스캔 요청 → 완료 대기 → 보고서 반환. 통합 함수."""
    if progress_callback:
        progress_callback(f"CriminalIP: {domain} 스캔 요청 중...")

    scan_id = scan_domain(domain)

    if scan_id is None:
        if progress_callback:
            progress_callback("CriminalIP: 이전 스캔 결과 조회 중...")
        reports_url = f"{CRIMINALIP_API}/domain/reports"
        headers = _get_headers()
        params = {"query": domain, "offset": 0}
        log_request("criminalip.reports", "GET", reports_url, params=params)
        resp = requests.get(reports_url, headers=headers, params=params, timeout=15)
        log_response("criminalip.reports", resp.status_code)
        if resp.ok:
            data = resp.json().get("data", {})
            reports = data.get("result", [])
            if reports:
                prev_id = reports[0].get("scan_id")
                if prev_id:
                    return get_domain_report(prev_id)
        raise Exception("CriminalIP: 이전 스캔 결과를 찾을 수 없습니다.")

    if progress_callback:
        progress_callback(f"CriminalIP: 스캔 진행 중... (scan_id: {scan_id})")

    start = time.time()
    while time.time() - start < timeout:
        pct = get_scan_status(scan_id)
        if progress_callback:
            progress_callback(f"CriminalIP: 스캔 진행 중... ({pct}%)")
        if pct >= 100:
            break
        time.sleep(5)
    else:
        raise Exception(f"CriminalIP: 스캔 타임아웃 ({timeout}초)")

    if progress_callback:
        progress_callback("CriminalIP: 보고서 조회 중...")

    return get_domain_report(scan_id)


def get_ip_data(ip):
    """IP 인텔리전스 조회."""
    url = f"{CRIMINALIP_API}/ip/data"
    headers = _get_headers()
    params = {"ip": ip}
    log_request("criminalip.ip", "GET", url, params=params)
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        log_response("criminalip.ip", resp.status_code)
        if resp.ok:
            return resp.json()
        return None
    except requests.RequestException as e:
        log_error("criminalip.ip", str(e))
        return None
