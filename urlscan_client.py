"""urlscan.io API 클라이언트"""

import time
import requests
from config import get_config
from api_logger import log_request, log_response, log_error

URLSCAN_API = "https://urlscan.io/api/v1"


def submit_scan(url):
    """URL 스캔 제출"""
    api_key = get_config("URLSCAN_API_KEY")
    if not api_key:
        raise Exception("URLSCAN_API_KEY가 설정되지 않았습니다.")
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    endpoint = f"{URLSCAN_API}/scan/"

    log_request("urlscan.submit", "POST", endpoint, data=data)
    resp = requests.post(endpoint, headers=headers, json=data, timeout=30)
    log_response("urlscan.submit", resp.status_code, resp.json() if resp.ok else resp.text)
    resp.raise_for_status()
    return resp.json()


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
