"""API 호출 로깅"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))

# 로그 디렉토리 생성
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# 로거 설정
logger = logging.getLogger("api_logger")
logger.setLevel(logging.DEBUG)

# 파일 핸들러 (일별 로그)
_current_date = None
_file_handler = None


def _ensure_handler():
    global _current_date, _file_handler
    today = datetime.now(KST).strftime("%Y-%m-%d")
    if _current_date != today:
        if _file_handler:
            logger.removeHandler(_file_handler)
            _file_handler.close()
        log_path = os.path.join(LOG_DIR, f"api_{today}.log")
        _file_handler = logging.FileHandler(log_path, encoding="utf-8")
        _file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(_file_handler)
        _current_date = today


def _truncate(data, max_len=2000):
    """긴 데이터 잘라내기"""
    text = str(data)
    if len(text) > max_len:
        return text[:max_len] + f"... (truncated, total {len(text)} chars)"
    return text


def log_request(api_name, method, url, data=None, params=None):
    """API 요청 로깅"""
    _ensure_handler()
    parts = [f"[REQ] {api_name} | {method} {url}"]
    if params:
        parts.append(f"  params: {_truncate(params)}")
    if data:
        parts.append(f"  body: {_truncate(json.dumps(data, ensure_ascii=False) if isinstance(data, (dict, list)) else data)}")
    logger.info("\n".join(parts))


def log_response(api_name, status_code, data=None):
    """API 응답 로깅"""
    _ensure_handler()
    parts = [f"[RES] {api_name} | status={status_code}"]
    if data:
        parts.append(f"  body: {_truncate(json.dumps(data, ensure_ascii=False) if isinstance(data, (dict, list)) else data)}")
    logger.info("\n".join(parts))


def log_error(api_name, error):
    """API 오류 로깅"""
    _ensure_handler()
    logger.error(f"[ERR] {api_name} | {error}")
