"""Supabase 이력 저장/조회/삭제"""

import uuid
from datetime import datetime, timezone

from config import get_config


def _get_client():
    url = get_config("SUPABASE_URL")
    key = get_config("SUPABASE_KEY")
    if not url or not key:
        return None
    from supabase import create_client
    return create_client(url, key)


def _next_seq(client, category):
    """카테고리별 다음 시퀀스 번호 조회"""
    result = (
        client.table("history")
        .select("seq")
        .eq("category", category)
        .order("seq", desc=True)
        .limit(1)
        .execute()
    )
    if result.data and result.data[0].get("seq"):
        return result.data[0]["seq"] + 1
    return 1


def save_history(category, title, data):
    """분석 결과 저장"""
    client = _get_client()
    if not client:
        return None
    seq = _next_seq(client, category)
    record = {
        "id": str(uuid.uuid4()),
        "category": category,
        "seq": seq,
        "title": title,
        "data": data,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    client.table("history").insert(record).execute()
    return record["id"]


def get_history_list(category) -> list[dict]:
    """이력 목록 조회"""
    client = _get_client()
    if not client:
        return []
    result = (
        client.table("history")
        .select("id, category, seq, title, created_at")
        .eq("category", category)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data  # type: ignore[return-value]


def get_history_detail(category, history_id) -> dict | None:
    """이력 상세 조회"""
    client = _get_client()
    if not client:
        return None
    result = (
        client.table("history")
        .select("*")
        .eq("id", history_id)
        .eq("category", category)
        .execute()
    )
    return result.data[0] if result.data else None  # type: ignore[return-value]


def delete_history(category, history_id):
    """이력 삭제"""
    client = _get_client()
    if not client:
        return False
    client.table("history").delete().eq("id", history_id).eq("category", category).execute()
    return True


# ── 키워드 모니터링 ──


def add_keyword(keyword):
    """키워드 등록 (중복 시 재활성화)"""
    client = _get_client()
    if not client:
        return None
    keyword = keyword.strip()
    # 기존 키워드 확인
    existing = (
        client.table("keywords")
        .select("id, is_active")
        .eq("keyword", keyword)
        .execute()
    )
    if existing.data:
        row = existing.data[0]
        if not row["is_active"]:
            client.table("keywords").update({"is_active": True}).eq("id", row["id"]).execute()
        return row["id"]
    record = {
        "id": str(uuid.uuid4()),
        "keyword": keyword,
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    client.table("keywords").insert(record).execute()
    return record["id"]


def get_keywords(active_only=True):
    """키워드 목록 조회"""
    client = _get_client()
    if not client:
        return []
    q = client.table("keywords").select("*").order("created_at", desc=True)
    if active_only:
        q = q.eq("is_active", True)
    result = q.execute()
    return result.data


def delete_keyword(keyword_id):
    """키워드 삭제 (cascade로 결과도 삭제)"""
    client = _get_client()
    if not client:
        return False
    client.table("keywords").delete().eq("id", keyword_id).execute()
    return True


def save_keyword_results(keyword_id, keyword, source, total, results):
    """키워드 검색 결과 저장"""
    client = _get_client()
    if not client:
        return None
    record = {
        "id": str(uuid.uuid4()),
        "keyword_id": keyword_id,
        "keyword": keyword,
        "source": source,
        "total_found": total,
        "results": results,
        "searched_at": datetime.now(timezone.utc).isoformat(),
    }
    client.table("keyword_results").insert(record).execute()
    # last_searched_at 업데이트
    client.table("keywords").update(
        {"last_searched_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", keyword_id).execute()
    return record["id"]


def get_latest_keyword_results(keyword_id, source):
    """source별 최신 검색 결과 조회"""
    client = _get_client()
    if not client:
        return None
    result = (
        client.table("keyword_results")
        .select("*")
        .eq("keyword_id", keyword_id)
        .eq("source", source)
        .order("searched_at", desc=True)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def get_seen_urls(keyword_id, source):
    """해당 키워드+소스의 이전 검색에서 발견된 모든 URL 집합 반환"""
    client = _get_client()
    if not client:
        return set()
    result = (
        client.table("keyword_results")
        .select("results")
        .eq("keyword_id", keyword_id)
        .eq("source", source)
        .order("searched_at", desc=True)
        .execute()
    )
    seen = set()
    for row in result.data:
        for item in (row.get("results") or []):
            if source == "urlscan":
                url = item.get("page", {}).get("url", "")
            else:
                url = item.get("url", "")
            if url:
                seen.add(url)
    return seen


def get_keyword_results_history(keyword_id, source=None, limit=10):
    """키워드 검색 이력 목록"""
    client = _get_client()
    if not client:
        return []
    q = (
        client.table("keyword_results")
        .select("id, keyword, source, total_found, searched_at")
        .eq("keyword_id", keyword_id)
        .order("searched_at", desc=True)
        .limit(limit)
    )
    if source:
        q = q.eq("source", source)
    result = q.execute()
    return result.data
