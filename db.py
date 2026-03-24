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


def save_history(category, title, data):
    """분석 결과 저장"""
    client = _get_client()
    if not client:
        return None
    record = {
        "id": str(uuid.uuid4()),
        "category": category,
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
        .select("id, category, title, created_at")
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
