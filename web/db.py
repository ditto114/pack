"""Supabase 클라이언트 및 테이블별 CRUD 헬퍼."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

_client: Optional[Client] = None


def get_client() -> Client:
    global _client
    if _client is None:
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key)
    return _client


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── capture_sessions ──────────────────────────────────────────────

def create_session(
    *,
    filter_ip: str = "",
    filter_port: Optional[int] = None,
    filter_text: str = "",
    max_packets: int = 500,
) -> dict[str, Any]:
    row = {
        "started_at": _now_iso(),
        "filter_ip": filter_ip,
        "filter_port": filter_port,
        "filter_text": filter_text,
        "max_packets": max_packets,
        "status": "running",
    }
    resp = get_client().table("capture_sessions").insert(row).execute()
    return resp.data[0]


def stop_session(session_id: str) -> None:
    get_client().table("capture_sessions").update(
        {"stopped_at": _now_iso(), "status": "stopped"}
    ).eq("id", session_id).execute()


def get_active_session() -> Optional[dict[str, Any]]:
    resp = (
        get_client()
        .table("capture_sessions")
        .select("*")
        .eq("status", "running")
        .order("started_at", desc=True)
        .limit(1)
        .execute()
    )
    return resp.data[0] if resp.data else None


# ── packets ───────────────────────────────────────────────────────

def insert_packets(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    get_client().table("packets").insert(rows).execute()


def get_packets(
    session_id: Optional[str] = None,
    *,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    q = get_client().table("packets").select("*")
    if session_id:
        q = q.eq("session_id", session_id)
    resp = q.order("captured_at", desc=True).range(offset, offset + limit - 1).execute()
    return resp.data


def get_packet_by_id(packet_id: int) -> Optional[dict[str, Any]]:
    resp = (
        get_client().table("packets").select("*").eq("id", packet_id).limit(1).execute()
    )
    return resp.data[0] if resp.data else None


# ── world_matches ─────────────────────────────────────────────────

def insert_world_match(
    channel_name: str,
    world_code: str,
    *,
    session_id: Optional[str] = None,
    captured_at: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    row: dict[str, Any] = {
        "channel_name": channel_name,
        "world_code": world_code,
        "captured_at": captured_at or _now_iso(),
    }
    if session_id:
        row["session_id"] = session_id
    try:
        resp = get_client().table("world_matches").insert(row).execute()
        return resp.data[0] if resp.data else None
    except Exception:
        # unique constraint violation → duplicate, ignore
        return None


def bulk_upsert_world_matches(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """월드 매치를 일괄 upsert한다. 오류 시 예외를 그대로 전파한다."""
    if not rows:
        return []
    resp = get_client().table("world_matches").upsert(
        rows, on_conflict="channel_name,world_code"
    ).execute()
    return resp.data or []


def get_world_matches(
    session_id: Optional[str] = None,
    *,
    limit: int = 0,
    offset: int = 0,
) -> list[dict[str, Any]]:
    q = get_client().table("world_matches").select("*")
    if session_id:
        q = q.eq("session_id", session_id)
    q = q.order("captured_at", desc=True)
    if limit > 0:
        q = q.range(offset, offset + limit - 1)
    resp = q.execute()
    return resp.data


def clear_world_matches(session_id: Optional[str] = None) -> None:
    q = get_client().table("world_matches")
    if session_id:
        q.delete().eq("session_id", session_id).execute()
    else:
        q.delete().neq("id", 0).execute()



# ── settings ──────────────────────────────────────────────────────

def upsert_setting(key: str, value: Any) -> None:
    get_client().table("settings").upsert(
        {"key": key, "value": value, "updated_at": _now_iso()},
        on_conflict="key",
    ).execute()


def get_setting(key: str) -> Any:
    resp = (
        get_client().table("settings").select("value").eq("key", key).limit(1).execute()
    )
    if resp.data:
        return resp.data[0]["value"]
    return None


def get_all_settings() -> dict[str, Any]:
    resp = get_client().table("settings").select("key, value").execute()
    return {row["key"]: row["value"] for row in resp.data}


# ── user_db ───────────────────────────────────────────────────────

def get_user_db_entries() -> list[dict[str, Any]]:
    PAGE = 1000
    all_rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        resp = (
            get_client()
            .table("user_db")
            .select("*")
            .order("updated_at", desc=True)
            .range(offset, offset + PAGE - 1)
            .execute()
        )
        batch = resp.data or []
        all_rows.extend(batch)
        if len(batch) < PAGE:
            break
        offset += PAGE
    return all_rows


_ALLOWED_SORT_COLUMNS = {
    "profile_code", "ingame_nick", "mw_nick", "guild",
    "main_map", "memo", "ppsn", "updated_at",
}


def _count_tags(val: Any) -> int:
    """콤마 구분 문자열의 태그 개수를 반환한다."""
    if not val:
        return 0
    return len([s for s in str(val).split(",") if s.strip()])


def get_user_db_paginated(
    *,
    limit: int = 100,
    offset: int = 0,
    search: str = "",
    sort_key: str = "",
    sort_asc: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    """페이지네이션 + 텍스트 검색 + 정렬을 지원하는 user_db 조회.
    (rows, total_count) 튜플을 반환한다."""
    client = get_client()

    # 검색 필터 빌더
    def _apply_search(q: Any) -> Any:
        if not search:
            return q
        pattern = f"%{search}%"
        return q.or_(
            f"profile_code.ilike.{pattern},"
            f"ingame_nick.ilike.{pattern},"
            f"mw_nick.ilike.{pattern},"
            f"guild.ilike.{pattern},"
            f"memo.ilike.{pattern},"
            f"friend_list.ilike.{pattern}"
        )

    # 총 건수
    count_q = _apply_search(client.table("user_db").select("*", count="exact"))
    count_resp = count_q.limit(0).execute()
    total = count_resp.count or 0

    # friend_list 는 태그 수 기준 정렬 → DB에서 할 수 없으므로 Python 처리
    if sort_key == "friend_list":
        # 전체 fetch 후 Python 정렬 + 슬라이싱
        PAGE = 1000
        all_rows: list[dict[str, Any]] = []
        off = 0
        while True:
            q = _apply_search(client.table("user_db").select("*"))
            resp = q.order("updated_at", desc=True).range(off, off + PAGE - 1).execute()
            batch = resp.data or []
            all_rows.extend(batch)
            if len(batch) < PAGE:
                break
            off += PAGE
        all_rows.sort(key=lambda r: _count_tags(r.get("friend_list")), reverse=not sort_asc)
        return all_rows[offset:offset + limit], total

    # 일반 컬럼 정렬 → Supabase order()
    data_q = _apply_search(client.table("user_db").select("*"))
    order_col = sort_key if sort_key in _ALLOWED_SORT_COLUMNS else "updated_at"
    order_desc = not sort_asc if sort_key in _ALLOWED_SORT_COLUMNS else True
    data_q = data_q.order(order_col, desc=order_desc)
    resp = data_q.range(offset, offset + limit - 1).execute()
    return resp.data or [], total


def get_user_db_by_codes(codes: list[str]) -> list[dict[str, Any]]:
    """주어진 profile_code 목록에 해당하는 행만 조회한다 (IN 조건)."""
    if not codes:
        return []
    client = get_client()
    all_rows: list[dict[str, Any]] = []
    # Supabase .in_() 은 한 번에 너무 많은 값을 넘기면 URL 길이 제한에 걸릴 수 있음
    BATCH = 200
    for i in range(0, len(codes), BATCH):
        batch_codes = codes[i:i + BATCH]
        resp = client.table("user_db").select("*").in_("profile_code", batch_codes).execute()
        all_rows.extend(resp.data or [])
    return all_rows


def upsert_user_db_entries(rows: list[dict[str, Any]], batch_size: int = 100) -> list[dict[str, Any]]:
    if not rows:
        return []
    client = get_client()
    result: list[dict[str, Any]] = []
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        resp = client.table("user_db").upsert(batch, on_conflict="profile_code").execute()
        result.extend(resp.data or [])
    return result


def update_user_db_field(profile_code: str, field: str, value: str) -> Optional[dict[str, Any]]:
    resp = (
        get_client()
        .table("user_db")
        .update({field: value, "updated_at": _now_iso()})
        .eq("profile_code", profile_code)
        .execute()
    )
    return resp.data[0] if resp.data else None


def delete_user_db_entry(profile_code: str) -> None:
    get_client().table("user_db").delete().eq("profile_code", profile_code).execute()


def delete_all_user_db_entries() -> None:
    get_client().table("user_db").delete().neq("profile_code", "").execute()


def deduplicate_user_db_entries() -> int:
    """대소문자 구분 없이 동일한 profile_code 중복 행을 제거한다.
    같은 그룹에서 updated_at 이 가장 최신인 행 1개만 남기고 나머지를 삭제한다.
    삭제된 행 수를 반환한다."""
    rows = get_user_db_entries()

    # 대문자 기준으로 그룹화 (NULL 행 스킵)
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        pc = row.get("profile_code")
        if not pc:
            continue
        key = pc.strip().upper()
        if not key:
            continue
        groups.setdefault(key, []).append(row)

    to_delete: list[str] = []
    for key, group in groups.items():
        if len(group) <= 1:
            continue
        # updated_at 내림차순 정렬 → 첫 번째(최신)만 남기고 나머지 삭제 대상
        group.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
        for row in group[1:]:
            to_delete.append(row["profile_code"])

    client = get_client()
    # 배치 삭제: IN 조건으로 한 번에 처리 (URL 길이 제한 고려 200개씩)
    BATCH = 200
    for i in range(0, len(to_delete), BATCH):
        batch = to_delete[i:i + BATCH]
        client.table("user_db").delete().in_("profile_code", batch).execute()

    return len(to_delete)
