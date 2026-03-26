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


def get_world_matches(session_id: Optional[str] = None) -> list[dict[str, Any]]:
    q = get_client().table("world_matches").select("*")
    if session_id:
        q = q.eq("session_id", session_id)
    resp = q.order("captured_at", desc=True).execute()
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
    for pc in to_delete:
        client.table("user_db").delete().eq("profile_code", pc).execute()

    return len(to_delete)
