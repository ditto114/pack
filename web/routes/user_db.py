"""유저 DB 관련 API 라우트."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from ..db import (
    get_user_db_entries,
    upsert_user_db_entries,
    update_user_db_field,
    delete_user_db_entry,
    delete_all_user_db_entries,
    deduplicate_user_db_entries,
    _now_iso,
)

router = APIRouter(prefix="/api/user-db", tags=["user-db"])

ALLOWED_FIELDS = {"ingame_nick", "mw_nick", "guild", "main_map", "ppsn", "friend_list"}


class UpsertEntry(BaseModel):
    profile_code: str
    ingame_nick: Optional[str] = None
    mw_nick: Optional[str] = None
    guild: Optional[str] = None
    main_map: Optional[str] = None
    ppsn: Optional[str] = None
    friend_list: Optional[str] = None


class BulkSaveRequest(BaseModel):
    entries: list[UpsertEntry]


class UpdateFieldRequest(BaseModel):
    field: str
    value: str


@router.get("")
def get_all() -> list[dict[str, Any]]:
    return get_user_db_entries()


@router.delete("")
def delete_all() -> dict[str, str]:
    delete_all_user_db_entries()
    return {"status": "cleared"}


@router.post("/deduplicate")
def deduplicate() -> dict[str, Any]:
    removed = deduplicate_user_db_entries()
    return {"status": "ok", "removed": removed}


@router.post("/bulk-save")
def bulk_save(body: BulkSaveRequest) -> dict[str, Any]:
    """부분 필드만 전달해도 기존 값을 보존하며 upsert."""
    if not body.entries:
        return {"status": "empty", "count": 0}

    # 기존 레코드 조회하여 병합
    existing_rows = get_user_db_entries()
    existing_map = {r["profile_code"]: r for r in existing_rows if r.get("profile_code")}

    now = _now_iso()
    rows: list[dict[str, Any]] = []
    for e in body.entries:
        if not e.profile_code:
            continue
        pc = e.profile_code.strip()
        base = existing_map.get(pc, {})
        row = {
            "profile_code": pc,
            "ingame_nick": e.ingame_nick if e.ingame_nick is not None else base.get("ingame_nick", ""),
            "mw_nick": e.mw_nick if e.mw_nick is not None else base.get("mw_nick", ""),
            "guild": e.guild if e.guild is not None else base.get("guild", ""),
            "main_map": e.main_map if e.main_map is not None else base.get("main_map", ""),
            "ppsn": e.ppsn if e.ppsn is not None else base.get("ppsn", ""),
            "friend_list": e.friend_list if e.friend_list is not None else base.get("friend_list", ""),
            "updated_at": now,
        }
        rows.append(row)

    if not rows:
        return {"status": "empty", "count": 0}
    result = upsert_user_db_entries(rows)
    return {"status": "saved", "count": len(result)}


@router.put("/{profile_code}")
def update_field(profile_code: str, body: UpdateFieldRequest) -> dict[str, Any]:
    if body.field not in ALLOWED_FIELDS:
        return {"status": "error", "error": f"허용되지 않는 필드: {body.field}"}
    update_user_db_field(profile_code, body.field, body.value)
    return {"status": "ok"}


@router.delete("/{profile_code}")
def delete_entry(profile_code: str) -> dict[str, str]:
    delete_user_db_entry(profile_code)
    return {"status": "deleted"}
