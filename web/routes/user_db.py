"""유저 DB 관련 API 라우트."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from ..db import (
    get_user_db_entries,
    get_user_db_paginated,
    get_user_db_by_codes,
    upsert_user_db_entries,
    update_user_db_field,
    delete_user_db_entry,
    delete_all_user_db_entries,
    deduplicate_user_db_entries,
    _now_iso,
)

router = APIRouter(prefix="/api/user-db", tags=["user-db"])

ALLOWED_FIELDS = {"ingame_nick", "mw_nick", "guild", "main_map", "memo", "ppsn", "friend_list"}


class UpsertEntry(BaseModel):
    profile_code: str
    ingame_nick: Optional[str] = None
    mw_nick: Optional[str] = None
    guild: Optional[str] = None
    main_map: Optional[str] = None
    memo: Optional[str] = None
    ppsn: Optional[str] = None
    friend_list: Optional[str] = None


class BulkSaveRequest(BaseModel):
    entries: list[UpsertEntry]


class UpdateFieldRequest(BaseModel):
    field: str
    value: str


class SaveFriendListRequest(BaseModel):
    search_code: str
    friend_codes: list[str]


@router.get("")
def get_all(
    limit: int = Query(default=0, ge=0),
    offset: int = Query(default=0, ge=0),
    search: str = Query(default=""),
    sort_key: str = Query(default=""),
    sort_asc: bool = Query(default=True),
) -> dict[str, Any]:
    """유저 DB 목록 조회. limit=0이면 전체 반환 (하위 호환)."""
    if limit <= 0 and not search and not sort_key:
        return {"rows": get_user_db_entries(), "total": -1}
    rows, total = get_user_db_paginated(
        limit=limit or 100, offset=offset, search=search,
        sort_key=sort_key, sort_asc=sort_asc,
    )
    return {"rows": rows, "total": total}


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
    try:
        if not body.entries:
            return {"status": "empty", "count": 0}

        target_codes = [e.profile_code.strip() for e in body.entries if e.profile_code]
        existing_rows = get_user_db_by_codes(target_codes)
        existing_map = {r["profile_code"]: r for r in existing_rows if r.get("profile_code")}

        now = _now_iso()
        seen_pcs: set[str] = set()
        rows: list[dict[str, Any]] = []
        for e in body.entries:
            if not e.profile_code:
                continue
            pc = e.profile_code.strip()
            if pc in seen_pcs:
                continue  # 동일 profile_code 중복 → ON CONFLICT 오류 방지
            seen_pcs.add(pc)
            base = existing_map.get(pc, {})
            # ingame_nick: 기존 태그와 병합 (중복 제거, 최대 3개)
            if e.ingame_nick is not None:
                existing_tags = [t.strip() for t in (base.get("ingame_nick") or "").split(",") if t.strip()]
                new_tags = [t.strip() for t in e.ingame_nick.split(",") if t.strip()]
                merged = list(existing_tags)
                seen = set(t.lower() for t in merged)
                for t in new_tags:
                    if t.lower() not in seen and len(merged) < 3:
                        merged.append(t)
                        seen.add(t.lower())
                ingame_nick_val = ",".join(merged)
            else:
                ingame_nick_val = base.get("ingame_nick", "")

            row = {
                "profile_code": pc,
                "ingame_nick": ingame_nick_val,
                "mw_nick": e.mw_nick if e.mw_nick is not None else base.get("mw_nick", ""),
                "guild": e.guild if e.guild is not None else base.get("guild", ""),
                "main_map": e.main_map if e.main_map is not None else base.get("main_map", ""),
                "memo": e.memo if e.memo is not None else base.get("memo", ""),
                "ppsn": e.ppsn if e.ppsn is not None else base.get("ppsn", ""),
                "friend_list": e.friend_list if e.friend_list is not None else base.get("friend_list", ""),
                "updated_at": now,
            }
            rows.append(row)

        if not rows:
            return {"status": "empty", "count": 0}
        result = upsert_user_db_entries(rows)
        return {"status": "saved", "count": len(result)}

    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@router.put("/{profile_code}")
def update_field(profile_code: str, body: UpdateFieldRequest) -> dict[str, Any]:
    if body.field not in ALLOWED_FIELDS:
        return {"status": "error", "error": f"허용되지 않는 필드: {body.field}"}
    update_user_db_field(profile_code, body.field, body.value)
    return {"status": "ok"}


@router.post("/save-friend-list")
def save_friend_list(body: SaveFriendListRequest) -> dict[str, Any]:
    """양방향 친구목록 저장 (중복 방지). 단일 배치 upsert로 처리."""
    try:
        search_code = body.search_code.strip()
        friend_codes = [c.strip() for c in body.friend_codes if c.strip()]
        if not search_code or not friend_codes:
            return {"status": "empty"}

        relevant_codes = list(set([search_code] + friend_codes))
        existing_rows = get_user_db_by_codes(relevant_codes)
        existing_map = {r["profile_code"]: r for r in existing_rows if r.get("profile_code")}

        def parse_list(val: str) -> list[str]:
            return [s.strip() for s in (val or "").split(",") if s.strip()]

        def merge_unique(existing_val: str, new_codes: list[str]) -> str:
            current = parse_list(existing_val)
            seen = set(current)
            for c in new_codes:
                if c not in seen:
                    seen.add(c)
                    current.append(c)
            return ",".join(current)

        now = _now_iso()
        rows_to_upsert: list[dict[str, Any]] = []

        def to_upsert_row(existing: dict[str, Any]) -> dict[str, Any]:
            """id(GENERATED ALWAYS) 컬럼을 제외한 upsert용 행 반환."""
            row = dict(existing)
            row.pop("id", None)
            return row

        # 1) 검색 대상의 friend_list에 모든 친구 코드 추가 + friend_list_direct 마킹
        if search_code in existing_map:
            base = existing_map[search_code]
            old_val = base.get("friend_list", "") or ""
            new_val = merge_unique(old_val, [fc for fc in friend_codes if fc != search_code])
            row = to_upsert_row(base)
            if new_val != old_val:
                row["friend_list"] = new_val
                row["updated_at"] = now
            row["friend_list_direct"] = True
            rows_to_upsert.append(row)

        # 2) 검색된 각 친구의 friend_list에 검색 대상 코드 추가
        #    search_code 본인은 스킵 (본인 검색 결과가 friend_codes에 포함될 수 있음)
        for fc in friend_codes:
            if fc == search_code:
                continue
            if fc in existing_map:
                base = existing_map[fc]
                old_val = base.get("friend_list", "") or ""
                new_val = merge_unique(old_val, [search_code])
                if new_val != old_val:
                    row = to_upsert_row(base)
                    row["friend_list"] = new_val
                    row["updated_at"] = now
                    rows_to_upsert.append(row)

        # 동일 profile_code가 두 번 들어가면 PostgreSQL upsert 오류 발생 → 중복 제거
        seen_pcs: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for row in rows_to_upsert:
            pc = row["profile_code"]
            if pc not in seen_pcs:
                seen_pcs.add(pc)
                deduped.append(row)
        rows_to_upsert = deduped

        if rows_to_upsert:
            upsert_user_db_entries(rows_to_upsert)

        return {"status": "ok", "updated": len(rows_to_upsert)}

    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@router.delete("/{profile_code}")
def delete_entry(profile_code: str) -> dict[str, str]:
    delete_user_db_entry(profile_code)
    return {"status": "deleted"}
