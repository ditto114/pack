"""설정 관련 API 라우트."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from ..db import get_all_settings, get_setting, upsert_setting

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingUpdate(BaseModel):
    key: str
    value: Any


class BulkSettingUpdate(BaseModel):
    settings: dict[str, Any]


@router.get("")
async def list_settings() -> dict[str, Any]:
    return get_all_settings()


@router.get("/{key}")
async def read_setting(key: str) -> dict[str, Any]:
    val = get_setting(key)
    return {"key": key, "value": val}


@router.put("")
async def update_settings(req: BulkSettingUpdate) -> dict[str, str]:
    for k, v in req.settings.items():
        upsert_setting(k, v)
    return {"status": "ok"}


@router.put("/{key}")
async def update_setting(key: str, req: SettingUpdate) -> dict[str, str]:
    upsert_setting(key, req.value)
    return {"status": "ok"}
