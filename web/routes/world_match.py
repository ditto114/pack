"""월드 매칭 관련 API 라우트."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ..db import (
    bulk_upsert_world_matches,
    clear_world_matches as db_clear,
    get_world_matches as db_get_world_matches,
)
from ..services.world_match_service import world_match_service

router = APIRouter(prefix="/api/world-match", tags=["world-match"])


class WorldMatchEntry(BaseModel):
    channel_name: str
    world_code: str


class SaveRequest(BaseModel):
    entries: list[WorldMatchEntry]


@router.get("")
def get_world_matches(session_id: Optional[str] = None) -> list[dict[str, Any]]:
    rows = db_get_world_matches(session_id)
    for row in rows:
        ca = row.get("captured_at")
        if isinstance(ca, str):
            try:
                dt = datetime.fromisoformat(ca.replace("Z", "+00:00"))
                row["captured_at"] = dt.timestamp()
            except (ValueError, TypeError):
                row["captured_at"] = 0
    return rows


@router.post("/save")
def save_world_matches(body: SaveRequest) -> dict[str, Any]:
    """프론트엔드에서 전달된 월드 매칭 데이터를 DB에 저장한다."""
    if not body.entries:
        return {"status": "empty", "count": 0}
    try:
        # 기존 데이터 삭제 후 새로 저장
        db_clear()
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            {
                "channel_name": e.channel_name,
                "world_code": e.world_code,
                "captured_at": now,
            }
            for e in body.entries
        ]
        result = bulk_upsert_world_matches(rows)
        return {"status": "saved", "count": len(result)}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "count": 0}


@router.delete("")
def clear_world_matches(session_id: Optional[str] = None) -> dict[str, str]:
    db_clear(session_id)
    return {"status": "cleared"}


@router.get("/order")
async def get_order() -> dict[str, Any]:
    return {
        "order": world_match_service.order,
        "locked": world_match_service.order_locked,
    }


@router.put("/order")
async def set_order(order: Optional[str] = None, locked: bool = False) -> dict[str, str]:
    world_match_service.set_order(order, locked=locked)
    return {"status": "ok"}


# ── WebSocket ─────────────────────────────────────────────────────

ws_router = APIRouter()


@ws_router.websocket("/ws/world-match")
async def ws_world_match(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            data = await world_match_service.get_ws_match()
            await websocket.send_json(data)
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
