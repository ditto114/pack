"""패킷 캡쳐 관련 API 라우트."""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from ..db import get_packet_by_id, get_packets
from ..services.export_service import export_packet_txt
from ..services.packet_service import packet_service
from ..services.world_match_service import world_match_service

router = APIRouter(prefix="/api/capture", tags=["capture"])


class CaptureStartRequest(BaseModel):
    ip: str = ""
    port: str = ""
    text_filter: str = ""
    max_packets: int = 500
    pid: str = ""


@router.post("/start")
async def start_capture(req: CaptureStartRequest) -> dict[str, Any]:
    result = await packet_service.start(
        ip_text=req.ip,
        port_text=req.port,
        text_filter=req.text_filter,
        max_packets=req.max_packets,
        pid_text=req.pid,
    )
    return result


@router.post("/stop")
async def stop_capture() -> dict[str, Any]:
    return await packet_service.stop()


@router.get("/status")
async def capture_status() -> dict[str, Any]:
    return packet_service.get_status()


@router.get("/packets")
async def list_packets(
    session_id: Optional[str] = None,
    limit: int = Query(default=500, le=2000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    return get_packets(session_id, limit=limit, offset=offset)


@router.get("/packets/{packet_id}")
async def get_packet(packet_id: int) -> dict[str, Any]:
    pkt = get_packet_by_id(packet_id)
    if not pkt:
        return {"error": "패킷을 찾을 수 없습니다."}
    return pkt


@router.post("/resend/{packet_idx}")
async def resend_packet(packet_idx: int) -> dict[str, str]:
    if packet_idx < 0 or packet_idx >= len(packet_service.packet_list):
        return {"error": "유효하지 않은 패킷 인덱스입니다."}
    pkt = packet_service.packet_list[packet_idx]
    if pkt.direction != "outgoing":
        return {"error": "송신 패킷만 다시 보낼 수 있습니다."}
    return packet_service.resend_packet(pkt)


@router.get("/export/{packet_id}")
async def export_packet(packet_id: int, encoding: str = "utf-8") -> PlainTextResponse:
    pkt = get_packet_by_id(packet_id)
    if not pkt:
        return PlainTextResponse("패킷을 찾을 수 없습니다.", status_code=404)
    txt = export_packet_txt(pkt, encoding)
    return PlainTextResponse(
        txt,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=packet_{packet_id}.txt"},
    )


# ── WebSocket: 실시간 패킷 스트림 ─────────────────────────────────

ws_router = APIRouter()


@ws_router.websocket("/ws/packets")
async def ws_packets(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            # 첫 패킷은 블로킹 대기
            data = await packet_service.get_ws_packet()
            batch = [data]
            # 큐에 남아있는 패킷을 최대 100개까지 모아서 배치 전송
            for _ in range(99):
                try:
                    extra = packet_service._ws_queue.get_nowait()
                    batch.append(extra)
                except asyncio.QueueEmpty:
                    break
            # world match service 에도 전달
            for pkt in batch:
                utf8_text = pkt.get("utf8_text")
                captured_at = pkt.get("captured_at", 0.0)
                if utf8_text:
                    world_match_service.process_text(
                        utf8_text, captured_at, session_id=packet_service.session_id
                    )
            await websocket.send_json({"type": "batch", "packets": batch})
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
