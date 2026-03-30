"""채널 모니터링 WebSocket 라우트."""

from __future__ import annotations

import asyncio
import threading

from fastapi import APIRouter
from fastapi.websockets import WebSocket, WebSocketDisconnect

from capture_app.monitor_service import monitor_friends_multi

ws_router = APIRouter()


@ws_router.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket) -> None:
    await websocket.accept()
    stop = threading.Event()

    try:
        msg = await websocket.receive_json()
        interval = max(1.0, float(msg.get("interval", 5.0)))

        # ppsns 배열 우선, 없으면 단일 ppsn 폴백
        raw_ppsns: list[str] = msg.get("ppsns") or []
        if not raw_ppsns:
            single = msg.get("ppsn", "").strip()
            if single:
                raw_ppsns = [single]
        ppsns = [p.strip() for p in raw_ppsns if p.strip().isdigit() and 15 <= len(p.strip()) <= 20]

        if not ppsns:
            await websocket.send_json({"type": "error", "text": "유효한 PPSN이 없습니다."})
            return

        loop = asyncio.get_event_loop()
        q: asyncio.Queue[dict] = asyncio.Queue()

        task = loop.run_in_executor(
            None, lambda: monitor_friends_multi(ppsns, interval, q.put_nowait, stop)
        )

        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=0.5)
                await websocket.send_json(item)
            except asyncio.TimeoutError:
                if task.done():
                    break

    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
    finally:
        stop.set()
