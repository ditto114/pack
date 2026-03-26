"""채널 모니터링 WebSocket 라우트."""

from __future__ import annotations

import asyncio
import threading

from fastapi import APIRouter
from fastapi.websockets import WebSocket, WebSocketDisconnect

from capture_app.monitor_service import monitor_friends

ws_router = APIRouter()


@ws_router.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket) -> None:
    await websocket.accept()
    stop = threading.Event()

    try:
        msg = await websocket.receive_json()
        ppsn = msg.get("ppsn", "").strip()
        interval = max(3.0, float(msg.get("interval", 5.0)))

        if not ppsn:
            await websocket.send_json({"type": "error", "text": "PPSN을 입력하세요."})
            return

        loop = asyncio.get_event_loop()
        q: asyncio.Queue[dict] = asyncio.Queue()

        task = loop.run_in_executor(
            None, lambda: monitor_friends(ppsn, interval, q.put_nowait, stop)
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
