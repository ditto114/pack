"""친구 검색 / PPSN 관련 API 라우트."""

from __future__ import annotations

import asyncio
import re
import threading
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from capture_app.friend_services import (
    find_friend_by_world_code,
    find_ppsn,
    find_profile_entry,
    iter_friend_pages,
)


router = APIRouter(prefix="/api", tags=["friends"])


# ── Models ────────────────────────────────────────────────────────

class PPSNSearchRequest(BaseModel):
    code: str
    delay: float = 0.5


class ChannelSearchRequest(BaseModel):
    code: str
    world_code: str
    delay: float = 0.5


class FriendSearchRequest(BaseModel):
    code: str
    phase: int = 1
    codes: list[str] = []


# ── State ─────────────────────────────────────────────────────────

_friend_search_stop = threading.Event()
_friend_search_running = False


@router.delete("/friends/search")
async def cancel_friend_search() -> dict[str, str]:
    _friend_search_stop.set()
    return {"status": "cancel_requested"}


# ── PPSN search ───────────────────────────────────────────────────

@router.post("/ppsn/search")
async def ppsn_search_start(req: PPSNSearchRequest) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9]{5,6}", req.code):
        return {"error": "프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다."}
    return {"status": "started", "code": req.code}


@router.post("/channel/search")
async def channel_search_start(req: ChannelSearchRequest) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9]{5,6}", req.code):
        return {"error": "프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다."}
    if not re.fullmatch(r"\d{17}", req.world_code):
        return {"error": "월드 코드는 숫자 17자리여야 합니다."}
    return {"status": "started"}


# ── WebSocket: PPSN 검색 실시간 ───────────────────────────────────

ws_router = APIRouter()


@ws_router.websocket("/ws/ppsn")
async def ws_ppsn(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            msg = await websocket.receive_json()
            action = msg.get("action")

            if action == "ppsn_search":
                code = msg.get("code", "")
                delay = float(msg.get("delay", 0.5))
                await _run_ppsn_ws(websocket, code, delay)

            elif action == "channel_search":
                code = msg.get("code", "")
                world_code = msg.get("world_code", "")
                delay = float(msg.get("delay", 0.5))
                await _run_channel_ws(websocket, code, world_code, delay)

            elif action == "profile_search":
                code = msg.get("code", "")
                delay = float(msg.get("delay", 0.5))
                await _run_profile_search_ws(websocket, code, delay)

    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass


async def _run_ppsn_ws(ws: WebSocket, code: str, delay: float) -> None:
    loop = asyncio.get_event_loop()
    logs: asyncio.Queue[dict] = asyncio.Queue()

    def log(message: str) -> None:
        logs.put_nowait({"type": "log", "text": message})

    def do_search() -> Optional[tuple[str, str]]:
        try:
            return find_ppsn(code, delay=delay, logger=log)
        except Exception as exc:
            logs.put_nowait({"type": "log", "text": f"[오류] {exc}"})
            return None

    task = loop.run_in_executor(None, do_search)

    # stream logs while search runs
    while not task.done():
        try:
            item = await asyncio.wait_for(logs.get(), timeout=0.2)
            await ws.send_json(item)
        except asyncio.TimeoutError:
            pass

    result = await task

    # drain remaining logs
    while not logs.empty():
        item = await logs.get()
        await ws.send_json(item)

    if result:
        ppsn, via = result
        await ws.send_json({
            "type": "done",
            "success": True,
            "ppsn": ppsn,
            "text": f"[결과] 프로필 코드 {code.upper()} 의 PPSN은 {ppsn} 입니다. (친구 {via} 에서 확인)",
        })
    else:
        await ws.send_json({
            "type": "done",
            "success": False,
            "text": "[결과] 친구 목록 어디에서도 해당 프로필 코드를 찾지 못했습니다.",
        })


async def _run_channel_ws(ws: WebSocket, code: str, world_code: str, delay: float) -> None:
    loop = asyncio.get_event_loop()
    logs: asyncio.Queue[dict] = asyncio.Queue()

    def log(message: str) -> None:
        logs.put_nowait({"type": "log", "text": message})

    def progress(count: int) -> None:
        logs.put_nowait({"type": "progress", "count": count})

    def do_search() -> Optional[tuple[str, str, str]]:
        try:
            return find_friend_by_world_code(
                code, world_code, delay=delay, logger=log, progress_callback=progress
            )
        except Exception as exc:
            logs.put_nowait({"type": "log", "text": f"[오류] {exc}"})
            return None

    task = loop.run_in_executor(None, do_search)

    while not task.done():
        try:
            item = await asyncio.wait_for(logs.get(), timeout=0.2)
            await ws.send_json(item)
        except asyncio.TimeoutError:
            pass

    result = await task

    while not logs.empty():
        item = await logs.get()
        await ws.send_json(item)

    if result:
        name, fcode, ppsn = result
        await ws.send_json({
            "type": "done",
            "success": True,
            "text": f"[결과] 월드 코드 {world_code} → {name} ({fcode})",
            "channel_result": f"{name} / {fcode}",
            "ppsn": ppsn,
        })
    else:
        await ws.send_json({
            "type": "done",
            "success": False,
            "text": "[결과] 입력한 월드 코드와 일치하는 친구를 찾지 못했습니다.",
        })


async def _run_profile_search_ws(ws: WebSocket, code: str, delay: float) -> None:
    loop = asyncio.get_event_loop()
    logs: asyncio.Queue[dict] = asyncio.Queue()

    def log(message: str) -> None:
        logs.put_nowait({"type": "log", "text": message})

    def do_search() -> Optional[dict]:
        try:
            return find_profile_entry(code, delay=delay, logger=log)
        except Exception as exc:
            logs.put_nowait({"type": "log", "text": f"[오류] {exc}"})
            return None

    task = loop.run_in_executor(None, do_search)

    while not task.done():
        try:
            item = await asyncio.wait_for(logs.get(), timeout=0.2)
            await ws.send_json(item)
        except asyncio.TimeoutError:
            pass

    result = await task

    while not logs.empty():
        item = await logs.get()
        await ws.send_json(item)

    if result:
        await ws.send_json({"type": "done", "success": True, "entry": result})
    else:
        await ws.send_json({
            "type": "done",
            "success": False,
            "text": "[결과] 해당 프로필 코드를 친구 목록에서 찾지 못했습니다.",
        })


# ── WebSocket: 친구 검색 실시간 ───────────────────────────────────

@ws_router.websocket("/ws/friends")
async def ws_friends(websocket: WebSocket) -> None:
    await websocket.accept()
    global _friend_search_running
    try:
        while True:
            msg = await websocket.receive_json()
            action = msg.get("action")
            if action != "search":
                continue

            codes = msg.get("codes", [])
            phase = msg.get("phase", 1)
            if not codes:
                code = msg.get("code", "")
                if code:
                    codes = [code]
            if not codes:
                await websocket.send_json({"type": "error", "text": "검색할 코드가 없습니다."})
                continue

            _friend_search_stop.clear()
            _friend_search_running = True

            loop = asyncio.get_event_loop()
            q: asyncio.Queue[dict] = asyncio.Queue()

            def run() -> None:
                _run_friend_search_blocking(codes, phase, q, _friend_search_stop)

            task = loop.run_in_executor(None, run)

            while not task.done():
                try:
                    item = await asyncio.wait_for(q.get(), timeout=0.2)
                    await websocket.send_json(item)
                except asyncio.TimeoutError:
                    pass

            await task

            while not q.empty():
                item = await q.get()
                await websocket.send_json(item)

            _friend_search_running = False

    except WebSocketDisconnect:
        _friend_search_stop.set()
        _friend_search_running = False
    except asyncio.CancelledError:
        _friend_search_stop.set()
        _friend_search_running = False


def _run_friend_search_blocking(
    codes: list[str],
    phase: int,
    q: asyncio.Queue[dict],
    stop: threading.Event,
) -> None:
    """blocking friend search — 친구 목록 페이지를 순회하며 결과를 스트리밍."""

    def log(message: str) -> None:
        q.put_nowait({"type": "status", "text": message})

    code = codes[0] if codes else ""
    total_entries = 0
    log(f"[정보] 프로필 코드 {code} 의 친구 목록을 검색합니다.")

    try:
        page_num = 0
        for _html, page_data in iter_friend_pages(code, delay=0.4):
            if stop.is_set():
                break
            page_num += 1

            entries = page_data.entries
            if not entries:
                continue

            total_entries += len(entries)
            result_list = [
                {
                    "status": "온라인" if e.is_online else "오프라인",
                    "ppsn": e.ppsn,
                    "profile_code": e.code,
                    "display_name": e.display_name,
                    "world_name": e.world_name,
                    "game_instance_id": e.game_instance_id,
                }
                for e in entries
            ]
            q.put_nowait({
                "type": "result",
                "entries": result_list,
            })
            q.put_nowait({"type": "progress", "count": total_entries})
            log(f"[정보] {page_num}페이지에서 {len(entries)}명의 친구를 확인했습니다. (총 {total_entries}명)")

    except Exception as exc:
        q.put_nowait({"type": "error", "text": f"[오류] {exc}"})

    finally:
        stopped = stop.is_set()
        summary = f"[결과] 총 {total_entries}명의 친구 데이터를 수집했습니다."
        if stopped:
            summary = "[정보] 검색이 중지되었습니다. " + summary
        q.put_nowait({"type": "status", "text": summary})
        q.put_nowait({"type": "finished"})
