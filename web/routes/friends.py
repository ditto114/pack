"""친구 검색 관련 API 라우트."""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from capture_app.friend_services import (
    find_profile_entry,
    iter_friend_pages,
)


router = APIRouter(prefix="/api", tags=["friends"])


# ── Models ────────────────────────────────────────────────────────

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


ws_router = APIRouter()


# ── WebSocket: 친구 검색 실시간 ───────────────────────────────────

@ws_router.websocket("/ws/friends")
async def ws_friends(websocket: WebSocket) -> None:
    await websocket.accept()
    global _friend_search_running
    try:
        while True:
            msg = await websocket.receive_json()
            action = msg.get("action")

            if action == "search":
                codes = msg.get("codes", [])
                phase = msg.get("phase", 1)
                if not codes:
                    code = msg.get("code", "")
                    if code:
                        codes = [code]
                if not codes:
                    await websocket.send_json({"type": "error", "text": "검색할 코드가 없습니다."})
                    continue

                self_only = bool(msg.get("self_only", False))
                _friend_search_stop.clear()
                _friend_search_running = True

                loop = asyncio.get_event_loop()
                q: asyncio.Queue[dict] = asyncio.Queue()

                def run() -> None:
                    _run_friend_search_blocking(codes, phase, q, _friend_search_stop, self_only)

                task = loop.run_in_executor(None, run)

            elif action == "search_self":
                targets = msg.get("targets", [])
                friend_map: dict[str, list[str]] = msg.get("friend_map", {})
                if not targets:
                    await websocket.send_json({"type": "error", "text": "찾을 대상이 없습니다."})
                    continue

                _friend_search_stop.clear()
                _friend_search_running = True

                loop = asyncio.get_event_loop()
                q = asyncio.Queue()

                def run() -> None:
                    _run_self_search_optimized(targets, friend_map, q, _friend_search_stop)

                task = loop.run_in_executor(None, run)

            else:
                continue

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
    self_only: bool = False,
) -> None:
    """blocking friend search — 여러 코드 순회, 각 코드마다 본인 + 친구 목록 검색."""

    def log(message: str) -> None:
        q.put_nowait({"type": "status", "text": message})

    total_entries = 0
    multi = len(codes) > 1

    try:
        for idx, code in enumerate(codes):
            if stop.is_set():
                break

            if multi:
                log(f"[정보] [{idx + 1}/{len(codes)}] 프로필 코드 {code} 검색을 시작합니다.")
            else:
                log(f"[정보] 프로필 코드 {code} 의 친구 목록을 검색합니다.")

            # ── 본인 프로필 검색 ──────────────────────────────────
            log(f"[정보] 본인({code}) 프로필을 검색합니다.")
            try:
                self_entry = find_profile_entry(code, delay=0.4, logger=log)
                if self_entry:
                    self_entry["is_self"] = True
                    q.put_nowait({"type": "result", "entries": [self_entry], "search_code": code})
                    total_entries += 1
                    q.put_nowait({"type": "progress", "count": total_entries})
                else:
                    log(f"[경고] 본인({code}) 프로필을 찾지 못했습니다.")
            except Exception as exc:
                log(f"[경고] 본인 프로필 검색 중 오류: {exc}")

            if stop.is_set():
                break

            if not self_only:
                # ── 친구 목록 순회 ────────────────────────────────────
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
                        q.put_nowait({"type": "result", "entries": result_list, "search_code": code})
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


def _run_self_search_optimized(
    targets: list[str],
    friend_map: dict[str, list[str]],
    q: asyncio.Queue[dict],
    stop: threading.Event,
) -> None:
    """최적화된 본인 프로필 검색.

    유저 DB의 친구 목록을 역방향 인덱스로 활용:
    target T의 friend_list 에 있는 F 의 친구 목록을 조회하면 T의 프로필을 발견할 수 있다.
    가장 많은 대상을 커버하는 렌즈 F를 탐욕적으로 선택해 조회 횟수를 최소화한다.
    """

    def log(message: str) -> None:
        q.put_nowait({"type": "status", "text": message})

    remaining: set[str] = {t.upper() for t in targets}
    # 대소문자 보존용 맵
    code_map: dict[str, str] = {t.upper(): t for t in targets}
    # friend_map 값에서 원본 케이스 보존용 맵
    upper_to_orig: dict[str, str] = {}
    for friends in friend_map.values():
        for f in friends:
            upper_to_orig[f.upper()] = f

    found_count = 0

    # ── 역방향 인덱스 구성: 렌즈 코드 → 해당 렌즈로 발견 가능한 대상 집합 ──
    lens_coverage: dict[str, set[str]] = defaultdict(set)
    for target, friends in friend_map.items():
        t_up = target.upper()
        if t_up in remaining:
            for f in friends:
                lens_coverage[f.upper()].add(t_up)

    log(f"[정보] {len(targets)}명의 본인 프로필 탐색을 시작합니다. (렌즈 후보: {len(lens_coverage)}개)")

    try:
        # ── 탐욕적 렌즈 선택 루프 ────────────────────────────────────
        while remaining and not stop.is_set() and lens_coverage:
            # 현재 남은 대상을 가장 많이 커버하는 렌즈 선택
            best_up = max(lens_coverage, key=lambda l: len(lens_coverage[l] & remaining))
            best_coverage = lens_coverage[best_up] & remaining

            if not best_coverage:
                break

            best_orig = upper_to_orig.get(best_up, best_up)
            names = ", ".join(code_map.get(c, c) for c in best_coverage)
            log(f"[정보] {best_orig} 의 친구 목록 조회 → {len(best_coverage)}명 탐색 ({names})")

            try:
                for _html, page_data in iter_friend_pages(best_orig, delay=0.4):
                    if stop.is_set():
                        break
                    for e in page_data.entries:
                        e_up = (e.code or "").upper()
                        if e_up in remaining:
                            original = code_map.get(e_up, e.code)
                            entry = {
                                "status": "온라인" if e.is_online else "오프라인",
                                "ppsn": e.ppsn,
                                "profile_code": e.code,
                                "display_name": e.display_name,
                                "world_name": e.world_name,
                                "game_instance_id": e.game_instance_id,
                                "is_self": True,
                            }
                            remaining.discard(e_up)
                            found_count += 1
                            q.put_nowait({"type": "result", "entries": [entry], "search_code": original})
                            q.put_nowait({"type": "progress", "count": found_count})
                            log(f"[정보] {e.code} 프로필을 발견했습니다.")

                    # 이 렌즈로 기대하던 대상을 모두 찾으면 페이지 순회 조기 종료
                    if not (best_coverage & remaining):
                        break

            except Exception as exc:
                log(f"[경고] {best_orig} 조회 중 오류: {exc}")

            del lens_coverage[best_up]

        # ── 렌즈로 못 찾은 대상 폴백: find_profile_entry ─────────────
        for code_up in list(remaining):
            if stop.is_set():
                break
            original = code_map.get(code_up, code_up)
            log(f"[정보] {original} 직접 탐색 중... (친구 목록 정보 없음)")
            try:
                entry = find_profile_entry(original, delay=0.4, logger=log)
                if entry:
                    entry["is_self"] = True
                    remaining.discard(code_up)
                    found_count += 1
                    q.put_nowait({"type": "result", "entries": [entry], "search_code": original})
                    q.put_nowait({"type": "progress", "count": found_count})
                else:
                    log(f"[경고] {original} 프로필을 찾지 못했습니다.")
            except Exception as exc:
                log(f"[경고] {original} 직접 탐색 중 오류: {exc}")

    finally:
        stopped = stop.is_set()
        summary = f"[결과] {found_count}/{len(targets)}명의 본인 프로필을 수집했습니다."
        if stopped:
            summary = "[정보] 검색이 중지되었습니다. " + summary
        q.put_nowait({"type": "status", "text": summary})
        q.put_nowait({"type": "finished"})
