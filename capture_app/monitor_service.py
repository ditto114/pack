"""친구 채널 변경 실시간 모니터링 서비스."""

from __future__ import annotations

import json
import time
import threading
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .constants import DEFAULT_REQUEST_HEADERS

_FRIENDS_API = "https://mverse-api.nexon.com/social/v1/{ppsn}/friends"
_PAGE_SIZE = 24


def _fetch_page(ppsn: str, page: int) -> tuple[list[dict], int]:
    """단일 페이지 친구 목록을 JSON API로 가져온다."""
    url = f"{_FRIENDS_API.format(ppsn=ppsn)}?ppsn={ppsn}&page={page}&size={_PAGE_SIZE}"
    headers = {
        **DEFAULT_REQUEST_HEADERS,
        "Accept": "application/json, text/plain, */*",
        "Referer": f"https://maplestoryworlds.nexon.com/ko/profile/{ppsn}/friends",
    }
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("code") != 0:
                raise RuntimeError(f"API 오류: {data.get('message', '알 수 없음')}")
            return data["data"]["result"], data["data"]["totalCount"]
        except (HTTPError, URLError) as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(1 + attempt)
    raise last_exc  # type: ignore[misc]


def _fetch_all(ppsn: str) -> dict[str, dict]:
    """전체 페이지를 순회하여 {ppsn: entry} 형태로 반환한다."""
    result: dict[str, dict] = {}
    page = 1
    while True:
        friends, total = _fetch_page(ppsn, page)
        for f in friends:
            result[f["ppsn"]] = f
        if len(result) >= total or not friends:
            break
        page += 1
    return result


def _diff(prev: dict[str, dict], curr: dict[str, dict]) -> list[dict]:
    """이전/현재 상태를 비교해 변경 이벤트 목록을 반환한다."""
    events: list[dict] = []
    for key in set(prev) & set(curr):
        p, c = prev[key], curr[key]
        if p["isOnline"] != c["isOnline"]:
            events.append({"type": "online", "entry": c, "prevOnline": p["isOnline"]})
        elif c["isOnline"] and p["gameInstanceId"] != c["gameInstanceId"]:
            # 둘 다 온라인 상태에서 채널이 바뀐 경우
            events.append({
                "type": "channel",
                "entry": c,
                "prevGameInstanceId": p["gameInstanceId"],
                "prevWorldName": p["worldName"],
            })
    return events


def monitor_friends_multi(
    ppsns: list[str],
    interval: float,
    emit: Callable[[dict], None],
    stop: threading.Event,
) -> None:
    """다중 PPSN 동시 모니터링. 각 PPSN마다 스레드를 실행하고 중복 이벤트를 제거한다."""
    if len(ppsns) == 1:
        monitor_friends(ppsns[0], interval, emit, stop)
        return

    lock = threading.Lock()
    recent_events: dict[tuple, float] = {}
    dedup_window = max(interval * 2, 10.0)

    def dedup_emit(msg: dict) -> None:
        if msg.get("type") in ("online", "channel"):
            entry = msg.get("entry", {})
            key = (
                entry.get("ppsn", ""),
                msg["type"],
                entry.get("isOnline"),
                entry.get("gameInstanceId", ""),
            )
            now = time.time()
            with lock:
                if now - recent_events.get(key, 0) < dedup_window:
                    return
                recent_events[key] = now
                cutoff = now - dedup_window * 2
                expired = [k for k, v in recent_events.items() if v < cutoff]
                for k in expired:
                    del recent_events[k]
        emit(msg)

    threads = [
        threading.Thread(
            target=monitor_friends,
            args=(ppsn, interval, dedup_emit, stop),
            daemon=True,
        )
        for ppsn in ppsns
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def monitor_friends(
    ppsn: str,
    interval: float,
    emit: Callable[[dict], None],
    stop: threading.Event,
) -> None:
    """
    친구 목록 변경을 주기적으로 감지하여 emit 콜백으로 이벤트를 전달한다.

    emit 메시지 타입:
      {"type": "init",    "friends": [...]}                              최초 전체 상태
      {"type": "online",  "entry": {...}, "prevOnline": 0|1}             온/오프라인 변화
      {"type": "channel", "entry": {...}, "prevGameInstanceId": "...",
                          "prevWorldName": "..."}                        채널 이동
      {"type": "status",  "text": "..."}                                 상태 메시지
      {"type": "error",   "text": "..."}                                 오류
    """
    prev: dict[str, dict] = {}
    first = True

    while not stop.is_set():
        try:
            curr = _fetch_all(ppsn)

            if first:
                first = False
                prev = curr
                online_cnt = sum(1 for f in curr.values() if f["isOnline"])
                emit({"type": "init", "friends": list(curr.values())})
                emit({"type": "status", "text": f"[정보] {len(curr)}명 모니터링 시작 (온라인: {online_cnt}명, 갱신 간격: {interval}초)"})
            else:
                events = _diff(prev, curr)
                prev = curr
                for ev in events:
                    emit(ev)

        except Exception as exc:
            emit({"type": "error", "text": f"[오류] {exc}"})

        # stop 이벤트에 빠르게 반응하도록 0.1초 단위로 분할 대기
        for _ in range(int(interval * 10)):
            if stop.is_set():
                break
            time.sleep(0.1)
