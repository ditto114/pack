"""월드 매칭 서비스 — 패킷 스트림에서 worldId·channelName 추출."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Optional

from capture_app.constants import CHANNEL_NAME_PATTERN, WORLD_ID_PATTERN
from capture_app.models import WorldMatchEntry

from ..db import bulk_upsert_world_matches, get_world_matches as db_get_world_matches, clear_world_matches as db_clear


class WorldMatchService:
    """패킷 페이로드 스트림에서 월드ID-채널명 쌍을 추출한다."""

    def __init__(self) -> None:
        self.entries: list[WorldMatchEntry] = []
        self.matched_channels: set[str] = set()
        self.world_code_to_channels: dict[str, set[str]] = {}
        self._buffer: str = ""
        self.order: Optional[str] = None  # "world-first" | "channel-first" | None
        self.order_locked: bool = False
        self._ws_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)

    def set_order(self, order: Optional[str], *, locked: bool = False) -> None:
        self.order = order
        self.order_locked = locked

    def process_text(self, text: Optional[str], captured_at: float = 0.0, session_id: Optional[str] = None) -> list[WorldMatchEntry]:
        """텍스트를 버퍼에 추가하고 매칭된 엔트리를 반환한다."""
        if not text:
            return []
        self._buffer += text
        if len(self._buffer) > 8192:
            self._buffer = self._buffer[-8192:]

        raw_matches = self._extract_matches()
        if not raw_matches:
            return []

        new_entries: list[WorldMatchEntry] = []
        for world_code, channel_name in raw_matches:
            entry = self._add_match(world_code, channel_name, captured_at, session_id)
            if entry:
                new_entries.append(entry)
        return new_entries

    def _add_match(
        self, world_code: str, channel_name: str, captured_at: float, session_id: Optional[str]
    ) -> Optional[WorldMatchEntry]:
        channel_name = channel_name.strip()
        if not channel_name:
            return None
        normalized = channel_name.upper()
        if normalized in self.matched_channels:
            return None
        self.matched_channels.add(normalized)
        if captured_at <= 0:
            captured_at = time.time()
        entry = WorldMatchEntry(
            channel_name=channel_name, world_code=world_code, captured_at=captured_at
        )
        self.entries.insert(0, entry)
        self.world_code_to_channels.setdefault(world_code, set()).add(channel_name)

        # push to WS
        ws_data = {
            "channel_name": channel_name,
            "world_code": world_code,
            "captured_at": captured_at,
        }
        try:
            self._ws_queue.put_nowait(ws_data)
        except asyncio.QueueFull:
            pass

        return entry

    def _extract_matches(self) -> list[tuple[str, str]]:
        matches: list[tuple[str, str]] = []
        order = self.order

        if self.order_locked and order == "world-first":
            while True:
                wm = WORLD_ID_PATTERN.search(self._buffer)
                if not wm:
                    break
                cm = CHANNEL_NAME_PATTERN.search(self._buffer, wm.end())
                if cm:
                    matches.append((wm.group(1), cm.group(1)))
                    self._buffer = self._buffer[cm.end():]
                else:
                    self._buffer = self._buffer[wm.start():]
                    break
        elif self.order_locked and order == "channel-first":
            while True:
                cm = CHANNEL_NAME_PATTERN.search(self._buffer)
                if not cm:
                    break
                wm = WORLD_ID_PATTERN.search(self._buffer, cm.end())
                if wm:
                    matches.append((wm.group(1), cm.group(1)))
                    self._buffer = self._buffer[wm.end():]
                else:
                    self._buffer = self._buffer[cm.start():]
                    break
        else:
            while True:
                cm = CHANNEL_NAME_PATTERN.search(self._buffer)
                wm = WORLD_ID_PATTERN.search(self._buffer)
                if not cm and not wm:
                    break
                if wm and (not cm or wm.start() <= cm.start()):
                    ca = CHANNEL_NAME_PATTERN.search(self._buffer, wm.end())
                    if ca:
                        matches.append((wm.group(1), ca.group(1)))
                        self._buffer = self._buffer[ca.end():]
                        self.order = "world-first"
                    else:
                        self._buffer = self._buffer[wm.start():]
                        break
                elif cm:
                    wa = WORLD_ID_PATTERN.search(self._buffer, cm.end())
                    if wa:
                        matches.append((wa.group(1), cm.group(1)))
                        self._buffer = self._buffer[wa.end():]
                        self.order = "channel-first"
                    else:
                        self._buffer = self._buffer[cm.start():]
                        break
                else:
                    break
        return matches

    def save_to_db(self, session_id: Optional[str] = None) -> int:
        """현재 메모리 엔트리를 DB에 저장한다. 오류 시 예외를 전파한다."""
        if not self.entries:
            return 0
        rows: list[dict[str, Any]] = []
        for entry in self.entries:
            ts = datetime.fromtimestamp(entry.captured_at, tz=timezone.utc).isoformat()
            row: dict[str, Any] = {
                "channel_name": entry.channel_name,
                "world_code": entry.world_code,
                "captured_at": ts,
            }
            if session_id:
                row["session_id"] = session_id
            rows.append(row)
        result = bulk_upsert_world_matches(rows)
        return len(result)

    def clear(self, session_id: Optional[str] = None) -> None:
        self.entries.clear()
        self.matched_channels.clear()
        self.world_code_to_channels.clear()
        self._buffer = ""
        self.order = None
        self.order_locked = False
        db_clear(session_id)

    def get_entries_json(self) -> list[dict[str, Any]]:
        return [
            {
                "channel_name": e.channel_name,
                "world_code": e.world_code,
                "captured_at": e.captured_at,
            }
            for e in self.entries
        ]

    async def get_ws_match(self) -> dict[str, Any]:
        return await self._ws_queue.get()


# singleton
world_match_service = WorldMatchService()
