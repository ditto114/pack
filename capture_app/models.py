"""데이터 모델 정의."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union

NetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class PacketDisplay:
    summary: str
    payload: Optional[bytes]
    note: Optional[str] = None
    utf8_text: Optional[str] = None
    identifier: int = 0
    preview: str = ""
    direction: str = "unknown"
    captured_at: float = 0.0


@dataclass
class WorldMatchEntry:
    channel_name: str
    world_code: str
    captured_at: float


@dataclass
class FriendEntry:
    code: str
    ppsn: str
    is_online: bool = False
    display_name: str = ""
    world_name: str = ""
    game_instance_id: str = ""


@dataclass
class FriendPageData:
    entries: list[FriendEntry]
    first_friend_code: Optional[str]


@dataclass
class FriendStatusEntry:
    status: str
    ppsn: str
    profile_code: str
    display_name: str
    world_name: str = ""
    game_instance_id: str = ""


@dataclass
class FilterConfig:
    networks: list[NetworkType]
    port: Optional[int]
