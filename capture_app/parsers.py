"""HTML 파서 모음."""

from __future__ import annotations

import html as html_lib
import re
from html.parser import HTMLParser
from typing import Optional

from .constants import CHANNEL_NAME_PATTERN, FRIEND_CODE_PATTERN
from .models import FriendEntry, FriendStatusEntry


class FriendListParser(HTMLParser):
    """MapleStory Worlds 친구 목록에서 (친구코드, PPSN) 쌍을 추출하는 파서."""

    def __init__(self) -> None:
        super().__init__()
        self._within_friend_section = False
        self._current_ppsn: Optional[str] = None
        self._current_code: Optional[str] = None
        self._current_is_online: Optional[bool] = None
        self._current_world_name: Optional[str] = None
        self._current_game_instance_id: Optional[str] = None
        self._current_entry: Optional[FriendEntry] = None
        self._capturing_name = False
        self._name_buffer: list[str] = []
        self.entries: list[FriendEntry] = []
        self.first_friend_code: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_dict = {key: value for key, value in attrs if value is not None}

        if tag == "section":
            class_name = attrs_dict.get("class", "")
            if "section_friend" in class_name:
                self._within_friend_section = True

        if not self._within_friend_section:
            return

        if tag in {"li", "article"}:
            if "isonline" in attrs_dict:
                self._current_is_online = attrs_dict.get("isonline", "").strip() == "1"
            else:
                self._current_is_online = None
            self._current_code = None
            self._current_entry = None
            self._current_world_name = None
            self._current_game_instance_id = None
            self._capturing_name = False
        elif tag == "div":
            class_name = attrs_dict.get("class", "")
            if "card_friend" in class_name or "card_user" in class_name:
                self._current_code = None
                self._current_entry = None
                if "isonline" not in attrs_dict:
                    self._current_is_online = None

        if "isonline" in attrs_dict:
            self._current_is_online = attrs_dict.get("isonline", "").strip() == "1"

        if "ppsn" in attrs_dict:
            self._current_ppsn = attrs_dict["ppsn"].strip()
            self._current_entry = None

        if "worldname" in attrs_dict:
            world_name = html_lib.unescape(attrs_dict["worldname"]).strip()
            if world_name:
                self._current_world_name = world_name
                if self._current_entry and not self._current_entry.world_name:
                    self._current_entry.world_name = world_name

        if "gameinstanceid" in attrs_dict:
            game_instance_id = attrs_dict["gameinstanceid"].strip()
            if game_instance_id:
                self._current_game_instance_id = game_instance_id
                if self._current_entry and not self._current_entry.game_instance_id:
                    self._current_entry.game_instance_id = game_instance_id

        if tag == "p":
            class_name = attrs_dict.get("class", "")
            if "txt_name" in class_name:
                self._capturing_name = True
                self._name_buffer.clear()

        if tag == "a" and "href" in attrs_dict:
            match = FRIEND_CODE_PATTERN.match(attrs_dict["href"])
            if match and not self._current_code:
                code = match.group(1)
                ppsn = attrs_dict.get("ppsn", self._current_ppsn)
                if ppsn:
                    is_online = self._current_is_online
                    if is_online is None:
                        is_online = attrs_dict.get("isonline", "").strip() == "1"
                    entry = FriendEntry(
                        code=code,
                        ppsn=ppsn,
                        is_online=bool(is_online),
                        display_name="",
                        world_name=self._current_world_name or "",
                        game_instance_id=self._current_game_instance_id or "",
                    )
                    self.entries.append(entry)
                    self._current_code = code
                    self._current_entry = entry
                    if self.first_friend_code is None:
                        self.first_friend_code = code

    def handle_endtag(self, tag: str) -> None:
        if self._capturing_name and tag == "p":
            self._capturing_name = False
            name = html_lib.unescape("".join(self._name_buffer)).strip()
            self._name_buffer.clear()
            if name and self._current_entry:
                self._current_entry.display_name = name
            return

        if tag == "section" and self._within_friend_section:
            self._within_friend_section = False
            self._current_ppsn = None
            self._current_code = None
            self._current_is_online = None
            self._current_world_name = None
            self._current_game_instance_id = None
            self._current_entry = None
            self._capturing_name = False
            self._name_buffer.clear()
        elif tag == "li":
            self._current_ppsn = None
            self._current_code = None
            self._current_is_online = None
            self._current_world_name = None
            self._current_game_instance_id = None
            self._current_entry = None
            self._capturing_name = False
            self._name_buffer.clear()
        elif tag == "article":
            self._current_ppsn = None
            self._current_code = None
            self._current_is_online = None
            self._current_world_name = None
            self._current_game_instance_id = None
            self._current_entry = None
            self._capturing_name = False
            self._name_buffer.clear()
        elif tag == "a":
            self._current_entry = None

    def handle_data(self, data: str) -> None:
        if self._capturing_name:
            self._name_buffer.append(data)


class FriendStatusParser(HTMLParser):
    """친구 카드에서 상태 및 프로필 정보를 추출하는 파서."""

    def __init__(self) -> None:
        super().__init__()
        self.entries: list[FriendStatusEntry] = []
        self._in_card = False
        self._card_depth = 0
        self._current_ppsn: Optional[str] = None
        self._current_profile_code: Optional[str] = None
        self._current_name_buffer: list[str] = []
        self._current_status_buffer: list[str] = []
        self._capturing_name = False
        self._capturing_status = False
        self._current_world_name: str = ""
        self._current_game_instance_id: str = ""
        self._current_status: str = ""
        self._current_name: str = ""
        self._current_is_online: Optional[bool] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_dict = {key: value for key, value in attrs if value is not None}

        if tag == "div" and not self._in_card:
            class_name = attrs_dict.get("class", "")
            ppsn = attrs_dict.get("ppsn")
            if ppsn and "card_friend" in class_name:
                self._in_card = True
                self._card_depth = 1
                self._current_ppsn = ppsn.strip()
                self._current_profile_code = None
                self._current_name_buffer.clear()
                self._current_status_buffer.clear()
                self._capturing_name = False
                self._capturing_status = False
                self._current_status = ""
                self._current_name = ""
                world_name = attrs_dict.get("worldname", "")
                self._current_world_name = html_lib.unescape(world_name).strip()
                self._current_game_instance_id = (attrs_dict.get("gameinstanceid") or "").strip()
                is_online_attr = attrs_dict.get("isonline")
                if is_online_attr is not None:
                    self._current_is_online = is_online_attr.strip() == "1"
                else:
                    self._current_is_online = None
                return

        if not self._in_card:
            return

        self._card_depth += 1

        if tag == "a":
            href = attrs_dict.get("href", "")
            match = FRIEND_CODE_PATTERN.match(href.strip())
            if match:
                self._current_profile_code = match.group(1)
        elif tag == "p":
            class_name = attrs_dict.get("class", "")
            if "txt_name" in class_name:
                self._capturing_name = True
                self._current_name_buffer.clear()
            elif "txt_status" in class_name:
                self._capturing_status = True
                self._current_status_buffer.clear()

    def handle_endtag(self, tag: str) -> None:
        if not self._in_card:
            return

        if self._capturing_name and tag == "p":
            self._capturing_name = False
            name = html_lib.unescape("".join(self._current_name_buffer)).strip()
            self._current_name_buffer.clear()
            if name:
                self._current_name = name
            else:
                self._current_name = ""
        elif self._capturing_status and tag == "p":
            self._capturing_status = False
            status_text = html_lib.unescape("".join(self._current_status_buffer)).strip()
            self._current_status_buffer.clear()
            normalized = re.sub(r"\s+", " ", status_text)
            if "접속" in normalized and "중" in normalized:
                self._current_status = "접속 중"
            elif "온라인" in normalized:
                self._current_status = "온라인"
            else:
                self._current_status = normalized

        self._card_depth -= 1

        if self._card_depth == 0:
            status = self._current_status.strip()
            if not status and self._current_is_online:
                status = "온라인"
            name = self._current_name.strip()
            profile_code = (self._current_profile_code or "").strip()
            ppsn = (self._current_ppsn or "").strip()

            if status in {"온라인", "접속 중"} and ppsn and profile_code:
                entry = FriendStatusEntry(
                    status=status,
                    ppsn=ppsn,
                    profile_code=profile_code,
                    display_name=name,
                    world_name=self._current_world_name,
                    game_instance_id=self._current_game_instance_id,
                )
                self.entries.append(entry)

            self._in_card = False
            self._card_depth = 0
            self._current_ppsn = None
            self._current_profile_code = None
            self._current_world_name = ""
            self._current_game_instance_id = ""
            self._current_status = ""
            self._current_name = ""
            self._current_is_online = None
            self._current_name_buffer.clear()
            self._current_status_buffer.clear()

    def handle_data(self, data: str) -> None:
        if not self._in_card:
            return
        if self._capturing_name:
            self._current_name_buffer.append(data)
        elif self._capturing_status:
            self._current_status_buffer.append(data)


class ChannelSearchParser(HTMLParser):
    """친구 목록 카드에서 월드 코드와 일치하는 정보를 추출하는 파서."""

    def __init__(self, target_world_code: str) -> None:
        super().__init__()
        self.target_world_code = target_world_code
        self._in_target_block = False
        self._block_depth = 0
        self._capturing_name = False
        self._name_buffer: list[str] = []
        self.friend_name: Optional[str] = None
        self.friend_code: Optional[str] = None
        self.ppsn: Optional[str] = None
        self._current_name: Optional[str] = None
        self._current_code: Optional[str] = None
        self._current_ppsn: Optional[str] = None
        self.found = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if self.found:
            return

        attrs_dict = {key: value for key, value in attrs if value is not None}

        if not self._in_target_block and attrs_dict.get("gameinstanceid") == self.target_world_code:
            self._in_target_block = True
            self._block_depth = 1
            self._current_ppsn = attrs_dict.get("ppsn")
            self._current_name = None
            self._current_code = None
            return

        if self._in_target_block:
            self._block_depth += 1
            if tag == "a" and "href" in attrs_dict and not self._current_code:
                match = FRIEND_CODE_PATTERN.match(attrs_dict["href"])
                if match:
                    self._current_code = match.group(1)
            if tag == "p":
                class_name = attrs_dict.get("class", "")
                if "txt_name" in class_name:
                    self._capturing_name = True
                    self._name_buffer.clear()

    def handle_endtag(self, tag: str) -> None:
        if self.found:
            return

        if self._capturing_name and tag == "p":
            self._capturing_name = False
            name = html_lib.unescape("".join(self._name_buffer)).strip()
            if name:
                self._current_name = name

        if self._in_target_block:
            self._block_depth -= 1
            if self._block_depth == 0:
                self._in_target_block = False
                if self._current_name and self._current_code:
                    self.friend_name = self._current_name
                    self.friend_code = self._current_code
                    self.ppsn = self._current_ppsn
                    self.found = True
                else:
                    self._current_ppsn = None
                    self._current_name = None
                    self._current_code = None

    def handle_data(self, data: str) -> None:
        if self._capturing_name:
            self._name_buffer.append(data)
