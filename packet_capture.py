"""패킷 캡쳐 UI 애플리케이션.

이 모듈은 Tkinter 기반의 간단한 사용자 인터페이스를 제공하여
네트워크 패킷을 캡쳐하고, 특정 IP 주소 기준 필터링 및 UTF-8 텍스트
디코딩 결과를 확인할 수 있도록 한다.
"""

from __future__ import annotations

import csv
import html as html_lib
import ipaddress
import json
import queue
import re
import socket
import threading
import time
import tkinter as tk
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Iterable, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from scapy.all import AsyncSniffer, IP, IPv6, Raw, TCP, UDP  # type: ignore
except ImportError as exc:  # pragma: no cover - scapy 미설치 환경 대비
    raise SystemExit(
        "Scapy가 설치되어 있지 않습니다. 'pip install scapy' 명령으로 설치 후 다시 실행하세요."
    ) from exc


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


NetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


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


BASE_URL = "https://maplestoryworlds.nexon.com"
PROFILE_URL = BASE_URL + "/ko/profile/{code}"
FRIENDS_PAGE_URL = (
    BASE_URL + "/ko/profile/{code}/friends?type=friends&page={page}"
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0 Safari/537.36"
)
DEFAULT_REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive",
}
FRIEND_CODE_PATTERN = re.compile(r"^/profile/([A-Za-z0-9]{5})$")
FRIEND_CODE_IN_TEXT_PATTERN = re.compile(r"/profile/([A-Za-z0-9]{5})")
VALUE_PREFIX_PATTERN = r"[\s:=\"'\x00-\x1F]*"
WORLD_ID_PATTERN = re.compile(
    rf"w\s*o\s*r\s*l\s*d\s*i\s*d{VALUE_PREFIX_PATTERN}(\d{{17}})",
    re.IGNORECASE,
)
CHANNEL_NAME_PATTERN = re.compile(
    rf"(?:c\s*h\s*a\s*n\s*n\s*e\s*l\s*n\s*a\s*m\s*e{VALUE_PREFIX_PATTERN})?"
    rf"([A-Za-z]-?[\uAC00-\uD7A3]-[0-9]{{2,3}})",
    re.IGNORECASE,
)
NOTIFICATION_CODE_PATTERN = re.compile(
    r"([A-Za-z][\uAC00-\uD7A3]-[0-9]{2,3}|[A-Za-z]-[\uAC00-\uD7A3][0-9]{2,3})"
)


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


def fetch_html(
    url: str,
    *,
    referer: Optional[str] = None,
    retries: int = 2,
    timeout: int = 10,
) -> str:
    """지정된 URL에서 HTML 문서를 가져온다.

    MapleStory Worlds 측의 접근 제어로 403 오류가 발생할 수 있으므로 현실적인 헤더를
    사용하고 동일 오류가 발생하면 재시도한다.
    """

    headers = dict(DEFAULT_REQUEST_HEADERS)
    headers.setdefault("Referer", referer or BASE_URL + "/")

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return response.read().decode(charset, "ignore")
        except HTTPError as exc:
            last_error = exc
            if exc.code in (403, 429) and attempt < retries:
                time.sleep(1 + attempt)
                continue
            if exc.code == 403:
                raise RuntimeError(
                    "서버에서 요청을 거부했습니다(403 Forbidden). 잠시 후 다시 시도하거나 "
                    "네트워크 환경을 확인하세요."
                ) from exc
            raise
        except URLError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(1 + attempt)
                continue
            raise

    assert last_error is not None
    raise last_error


def extract_friend_codes_from_profile(html: str) -> list[str]:
    parser = FriendListParser()
    parser.feed(html)
    return [entry.code for entry in parser.entries]


def extract_entries_from_friends_page(html: str) -> FriendPageData:
    parser = FriendListParser()
    parser.feed(html)
    return FriendPageData(entries=list(parser.entries), first_friend_code=parser.first_friend_code)


def get_initial_friends(target_code: str) -> list[str]:
    profile_url = PROFILE_URL.format(code=target_code)
    html = fetch_html(profile_url, referer=BASE_URL + "/ko")
    codes = extract_friend_codes_from_profile(html)
    if not codes:
        raise RuntimeError(
            "프로필 페이지에서 친구 목록을 찾지 못했습니다. 친구 코드가 올바른지 확인하세요."
        )
    return codes


def iter_friend_pages(
    friend_code: str, *, delay: float = 0.5
) -> Iterable[tuple[str, FriendPageData]]:
    page = 1
    seen_empty = 0
    while True:
        url = FRIENDS_PAGE_URL.format(code=friend_code, page=page)
        try:
            html = fetch_html(url, referer=PROFILE_URL.format(code=friend_code))
        except HTTPError as exc:
            if exc.code == 404:
                break
            raise
        page_data = extract_entries_from_friends_page(html)
        if not page_data.entries:
            seen_empty += 1
            if seen_empty >= 2:
                break
        else:
            seen_empty = 0
            yield html, page_data
        page += 1
        if delay:
            time.sleep(delay)


def fetch_friend_statuses(
    friend_code: str,
    *,
    delay: float = 0.5,
    logger: Optional[Callable[[str], None]] = None,
    progress_callback: Optional[Callable[[int], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> list[FriendStatusEntry]:
    """친구 목록 페이지를 순회하며 상태 정보를 수집한다."""

    log = logger or (lambda message: None)
    results: list[FriendStatusEntry] = []
    total = 0
    page = 1

    while True:
        if stop_event and stop_event.is_set():
            log("[정보] 친구 목록 수집이 사용자 요청으로 중지되었습니다.")
            break
        url = FRIENDS_PAGE_URL.format(code=friend_code, page=page)
        log(f"[정보] {page} 페이지의 친구 목록을 요청합니다.")
        try:
            html = fetch_html(url, referer=PROFILE_URL.format(code=friend_code))
        except HTTPError as exc:
            if exc.code == 404:
                if page == 1:
                    raise RuntimeError(
                        "친구 목록 페이지를 찾지 못했습니다. 친구 코드가 올바른지 확인하세요."
                    ) from exc
                log("[정보] 더 이상 친구 목록 페이지가 없습니다.")
                break
            raise
        parser = FriendStatusParser()
        parser.feed(html)
        entries = parser.entries
        log(f"[정보] {page} 페이지에서 {len(entries)}명의 친구를 추출했습니다.")
        if not entries:
            if page == 1:
                log("[정보] 수집할 친구 데이터가 없습니다.")
            break

        for entry in entries:
            if stop_event and stop_event.is_set():
                log("[정보] 친구 목록 항목 수집을 중지합니다.")
                return results
            total += 1
            results.append(entry)
            if progress_callback:
                progress_callback(total)

        page += 1
        if stop_event and stop_event.is_set():
            log("[정보] 친구 목록 페이지 순회를 중지합니다.")
            break
        if delay:
            time.sleep(delay)

    return results


def find_ppsn(
    target_code: str,
    *,
    delay: float = 0.5,
    logger: Optional[Callable[[str], None]] = None,
) -> Optional[tuple[str, str]]:
    """친구 코드에 해당하는 PPSN을 탐색한다."""

    target_code_upper = target_code.upper()
    log = logger or (lambda message: None)

    friends = get_initial_friends(target_code)
    log(f"[정보] 초기 친구 {len(friends)}명을 확인했습니다.")

    for friend_code in friends:
        log(f"[정보] 친구 {friend_code} 의 목록을 탐색합니다...")
        try:
            for _html, page_data in iter_friend_pages(friend_code, delay=delay):
                for entry in page_data.entries:
                    if entry.code.upper() == target_code_upper:
                        log(
                            f"[결과] 친구 {friend_code} 의 목록에서 대상 코드를 찾았습니다."
                        )
                        return entry.ppsn, friend_code
        except URLError as exc:
            log(f"[경고] {friend_code} 의 친구 목록을 불러오지 못했습니다: {exc}")
        except HTTPError as exc:
            log(f"[경고] {friend_code} 의 친구 목록 요청 실패({exc.code}): {exc.reason}")

    return None


def _strip_html_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)


def extract_world_matches_from_html(html_text: str, world_code: str) -> list[tuple[str, str]]:
    if not world_code:
        return []
    lower_text = html_text.lower()
    target = world_code.lower()
    results: list[tuple[str, str]] = []
    search_pos = 0

    while True:
        index = lower_text.find(target, search_pos)
        if index == -1:
            break

        before_index = lower_text.rfind("gameinstanceid", 0, index)
        if before_index == -1:
            search_pos = index + len(target)
            continue

        start_candidates = [
            html_text.rfind(tag, 0, index) for tag in ("<li", "<article", "<div")
        ]
        block_start = max(start_candidates)
        if block_start == -1:
            block_start = max(0, index - 400)

        end_candidates = []
        for tag in ("</li", "</article", "</div"):
            pos = html_text.find(tag, index)
            if pos != -1:
                close_pos = html_text.find(">", pos)
                if close_pos != -1:
                    end_candidates.append(close_pos + 1)
        if end_candidates:
            block_end = min(end_candidates)
        else:
            block_end = min(len(html_text), index + 400)

        block = html_text[block_start:block_end]
        game_match = re.search(
            rf"gameinstanceid{VALUE_PREFIX_PATTERN}(\d{{17}})", block, re.IGNORECASE
        )
        if not game_match or game_match.group(1) != world_code:
            search_pos = index + len(target)
            continue

        name_match = re.search(
            r"<p[^>]*class=\"[^\"]*txt_name[^\"]*\"[^>]*>(.*?)</p>",
            block,
            re.IGNORECASE | re.DOTALL,
        )
        friend_match = FRIEND_CODE_IN_TEXT_PATTERN.search(block)

        if name_match and friend_match:
            name_text = html_lib.unescape(_strip_html_tags(name_match.group(1))).strip()
            friend_code = friend_match.group(1)
            if name_text and friend_code:
                results.append((name_text, friend_code))

        search_pos = index + len(target)

    return results


def find_friend_by_world_code(
    target_code: str,
    world_code: str,
    *,
    delay: float = 0.5,
    logger: Optional[Callable[[str], None]] = None,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> Optional[tuple[str, str, str]]:
    """지정한 친구 코드의 친구 목록에서 월드 코드를 탐색한다."""

    log = logger or (lambda message: None)

    processed_online_total = 0
    if progress_callback:
        progress_callback(processed_online_total)

    queue: deque[str] = deque([target_code])
    queued: set[str] = {target_code.upper()}
    visited: set[str] = set()

    while queue:
        current_code = queue.popleft()
        normalized_code = current_code.upper()
        if normalized_code in visited:
            continue
        visited.add(normalized_code)
        log(f"[정보] 친구 {current_code} 의 친구 목록에서 월드 코드를 탐색합니다.")

        fallback_friend_code: Optional[str] = None
        enqueue_fallback = False

        for page in range(1, 11):
            url = FRIENDS_PAGE_URL.format(code=current_code, page=page)
            referer = PROFILE_URL.format(code=current_code)
            log(f"[정보] {current_code} 의 {page} 페이지에서 월드 코드 검색을 시도합니다...")
            try:
                html = fetch_html(url, referer=referer)
            except HTTPError as exc:
                if exc.code == 404:
                    log("[경고] 친구 목록 페이지를 찾을 수 없습니다. 입력한 친구 코드를 확인하세요.")
                    enqueue_fallback = True
                    break
                raise

            page_data = extract_entries_from_friends_page(html)
            if fallback_friend_code is None and page_data.first_friend_code:
                fallback_friend_code = page_data.first_friend_code
                log(
                    f"[정보] 첫 번째 친구 코드 {fallback_friend_code} 를 다음 탐색 후보로 기록합니다."
                )

            online_entries = [entry for entry in page_data.entries if entry.is_online]
            if not online_entries:
                log("[정보] 온라인 상태의 친구가 없어 이 친구의 탐색을 중단합니다.")
                enqueue_fallback = True
                break

            processed_online_total += len(online_entries)
            if progress_callback:
                progress_callback(processed_online_total)
            log(
                f"[정보] 현재 페이지에서 온라인 친구 {len(online_entries)}명을 확인했습니다."
            )

            if world_code in html:
                parser = ChannelSearchParser(world_code)
                parser.feed(html)
                if parser.found and parser.friend_name and parser.friend_code:
                    log(
                        "[결과] 월드 코드와 일치하는 친구 정보를 찾았습니다."
                    )
                    friend_name = parser.friend_name
                    friend_code = parser.friend_code
                    ppsn = parser.ppsn or ""
                    return friend_name, friend_code, ppsn
                log("[경고] 월드 코드를 포함한 블럭에서 필요한 정보를 추출하지 못했습니다.")
            else:
                log("[정보] 해당 페이지에서 월드 코드를 찾지 못했습니다.")

            if delay:
                time.sleep(delay)
        else:
            enqueue_fallback = True

        if enqueue_fallback and fallback_friend_code:
            fallback_upper = fallback_friend_code.upper()
            if fallback_upper not in visited and fallback_upper not in queued:
                log(
                    f"[정보] 친구 {fallback_friend_code} 의 친구 목록으로 탐색을 이어갑니다."
                )
                queue.append(fallback_friend_code)
                queued.add(fallback_upper)
            else:
                log(
                    f"[정보] 친구 {fallback_friend_code} 는 이미 탐색 대상에 포함되어 있습니다."
                )
        elif enqueue_fallback and not fallback_friend_code:
            log("[경고] 이어서 탐색할 친구 코드를 찾지 못했습니다.")

    return None


@dataclass
class FilterConfig:
    networks: list[NetworkType]
    port: Optional[int]


class PacketCaptureApp:
    """패킷 캡쳐 애플리케이션.

    Tkinter 위젯을 기반으로 캡쳐 시작/중지, IP 필터링, UTF-8 디코딩 결과
    확인 기능을 제공한다.
    """

    DEFAULT_MAX_PACKETS = 500

    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        self.master.title("패킷 캡쳐 도구")
        self.packet_queue: "queue.Queue[PacketDisplay]" = queue.Queue()
        self.packet_list_data: list[PacketDisplay] = []
        self.stop_event = threading.Event()
        self.sniffer: Optional[AsyncSniffer] = None
        self.packet_counter = 0
        self.settings_path = Path(__file__).resolve().with_name("packet_capture_settings.json")
        self.ppsn_queue: "queue.Queue[dict[str, object]]" = queue.Queue()
        self.ppsn_thread: Optional[threading.Thread] = None
        self.lookup_running = False
        self.local_addresses = self._detect_local_addresses()
        self.direction_filter_var = tk.StringVar(value="전체")
        self.world_match_entries: list[WorldMatchEntry] = []
        self.world_match_channels: set[str] = set()
        self.world_code_to_channels: dict[str, set[str]] = {}
        self._world_match_buffer: str = ""
        self._world_last_clicked_item: Optional[str] = None
        self.world_export_button: Optional[ttk.Button] = None
        self.ppsn_window: Optional[tk.Toplevel] = None
        self.ppsn_code_entry: Optional[ttk.Entry] = None
        self.ppsn_delay_entry: Optional[ttk.Entry] = None
        self.ppsn_search_button: Optional[ttk.Button] = None
        self.channel_world_entry: Optional[ttk.Entry] = None
        self.channel_search_button: Optional[ttk.Button] = None
        self.ppsn_log: Optional[tk.Text] = None
        self.ppsn_result_entry: Optional[ttk.Entry] = None
        self.ppsn_copy_button: Optional[ttk.Button] = None
        self.channel_result_entry: Optional[ttk.Entry] = None
        self.channel_count_entry: Optional[ttk.Entry] = None
        self.friend_queue: "queue.Queue[dict[str, object]]" = queue.Queue()
        self.friend_search_thread: Optional[threading.Thread] = None
        self.friend_search_running = False
        self.friend_search_phase = 1
        self.friend_panel: Optional[ttk.LabelFrame] = None
        self.friend_tree: Optional[ttk.Treeview] = None
        self.friend_code_var = tk.StringVar()
        self.friend_status_var = tk.StringVar(value="친구 코드를 입력하고 검색을 시작하세요.")
        self.friend_count_var = tk.StringVar(value="0")
        self.friend_toggle_button: Optional[ttk.Button] = None
        self.friend_code_entry: Optional[ttk.Entry] = None
        self.friend_search_button: Optional[ttk.Button] = None
        self.friend_stop_button: Optional[ttk.Button] = None
        self.friend_search_stop_event = threading.Event()
        self.friend_entries: list[FriendStatusEntry] = []
        self.friend_entry_keys: set[tuple[str, str]] = set()
        self.last_friend_primary_code: str = ""
        self.world_match_order_var = tk.StringVar(value="")
        self.world_match_world_first_var = tk.BooleanVar(value=False)
        self.world_match_channel_first_var = tk.BooleanVar(value=False)
        self.world_match_order_locked = False
        self.notification_window: Optional[tk.Toplevel] = None
        self.notification_text: Optional[tk.Text] = None
        self.notification_logs: deque[str] = deque(maxlen=200)
        self._notification_buffer: str = ""

        self._build_widgets()
        self._load_settings()
        self._poll_queue()
        self._poll_ppsn_queue()
        self._poll_friend_queue()
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI 구성
    def _build_widgets(self) -> None:
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(3, weight=0)
        main_frame.columnconfigure(4, weight=0)
        main_frame.rowconfigure(2, weight=1)
        main_frame.rowconfigure(3, weight=1)

        # 필터 입력
        filter_frame = ttk.LabelFrame(main_frame, text="필터")
        filter_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        filter_frame.columnconfigure(1, weight=1)
        filter_frame.columnconfigure(3, weight=1)

        ttk.Label(filter_frame, text="대상 IP/네트워크").grid(row=0, column=0, padx=(8, 4), pady=8)
        self.ip_entry = ttk.Entry(filter_frame)
        self.ip_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=8)
        ttk.Label(filter_frame, text="예: 192.168.0.10 또는 2001:db8::/64").grid(
            row=0, column=2, columnspan=2, padx=(0, 8), sticky="w"
        )

        ttk.Label(filter_frame, text="포트").grid(row=1, column=0, padx=(8, 4), pady=(0, 8))
        self.port_entry = ttk.Entry(filter_frame)
        self.port_entry.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(0, 8))
        ttk.Label(filter_frame, text="(비우면 모든 포트)").grid(row=1, column=2, padx=(0, 8), pady=(0, 8))

        ttk.Label(filter_frame, text="텍스트 포함").grid(row=2, column=0, padx=(8, 4), pady=(0, 8))
        self.text_filter_var = tk.StringVar()
        self.text_filter_entry = ttk.Entry(filter_frame, textvariable=self.text_filter_var)
        self.text_filter_entry.grid(row=2, column=1, sticky="ew", padx=(0, 8), pady=(0, 8))
        ttk.Label(filter_frame, text="(UTF-8 텍스트 기준 검색)").grid(
            row=2,
            column=2,
            columnspan=2,
            padx=(0, 8),
            pady=(0, 8),
            sticky="w",
        )
        self.text_filter_var.trace_add("write", self._on_text_filter_change)

        ttk.Label(filter_frame, text="표시 최대 패킷 수").grid(
            row=3, column=0, padx=(8, 4), pady=(0, 8)
        )
        self.max_packets_var = tk.StringVar(value=str(self.DEFAULT_MAX_PACKETS))
        self.max_packets_entry = ttk.Entry(filter_frame, textvariable=self.max_packets_var)
        self.max_packets_entry.grid(row=3, column=1, sticky="ew", padx=(0, 8), pady=(0, 8))
        ttk.Label(filter_frame, text="(최대값 초과 시 오래된 패킷을 삭제)").grid(
            row=3, column=2, columnspan=2, padx=(0, 8), pady=(0, 8), sticky="w"
        )

        ttk.Label(filter_frame, text="패킷 방향").grid(
            row=4, column=0, padx=(8, 4), pady=(0, 8)
        )
        self.direction_filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.direction_filter_var,
            values=("전체", "수신", "송신", "미확인"),
            state="readonly",
        )
        self.direction_filter_combo.grid(row=4, column=1, sticky="ew", padx=(0, 8), pady=(0, 8))
        self.direction_filter_combo.current(0)
        self.direction_filter_combo.bind("<<ComboboxSelected>>", self._on_direction_filter_change)
        ttk.Label(filter_frame, text="(방향 기준 필터링)").grid(
            row=4, column=2, columnspan=2, padx=(0, 8), pady=(0, 8), sticky="w"
        )

        # 제어 버튼
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        button_frame.columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.start_button = ttk.Button(button_frame, text="캡쳐 시작", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=4, sticky="ew")
        self.stop_button = ttk.Button(button_frame, text="캡쳐 중지", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=4, sticky="ew")
        self.ppsn_toggle_button = ttk.Button(
            button_frame,
            text="PPSN 찾기",
            command=self._toggle_ppsn_panel,
        )
        self.ppsn_toggle_button.grid(row=0, column=2, padx=4, sticky="ew")
        self.world_toggle_button = ttk.Button(
            button_frame,
            text="월드 매칭",
            command=self._toggle_world_panel,
        )
        self.world_toggle_button.grid(row=0, column=3, padx=4, sticky="ew")

        self.friend_toggle_button = ttk.Button(
            button_frame,
            text="친구검색",
            command=self._toggle_friend_panel,
        )
        self.friend_toggle_button.grid(row=0, column=4, padx=4, sticky="ew")

        self.alert_button = ttk.Button(
            button_frame,
            text="알림",
            command=self._show_notification_overlay,
        )
        self.alert_button.grid(row=0, column=5, padx=4, sticky="ew")

        # 패킷 리스트
        packet_frame = ttk.LabelFrame(main_frame, text="캡쳐된 패킷")
        packet_frame.grid(row=2, column=0, sticky="nsew")
        packet_frame.columnconfigure(0, weight=1)
        packet_frame.rowconfigure(0, weight=1)

        columns = ("time", "summary", "direction", "preview")
        self.packet_tree = ttk.Treeview(
            packet_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.packet_tree.heading("time", text="시간")
        self.packet_tree.heading("summary", text="요약")
        self.packet_tree.heading("direction", text="방향")
        self.packet_tree.heading("preview", text="미리보기(한글)")
        self.packet_tree.column("time", anchor="center", width=80, stretch=False)
        self.packet_tree.column("summary", anchor="w", stretch=True)
        self.packet_tree.column("direction", anchor="center", width=70, stretch=False)
        self.packet_tree.column("preview", anchor="w", width=200, stretch=False)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        self.packet_tree.bind("<<TreeviewSelect>>", self._on_select_packet)

        scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.packet_tree.configure(yscrollcommand=scrollbar.set)

        # 패킷 상세
        detail_frame = ttk.LabelFrame(main_frame, text="패킷 상세 및 페이로드")
        detail_frame.grid(row=3, column=0, sticky="nsew", pady=(8, 0))
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(1, weight=1)

        encoding_frame = ttk.Frame(detail_frame)
        encoding_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=(4, 0))
        encoding_frame.columnconfigure(1, weight=1)

        ttk.Label(encoding_frame, text="텍스트 인코딩").grid(row=0, column=0, padx=(0, 8))
        self.encoding_var = tk.StringVar(value="utf-8")
        self.encoding_combo = ttk.Combobox(
            encoding_frame,
            textvariable=self.encoding_var,
            values=("utf-8", "euc-kr", "cp949", "latin-1", "shift_jis"),
            state="readonly",
        )
        self.encoding_combo.grid(row=0, column=1, sticky="ew")
        self.encoding_combo.bind("<<ComboboxSelected>>", self._on_change_encoding)

        self.detail_text = tk.Text(detail_frame, height=12, wrap="word")
        self.detail_text.grid(row=1, column=0, sticky="nsew")
        detail_scroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.detail_text.yview)
        detail_scroll.grid(row=1, column=1, sticky="ns")
        self.detail_text.configure(yscrollcommand=detail_scroll.set, state=tk.NORMAL)
        self.detail_text.bind("<Key>", self._prevent_detail_edit)
        self.detail_text.bind("<<Paste>>", lambda _event: "break")

        self.export_button = ttk.Button(
            detail_frame,
            text="TXT로 내보내기",
            command=self._export_selected_packet,
        )
        self.export_button.grid(row=2, column=0, columnspan=2, sticky="e", padx=4, pady=(4, 8))
        self.detail_text.bind("<Button-3>", lambda _event: "break")
        self._set_detail_text("캡쳐를 시작하면 패킷이 여기에 표시됩니다.")

        self.ppsn_code_var = tk.StringVar()
        self.ppsn_delay_var = tk.StringVar(value="0.5")
        self.ppsn_result_var = tk.StringVar()
        self.channel_world_var = tk.StringVar()
        self.channel_result_var = tk.StringVar()
        self.channel_friend_count_var = tk.StringVar(value="0")

        self.world_panel = ttk.LabelFrame(main_frame, text="월드 매칭", padding=8)
        self.world_panel.grid(row=0, column=3, rowspan=4, sticky="nsew", padx=(12, 0))
        self.world_panel.columnconfigure(0, weight=1)
        self.world_panel.rowconfigure(2, weight=1)

        ttk.Label(self.world_panel, text="감지된 월드-채널 매칭").grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )

        order_frame = ttk.Frame(self.world_panel)
        order_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Label(order_frame, text="매칭 순서").grid(row=0, column=0, sticky="w")

        ttk.Checkbutton(
            order_frame,
            text="월드ID → 채널 이름",
            variable=self.world_match_world_first_var,
            command=self._on_world_first_toggle,
        ).grid(row=0, column=1, padx=(8, 0))
        ttk.Checkbutton(
            order_frame,
            text="채널 이름 → 월드ID",
            variable=self.world_match_channel_first_var,
            command=self._on_channel_first_toggle,
        ).grid(row=0, column=2, padx=(8, 0))

        self._set_world_match_order_ui(None)

        world_columns = ("captured_at", "channel", "world")
        self.world_tree = ttk.Treeview(
            self.world_panel,
            columns=world_columns,
            show="headings",
            selectmode="browse",
            height=12,
        )
        self.world_tree.heading("captured_at", text="캡쳐 시간")
        self.world_tree.heading("channel", text="채널 이름")
        self.world_tree.heading("world", text="월드 코드")
        self.world_tree.column("captured_at", anchor="center", width=90, stretch=False)
        self.world_tree.column("channel", anchor="w", width=120, stretch=True)
        self.world_tree.column("world", anchor="w", width=180, stretch=True)
        self.world_tree.grid(row=2, column=0, sticky="nsew")
        self.world_tree.bind("<ButtonRelease-1>", self._on_world_tree_click)

        world_scroll = ttk.Scrollbar(self.world_panel, orient=tk.VERTICAL, command=self.world_tree.yview)
        world_scroll.grid(row=2, column=1, sticky="ns")
        self.world_tree.configure(yscrollcommand=world_scroll.set)

        world_button_frame = ttk.Frame(self.world_panel)
        world_button_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        world_button_frame.columnconfigure(1, weight=1)

        ttk.Button(
            world_button_frame,
            text="기록 삭제",
            command=self._clear_world_matches,
        ).grid(row=0, column=0, sticky="w")

        self.world_export_button = ttk.Button(
            world_button_frame,
            text="CSV로 저장",
            command=self._export_world_matches_to_csv,
        )
        self.world_export_button.grid(row=0, column=1, sticky="e")
        self.world_export_button.config(state=tk.DISABLED)

        self.world_panel.grid_remove()

        self.friend_panel = ttk.LabelFrame(main_frame, text="친구 검색", padding=8)
        self.friend_panel.grid(row=0, column=4, rowspan=4, sticky="nsew", padx=(12, 0))
        self.friend_panel.columnconfigure(0, weight=1)
        self.friend_panel.rowconfigure(3, weight=1)

        friend_input = ttk.Frame(self.friend_panel)
        friend_input.grid(row=0, column=0, sticky="ew")
        friend_input.columnconfigure(1, weight=1)

        ttk.Label(friend_input, text="친구 코드 (5글자)").grid(
            row=0, column=0, padx=(0, 8), pady=(0, 4), sticky="w"
        )
        self.friend_code_entry = ttk.Entry(friend_input, textvariable=self.friend_code_var, width=12)
        self.friend_code_entry.grid(row=0, column=1, sticky="ew", pady=(0, 4))
        self.friend_search_button = ttk.Button(
            friend_input,
            text="1차 검색",
            command=self._on_friend_search,
        )
        self.friend_search_button.grid(row=0, column=2, padx=(8, 0), pady=(0, 4))
        self.friend_stop_button = ttk.Button(
            friend_input,
            text="중지",
            command=self._on_friend_search_stop,
            state=tk.DISABLED,
        )
        self.friend_stop_button.grid(row=0, column=3, padx=(8, 0), pady=(0, 4))

        # 상태 및 결과 표시
        self.friend_status_var.set("친구 코드를 입력하고 검색을 시작하세요.")
        friend_status_label = ttk.Label(
            self.friend_panel,
            textvariable=self.friend_status_var,
            wraplength=260,
            justify="left",
        )
        friend_status_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        friend_count_frame = ttk.Frame(self.friend_panel)
        friend_count_frame.grid(row=2, column=0, sticky="ew", pady=(4, 4))
        ttk.Label(friend_count_frame, text="탐색한 친구 수").grid(row=0, column=0, sticky="w")
        ttk.Label(friend_count_frame, textvariable=self.friend_count_var).grid(
            row=0, column=1, sticky="w", padx=(4, 0)
        )

        friend_columns = ("status", "ppsn", "profile", "name", "world", "channel_name", "channel")
        self.friend_tree = ttk.Treeview(
            self.friend_panel,
            columns=friend_columns,
            show="headings",
            selectmode="browse",
            height=18,
        )
        self.friend_tree.heading("status", text="상태")
        self.friend_tree.heading("ppsn", text="친구 코드 (PPSN)")
        self.friend_tree.heading("profile", text="친구 코드 (프로필)")
        self.friend_tree.heading("name", text="친구 이름")
        self.friend_tree.heading("world", text="월드 이름")
        self.friend_tree.heading("channel_name", text="채널 이름")
        self.friend_tree.heading("channel", text="채널 정보")
        self.friend_tree.column("status", anchor="center", width=80, stretch=False)
        self.friend_tree.column("ppsn", anchor="w", width=180, stretch=False)
        self.friend_tree.column("profile", anchor="center", width=120, stretch=False)
        self.friend_tree.column("name", anchor="w", width=180, stretch=True)
        self.friend_tree.column("world", anchor="w", width=200, stretch=True)
        self.friend_tree.column("channel_name", anchor="w", width=180, stretch=True)
        self.friend_tree.column("channel", anchor="w", width=200, stretch=True)
        self.friend_tree.grid(row=3, column=0, sticky="nsew")

        friend_scroll = ttk.Scrollbar(self.friend_panel, orient=tk.VERTICAL, command=self.friend_tree.yview)
        friend_scroll.grid(row=3, column=1, sticky="ns")
        self.friend_tree.configure(yscrollcommand=friend_scroll.set)

        self.friend_panel.grid_remove()
        self._update_friend_search_button()

    def _set_world_match_order_ui(self, order: Optional[str], *, locked: Optional[bool] = None) -> None:
        if order == "world-first":
            self.world_match_order_var.set("world-first")
            self.world_match_world_first_var.set(True)
            self.world_match_channel_first_var.set(False)
        elif order == "channel-first":
            self.world_match_order_var.set("channel-first")
            self.world_match_world_first_var.set(False)
            self.world_match_channel_first_var.set(True)
        else:
            self.world_match_order_var.set("")
            self.world_match_world_first_var.set(False)
            self.world_match_channel_first_var.set(False)
        if locked is not None:
            self.world_match_order_locked = locked

    def _on_world_first_toggle(self) -> None:
        if self.world_match_world_first_var.get():
            self._set_world_match_order_ui("world-first", locked=True)
        else:
            self._set_world_match_order_ui(None, locked=False)

    def _on_channel_first_toggle(self) -> None:
        if self.world_match_channel_first_var.get():
            self._set_world_match_order_ui("channel-first", locked=True)
        else:
            self._set_world_match_order_ui(None, locked=False)

    # ------------------------------------------------------------------
    # 이벤트 핸들러
    def start_capture(self) -> None:
        if self.sniffer and self.sniffer.running:
            messagebox.showinfo("알림", "이미 캡쳐가 진행 중입니다.")
            return

        try:
            filter_config = self._build_filter_config(
                self.ip_entry.get().strip(), self.port_entry.get().strip()
            )
        except ValueError as exc:
            messagebox.showerror("입력 오류", str(exc))
            return

        self._clear_capture_results()
        self.stop_event.clear()

        def packet_handler(packet) -> None:
            if self.stop_event.is_set():
                return

            payload = self._extract_payload_bytes(packet)
            summary = packet.summary()
            direction = self._determine_direction(packet)
            utf8_text = None
            if payload:
                try:
                    utf8_text = payload.decode("utf-8")
                except UnicodeDecodeError:
                    utf8_text = payload.decode("utf-8", errors="replace")
            preview = self._extract_hangul_preview(utf8_text)
            self.packet_queue.put(
                PacketDisplay(
                    summary=summary,
                    payload=payload,
                    utf8_text=utf8_text,
                    preview=preview,
                    direction=direction,
                    captured_at=time.time(),
                )
            )

        self.sniffer = AsyncSniffer(
            store=False,
            prn=packet_handler,
            lfilter=lambda pkt: self._packet_matches_filter(pkt, filter_config),
        )

        self._set_running_state(True)
        try:
            self.sniffer.start()
        except PermissionError:
            self.sniffer = None
            self._set_running_state(False)
            self.packet_queue.put(
                PacketDisplay(
                    summary="[오류] 캡쳐 권한이 필요합니다.",
                    payload=None,
                    note="관리자 권한 또는 sudo로 다시 실행하세요.",
                    captured_at=time.time(),
                )
            )
            return
        except OSError as exc:
            self.sniffer = None
            self._set_running_state(False)
            self.packet_queue.put(
                PacketDisplay(
                    summary="[오류] 캡쳐 도중 문제가 발생했습니다.",
                    payload=None,
                    note=str(exc),
                    captured_at=time.time(),
                )
            )
            return

    def stop_capture(self) -> None:
        if not self.sniffer:
            return
        self.stop_event.set()
        try:
            self.sniffer.stop()
            self.sniffer.join()
        except Exception as exc:  # pragma: no cover - 예외 상황 기록용
            self.packet_queue.put(
                PacketDisplay(
                    summary="[경고] 캡쳐 중지 과정에서 문제가 발생했습니다.",
                    payload=None,
                    note=str(exc),
                    captured_at=time.time(),
                )
            )
        finally:
            self.sniffer = None
            self.stop_event.clear()
            self._set_running_state(False)

    def _on_select_packet(self, _: tk.Event) -> None:
        self._refresh_detail_view()

    # ------------------------------------------------------------------
    # PPSN 찾기 기능
    def _toggle_ppsn_panel(self) -> None:
        if self.ppsn_window and self.ppsn_window.winfo_exists():
            self.ppsn_window.deiconify()
            self.ppsn_window.lift()
            self.ppsn_window.focus_force()
            if self.ppsn_code_entry:
                self.ppsn_code_entry.focus_set()
            return

        self._create_ppsn_window()

    def _create_ppsn_window(self) -> None:
        window = tk.Toplevel(self.master)
        window.title("PPSN 찾기")
        window.transient(self.master)

        frame = ttk.Frame(window, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)
        frame.rowconfigure(3, weight=1)

        ttk.Label(frame, text="친구 코드 (5글자)").grid(
            row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 4)
        )
        self.ppsn_code_entry = ttk.Entry(frame, textvariable=self.ppsn_code_var, width=12)
        self.ppsn_code_entry.grid(row=0, column=1, sticky="ew", pady=(0, 4))

        ttk.Label(frame, text="요청 간 대기 (초)").grid(
            row=0, column=2, sticky="w", padx=(12, 8), pady=(0, 4)
        )
        self.ppsn_delay_entry = ttk.Entry(frame, textvariable=self.ppsn_delay_var, width=10)
        self.ppsn_delay_entry.grid(row=0, column=3, sticky="ew", pady=(0, 4))

        self.ppsn_search_button = ttk.Button(
            frame,
            text="PPSN 검색",
            command=self._on_ppsn_search,
        )
        self.ppsn_search_button.grid(row=0, column=4, padx=(12, 0), pady=(0, 4))

        ttk.Label(frame, text="월드 코드 (17자리)").grid(
            row=1, column=0, sticky="w", padx=(0, 8), pady=(4, 0)
        )
        self.channel_world_entry = ttk.Entry(
            frame, textvariable=self.channel_world_var, width=20
        )
        self.channel_world_entry.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(4, 0))

        self.channel_search_button = ttk.Button(
            frame,
            text="채널검색",
            command=self._on_channel_search,
        )
        self.channel_search_button.grid(row=1, column=4, padx=(12, 0), pady=(4, 0))

        ttk.Label(frame, text="검색 로그").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.ppsn_log = tk.Text(frame, height=8, state=tk.DISABLED, wrap="word")
        self.ppsn_log.grid(row=3, column=0, columnspan=5, sticky="nsew", pady=(0, 4))
        log_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.ppsn_log.yview)
        log_scroll.grid(row=3, column=5, sticky="ns", pady=(0, 4))
        self.ppsn_log.configure(yscrollcommand=log_scroll.set)

        ttk.Label(frame, text="결과 PPSN").grid(row=4, column=0, sticky="w", pady=(4, 0))
        self.ppsn_result_entry = ttk.Entry(
            frame,
            textvariable=self.ppsn_result_var,
            state="readonly",
        )
        self.ppsn_result_entry.grid(row=4, column=1, columnspan=3, sticky="ew", pady=(4, 0))
        self.ppsn_copy_button = ttk.Button(
            frame,
            text="복사",
            command=self._copy_ppsn_result,
            state=tk.DISABLED,
        )
        self.ppsn_copy_button.grid(row=4, column=4, padx=(12, 0), pady=(4, 0))

        ttk.Label(frame, text="채널 검색 결과").grid(row=5, column=0, sticky="w", pady=(4, 0))
        self.channel_result_entry = ttk.Entry(
            frame,
            textvariable=self.channel_result_var,
            state="readonly",
        )
        self.channel_result_entry.grid(row=5, column=1, columnspan=4, sticky="ew", pady=(4, 0))

        ttk.Label(frame, text="탐색한 온라인 친구 수").grid(
            row=6, column=0, sticky="w", pady=(4, 0)
        )
        self.channel_count_entry = ttk.Entry(
            frame,
            textvariable=self.channel_friend_count_var,
            state="readonly",
            width=12,
        )
        self.channel_count_entry.grid(
            row=6, column=1, sticky="w", pady=(4, 0), padx=(0, 8)
        )

        window.protocol("WM_DELETE_WINDOW", self._close_ppsn_window)
        self.ppsn_window = window
        self.ppsn_code_entry.focus_set()

    def _close_ppsn_window(self) -> None:
        if not self.ppsn_window or not self.ppsn_window.winfo_exists():
            self.ppsn_window = None
            return
        self.ppsn_window.destroy()
        self.ppsn_window = None
        self.ppsn_code_entry = None
        self.ppsn_delay_entry = None
        self.ppsn_search_button = None
        self.channel_world_entry = None
        self.channel_search_button = None
        self.ppsn_log = None
        self.ppsn_result_entry = None
        self.ppsn_copy_button = None
        self.channel_result_entry = None
        self.channel_count_entry = None
        self.channel_friend_count_var.set("0")

    def _on_ppsn_search(self) -> None:
        if self.lookup_running:
            messagebox.showinfo("알림", "다른 검색 작업이 진행 중입니다.")
            return

        code = self.ppsn_code_var.get().strip()
        if not re.fullmatch(r"[A-Za-z0-9]{5}", code):
            messagebox.showerror("입력 오류", "친구 코드는 영문 대소문자/숫자의 5글자여야 합니다.")
            self.ppsn_code_entry.focus_set()
            return

        delay_text = self.ppsn_delay_var.get().strip() or "0.5"
        try:
            delay = float(delay_text)
        except ValueError:
            messagebox.showerror("입력 오류", "대기 시간은 숫자 형식이어야 합니다.")
            self.ppsn_delay_entry.focus_set()
            return

        if delay < 0:
            messagebox.showerror("입력 오류", "대기 시간은 0 이상이어야 합니다.")
            self.ppsn_delay_entry.focus_set()
            return

        self.lookup_running = True
        if self.ppsn_search_button and self.ppsn_search_button.winfo_exists():
            self.ppsn_search_button.config(state=tk.DISABLED)
        if self.channel_search_button and self.channel_search_button.winfo_exists():
            self.channel_search_button.config(state=tk.DISABLED)
        if self.ppsn_copy_button and self.ppsn_copy_button.winfo_exists():
            self.ppsn_copy_button.config(state=tk.DISABLED)
        self.ppsn_result_var.set("")
        self.channel_friend_count_var.set("0")
        self._clear_ppsn_log()
        self._append_ppsn_log("[정보] PPSN 검색을 시작합니다.")

        self.ppsn_thread = threading.Thread(
            target=self._run_ppsn_lookup,
            args=(code, delay),
            daemon=True,
        )
        self.ppsn_thread.start()

    def _on_channel_search(self) -> None:
        if self.lookup_running:
            messagebox.showinfo("알림", "다른 검색 작업이 진행 중입니다.")
            return

        code = self.ppsn_code_var.get().strip()
        if not re.fullmatch(r"[A-Za-z0-9]{5}", code):
            messagebox.showerror("입력 오류", "친구 코드는 영문 대소문자/숫자의 5글자여야 합니다.")
            if self.ppsn_code_entry:
                self.ppsn_code_entry.focus_set()
            return

        world_code = self.channel_world_var.get().strip()
        if not re.fullmatch(r"\d{17}", world_code):
            messagebox.showerror("입력 오류", "월드 코드는 숫자 17자리여야 합니다.")
            if self.channel_world_entry:
                self.channel_world_entry.focus_set()
            return

        delay_text = self.ppsn_delay_var.get().strip() or "0.5"
        try:
            delay = float(delay_text)
        except ValueError:
            messagebox.showerror("입력 오류", "대기 시간은 숫자 형식이어야 합니다.")
            if self.ppsn_delay_entry:
                self.ppsn_delay_entry.focus_set()
            return

        if delay < 0:
            messagebox.showerror("입력 오류", "대기 시간은 0 이상이어야 합니다.")
            if self.ppsn_delay_entry:
                self.ppsn_delay_entry.focus_set()
            return

        self.channel_friend_count_var.set("0")
        self.lookup_running = True
        if self.ppsn_search_button and self.ppsn_search_button.winfo_exists():
            self.ppsn_search_button.config(state=tk.DISABLED)
        if self.channel_search_button and self.channel_search_button.winfo_exists():
            self.channel_search_button.config(state=tk.DISABLED)
        if self.ppsn_copy_button and self.ppsn_copy_button.winfo_exists():
            self.ppsn_copy_button.config(state=tk.DISABLED)
        self.ppsn_result_var.set("")
        self.channel_result_var.set("")
        self._clear_ppsn_log()
        self._append_ppsn_log("[정보] 채널 검색을 시작합니다.")

        self.ppsn_thread = threading.Thread(
            target=self._run_channel_lookup,
            args=(code, world_code, delay),
            daemon=True,
        )
        self.ppsn_thread.start()

    def _run_ppsn_lookup(self, code: str, delay: float) -> None:
        def log(message: str) -> None:
            self.ppsn_queue.put({"type": "log", "task": "ppsn", "text": message})

        try:
            result = find_ppsn(code, delay=delay, logger=log)
        except HTTPError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "ppsn",
                    "success": False,
                    "text": f"[오류] 프로필 페이지 요청 실패({exc.code}): {exc.reason}",
                }
            )
        except URLError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "ppsn",
                    "success": False,
                    "text": f"[오류] 네트워크 오류가 발생했습니다: {exc}",
                }
            )
        except RuntimeError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "ppsn",
                    "success": False,
                    "text": f"[오류] {exc}",
                }
            )
        except Exception as exc:  # pragma: no cover - 예기치 못한 예외 대비
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "ppsn",
                    "success": False,
                    "text": f"[오류] 알 수 없는 오류가 발생했습니다: {exc}",
                }
            )
        else:
            if result is None:
                self.ppsn_queue.put(
                    {
                        "type": "done",
                        "task": "ppsn",
                        "success": False,
                        "text": "[결과] 친구 목록 어디에서도 해당 친구 코드를 찾지 못했습니다.",
                    }
                )
            else:
                ppsn, via_friend = result
                self.ppsn_queue.put(
                    {
                        "type": "done",
                        "task": "ppsn",
                        "success": True,
                        "text": (
                            f"[결과] 친구 코드 {code.upper()} 의 PPSN은 {ppsn} 입니다. "
                            f"(친구 {via_friend} 의 목록에서 확인)"
                        ),
                        "ppsn": ppsn,
                    }
                )
        finally:
            self.ppsn_queue.put({"type": "finished", "task": "ppsn"})

    def _run_channel_lookup(self, code: str, world_code: str, delay: float) -> None:
        def log(message: str) -> None:
            self.ppsn_queue.put({"type": "log", "task": "channel", "text": message})

        def progress(count: int) -> None:
            self.ppsn_queue.put({"type": "progress", "task": "channel", "count": count})

        try:
            result = find_friend_by_world_code(
                code,
                world_code,
                delay=delay,
                logger=log,
                progress_callback=progress,
            )
        except HTTPError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "channel",
                    "success": False,
                    "text": f"[오류] 프로필 페이지 요청 실패({exc.code}): {exc.reason}",
                    "channel_result": "",
                }
            )
        except URLError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "channel",
                    "success": False,
                    "text": f"[오류] 네트워크 오류가 발생했습니다: {exc}",
                    "channel_result": "",
                }
            )
        except RuntimeError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "channel",
                    "success": False,
                    "text": f"[오류] {exc}",
                    "channel_result": "",
                }
            )
        except Exception as exc:  # pragma: no cover - 예기치 못한 예외 대비
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "task": "channel",
                    "success": False,
                    "text": f"[오류] 알 수 없는 오류가 발생했습니다: {exc}",
                    "channel_result": "",
                }
            )
        else:
            if result is None:
                self.ppsn_queue.put(
                    {
                        "type": "done",
                        "task": "channel",
                        "success": False,
                        "text": "[결과] 입력한 월드 코드와 일치하는 친구를 찾지 못했습니다.",
                        "channel_result": "",
                    }
                )
            else:
                friend_name, friend_code, ppsn_value = result
                self.ppsn_queue.put(
                    {
                        "type": "done",
                        "task": "channel",
                        "success": True,
                        "text": (
                            f"[결과] 월드 코드 {world_code} 은(는) {friend_name} ({friend_code}) 와 "
                            "일치합니다."
                        ),
                        "channel_result": f"{friend_name} / {friend_code}",
                        "ppsn": ppsn_value,
                    }
                )
        finally:
            self.ppsn_queue.put({"type": "finished", "task": "channel"})

    # ------------------------------------------------------------------
    # 친구 검색 기능
    def _update_friend_search_button(self) -> None:
        if self.friend_search_button and self.friend_search_button.winfo_exists():
            text = "1차 검색" if self.friend_search_phase == 1 else "2차 검색"
            self.friend_search_button.config(text=text)

    def _set_friend_search_running(self, running: bool) -> None:
        self.friend_search_running = running
        if self.friend_search_button and self.friend_search_button.winfo_exists():
            state = tk.DISABLED if running else tk.NORMAL
            self.friend_search_button.config(state=state)
        if self.friend_stop_button and self.friend_stop_button.winfo_exists():
            state = tk.NORMAL if running else tk.DISABLED
            self.friend_stop_button.config(state=state)
        if not running:
            self.friend_search_stop_event.clear()

    def _collect_second_phase_codes(self) -> list[str]:
        codes: list[str] = []
        seen: set[str] = set()
        for entry in self.friend_entries:
            profile = (entry.profile_code or "").strip().upper()
            if not profile or profile in seen:
                continue
            if not re.fullmatch(r"[A-Za-z0-9]{5}", profile):
                continue
            seen.add(profile)
            codes.append(profile)
        return codes

    def _on_friend_search(self) -> None:
        if self.friend_search_running:
            messagebox.showinfo("알림", "친구 검색이 이미 진행 중입니다.")
            return

        current_code_upper = self.friend_code_var.get().strip().upper()
        if (
            self.friend_search_phase != 1
            and current_code_upper
            and current_code_upper != self.last_friend_primary_code
        ):
            self.friend_search_phase = 1
            self._update_friend_search_button()

        if self.friend_search_phase == 1:
            code = self.friend_code_var.get().strip()
            if not re.fullmatch(r"[A-Za-z0-9]{5}", code):
                messagebox.showerror("입력 오류", "친구 코드는 영문 대소문자/숫자의 5글자여야 합니다.")
                if self.friend_code_entry and self.friend_code_entry.winfo_exists():
                    self.friend_code_entry.focus_set()
                return

            self.friend_status_var.set("[정보] 1차 검색을 시작합니다.")
            self.friend_count_var.set("0")
            self._clear_friend_tree()
            self.friend_search_stop_event.clear()
            self.last_friend_primary_code = code.upper()
            self._set_friend_search_running(True)

            thread = threading.Thread(
                target=self._run_friend_search,
                args=([code], 1),
                daemon=True,
            )
            self.friend_search_thread = thread
            thread.start()
        else:
            codes = self._collect_second_phase_codes()
            if not codes:
                messagebox.showinfo("알림", "2차 검색에 사용할 친구 코드가 없습니다.")
                return
            self.friend_status_var.set("[정보] 2차 검색을 시작합니다.")
            self.friend_search_stop_event.clear()
            self._set_friend_search_running(True)
            thread = threading.Thread(
                target=self._run_friend_search,
                args=(codes, 2),
                daemon=True,
            )
            self.friend_search_thread = thread
            thread.start()

    def _on_friend_search_stop(self) -> None:
        if not self.friend_search_running:
            return
        self.friend_search_stop_event.set()
        self.friend_status_var.set("[정보] 검색 중지 요청을 전달했습니다.")
        if self.friend_stop_button and self.friend_stop_button.winfo_exists():
            self.friend_stop_button.config(state=tk.DISABLED)

    def _run_friend_search(self, codes: list[str], phase: int) -> None:
        stop_event = self.friend_search_stop_event

        def log(message: str) -> None:
            self.friend_queue.put({"type": "status", "text": message})

        total_count = 0
        phase_entries = 0

        def progress(_: int) -> None:
            nonlocal total_count
            total_count += 1
            self.friend_queue.put({"type": "progress", "count": total_count})

        if not codes:
            self.friend_queue.put({"type": "finished"})
            return

        description = "1차" if phase == 1 else "2차"
        log(f"[정보] {description} 친구 검색 백그라운드 작업을 시작합니다. 대상 수: {len(codes)}")

        try:
            for index, code in enumerate(codes, start=1):
                if stop_event.is_set():
                    break
                log(
                    f"[정보] {description} 검색 {index}/{len(codes)} - 친구 코드 {code} 의 목록을 수집합니다."
                )
                try:
                    entries = fetch_friend_statuses(
                        code,
                        delay=0.5,
                        logger=log,
                        progress_callback=progress,
                        stop_event=stop_event,
                    )
                except HTTPError as exc:
                    error_text = f"[오류] 친구 목록 요청 실패({exc.code}): {exc.reason} (코드: {code})"
                    log(error_text)
                    self.friend_queue.put(
                        {
                            "type": "error",
                            "text": error_text,
                            "nonfatal": phase != 1,
                        }
                    )
                    if phase == 1:
                        break
                    continue
                except URLError as exc:
                    error_text = f"[오류] 네트워크 오류가 발생했습니다: {exc} (코드: {code})"
                    log(error_text)
                    self.friend_queue.put(
                        {
                            "type": "error",
                            "text": error_text,
                            "nonfatal": phase != 1,
                        }
                    )
                    if phase == 1:
                        break
                    continue
                except RuntimeError as exc:
                    error_text = f"[오류] {exc}"
                    log(error_text)
                    self.friend_queue.put(
                        {
                            "type": "error",
                            "text": error_text,
                            "nonfatal": phase != 1,
                        }
                    )
                    if phase == 1:
                        break
                    continue
                except Exception as exc:  # pragma: no cover - 예기치 못한 예외 대비
                    error_text = f"[오류] 알 수 없는 오류가 발생했습니다: {exc}"
                    log(error_text)
                    self.friend_queue.put(
                        {
                            "type": "error",
                            "text": error_text,
                            "nonfatal": phase != 1,
                        }
                    )
                    if phase == 1:
                        break
                    continue

                if stop_event.is_set():
                    break

                filtered = [entry for entry in entries if isinstance(entry, FriendStatusEntry)]
                if filtered:
                    phase_entries += len(filtered)
                    self.friend_queue.put(
                        {
                            "type": "result",
                            "entries": filtered,
                            "append": phase != 1,
                            "phase": phase,
                        }
                    )
                else:
                    log(f"[정보] 친구 데이터가 없습니다. (코드: {code})")
        finally:
            stopped = stop_event.is_set()
            if phase_entries:
                summary = f"[결과] {description} 검색으로 {phase_entries}명의 친구 데이터를 확인했습니다."
            else:
                summary = f"[결과] {description} 검색에서 수집된 친구 데이터가 없습니다."
            if stopped:
                summary = f"[정보] {description} 검색이 중지되었습니다. " + summary
            self.friend_queue.put({"type": "status", "text": summary})
            log("[정보] 친구 검색 백그라운드 작업을 종료합니다.")
            self.friend_queue.put(
                {
                    "type": "phase_finished",
                    "phase": phase,
                    "stopped": stopped,
                    "had_entries": phase_entries > 0,
                }
            )
            self.friend_queue.put({"type": "finished"})

    def _clear_friend_tree(self) -> None:
        if not self.friend_tree or not self.friend_tree.winfo_exists():
            return
        for child in self.friend_tree.get_children():
            self.friend_tree.delete(child)
        self.friend_entries = []
        self.friend_entry_keys.clear()

    def _resolve_channel_name(self, channel_info: str) -> str:
        if not channel_info:
            return ""
        names = self.world_code_to_channels.get(channel_info)
        if not names:
            return ""
        return ", ".join(sorted(names))

    def _display_friend_entries(
        self, entries: list[FriendStatusEntry], *, append: bool = False
    ) -> None:
        if not self.friend_tree or not self.friend_tree.winfo_exists():
            return
        if not append:
            self.friend_tree.delete(*self.friend_tree.get_children())
            self.friend_entries = []
            self.friend_entry_keys.clear()
        for entry in entries:
            if not isinstance(entry, FriendStatusEntry):
                continue
            profile = (entry.profile_code or "").strip().upper()
            profile_value = f"#{profile}" if profile else ""
            name = (entry.display_name or "").strip()
            world = (entry.world_name or "").strip()
            channel = (entry.game_instance_id or "").strip()
            key = (entry.ppsn.strip().upper(), profile)
            if key in self.friend_entry_keys:
                continue
            self.friend_entry_keys.add(key)
            self.friend_entries.append(entry)
            channel_name = self._resolve_channel_name(channel)
            self.friend_tree.insert(
                "",
                tk.END,
                values=(
                    entry.status.strip(),
                    entry.ppsn.strip(),
                    profile_value,
                    name,
                    world,
                    channel_name,
                    channel,
                ),
            )
        self.friend_count_var.set(str(len(self.friend_entries)))

    def _clear_ppsn_log(self) -> None:
        if not self.ppsn_log or not self.ppsn_log.winfo_exists():
            return
        self.ppsn_log.config(state=tk.NORMAL)
        self.ppsn_log.delete("1.0", tk.END)
        self.ppsn_log.config(state=tk.DISABLED)

    def _append_ppsn_log(self, message: str) -> None:
        if not message:
            return
        if not self.ppsn_log or not self.ppsn_log.winfo_exists():
            return
        self.ppsn_log.config(state=tk.NORMAL)
        self.ppsn_log.insert(tk.END, message + "\n")
        self.ppsn_log.see(tk.END)
        self.ppsn_log.config(state=tk.DISABLED)

    def _copy_ppsn_result(self) -> None:
        result = self.ppsn_result_var.get().strip()
        if not result:
            messagebox.showinfo("알림", "복사할 PPSN 결과가 없습니다.")
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(result)
        except tk.TclError:
            messagebox.showerror("오류", "클립보드에 접근할 수 없습니다.")
            return
        messagebox.showinfo("완료", "PPSN이 클립보드에 복사되었습니다.")

    # ------------------------------------------------------------------
    # 캡쳐 로직 및 필터
    def _build_filter_config(self, ip_text: str, port_text: str) -> FilterConfig:
        networks: list[NetworkType] = []
        if ip_text:
            try:
                network = ipaddress.ip_network(ip_text, strict=False)
            except ValueError as exc:
                raise ValueError("유효한 IP 주소 또는 CIDR 표기법이 아닙니다.") from exc
            networks.append(network)

        port: Optional[int] = None
        if port_text:
            if not port_text.isdigit():
                raise ValueError("포트 값은 0~65535 범위의 숫자여야 합니다.")
            port = int(port_text)
            if not 0 <= port <= 65535:
                raise ValueError("포트 값은 0~65535 범위여야 합니다.")

        return FilterConfig(networks=networks, port=port)

    def _packet_matches_filter(self, packet, filter_config: FilterConfig) -> bool:
        network_ok = True
        if filter_config.networks:
            addresses: list[str] = []
            if IP in packet:
                ip_layer = packet[IP]
                addresses = [ip_layer.src, ip_layer.dst]
            if not addresses and IPv6 in packet:
                ip6_layer = packet[IPv6]
                addresses = [ip6_layer.src, ip6_layer.dst]

            if not addresses:
                network_ok = False
            else:
                network_ok = False
                for network in filter_config.networks:
                    for addr in addresses:
                        try:
                            if ipaddress.ip_address(addr) in network:
                                network_ok = True
                                break
                        except ValueError:
                            continue
                    if network_ok:
                        break

        port_ok = True
        if filter_config.port is not None:
            port = filter_config.port
            port_ok = False
            if TCP in packet:
                tcp_layer = packet[TCP]
                port_ok = port in (getattr(tcp_layer, "sport", None), getattr(tcp_layer, "dport", None))
            if not port_ok and UDP in packet:
                udp_layer = packet[UDP]
                port_ok = port in (getattr(udp_layer, "sport", None), getattr(udp_layer, "dport", None))

        return network_ok and port_ok

    @staticmethod
    def _extract_payload_bytes(packet) -> Optional[bytes]:
        if Raw in packet:
            data = packet[Raw].load
            if isinstance(data, bytes):
                return data
            if data is None:
                return None
            return bytes(str(data), "utf-8", "replace")
        return None

    # ------------------------------------------------------------------
    # UI 보조 메서드
    def _poll_queue(self) -> None:
        updated = False
        max_packets = self._get_max_packets()
        while True:
            try:
                item = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.packet_counter += 1
                item.identifier = self.packet_counter
                if not item.captured_at:
                    item.captured_at = time.time()
                if not item.preview:
                    item.preview = self._extract_hangul_preview(item.utf8_text)
                self._process_world_matching(item)
                self._process_notification_stream(item.utf8_text, item.captured_at)
                self.packet_list_data.insert(0, item)
                if max_packets and max_packets > 0:
                    while len(self.packet_list_data) > max_packets:
                        removed = self.packet_list_data.pop()
                        if self.packet_tree.exists(str(removed.identifier)):
                            self.packet_tree.delete(str(removed.identifier))
                updated = True

        if max_packets and max_packets > 0 and len(self.packet_list_data) > max_packets:
            while len(self.packet_list_data) > max_packets:
                removed = self.packet_list_data.pop()
                if self.packet_tree.exists(str(removed.identifier)):
                    self.packet_tree.delete(str(removed.identifier))
            updated = True

        if updated:
            self._refresh_packet_list()

        self.master.after(200, self._poll_queue)

    def _poll_friend_queue(self) -> None:
        while True:
            try:
                item = self.friend_queue.get_nowait()
            except queue.Empty:
                break

            message_type = item.get("type")
            if message_type == "status":
                text = item.get("text")
                if isinstance(text, str):
                    self.friend_status_var.set(text)
            elif message_type == "progress":
                count = item.get("count")
                if isinstance(count, int):
                    self.friend_count_var.set(str(count))
            elif message_type == "result":
                entries = item.get("entries")
                append_mode = bool(item.get("append"))
                if isinstance(entries, list):
                    filtered_entries = [
                        entry
                        for entry in entries
                        if isinstance(entry, FriendStatusEntry)
                    ]
                    if filtered_entries:
                        self._display_friend_entries(filtered_entries, append=append_mode)
                    elif not append_mode:
                        self.friend_count_var.set(str(len(self.friend_entries)))
                count = item.get("count")
                if isinstance(count, int):
                    self.friend_count_var.set(str(count))
                else:
                    self.friend_count_var.set(str(len(self.friend_entries)))
            elif message_type == "error":
                text = item.get("text")
                nonfatal = bool(item.get("nonfatal"))
                if isinstance(text, str):
                    self.friend_status_var.set(text)
                    if not nonfatal:
                        messagebox.showerror("친구 검색 오류", text)
            elif message_type == "phase_finished":
                phase_value = item.get("phase")
                stopped = bool(item.get("stopped"))
                had_entries = bool(item.get("had_entries"))
                if phase_value == 1 and not stopped and had_entries:
                    self.friend_search_phase = 2
                else:
                    self.friend_search_phase = 1
                self._update_friend_search_button()
            elif message_type == "finished":
                self._set_friend_search_running(False)
                self.friend_search_thread = None

        self.master.after(200, self._poll_friend_queue)

    def _poll_ppsn_queue(self) -> None:
        finished_tasks: set[str] = set()
        while True:
            try:
                item = self.ppsn_queue.get_nowait()
            except queue.Empty:
                break
            message_type = item.get("type")
            task = item.get("task", "ppsn")
            if message_type == "log":
                self._append_ppsn_log(item.get("text", ""))
            elif message_type == "done":
                text = item.get("text", "")
                if text:
                    self._append_ppsn_log(text)
                success = bool(item.get("success"))
                if task == "ppsn":
                    ppsn_value = item.get("ppsn")
                    if success and isinstance(ppsn_value, str) and ppsn_value:
                        self.ppsn_result_var.set(ppsn_value)
                        if self.ppsn_copy_button and self.ppsn_copy_button.winfo_exists():
                            self.ppsn_copy_button.config(state=tk.NORMAL)
                    else:
                        if isinstance(ppsn_value, str):
                            self.ppsn_result_var.set(ppsn_value)
                        if self.ppsn_copy_button and self.ppsn_copy_button.winfo_exists():
                            self.ppsn_copy_button.config(state=tk.DISABLED)
                elif task == "channel":
                    result_text = item.get("channel_result")
                    if isinstance(result_text, str):
                        self.channel_result_var.set(result_text)
                    ppsn_value = item.get("ppsn")
                    if isinstance(ppsn_value, str):
                        self.ppsn_result_var.set(ppsn_value)
                        if self.ppsn_copy_button and self.ppsn_copy_button.winfo_exists():
                            if success and ppsn_value:
                                self.ppsn_copy_button.config(state=tk.NORMAL)
                            else:
                                self.ppsn_copy_button.config(state=tk.DISABLED)
            elif message_type == "progress" and task == "channel":
                count = item.get("count")
                if isinstance(count, int):
                    self.channel_friend_count_var.set(str(count))
            elif message_type == "finished":
                finished_tasks.add(task)

        if finished_tasks:
            self.lookup_running = False
            if self.ppsn_search_button and self.ppsn_search_button.winfo_exists():
                self.ppsn_search_button.config(state=tk.NORMAL)
            if self.channel_search_button and self.channel_search_button.winfo_exists():
                self.channel_search_button.config(state=tk.NORMAL)
            self.ppsn_thread = None

        self.master.after(200, self._poll_ppsn_queue)

    def _set_detail_text(self, text: str) -> None:
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, text)

    def _refresh_detail_view(self) -> None:
        selection = self.packet_tree.selection()
        if not selection:
            self._set_detail_text("패킷을 선택하면 상세 정보가 여기에 표시됩니다.")
            return

        selected_id = selection[0]
        item = next((pkt for pkt in self.packet_list_data if str(pkt.identifier) == selected_id), None)
        if item is None:
            self._set_detail_text("패킷을 선택하면 상세 정보가 여기에 표시됩니다.")
            return

        detail_text = self._format_detail_text(item)
        self._set_detail_text(detail_text)

    def _export_selected_packet(self) -> None:
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showinfo("알림", "먼저 저장할 패킷을 선택하세요.")
            return

        selected_id = selection[0]
        item = next((pkt for pkt in self.packet_list_data if str(pkt.identifier) == selected_id), None)
        if item is None:
            messagebox.showerror("오류", "선택한 패킷 정보를 찾을 수 없습니다.")
            return

        detail_text = self._format_detail_text(item)
        timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
        target_dir = Path(__file__).resolve().parent
        file_path = target_dir / f"{timestamp}.txt"

        if file_path.exists():
            messagebox.showerror(
                "오류",
                f"같은 이름의 파일이 이미 존재합니다: {file_path.name}\n잠시 후 다시 시도하세요.",
            )
            return

        try:
            file_path.write_text(detail_text, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("오류", f"파일 저장에 실패했습니다: {exc}")
            return

        messagebox.showinfo("완료", f"'{file_path.name}' 파일로 저장했습니다.")

    def _format_detail_text(self, item: PacketDisplay) -> str:
        captured_time = self._format_capture_time(item.captured_at)
        lines = [f"캡쳐 시각: {captured_time}", "", "요약:", item.summary]
        if item.note:
            lines.extend(["", "비고:", item.note])

        if item.payload is None:
            lines.extend(["", "페이로드:", "(페이로드 없음)"])
            return "\n".join(lines)

        encoding = self.encoding_var.get()
        lines.extend(["", f"텍스트 ({encoding}):"])
        decode_message = ""
        text_truncated = False
        try:
            decoded = item.payload.decode(encoding)
        except UnicodeDecodeError:
            decoded = item.payload.decode(encoding, errors="replace")
            decode_message = "(일부 문자를 대체하여 표시합니다.)"

        if decode_message:
            lines.append(decode_message)
        if decoded and len(decoded) > 4096:
            decoded = decoded[:4096]
            text_truncated = True
        lines.append(decoded if decoded else "(텍스트 데이터 없음)")

        if text_truncated:
            lines.append("(텍스트 출력이 길이 제한으로 잘렸습니다.)")

        hex_dump, truncated = self._hex_dump(item.payload)
        lines.extend(["", "HEX 덤프:", hex_dump])
        if truncated:
            lines.append("(일부 데이터는 길이 제한으로 생략되었습니다.)")

        return "\n".join(lines)

    @staticmethod
    def _hex_dump(data: bytes, max_length: int = 2048) -> tuple[str, bool]:
        if not data:
            return "(데이터 없음)", False

        shown = data[:max_length]
        lines = []
        for offset in range(0, len(shown), 16):
            chunk = shown[offset : offset + 16]
            hex_part = " ".join(f"{byte:02X}" for byte in chunk)
            ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            lines.append(f"{offset:08X}  {hex_part:<47}  {ascii_part}")

        truncated = len(data) > max_length
        return "\n".join(lines), truncated

    def _on_change_encoding(self, _: tk.Event | None = None) -> None:
        self._refresh_detail_view()

    def _on_text_filter_change(self, *_: object) -> None:
        self._refresh_packet_list()

    def _on_direction_filter_change(self, *_: object) -> None:
        self._refresh_packet_list()

    def _refresh_packet_list(self) -> None:
        filter_text = self.text_filter_var.get().strip().lower()
        direction_filter = self.direction_filter_var.get().strip()
        previous_selection = self.packet_tree.selection()
        selected_id = previous_selection[0] if previous_selection else None

        for child in self.packet_tree.get_children():
            self.packet_tree.delete(child)

        visible_ids: list[str] = []
        for item in self.packet_list_data:
            if not self._matches_text_filter(item, filter_text):
                continue
            if not self._matches_direction_filter(item, direction_filter):
                continue
            if not item.preview:
                item.preview = self._extract_hangul_preview(item.utf8_text)
            iid = str(item.identifier)
            values = (
                self._format_capture_time(item.captured_at),
                item.summary,
                self._format_direction_text(item.direction),
                item.preview,
            )
            self.packet_tree.insert("", tk.END, iid=iid, values=values)
            visible_ids.append(iid)

        if selected_id and selected_id in visible_ids:
            self.packet_tree.selection_set(selected_id)
            self.packet_tree.see(selected_id)
        elif visible_ids:
            first_id = visible_ids[0]
            self.packet_tree.selection_set(first_id)
            self.packet_tree.see(first_id)
        else:
            current_selection = self.packet_tree.selection()
            if current_selection:
                self.packet_tree.selection_remove(*current_selection)

        self._refresh_detail_view()

    @staticmethod
    def _matches_text_filter(item: PacketDisplay, filter_text: str) -> bool:
        if not filter_text:
            return True
        if not item.utf8_text:
            return False
        return filter_text in item.utf8_text.lower()

    @staticmethod
    def _format_direction_text(direction: str) -> str:
        if direction == "incoming":
            return "수신"
        if direction == "outgoing":
            return "송신"
        return "미확인"

    @staticmethod
    def _matches_direction_filter(item: PacketDisplay, filter_value: str) -> bool:
        if filter_value == "전체" or not filter_value:
            return True
        if filter_value == "수신":
            return item.direction == "incoming"
        if filter_value == "송신":
            return item.direction == "outgoing"
        if filter_value == "미확인":
            return item.direction not in {"incoming", "outgoing"}
        return True

    @staticmethod
    def _format_capture_time(timestamp: float) -> str:
        if timestamp <= 0:
            return "--:--:--"
        try:
            return time.strftime("%H:%M:%S", time.localtime(timestamp))
        except (OverflowError, ValueError):  # pragma: no cover - 드문 플랫폼 예외 대비
            return "--:--:--"

    def _clear_capture_results(self, *, clear_world: bool = False) -> None:
        self.packet_list_data.clear()
        for child in self.packet_tree.get_children():
            self.packet_tree.delete(child)
        self.packet_counter = 0
        self._world_match_buffer = ""
        self._notification_buffer = ""
        self._world_last_clicked_item = None
        if clear_world:
            self._clear_world_matches()
        self._set_detail_text("캡쳐를 시작하면 패킷이 여기에 표시됩니다.")

    def _clear_world_matches(self) -> None:
        self.world_match_entries.clear()
        self.world_match_channels.clear()
        self.world_code_to_channels.clear()
        self._world_match_buffer = ""
        self._world_last_clicked_item = None
        self._set_world_match_order_ui(None, locked=False)
        self._refresh_world_table()
        self._refresh_friend_channel_names()

    def _set_running_state(self, running: bool) -> None:
        self.start_button.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if running else tk.DISABLED)

    def _toggle_friend_panel(self) -> None:
        if not self.friend_panel:
            return
        if self.friend_panel.winfo_ismapped():
            self.friend_panel.grid_remove()
            if self.friend_toggle_button and self.friend_toggle_button.winfo_exists():
                self.friend_toggle_button.config(text="친구검색")
        else:
            self.friend_panel.grid()
            if self.friend_toggle_button and self.friend_toggle_button.winfo_exists():
                self.friend_toggle_button.config(text="친구검색 닫기")
            if self.friend_tree and not self.friend_tree.get_children():
                self._clear_friend_tree()

    def _toggle_world_panel(self) -> None:
        if self.world_panel.winfo_ismapped():
            self.world_panel.grid_remove()
            self.world_toggle_button.config(text="월드 매칭")
        else:
            self.world_panel.grid()
            self.world_toggle_button.config(text="월드 매칭 닫기")
            self._refresh_world_table()

    def _on_close(self) -> None:
        self.stop_capture()
        self._save_settings()
        self.master.destroy()

    def _prevent_detail_edit(self, event: tk.Event) -> str | None:
        allowed_navigation = {
            "Left",
            "Right",
            "Up",
            "Down",
            "Home",
            "End",
            "Prior",
            "Next",
        }
        if event.keysym in allowed_navigation:
            return None
        if event.state & 0x4 and event.keysym.lower() in {"c", "a"}:
            return None
        if event.keysym == "Escape":
            return None
        return "break"

    def _get_max_packets(self) -> int:
        raw_value = self.max_packets_var.get().strip()
        try:
            parsed = int(raw_value)
        except ValueError:
            return self.DEFAULT_MAX_PACKETS
        if parsed <= 0:
            return self.DEFAULT_MAX_PACKETS
        return parsed

    @staticmethod
    def _extract_hangul_preview(text: Optional[str], limit: int = 10) -> str:
        if not text:
            return ""
        preview_chars: list[str] = []
        for ch in text:
            if "\uAC00" <= ch <= "\uD7A3":
                preview_chars.append(ch)
                if len(preview_chars) >= limit:
                    break
        return "".join(preview_chars)

    @staticmethod
    def _normalize_ip(address: str) -> str:
        return address.split("%", 1)[0] if "%" in address else address

    def _detect_local_addresses(self) -> set[str]:
        addresses: set[str] = set()
        host_candidates: set[str] = set()
        try:
            hostname = socket.gethostname()
            if hostname:
                host_candidates.add(hostname)
        except OSError:
            pass
        try:
            fqdn = socket.getfqdn()
            if fqdn:
                host_candidates.add(fqdn)
        except OSError:
            pass

        for host in host_candidates:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                continue
            for info in infos:
                sockaddr = info[4]
                if not sockaddr:
                    continue
                address = sockaddr[0]
                normalized = self._normalize_ip(address)
                if normalized:
                    addresses.add(normalized)

        addresses.update({"127.0.0.1", "::1"})

        probe_targets = [
            (socket.AF_INET, ("8.8.8.8", 80)),
            (socket.AF_INET6, ("2001:4860:4860::8888", 80)),
        ]
        for family, target in probe_targets:
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(0.2)
                    sock.connect(target)
                    addr = sock.getsockname()[0]
            except OSError:
                continue
            else:
                normalized = self._normalize_ip(addr)
                if normalized:
                    addresses.add(normalized)

        return addresses

    def _determine_direction(self, packet) -> str:
        ip_src: Optional[str] = None
        ip_dst: Optional[str] = None
        if IP in packet:
            ip_layer = packet[IP]
            ip_src = getattr(ip_layer, "src", None)
            ip_dst = getattr(ip_layer, "dst", None)
        elif IPv6 in packet:
            ip6_layer = packet[IPv6]
            ip_src = getattr(ip6_layer, "src", None)
            ip_dst = getattr(ip6_layer, "dst", None)

        if not ip_src or not ip_dst:
            return "unknown"

        src = self._normalize_ip(str(ip_src))
        dst = self._normalize_ip(str(ip_dst))
        locals_set = self.local_addresses

        if src in locals_set and dst not in locals_set:
            return "outgoing"
        if dst in locals_set and src not in locals_set:
            return "incoming"
        if src in locals_set and dst in locals_set:
            return "internal"
        return "unknown"

    def _process_world_matching(self, item: PacketDisplay) -> None:
        if not item.utf8_text:
            return
        matches = self._extract_world_matches_from_stream(item.utf8_text)
        if not matches:
            return
        added = False
        for world_code, channel_name in matches:
            added = self._add_world_match(world_code, channel_name, item.captured_at) or added
        if added:
            self._refresh_world_table()

    def _add_world_match(self, world_code: str, channel_name: str, captured_at: float) -> bool:
        channel_name = channel_name.strip()
        if not channel_name:
            return False
        normalized_channel = channel_name.upper()
        if normalized_channel in self.world_match_channels:
            return False
        self.world_match_channels.add(normalized_channel)
        if captured_at <= 0:
            captured_at = time.time()
        entry = WorldMatchEntry(channel_name=channel_name, world_code=world_code, captured_at=captured_at)
        self.world_match_entries.insert(0, entry)
        channels = self.world_code_to_channels.setdefault(world_code, set())
        channels.add(channel_name)
        return True

    def _refresh_world_table(self) -> None:
        if not hasattr(self, "world_tree") or self.world_tree is None:
            return
        for child in self.world_tree.get_children():
            self.world_tree.delete(child)
        for entry in self.world_match_entries:
            self.world_tree.insert(
                "",
                tk.END,
                values=(self._format_capture_time(entry.captured_at), entry.channel_name, entry.world_code),
            )
        self._world_last_clicked_item = None
        if self.world_export_button and self.world_export_button.winfo_exists():
            state = tk.NORMAL if self.world_match_entries else tk.DISABLED
            self.world_export_button.config(state=state)
        self._refresh_friend_channel_names()

    def _refresh_friend_channel_names(self) -> None:
        if not self.friend_entries:
            return
        self._display_friend_entries(list(self.friend_entries), append=False)

    def _show_notification_overlay(self) -> None:
        if self.notification_window and self.notification_window.winfo_exists():
            self.notification_window.deiconify()
            self.notification_window.lift()
            return

        self.notification_window = tk.Toplevel(self.master)
        self.notification_window.title("알림 로그")
        self.notification_window.attributes("-topmost", True)
        self.notification_window.geometry("320x240")
        self.notification_window.protocol("WM_DELETE_WINDOW", self._close_notification_overlay)

        self.notification_window.columnconfigure(0, weight=1)
        self.notification_window.rowconfigure(0, weight=1)

        frame = ttk.Frame(self.notification_window, padding=8)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.notification_text = tk.Text(frame, state=tk.DISABLED, wrap="none")
        self.notification_text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.notification_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.notification_text.configure(yscrollcommand=scroll.set)

        self._refresh_notification_overlay()

    def _close_notification_overlay(self) -> None:
        if self.notification_window and self.notification_window.winfo_exists():
            self.notification_window.destroy()
        self.notification_window = None
        self.notification_text = None

    def _refresh_notification_overlay(self) -> None:
        if not self.notification_text or not self.notification_text.winfo_exists():
            return
        self.notification_text.config(state=tk.NORMAL)
        self.notification_text.delete("1.0", tk.END)
        for line in self.notification_logs:
            self.notification_text.insert(tk.END, line + "\n")
        self.notification_text.config(state=tk.DISABLED)
        self.notification_text.see(tk.END)

    def _append_notification_entry(self, captured_at: float, code: str) -> None:
        if captured_at <= 0:
            captured_at = time.time()
        timestamp = time.strftime("%H:%M:%S", time.localtime(captured_at))
        message = f"{timestamp} {code}"
        self.notification_logs.append(message)
        self._refresh_notification_overlay()

    def _process_notification_stream(self, text: Optional[str], captured_at: float) -> None:
        if not text:
            return
        self._notification_buffer += text
        if len(self._notification_buffer) > 8192:
            self._notification_buffer = self._notification_buffer[-8192:]

        while True:
            dev_index = self._notification_buffer.find("DevLogic")
            if dev_index == -1:
                keep_length = max(len("DevLogic") + 8, 16)
                if len(self._notification_buffer) > keep_length:
                    self._notification_buffer = self._notification_buffer[-keep_length:]
                break
            code_match = NOTIFICATION_CODE_PATTERN.search(
                self._notification_buffer, dev_index + len("DevLogic")
            )
            if code_match:
                code = code_match.group(1)
                self._append_notification_entry(captured_at, code)
                self._notification_buffer = self._notification_buffer[code_match.end() :]
            else:
                self._notification_buffer = self._notification_buffer[dev_index:]
                break

    def _on_world_tree_click(self, event: tk.Event) -> None:
        if not hasattr(self, "world_tree") or self.world_tree is None:
            return
        item_id = self.world_tree.identify_row(event.y)
        if not item_id:
            self._world_last_clicked_item = None
            return
        if self._world_last_clicked_item == item_id:
            self._copy_world_code_to_clipboard(item_id)
        self._world_last_clicked_item = item_id

    def _export_world_matches_to_csv(self) -> None:
        if not self.world_match_entries:
            messagebox.showinfo("알림", "저장할 월드 매칭 정보가 없습니다.")
            return

        timestamp = time.strftime("world_matches_%Y%m%d%H%M%S", time.localtime())
        default_name = f"{timestamp}.csv"
        initial_dir = str(Path(__file__).resolve().parent)
        file_path = filedialog.asksaveasfilename(
            parent=self.master,
            title="월드 매칭 CSV 저장",
            defaultextension=".csv",
            initialfile=default_name,
            initialdir=initial_dir,
            filetypes=[("CSV 파일", "*.csv"), ("모든 파일", "*.*")],
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["캡쳐 시간", "채널 이름", "월드 코드"])
                for entry in reversed(self.world_match_entries):
                    writer.writerow(
                        [
                            self._format_capture_time(entry.captured_at),
                            entry.channel_name,
                            entry.world_code,
                        ]
                    )
        except OSError as exc:
            messagebox.showerror("오류", f"CSV 파일 저장에 실패했습니다: {exc}")
            return

        messagebox.showinfo("완료", f"'{Path(file_path).name}' 파일로 저장했습니다.")

    def _copy_world_code_to_clipboard(self, item_id: str) -> None:
        if not hasattr(self, "world_tree") or self.world_tree is None:
            return
        values = self.world_tree.item(item_id, "values")
        if len(values) < 3:
            return
        world_code = values[2]
        if not world_code:
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(world_code)
            self.master.update()
        except tk.TclError:
            pass

    def _extract_world_matches_from_stream(self, text: Optional[str]) -> list[tuple[str, str]]:
        if not text:
            return []
        self._world_match_buffer += text
        if len(self._world_match_buffer) > 8192:
            self._world_match_buffer = self._world_match_buffer[-8192:]

        matches: list[tuple[str, str]] = []
        order = self.world_match_order_var.get()

        if self.world_match_order_locked and order == "world-first":
            while True:
                world_match = WORLD_ID_PATTERN.search(self._world_match_buffer)
                if not world_match:
                    break
                channel_match = CHANNEL_NAME_PATTERN.search(
                    self._world_match_buffer, world_match.end()
                )
                if channel_match:
                    world_code = world_match.group(1)
                    channel_name = channel_match.group(1)
                    matches.append((world_code, channel_name))
                    self._world_match_buffer = self._world_match_buffer[channel_match.end() :]
                else:
                    self._world_match_buffer = self._world_match_buffer[world_match.start() :]
                    break
        elif self.world_match_order_locked and order == "channel-first":
            while True:
                channel_match = CHANNEL_NAME_PATTERN.search(self._world_match_buffer)
                if not channel_match:
                    break
                world_match = WORLD_ID_PATTERN.search(
                    self._world_match_buffer, channel_match.end()
                )
                if world_match:
                    channel_name = channel_match.group(1)
                    world_code = world_match.group(1)
                    matches.append((world_code, channel_name))
                    self._world_match_buffer = self._world_match_buffer[world_match.end() :]
                else:
                    self._world_match_buffer = self._world_match_buffer[channel_match.start() :]
                    break
        else:
            while True:
                channel_match = CHANNEL_NAME_PATTERN.search(self._world_match_buffer)
                world_match = WORLD_ID_PATTERN.search(self._world_match_buffer)
                if not channel_match and not world_match:
                    break
                if world_match and (not channel_match or world_match.start() <= channel_match.start()):
                    channel_after = CHANNEL_NAME_PATTERN.search(
                        self._world_match_buffer, world_match.end()
                    )
                    if channel_after:
                        world_code = world_match.group(1)
                        channel_name = channel_after.group(1)
                        matches.append((world_code, channel_name))
                        self._world_match_buffer = self._world_match_buffer[channel_after.end() :]
                        self._set_world_match_order_ui("world-first", locked=False)
                    else:
                        self._world_match_buffer = self._world_match_buffer[world_match.start() :]
                        break
                elif channel_match:
                    world_after = WORLD_ID_PATTERN.search(
                        self._world_match_buffer, channel_match.end()
                    )
                    if world_after:
                        world_code = world_after.group(1)
                        channel_name = channel_match.group(1)
                        matches.append((world_code, channel_name))
                        self._world_match_buffer = self._world_match_buffer[world_after.end() :]
                        self._set_world_match_order_ui("channel-first", locked=False)
                    else:
                        self._world_match_buffer = self._world_match_buffer[channel_match.start() :]
                        break
                else:
                    break

        return matches

    def _save_settings(self) -> None:
        data = {
            "ip": self.ip_entry.get().strip(),
            "port": self.port_entry.get().strip(),
            "text_filter": self.text_filter_var.get().strip(),
            "max_packets": self.max_packets_var.get().strip(),
        }
        try:
            with self.settings_path.open("w", encoding="utf-8") as fp:
                json.dump(data, fp, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _load_settings(self) -> None:
        try:
            with self.settings_path.open("r", encoding="utf-8") as fp:
                data = json.load(fp)
        except (OSError, json.JSONDecodeError):
            return

        ip_value = data.get("ip")
        if isinstance(ip_value, str):
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, ip_value)

        port_value = data.get("port")
        if isinstance(port_value, str):
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, port_value)

        text_filter_value = data.get("text_filter")
        if isinstance(text_filter_value, str):
            self.text_filter_var.set(text_filter_value)

        max_packets_value = data.get("max_packets")
        if isinstance(max_packets_value, str) and max_packets_value.strip():
            self.max_packets_var.set(max_packets_value)


def main() -> None:
    root = tk.Tk()
    app = PacketCaptureApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

