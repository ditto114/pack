"""친구 관련 HTML 처리 및 검색 로직."""

from __future__ import annotations

import html as html_lib
import re
import time
from collections import deque
from typing import Callable, Iterable, Optional
from urllib.error import HTTPError, URLError

from .constants import (
    BASE_URL,
    FRIENDS_PAGE_URL,
    FRIEND_CODE_IN_TEXT_PATTERN,
    FRIEND_CODE_PATTERN,
    PROFILE_URL,
    VALUE_PREFIX_PATTERN,
)
from .models import FriendEntry, FriendPageData, FriendStatusEntry
from .network import fetch_html
from .parsers import ChannelSearchParser, FriendListParser, FriendStatusParser


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


def iter_friend_pages(friend_code: str, *, delay: float = 0.5) -> Iterable[tuple[str, FriendPageData]]:
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


def fetch_friend_statuses(html: str) -> list[FriendStatusEntry]:
    parser = FriendStatusParser()
    parser.feed(html)
    return parser.entries


def find_ppsn(
    target_code: str, *, delay: float = 0.5, logger: Optional[Callable[[str], None]] = None
) -> Optional[tuple[str, str]]:
    log = logger or (lambda message: None)

    target_code_upper = target_code.upper()
    log("[정보] 친구 목록을 가져오는 중입니다...")
    try:
        friends = get_initial_friends(target_code_upper)
    except HTTPError as exc:
        log(f"[경고] 프로필 페이지 요청 실패({exc.code}): {exc.reason}")
        return None
    except RuntimeError as exc:
        log(f"[오류] {exc}")
        return None

    log("[정보] 프로필에서 찾은 친구 목록을 사용합니다.")

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
            log(f"[경고] {friend_code} 의 친구 목 요청 실패({exc.code}): {exc.reason}")

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

        start_candidates = [html_text.rfind(tag, 0, index) for tag in ("<li", "<article", "<div")]
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
