"""애플리케이션에서 공유하는 상수 및 정규식 패턴."""

from __future__ import annotations

import re

BASE_URL = "https://maplestoryworlds.nexon.com"
PROFILE_URL = BASE_URL + "/ko/profile/{code}"
FRIENDS_PAGE_URL = BASE_URL + "/ko/profile/{code}/friends?type=friends&page={page}"
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
    rf"c\s*h\s*a\s*n\s*n\s*e\s*l\s*n\s*a\s*m\s*e{VALUE_PREFIX_PATTERN}([A-Za-z]-[\uAC00-\uD7A3][0-9]{{2,3}})",
    re.IGNORECASE,
)
NOTIFICATION_CODE_PATTERN = re.compile(
    r"([A-Za-z][\uAC00-\uD7A3]-[0-9]{2,3}|[A-Za-z]-[\uAC00-\uD7A3][0-9]{2,3})"
)
