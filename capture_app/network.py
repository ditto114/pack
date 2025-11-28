"""네트워크 관련 유틸리티."""

from __future__ import annotations

import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .constants import BASE_URL, DEFAULT_REQUEST_HEADERS


def fetch_html(
    url: str,
    *,
    referer: Optional[str] = None,
    retries: int = 2,
    timeout: int = 10,
) -> str:
    """지정된 URL에서 HTML 문서를 가져온다."""

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
