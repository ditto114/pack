"""내보내기 서비스 — CSV/TXT 생성."""

from __future__ import annotations

import csv
import io
import time
from typing import Any

from ..db import get_packets, get_world_matches


def export_world_matches_csv(session_id: str | None = None) -> str:
    rows = get_world_matches(session_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["캡쳐 시간", "채널 이름", "월드 코드"])
    for row in reversed(rows):
        ts = row.get("captured_at", "")
        writer.writerow([ts, row["channel_name"], row["world_code"]])
    return buf.getvalue()


def export_packet_txt(packet: dict[str, Any], encoding: str = "utf-8") -> str:
    lines = [
        f"캡쳐 시각: {packet.get('captured_at', '')}",
        "",
        "요약:",
        packet.get("summary", ""),
    ]
    note = packet.get("note")
    if note:
        lines.extend(["", "비고:", note])

    payload_hex = packet.get("payload_hex")
    if not payload_hex:
        lines.extend(["", "페이로드:", "(페이로드 없음)"])
        return "\n".join(lines)

    raw = bytes.fromhex(payload_hex)

    lines.extend(["", f"텍스트 ({encoding}):"])
    try:
        decoded = raw.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        decoded = raw.decode(encoding, errors="replace")
        lines.append("(일부 문자를 대체하여 표시합니다.)")
    if len(decoded) > 4096:
        decoded = decoded[:4096]
        lines.append(decoded)
        lines.append("(텍스트 출력이 길이 제한으로 잘렸습니다.)")
    else:
        lines.append(decoded if decoded else "(텍스트 데이터 없음)")

    hex_str = _hex_dump(raw)
    lines.extend(["", "HEX 덤프:", hex_str])
    return "\n".join(lines)


def _hex_dump(data: bytes, max_length: int = 2048) -> str:
    shown = data[:max_length]
    lines = []
    for offset in range(0, len(shown), 16):
        chunk = shown[offset : offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hex_part:<47}  {ascii_part}")
    if len(data) > max_length:
        lines.append("(일부 데이터는 길이 제한으로 생략되었습니다.)")
    return "\n".join(lines)
