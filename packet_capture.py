"""패킷 캡쳐 UI 애플리케이션.

이 모듈은 Tkinter 기반의 간단한 사용자 인터페이스를 제공하여
네트워크 패킷을 캡쳐하고, 특정 IP 주소 기준 필터링 및 UTF-8 텍스트
디코딩 결과를 확인할 수 있도록 한다.
"""

from __future__ import annotations

import ipaddress
import json
import queue
import re
import socket
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from tkinter import messagebox, ttk
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


BASE_URL = "https://maplestoryworlds.nexon.com"
PROFILE_URL = BASE_URL + "/ko/profile/{code}"
FRIENDS_PAGE_URL = BASE_URL + "/profile/{code}/friends?type=friends&page={page}"
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
VALUE_PREFIX_PATTERN = r"[\s:=\"'\x00-\x1F]*"
WORLD_ID_PATTERN = re.compile(
    rf"w\s*o\s*r\s*l\s*d\s*i\s*d{VALUE_PREFIX_PATTERN}(\d{{17}})",
    re.IGNORECASE,
)
CHANNEL_NAME_PATTERN = re.compile(
    rf"c\s*h\s*a\s*n\s*n\s*e\s*l\s*n\s*a\s*m\s*e{VALUE_PREFIX_PATTERN}([A-Za-z]-[\uAC00-\uD7A3][0-9]{{2,3}})",
    re.IGNORECASE,
)


class FriendListParser(HTMLParser):
    """MapleStory Worlds 친구 목록에서 (친구코드, PPSN) 쌍을 추출하는 파서."""

    def __init__(self) -> None:
        super().__init__()
        self._within_friend_section = False
        self._current_ppsn: Optional[str] = None
        self.entries: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_dict = {key: value for key, value in attrs if value is not None}

        if tag == "section":
            class_name = attrs_dict.get("class", "")
            if "section_friend" in class_name:
                self._within_friend_section = True

        if not self._within_friend_section:
            return

        if "ppsn" in attrs_dict:
            self._current_ppsn = attrs_dict["ppsn"]

        if tag == "a" and "href" in attrs_dict:
            match = FRIEND_CODE_PATTERN.match(attrs_dict["href"])
            if match:
                code = match.group(1)
                ppsn = attrs_dict.get("ppsn", self._current_ppsn)
                if ppsn:
                    self.entries.append((code, ppsn))

    def handle_endtag(self, tag: str) -> None:
        if tag == "section" and self._within_friend_section:
            self._within_friend_section = False
            self._current_ppsn = None
        elif tag == "li":
            self._current_ppsn = None


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
    return [code for code, _ in parser.entries]


def extract_entries_from_friends_page(html: str) -> list[tuple[str, str]]:
    parser = FriendListParser()
    parser.feed(html)
    return parser.entries


def get_initial_friends(target_code: str) -> list[str]:
    profile_url = PROFILE_URL.format(code=target_code)
    html = fetch_html(profile_url, referer=BASE_URL + "/ko")
    codes = extract_friend_codes_from_profile(html)
    if not codes:
        raise RuntimeError(
            "프로필 페이지에서 친구 목록을 찾지 못했습니다. 친구 코드가 올바른지 확인하세요."
        )
    return codes


def iter_friend_pages(friend_code: str, *, delay: float = 0.5) -> Iterable[list[tuple[str, str]]]:
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
        entries = extract_entries_from_friends_page(html)
        if not entries:
            seen_empty += 1
            if seen_empty >= 2:
                break
        else:
            seen_empty = 0
            yield entries
        page += 1
        if delay:
            time.sleep(delay)


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
            for entries in iter_friend_pages(friend_code, delay=delay):
                for code, ppsn in entries:
                    if code.upper() == target_code_upper:
                        log(
                            f"[결과] 친구 {friend_code} 의 목록에서 대상 코드를 찾았습니다."
                        )
                        return ppsn, friend_code
        except URLError as exc:
            log(f"[경고] {friend_code} 의 친구 목록을 불러오지 못했습니다: {exc}")
        except HTTPError as exc:
            log(f"[경고] {friend_code} 의 친구 목록 요청 실패({exc.code}): {exc.reason}")

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
        self.ppsn_running = False
        self.local_addresses = self._detect_local_addresses()
        self.direction_filter_var = tk.StringVar(value="전체")
        self.world_match_entries: list[tuple[str, str]] = []
        self.world_match_keys: set[tuple[str, str]] = set()
        self._world_match_buffer: str = ""
        self._world_last_clicked_item: Optional[str] = None
        self.ppsn_window: Optional[tk.Toplevel] = None
        self.ppsn_code_entry: Optional[ttk.Entry] = None
        self.ppsn_delay_entry: Optional[ttk.Entry] = None
        self.ppsn_search_button: Optional[ttk.Button] = None
        self.ppsn_log: Optional[tk.Text] = None
        self.ppsn_result_entry: Optional[ttk.Entry] = None
        self.ppsn_copy_button: Optional[ttk.Button] = None

        self._build_widgets()
        self._load_settings()
        self._poll_queue()
        self._poll_ppsn_queue()
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
        button_frame.columnconfigure((0, 1, 2, 3), weight=1)

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

        self.world_panel = ttk.LabelFrame(main_frame, text="월드 매칭", padding=8)
        self.world_panel.grid(row=0, column=3, rowspan=4, sticky="nsew", padx=(12, 0))
        self.world_panel.columnconfigure(0, weight=1)
        self.world_panel.rowconfigure(1, weight=1)

        ttk.Label(self.world_panel, text="감지된 월드-채널 매칭").grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )
        world_columns = ("channel", "world")
        self.world_tree = ttk.Treeview(
            self.world_panel,
            columns=world_columns,
            show="headings",
            selectmode="browse",
            height=12,
        )
        self.world_tree.heading("channel", text="채널 이름")
        self.world_tree.heading("world", text="월드 코드")
        self.world_tree.column("channel", anchor="w", width=120, stretch=True)
        self.world_tree.column("world", anchor="w", width=180, stretch=True)
        self.world_tree.grid(row=1, column=0, sticky="nsew")
        self.world_tree.bind("<ButtonRelease-1>", self._on_world_tree_click)

        world_scroll = ttk.Scrollbar(self.world_panel, orient=tk.VERTICAL, command=self.world_tree.yview)
        world_scroll.grid(row=1, column=1, sticky="ns")
        self.world_tree.configure(yscrollcommand=world_scroll.set)

        self.world_panel.grid_remove()

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
            text="검색",
            command=self._on_ppsn_search,
        )
        self.ppsn_search_button.grid(row=0, column=4, padx=(12, 0), pady=(0, 4))

        ttk.Label(frame, text="검색 로그").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.ppsn_log = tk.Text(frame, height=8, state=tk.DISABLED, wrap="word")
        self.ppsn_log.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(0, 4))
        log_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.ppsn_log.yview)
        log_scroll.grid(row=2, column=5, sticky="ns", pady=(0, 4))
        self.ppsn_log.configure(yscrollcommand=log_scroll.set)

        ttk.Label(frame, text="결과 PPSN").grid(row=3, column=0, sticky="w", pady=(4, 0))
        self.ppsn_result_entry = ttk.Entry(
            frame,
            textvariable=self.ppsn_result_var,
            state="readonly",
        )
        self.ppsn_result_entry.grid(row=3, column=1, columnspan=3, sticky="ew", pady=(4, 0))
        self.ppsn_copy_button = ttk.Button(
            frame,
            text="복사",
            command=self._copy_ppsn_result,
            state=tk.DISABLED,
        )
        self.ppsn_copy_button.grid(row=3, column=4, padx=(12, 0), pady=(4, 0))

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
        self.ppsn_log = None
        self.ppsn_result_entry = None
        self.ppsn_copy_button = None

    def _on_ppsn_search(self) -> None:
        if self.ppsn_running:
            messagebox.showinfo("알림", "PPSN 검색이 진행 중입니다.")
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

        self.ppsn_running = True
        if self.ppsn_search_button and self.ppsn_search_button.winfo_exists():
            self.ppsn_search_button.config(state=tk.DISABLED)
        if self.ppsn_copy_button and self.ppsn_copy_button.winfo_exists():
            self.ppsn_copy_button.config(state=tk.DISABLED)
        self.ppsn_result_var.set("")
        self._clear_ppsn_log()
        self._append_ppsn_log("[정보] PPSN 검색을 시작합니다.")

        self.ppsn_thread = threading.Thread(
            target=self._run_ppsn_lookup,
            args=(code, delay),
            daemon=True,
        )
        self.ppsn_thread.start()

    def _run_ppsn_lookup(self, code: str, delay: float) -> None:
        def log(message: str) -> None:
            self.ppsn_queue.put({"type": "log", "text": message})

        try:
            result = find_ppsn(code, delay=delay, logger=log)
        except HTTPError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "success": False,
                    "text": f"[오류] 프로필 페이지 요청 실패({exc.code}): {exc.reason}",
                }
            )
        except URLError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "success": False,
                    "text": f"[오류] 네트워크 오류가 발생했습니다: {exc}",
                }
            )
        except RuntimeError as exc:
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "success": False,
                    "text": f"[오류] {exc}",
                }
            )
        except Exception as exc:  # pragma: no cover - 예기치 못한 예외 대비
            self.ppsn_queue.put(
                {
                    "type": "done",
                    "success": False,
                    "text": f"[오류] 알 수 없는 오류가 발생했습니다: {exc}",
                }
            )
        else:
            if result is None:
                self.ppsn_queue.put(
                    {
                        "type": "done",
                        "success": False,
                        "text": "[결과] 친구 목록 어디에서도 해당 친구 코드를 찾지 못했습니다.",
                    }
                )
            else:
                ppsn, via_friend = result
                self.ppsn_queue.put(
                    {
                        "type": "done",
                        "success": True,
                        "text": (
                            f"[결과] 친구 코드 {code.upper()} 의 PPSN은 {ppsn} 입니다. "
                            f"(친구 {via_friend} 의 목록에서 확인)"
                        ),
                        "ppsn": ppsn,
                    }
                )
        finally:
            self.ppsn_queue.put({"type": "finished"})

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

    def _poll_ppsn_queue(self) -> None:
        has_done_message = False
        while True:
            try:
                item = self.ppsn_queue.get_nowait()
            except queue.Empty:
                break
            message_type = item.get("type")
            if message_type == "log":
                self._append_ppsn_log(item.get("text", ""))
            elif message_type == "done":
                text = item.get("text", "")
                if text:
                    self._append_ppsn_log(text)
                success = bool(item.get("success"))
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
            elif message_type == "finished":
                has_done_message = True

        if has_done_message:
            self.ppsn_running = False
            if self.ppsn_search_button and self.ppsn_search_button.winfo_exists():
                self.ppsn_search_button.config(state=tk.NORMAL)
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

    def _clear_capture_results(self) -> None:
        self.packet_list_data.clear()
        for child in self.packet_tree.get_children():
            self.packet_tree.delete(child)
        self.packet_counter = 0
        self.world_match_entries.clear()
        self.world_match_keys.clear()
        self._world_match_buffer = ""
        self._world_last_clicked_item = None
        self._refresh_world_table()
        self._set_detail_text("캡쳐를 시작하면 패킷이 여기에 표시됩니다.")

    def _set_running_state(self, running: bool) -> None:
        self.start_button.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if running else tk.DISABLED)

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
            added = self._add_world_match(world_code, channel_name) or added
        if added:
            self._refresh_world_table()

    def _add_world_match(self, world_code: str, channel_name: str) -> bool:
        key = (world_code, channel_name)
        if key in self.world_match_keys:
            return False
        self.world_match_keys.add(key)
        self.world_match_entries.insert(0, (channel_name, world_code))
        return True

    def _refresh_world_table(self) -> None:
        if not hasattr(self, "world_tree") or self.world_tree is None:
            return
        for child in self.world_tree.get_children():
            self.world_tree.delete(child)
        for channel_name, world_code in self.world_match_entries:
            self.world_tree.insert("", tk.END, values=(channel_name, world_code))
        self._world_last_clicked_item = None

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

    def _copy_world_code_to_clipboard(self, item_id: str) -> None:
        if not hasattr(self, "world_tree") or self.world_tree is None:
            return
        values = self.world_tree.item(item_id, "values")
        if len(values) < 2:
            return
        world_code = values[1]
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
