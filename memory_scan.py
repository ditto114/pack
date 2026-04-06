"""msw.exe 프로세스 메모리 스캔 — Frida 없음, ReadProcessMemory 사용.

DLL 인젝션 없이 외부에서 읽기만 하므로 GRAP 탐지 대상이 아님.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

import psutil

# ── WinAPI ────────────────────────────────────────────────────────

PROCESS_VM_READ          = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT   = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100

_k32 = ctypes.windll.kernel32
_k32.OpenProcess.restype      = ctypes.wintypes.HANDLE
_k32.CloseHandle.restype      = ctypes.wintypes.BOOL
_k32.VirtualQueryEx.restype   = ctypes.c_size_t
_k32.ReadProcessMemory.restype = ctypes.wintypes.BOOL


class _MBI(ctypes.Structure):
    """MEMORY_BASIC_INFORMATION (64-bit)."""
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),
        ("AllocationBase",    ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("_pad1",             ctypes.c_ulong),
        ("RegionSize",        ctypes.c_ulonglong),
        ("State",             ctypes.c_ulong),
        ("Protect",           ctypes.c_ulong),
        ("Type",              ctypes.c_ulong),
        ("_pad2",             ctypes.c_ulong),
    ]


# ── 검색 패턴 ─────────────────────────────────────────────────────

# ASCII 정확히 17자리 숫자
_RE_ASCII  = re.compile(rb'(?<!\d)\d{17}(?!\d)')

# UTF-16LE 17자리 숫자: (0x3X 0x00) × 17
_RE_UTF16  = re.compile(rb'(?:[0-9]\x00){17}')

# ── "A-가00" 형식 패턴 ─────────────────────────────────────────────
# 예시: B-리03  형태 (영문1자 + 하이픈 + 한글1자이상 + 2~3자리숫자)

# UTF-8
_RE_SLOT_UTF8 = re.compile(
    rb'[A-Z]\x2D'
    rb'(?:[\xEA-\xED][\x80-\xBF]{2})+'
    rb'[0-9]{2,3}'
)

# UTF-16LE
_RE_SLOT_UTF16 = re.compile(
    rb'[A-Z]\x00\x2D\x00'
    rb'(?:[\x00-\xFF][\xAC-\xD7])+'
    rb'(?:[0-9]\x00){2,3}'
)

# EUC-KR / CP949: 한글 2바이트 (첫 바이트 0xA1-0xFE)
_RE_SLOT_EUCKR = re.compile(
    rb'[A-Z]\x2D'
    rb'(?:[\xA1-\xFE][\xA1-\xFE])+'
    rb'[0-9]{2,3}'
)

# 하이픈 없는 변형: 영문+한글+숫자 (메모리 저장 방식이 다를 수 있음)
_RE_SLOT_NOHYPHEN_UTF8 = re.compile(
    rb'[A-Z]'
    rb'(?:[\xEA-\xED][\x80-\xBF]{2})+'
    rb'[0-9]{2,3}'
)

_RE_SLOT_NOHYPHEN_UTF16 = re.compile(
    rb'[A-Z]\x00'
    rb'(?:[\x00-\xFF][\xAC-\xD7])+'
    rb'(?:[0-9]\x00){2,3}'
)

# 채널명 관련 한글 키워드 (UTF-16LE = 유니코드 코드포인트를 LE 2바이트로)
def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")

_KW = [
    (_utf16le("채널"), "채널"),
    (_utf16le("마을"), "마을"),
    (_utf16le("광장"), "광장"),
    (_utf16le("월드"), "월드"),
    (_utf16le("세계"), "세계"),
    (_utf16le("숲"),   "숲"),
    (_utf16le("평원"), "평원"),
    (_utf16le("동굴"), "동굴"),
]

MAX_REGION = 256 * 1024 * 1024   # 256 MB 이상 region 스킵
CHUNK_SIZE =   4 * 1024 * 1024   # 4 MB 씩 읽기


# ── 메모리 접근 헬퍼 ──────────────────────────────────────────────

def _open(pid: int) -> int:
    h = _k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise PermissionError(f"OpenProcess 실패 (오류 {_k32.GetLastError()}) — 관리자 권한 필요")
    return h


def _regions(handle: int):
    mbi  = _MBI()
    addr = 0
    while True:
        n = _k32.VirtualQueryEx(handle, ctypes.c_ulonglong(addr),
                                ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not n:
            break
        readable = (mbi.State == MEM_COMMIT
                    and not (mbi.Protect & PAGE_NOACCESS)
                    and not (mbi.Protect & PAGE_GUARD)
                    and mbi.Protect != 0)
        if readable:
            yield int(mbi.BaseAddress), int(mbi.RegionSize)
        addr = int(mbi.BaseAddress) + int(mbi.RegionSize)
        if addr >= 0x7FFFFFFFFFFF:   # 64-bit 사용자 공간 상한
            break


def _read(handle: int, addr: int, size: int) -> bytes:
    buf  = (ctypes.c_char * size)()
    done = ctypes.c_size_t(0)
    ok   = _k32.ReadProcessMemory(handle, ctypes.c_ulonglong(addr),
                                   buf, size, ctypes.byref(done))
    return bytes(buf[:done.value]) if ok else b""


# ── 문자열 추출 ───────────────────────────────────────────────────

def _ctx_utf16(data: bytes, pos: int, radius: int = 24) -> str:
    """pos 주변 UTF-16LE 가독 문자열 추출 (한글 + ASCII 숫자/영문)."""
    start = max(0, (pos - radius * 2)) & ~1
    end   = min(len(data), pos + radius * 2 + 2)
    chars: list[str] = []
    for i in range(start, end - 1, 2):
        cp = data[i] | (data[i + 1] << 8)
        if (0xAC00 <= cp <= 0xD7A3          # 한글 음절
                or 0x30 <= cp <= 0x39        # 숫자
                or 0x41 <= cp <= 0x5A        # 대문자
                or 0x61 <= cp <= 0x7A        # 소문자
                or cp == 0x20):              # 공백
            chars.append(chr(cp))
        elif chars:
            break  # 처음 등장한 비-가독 문자에서 끊음
    return "".join(chars).strip()


# ── 스캔 엔진 ─────────────────────────────────────────────────────

def scan(pid: int,
         stop_evt: threading.Event,
         on_result,     # callable(kind, item_dict)
         on_progress,   # callable(msg)
         ) -> None:
    try:
        h = _open(pid)
    except PermissionError as e:
        on_progress(f"오류: {e}")
        return

    seen:    set[str] = set()
    regions  = list(_regions(h))
    total_mb = sum(min(r, MAX_REGION) for _, r in regions) / 1024 / 1024
    scanned  = 0.0

    try:
        for base, rsize in regions:
            if stop_evt.is_set():
                break
            if rsize > MAX_REGION:
                continue

            OVERLAP = 128   # 청크 경계 걸친 패턴 놓치지 않도록
            prev_tail = b""
            for off in range(0, rsize, CHUNK_SIZE):
                if stop_evt.is_set():
                    break
                chunk = min(CHUNK_SIZE, rsize - off)
                raw_data = _read(h, base + off, chunk)
                if not raw_data:
                    prev_tail = b""
                    continue
                scanned += len(raw_data) / 1024 / 1024
                data = prev_tail + raw_data
                prev_tail = raw_data[-OVERLAP:] if len(raw_data) >= OVERLAP else raw_data

                # 1) ASCII 17자리 WorldID
                for m in _RE_ASCII.finditer(data):
                    s = m.group().decode()
                    if s not in seen:
                        seen.add(s)
                        on_result("worldid", {"enc": "ASCII", "val": s})

                # 2) UTF-16LE 17자리 WorldID
                for m in _RE_UTF16.finditer(data):
                    raw = m.group()
                    # 정확히 17자리인지 앞뒤 확인
                    p = m.start()
                    if p >= 2 and 0x30 <= data[p - 2] <= 0x39 and data[p - 1] == 0x00:
                        continue   # 앞에 더 있음
                    e = m.end()
                    if e + 1 < len(data) and 0x30 <= data[e] <= 0x39 and data[e + 1] == 0x00:
                        continue   # 뒤에 더 있음
                    s = raw[::2].decode("ascii", errors="ignore")
                    if s.isdigit() and s not in seen:
                        seen.add(s)
                        on_result("worldid", {"enc": "UTF-16LE", "val": s})

                # 3) "A-가00" 슬롯 코드 패턴 (여러 인코딩)
                for pattern, enc_label, codec in [
                    (_RE_SLOT_UTF8,           "UTF-8",     "utf-8"),
                    (_RE_SLOT_NOHYPHEN_UTF8,  "UTF-8(NH)", "utf-8"),
                    (_RE_SLOT_EUCKR,          "EUC-KR",    "cp949"),
                ]:
                    for m in pattern.finditer(data):
                        try:
                            s = m.group().decode(codec)
                            if s not in seen:
                                seen.add(s)
                                on_result("slot", {"enc": enc_label, "val": s})
                        except (UnicodeDecodeError, ValueError):
                            pass

                for pattern, enc_label in [
                    (_RE_SLOT_UTF16,          "UTF-16LE"),
                    (_RE_SLOT_NOHYPHEN_UTF16, "UTF-16LE(NH)"),
                ]:
                    for m in pattern.finditer(data):
                        try:
                            s = m.group().decode("utf-16-le")
                            if s not in seen:
                                seen.add(s)
                                on_result("slot", {"enc": enc_label, "val": s})
                        except (UnicodeDecodeError, ValueError):
                            pass

                # 4) 한글 채널명 키워드
                for kw_bytes, kw_label in _KW:
                    pos = 0
                    while True:
                        pos = data.find(kw_bytes, pos)
                        if pos < 0:
                            break
                        ctx = _ctx_utf16(data, pos)
                        if ctx and len(ctx) >= 2 and ctx not in seen:
                            seen.add(ctx)
                            on_result("channel", {"label": kw_label, "val": ctx})
                        pos += 2

            on_progress(f"스캔 중... {scanned:.0f} / {total_mb:.0f} MB")

    finally:
        _k32.CloseHandle(h)

    on_progress(f"완료 — {scanned:.0f} MB 스캔 | {len(seen)}개 발견")


# ── GUI ───────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("메모리 스캔 — WorldID / 채널명 (Frida 없음)")
        self.geometry("680x520")

        self._stop_evt  = threading.Event()
        self._results:   list[dict] = []
        self._proc_map:  dict[str, int] = {}
        self._lock       = threading.Lock()
        self._queue:     list[tuple[str, dict]] = []

        self._build_ui()
        self._refresh_procs()
        self._poll()

    # ── UI ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=6)
        top.pack(fill="x")

        tk.Label(top, text="프로세스").pack(side="left")
        self._proc_var = tk.StringVar()
        self._proc_cb  = ttk.Combobox(top, textvariable=self._proc_var,
                                       width=32, state="readonly")
        self._proc_cb.pack(side="left", padx=(4, 2))
        tk.Button(top, text="↺", width=2,
                  command=self._refresh_procs).pack(side="left", padx=(0, 8))

        self._btn_scan = tk.Button(top, text="▶ 스캔",
                                    bg="#2d7d2d", fg="white",
                                    command=self._start_scan)
        self._btn_scan.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중지",
                                    state="disabled", command=self._stop_scan)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="목록 지우기",
                  command=self._clear).pack(side="left", padx=(12, 2))

        self._lbl = tk.Label(top, text="대기 중", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 자동 반복 스캔
        bot_ctrl = tk.Frame(self, padx=8)
        bot_ctrl.pack(fill="x")
        self._auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(bot_ctrl, text="채널 진입 후 자동 재스캔",
                       variable=self._auto_var).pack(side="left")
        tk.Label(bot_ctrl, text="  간격(초):").pack(side="left")
        self._interval_var = tk.StringVar(value="10")
        tk.Entry(bot_ctrl, textvariable=self._interval_var,
                 width=5).pack(side="left")

        # 결과 목록
        frm = tk.Frame(self)
        frm.pack(fill="both", expand=True, padx=8, pady=4)

        cols = ("#", "종류", "인코딩/키워드", "값")
        self._tree = ttk.Treeview(frm, columns=cols, show="headings")
        self._tree.heading("#",          text="#",    anchor="e")
        self._tree.heading("종류",       text="종류")
        self._tree.heading("인코딩/키워드", text="인코딩/키워드")
        self._tree.heading("값",         text="값")
        self._tree.column("#",           width=44,  anchor="e", stretch=False)
        self._tree.column("종류",        width=80,  stretch=False)
        self._tree.column("인코딩/키워드", width=100, stretch=False)
        self._tree.column("값",          width=380)
        self._tree.tag_configure("worldid", foreground="#1a6fba")
        self._tree.tag_configure("channel", foreground="#2d7d2d")
        self._tree.tag_configure("slot",    foreground="#9b2d00", font=("", 9, "bold"))

        vsb = ttk.Scrollbar(frm, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 하단 바
        bot = tk.Frame(self, padx=8, pady=4)
        bot.pack(fill="x")
        self._lbl_val = tk.Label(bot, text="", font=("Consolas", 10),
                                  fg="#1a6fba", anchor="w")
        self._lbl_val.pack(side="left", fill="x", expand=True)
        self._btn_copy = tk.Button(bot, text="클립보드 복사",
                                    state="disabled", command=self._copy)
        self._btn_copy.pack(side="right")

    # ── 프로세스 목록 ─────────────────────────────────────────────

    def _refresh_procs(self) -> None:
        items, m = [], {}
        for p in sorted(psutil.process_iter(["pid", "name"]),
                        key=lambda p: p.info["name"].lower()):
            label = f"[{p.info['pid']:6}]  {p.info['name']}"
            items.append(label)
            m[label] = p.info["pid"]
        self._proc_cb["values"] = items
        self._proc_map = m
        for item in items:
            if "msw.exe" in item.lower():
                self._proc_var.set(item)
                break

    # ── 스캔 제어 ─────────────────────────────────────────────────

    def _start_scan(self) -> None:
        sel = self._proc_var.get().strip()
        if not sel:
            messagebox.showwarning("선택 필요", "프로세스를 선택하세요.")
            return
        pid = self._proc_map.get(sel)
        if pid is None:
            return

        self._stop_evt.clear()
        self._btn_scan.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._lbl.config(text="스캔 준비 중...", fg="#2d7d2d")

        def _on_result(kind: str, item: dict) -> None:
            with self._lock:
                self._queue.append((kind, item))

        def _on_progress(msg: str) -> None:
            self.after(0, lambda: self._lbl.config(text=msg, fg="#2d7d2d"))

        def _done() -> None:
            self.after(0, self._on_scan_done)
            # 자동 재스캔
            if self._auto_var.get() and not self._stop_evt.is_set():
                try:
                    interval = max(1, int(self._interval_var.get()))
                except ValueError:
                    interval = 10
                self.after(interval * 1000, self._start_scan)

        def _thread() -> None:
            scan(pid, self._stop_evt, _on_result, _on_progress)
            _done()

        threading.Thread(target=_thread, daemon=True).start()

    def _stop_scan(self) -> None:
        self._stop_evt.set()

    def _on_scan_done(self) -> None:
        self._btn_scan.config(state="normal")
        self._btn_stop.config(state="disabled")

    def _clear(self) -> None:
        self._results.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._lbl_val.config(text="")
        self._btn_copy.config(state="disabled")

    # ── 폴링 ──────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for kind, item in batch:
            idx = len(self._results) + 1
            self._results.append(item)
            enc = item.get("enc") or item.get("label", "")
            val = item.get("val", "")
            self._tree.insert("", "end", iid=str(idx),
                              tags=(kind,),
                              values=(idx, kind, enc, val))
            self._tree.see(str(idx))
        self.after(200, self._poll)

    # ── 선택 / 복사 ───────────────────────────────────────────────

    def _on_select(self, _: object) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        val = self._results[int(sel[0]) - 1].get("val", "")
        self._lbl_val.config(text=val)
        self._btn_copy.config(state="normal")

    def _copy(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        val = self._results[int(sel[0]) - 1].get("val", "")
        self.clipboard_clear()
        self.clipboard_append(val)
        self._lbl.config(text="복사됨!", fg="#1a6fba")

    def on_close(self) -> None:
        self._stop_evt.set()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
