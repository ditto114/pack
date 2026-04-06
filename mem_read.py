"""메모리 스캐너 v2 — 64비트 주소 타입 수정 + 상세 에러 출력.

수정 사항:
  - lpAddress를 c_void_p 대신 c_ulonglong으로 명시
  - MEMORY_BASIC_INFORMATION 구조체 64비트 정확히 정의
  - VirtualQueryEx 실패 시 에러 코드 출력
  - 대체 방법: addr 0x10000부터 ReadProcessMemory 직접 시도
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import sys
import threading
import tkinter as tk
from tkinter import ttk
from typing import Optional

import psutil

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ── 64비트 MEMORY_BASIC_INFORMATION ─────────────────────────────────
# Windows 64비트 레이아웃 (ctypes 자동 패딩 포함)
class MBI64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),   #  8
        ("AllocationBase",    ctypes.c_ulonglong),   #  8
        ("AllocationProtect", wt.DWORD),             #  4
        ("_pad1",             wt.DWORD),             #  4  ← 패딩
        ("RegionSize",        ctypes.c_ulonglong),   #  8
        ("State",             wt.DWORD),             #  4
        ("Protect",           wt.DWORD),             #  4
        ("Type",              wt.DWORD),             #  4
        ("_pad2",             wt.DWORD),             #  4  ← 패딩
    ]  # 합계 48 bytes

MBI_SIZE = ctypes.sizeof(MBI64)

_OpenProcess = k32.OpenProcess
_OpenProcess.restype   = wt.HANDLE
_OpenProcess.argtypes  = [wt.DWORD, wt.BOOL, wt.DWORD]

_VQEx = k32.VirtualQueryEx
_VQEx.restype  = ctypes.c_size_t
_VQEx.argtypes = [
    wt.HANDLE,
    ctypes.c_ulonglong,                  # ← c_void_p 아님!
    ctypes.POINTER(MBI64),
    ctypes.c_size_t,
]

_RPM = k32.ReadProcessMemory
_RPM.restype  = wt.BOOL
_RPM.argtypes = [
    wt.HANDLE,
    ctypes.c_ulonglong,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

_CloseHandle = k32.CloseHandle

PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT   = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100

# ── 검색 대상 ─────────────────────────────────────────────────────────
TARGETS_UTF8: list[bytes] = [
    b"MapOnline", b"CharOnline", b"ChannelOnline",
    b"PetComponent", b"StateComponent", b"WsUserController",
    b"MapOnline\x00", b"CharOnline\x00",
]

TARGETS_UTF16: list[str] = [
    "망가진 용의 둥지", "블루 와이번의 둥지", "리프레",
    "협곡의 동쪽길", "남겨진 용의 둥지", "마뇽의 숲",
    "위험한 용의 둥지", "켄타우로스", "오르비스",
]


def to_utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


# ── 메모리 스캔 ──────────────────────────────────────────────────────

def scan(handle: wt.HANDLE, targets: list[bytes],
         log_fn=None, stop: Optional[threading.Event] = None,
         max_hits: int = 300) -> list[dict]:
    results: list[dict] = []
    addr = 0x10000          # 낮은 주소 skip
    pages = 0
    errors = 0
    chunk = 1 << 20         # 1 MB

    mbi = MBI64()

    while True:
        if stop and stop.is_set():
            break
        if len(results) >= max_hits:
            break

        ret = _VQEx(handle, addr, ctypes.byref(mbi), MBI_SIZE)
        if ret == 0:
            err = ctypes.get_last_error()
            errors += 1
            if errors == 1 and log_fn:
                log_fn(f"VirtualQueryEx 첫 오류: 코드 {err} "
                       f"(5=권한없음, 6=핸들무효, 87=인수오류, addr={hex(addr)})")
            # 오류 시 4KB 앞으로 이동해서 재시도
            addr += 0x1000
            if addr >= 0x7FFFFFFFFFFF:
                break
            continue

        base = mbi.BaseAddress
        size = mbi.RegionSize

        if mbi.State == MEM_COMMIT:
            protect = mbi.Protect
            if protect != PAGE_NOACCESS and not (protect & PAGE_GUARD):
                for off in range(0, size, chunk):
                    ra   = base + off
                    rlen = min(chunk, size - off)
                    buf  = ctypes.create_string_buffer(rlen)
                    read = ctypes.c_size_t(0)
                    ok   = _RPM(handle, ra, buf, rlen, ctypes.byref(read))
                    if ok and read.value > 0:
                        data = buf.raw[:read.value]
                        for tgt in targets:
                            i = 0
                            while True:
                                i = data.find(tgt, i)
                                if i == -1:
                                    break
                                actual = ra + i
                                cs     = max(0, i - 64)
                                ce     = min(len(data), i + len(tgt) + 128)
                                results.append({
                                    "target": tgt,
                                    "addr":   actual,
                                    "ctx":    data[cs:ce],
                                })
                                if len(results) >= max_hits:
                                    break
                                i += 1
                    if len(results) >= max_hits:
                        break
                pages += 1

        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
        if addr >= 0x7FFFFFFFFFFF:
            break

    if log_fn:
        log_fn(f"스캔 완료 | 영역:{pages} | 오류:{errors} | 발견:{len(results)}")
    return results


def hex_dump(data: bytes, limit: int = 512) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{off:04X}  {h:<47}  {a}")
    if len(data) > limit:
        lines.append(f"...{len(data)}B")
    return "\n".join(lines)


# ── GUI ──────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"메모리 스캐너 v2  (MBI_SIZE={MBI_SIZE})")
        self.geometry("1050x760")

        self._handle:   Optional[wt.HANDLE] = None
        self._pid:      int = 0
        self._proc_map: dict[str, int] = {}
        self._results:  list[dict] = []
        self._lock      = threading.Lock()
        self._queue:    list[dict] = []
        self._stop      = threading.Event()

        self._build_ui()
        self._refresh_procs()
        self._poll()

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=5)
        top.pack(fill="x")

        tk.Label(top, text="프로세스:").pack(side="left")
        self._proc_var = tk.StringVar()
        self._proc_cb  = ttk.Combobox(top, textvariable=self._proc_var,
                                       width=35, state="readonly")
        self._proc_cb.pack(side="left", padx=(4, 2))
        tk.Button(top, text="↺", command=self._refresh_procs, width=2).pack(side="left")

        self._btn_open = tk.Button(top, text="▶ OpenProcess",
                                    bg="#2d5c9e", fg="white", command=self._open)
        self._btn_open.pack(side="left", padx=(6, 2))
        self._btn_scan = tk.Button(top, text="🔍 스캔",
                                    bg="#2d7d2d", fg="white",
                                    state="disabled", command=self._start_scan)
        self._btn_scan.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중단",
                                    state="disabled", command=self._stop_scan)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="지우기", command=self._clear).pack(side="left", padx=8)

        self._lbl = tk.Label(top, text="대기", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 결과 목록
        frm = tk.Frame(self); frm.pack(fill="x", padx=8, pady=(4, 4))
        cols = ("#", "대상", "인코딩", "주소")
        self._tree = ttk.Treeview(frm, columns=cols, show="headings", height=10)
        for c, w in [("#", 40), ("대상", 220), ("인코딩", 70), ("주소", 180)]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, stretch=False)
        vsb = ttk.Scrollbar(frm, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="x")
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self._hex_txt = self._make_tab(nb, "hex 문맥 (±64B)")
        self._dec_txt = self._make_tab(nb, "텍스트 디코딩")
        self._log_txt = self._make_tab(nb, "로그")

    def _make_tab(self, nb: ttk.Notebook, label: str) -> tk.Text:
        frm = tk.Frame(nb); nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sv = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sh = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y")
        sh.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    def _refresh_procs(self) -> None:
        try:
            procs = sorted(psutil.process_iter(["pid", "name"]),
                           key=lambda p: p.info["name"].lower())
            items = [f"[{p.info['pid']:6d}]  {p.info['name']}" for p in procs]
            self._proc_cb["values"] = items
            self._proc_map = {f"[{p.info['pid']:6d}]  {p.info['name']}": p.info["pid"]
                              for p in procs}
            for item in items:
                if "msw" in item.lower():
                    self._proc_var.set(item)
                    self._log(f"msw.exe 자동 선택")
                    break
        except Exception as e:
            self._log(f"프로세스 목록 오류: {e}")

    def _open(self) -> None:
        sel = self._proc_var.get().strip()
        if not sel: return
        pid = self._proc_map.get(sel)
        if not pid: return
        if self._handle:
            try: _CloseHandle(self._handle)
            except Exception: pass
        h = _OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        err = ctypes.get_last_error()
        if h:
            self._handle = h
            self._pid    = pid
            self._btn_scan.config(state="normal")
            self._lbl.config(text=f"열림: PID {pid}  MBI={MBI_SIZE}B", fg="#2d7d2d")
            self._log(f"OpenProcess 성공: PID {pid}, HANDLE={h}")
            self._log(f"MBI 구조체 크기: {MBI_SIZE}B (정상=48B)")
        else:
            self._lbl.config(text=f"OpenProcess 실패 (오류 {err})", fg="red")
            self._log(f"실패: 오류 {err}  (5=ACCESS_DENIED, 6=INVALID_HANDLE)")

    def _start_scan(self) -> None:
        if not self._handle: return
        targets: list[bytes] = list(TARGETS_UTF8)
        targets += [to_utf16le(s) for s in TARGETS_UTF16]
        self._stop.clear()
        self._btn_scan.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._lbl.config(text="스캔 중...", fg="#7d4d00")
        self._log(f"스캔 시작: {len(targets)}종 | PID={self._pid} | MBI={MBI_SIZE}B")

        h = self._handle
        def _do() -> None:
            res = scan(h, targets, log_fn=self._log, stop=self._stop)
            with self._lock:
                self._queue.extend(res)
            self.after(0, self._done)
        threading.Thread(target=_do, daemon=True).start()

    def _stop_scan(self) -> None:
        self._stop.set()
        self._btn_stop.config(state="disabled")

    def _done(self) -> None:
        self._btn_scan.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._lbl.config(text=f"완료: {len(self._results)}개", fg="#2d7d2d")

    def _clear(self) -> None:
        with self._lock: self._queue.clear()
        self._results.clear()
        for iid in self._tree.get_children(): self._tree.delete(iid)

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for item in batch:
            tgt = item["target"]
            try:
                label = tgt.decode("utf-8"); enc = "utf-8"
            except Exception:
                label = tgt.decode("utf-16-le", errors="replace"); enc = "utf-16le"
            idx = len(self._results) + 1
            self._results.append(item)
            self._tree.insert("", "end", iid=str(idx),
                              values=(idx, label, enc, hex(item["addr"])))
            self._tree.see(str(idx))
        if batch:
            self._lbl.config(text=f"발견: {len(self._results)}개", fg="#2d7d2d")
        self.after(300, self._poll)

    def _on_select(self, _: object) -> None:
        sel = self._tree.selection()
        if not sel: return
        idx = int(sel[0]) - 1
        if not (0 <= idx < len(self._results)): return
        item = self._results[idx]
        ctx = item["ctx"]

        tgt = item["target"]
        try: label = tgt.decode("utf-8")
        except Exception: label = tgt.decode("utf-16-le", errors="replace")

        self._set_text(self._hex_txt,
            f"주소: {hex(item['addr'])}  |  대상: {label!r}\n\n" + hex_dump(ctx))
        self._set_text(self._dec_txt,
            f"=== UTF-8 ===\n{ctx.decode('utf-8','replace')}\n\n"
            f"=== UTF-16LE ===\n{ctx.decode('utf-16-le','replace')}\n\n"
            f"=== CP949 ===\n{ctx.decode('cp949','replace')}")

    def _set_text(self, w: tk.Text, text: str) -> None:
        w.config(state="normal"); w.delete("1.0","end")
        w.insert("1.0", text); w.config(state="disabled")

    def _log(self, msg: str) -> None:
        from datetime import datetime
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
        self.after(0, lambda: self._append_log(line))

    def _append_log(self, line: str) -> None:
        self._log_txt.config(state="normal")
        self._log_txt.insert("end", line)
        self._log_txt.see("end")
        self._log_txt.config(state="disabled")

    def on_close(self) -> None:
        self._stop.set()
        if self._handle:
            try: _CloseHandle(self._handle)
            except Exception: pass
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
