"""패킷 진단 GUI — 캡쳐된 패킷을 선택해서 클립보드에 복사할 수 있습니다."""

from __future__ import annotations

import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import Optional

try:
    from scapy.all import AsyncSniffer, IP, IPv6, Raw, TCP, UDP  # type: ignore
except ImportError:
    import tkinter.messagebox as mb
    root = tk.Tk(); root.withdraw()
    mb.showerror("오류", "scapy가 설치되지 않았습니다.\npip install scapy")
    sys.exit(1)


# ── 프로토콜 감지 ─────────────────────────────────────────────────

_TLS_CT = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake",
            0x17: "AppData", 0x18: "Heartbeat"}
_TLS_VER = {(3,1):"TLS1.0",(3,2):"TLS1.1",(3,3):"TLS1.2",(3,4):"TLS1.3"}
_HTTP_REQ = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS "]
_HTTP_RES = [b"HTTP/1.", b"HTTP/2"]

def detect(data: bytes) -> str:
    if not data:
        return "EMPTY"
    if len(data) >= 5 and data[0] in _TLS_CT and data[1] == 0x03:
        ver = _TLS_VER.get((data[1], data[2]), "TLS?")
        return f"TLS  [{ver} / {_TLS_CT[data[0]]}]"
    for p in _HTTP_REQ:
        if data.startswith(p):
            return "HTTP_REQ  " + data.split(b"\r\n")[0].decode("utf-8","replace")[:80]
    for p in _HTTP_RES:
        if data.startswith(p):
            return "HTTP_RES  " + data.split(b"\r\n")[0].decode("utf-8","replace")[:80]
    ratio = sum(1 for b in data[:64] if 32<=b<127 or b in(9,10,13)) / min(len(data),64)
    if ratio >= 0.70:
        snippet = data[:80].decode("utf-8","replace").replace("\n"," ").replace("\r","")
        return f"PLAINTEXT  {snippet}"
    return f"BINARY/ENCRYPTED  (가독 {ratio:.0%})"

def hex_dump(data: bytes, limit: int = 256) -> str:
    shown = data[:limit]
    lines = []
    for off in range(0, len(shown), 16):
        chunk = shown[off:off+16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32<=b<=126 else "." for b in chunk)
        lines.append(f"{off:04X}  {h:<47}  {a}")
    if len(data) > limit:
        lines.append(f"... (전체 {len(data)}B, {len(data)-limit}B 생략)")
    return "\n".join(lines)


# ── GUI ───────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("패킷 진단")
        self.geometry("900x620")
        self.resizable(True, True)

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._packets: list[dict] = []   # {id, proto, src, dst, size, data}
        self._queue: list[dict] = []

        self._build_ui()
        self._poll()

    # ── UI 구성 ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # 상단 필터 바
        top = tk.Frame(self, padx=8, pady=6)
        top.pack(fill="x")

        tk.Label(top, text="IP").pack(side="left")
        self._ip = tk.Entry(top, width=18)
        self._ip.pack(side="left", padx=(2,8))

        tk.Label(top, text="포트").pack(side="left")
        self._port = tk.Entry(top, width=7)
        self._port.pack(side="left", padx=(2,12))

        self._btn_start = tk.Button(top, text="▶ 시작", width=8,
                                    bg="#2d7d2d", fg="white",
                                    command=self._start)
        self._btn_start.pack(side="left", padx=2)

        self._btn_stop = tk.Button(top, text="■ 중지", width=8,
                                   state="disabled", command=self._stop)
        self._btn_stop.pack(side="left", padx=2)

        tk.Button(top, text="목록 지우기", command=self._clear).pack(side="left", padx=(12,2))

        self._status = tk.Label(top, text="대기 중", fg="gray")
        self._status.pack(side="right", padx=8)

        # 패킷 목록
        cols = ("#", "프로토콜", "경로", "크기")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        self._tree.heading("#",     text="#",     anchor="e")
        self._tree.heading("프로토콜", text="프로토콜")
        self._tree.heading("경로",   text="경로")
        self._tree.heading("크기",   text="크기",   anchor="e")
        self._tree.column("#",      width=45,  anchor="e", stretch=False)
        self._tree.column("프로토콜", width=300)
        self._tree.column("경로",   width=320)
        self._tree.column("크기",   width=70,  anchor="e", stretch=False)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 하단 상세 패널
        bottom = tk.Frame(self)
        bottom.pack(fill="both", expand=False, padx=8, pady=(0,6))

        btn_row = tk.Frame(bottom)
        btn_row.pack(fill="x")
        tk.Label(btn_row, text="선택 패킷 상세").pack(side="left")
        self._btn_copy = tk.Button(btn_row, text="클립보드에 복사",
                                   state="disabled", command=self._copy)
        self._btn_copy.pack(side="right")

        self._detail = tk.Text(bottom, height=12, font=("Consolas", 9),
                               state="disabled", wrap="none")
        sb_h = ttk.Scrollbar(bottom, orient="horizontal", command=self._detail.xview)
        sb_v = ttk.Scrollbar(bottom, orient="vertical",   command=self._detail.yview)
        self._detail.configure(xscrollcommand=sb_h.set, yscrollcommand=sb_v.set)
        sb_v.pack(side="right", fill="y")
        self._detail.pack(fill="both", expand=True)
        sb_h.pack(fill="x")

    # ── 캡쳐 제어 ─────────────────────────────────────────────────

    def _lfilter(self, pkt: object) -> bool:
        if IP not in pkt and IPv6 not in pkt:  # type: ignore[operator]
            return False
        if Raw not in pkt:  # type: ignore[operator]
            return False
        ip_f = self._ip.get().strip()
        port_f = self._port.get().strip()
        if ip_f:
            src = dst = ""
            if IP in pkt:  # type: ignore[operator]
                src, dst = pkt[IP].src, pkt[IP].dst  # type: ignore[index]
            elif IPv6 in pkt:  # type: ignore[operator]
                src, dst = pkt[IPv6].src, pkt[IPv6].dst  # type: ignore[index]
            if ip_f not in (src, dst):
                return False
        if port_f:
            try:
                p = int(port_f)
            except ValueError:
                return False
            ok = False
            if TCP in pkt:  # type: ignore[operator]
                ok = p in (pkt[TCP].sport, pkt[TCP].dport)  # type: ignore[index]
            elif UDP in pkt:  # type: ignore[operator]
                ok = p in (pkt[UDP].sport, pkt[UDP].dport)  # type: ignore[index]
            if not ok:
                return False
        return True

    def _handler(self, pkt: object) -> None:
        data: bytes = pkt[Raw].load if Raw in pkt else b""  # type: ignore[index,operator]
        proto = detect(data)

        src_ip = dst_ip = "?"
        src_p = dst_p = 0
        transport = "?"
        if IP in pkt:  # type: ignore[operator]
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst  # type: ignore[index]
        elif IPv6 in pkt:  # type: ignore[operator]
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst  # type: ignore[index]
        if TCP in pkt:  # type: ignore[operator]
            src_p, dst_p = pkt[TCP].sport, pkt[TCP].dport  # type: ignore[index]
            transport = "TCP"
        elif UDP in pkt:  # type: ignore[operator]
            src_p, dst_p = pkt[UDP].sport, pkt[UDP].dport  # type: ignore[index]
            transport = "UDP"

        row = {
            "proto": proto,
            "src": f"{src_ip}:{src_p}",
            "dst": f"{dst_ip}:{dst_p}",
            "transport": transport,
            "size": len(data),
            "data": data,
        }
        with self._lock:
            self._queue.append(row)

    def _start(self) -> None:
        self._sniffer = AsyncSniffer(store=False, prn=self._handler, lfilter=self._lfilter)
        try:
            self._sniffer.start()
        except PermissionError:
            from tkinter import messagebox
            messagebox.showerror("권한 오류", "관리자 권한으로 실행하세요.")
            return
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._status.config(text="캡쳐 중...", fg="#2d7d2d")

    def _stop(self) -> None:
        sniffer = self._sniffer
        self._sniffer = None
        self._btn_stop.config(state="disabled")
        self._status.config(text="중지 중...", fg="gray")

        def _do_stop() -> None:
            if sniffer:
                try:
                    sniffer.stop()
                    sniffer.join(timeout=3)
                except Exception:
                    pass
            self.after(0, self._on_stopped)

        threading.Thread(target=_do_stop, daemon=True).start()

    def _on_stopped(self) -> None:
        self._btn_start.config(state="normal")
        self._status.config(text=f"중지 — 총 {len(self._packets)}개", fg="gray")

    def _clear(self) -> None:
        self._packets.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._set_detail("")
        self._btn_copy.config(state="disabled")
        self._status.config(text="목록 지워짐", fg="gray")

    # ── 폴링 (메인 스레드에서 큐 처리) ───────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()

        for row in batch:
            idx = len(self._packets) + 1
            self._packets.append(row)
            path = f"{row['src']} → {row['dst']} ({row['transport']})"
            self._tree.insert("", "end", iid=str(idx),
                              values=(idx, row["proto"][:60], path, f"{row['size']}B"))
            # 최신 항목으로 스크롤
            self._tree.see(str(idx))

        if batch:
            self._status.config(text=f"캡쳐 중... {len(self._packets)}개", fg="#2d7d2d")

        self.after(200, self._poll)

    # ── 선택/복사 ─────────────────────────────────────────────────

    def _on_select(self, _event: object) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(sel[0]) - 1
        row = self._packets[idx]
        text = self._make_detail(idx + 1, row)
        self._set_detail(text)
        self._btn_copy.config(state="normal")

    def _make_detail(self, num: int, row: dict) -> str:
        lines = [
            f"패킷 #{num}",
            f"  경로     : {row['src']} → {row['dst']} ({row['transport']})",
            f"  프로토콜  : {row['proto']}",
            f"  페이로드  : {row['size']} 바이트",
            "",
            "Hex dump (첫 256B):",
            hex_dump(row["data"], limit=256),
        ]
        return "\n".join(lines)

    def _set_detail(self, text: str) -> None:
        self._detail.config(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("1.0", text)
        self._detail.config(state="disabled")

    def _copy(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(sel[0]) - 1
        text = self._make_detail(idx + 1, self._packets[idx])
        self.clipboard_clear()
        self.clipboard_append(text)
        self._status.config(text="클립보드에 복사됨!", fg="#1a6fba")
        self.after(2000, lambda: self._status.config(
            text=f"{'캡쳐 중...' if self._sniffer else '중지'} {len(self._packets)}개",
            fg="#2d7d2d" if self._sniffer else "gray"
        ))

    def on_close(self) -> None:
        sniffer = self._sniffer
        self._sniffer = None
        self.destroy()
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
