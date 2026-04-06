"""Frida 메모리 스캐너 — msw.exe 메모리에서 게임 데이터 직접 읽기.

네트워크 훅 없음. 메모리 Read-Only 스캔만 수행.
anti-cheat가 감지할 인터셉터를 설치하지 않으므로 안전.

동작 방식:
  1. msw.exe에 Frida 연결 (인터셉터 없음)
  2. 메모리 페이지를 스캔해서 알려진 문자열 탐색
  3. 발견된 위치 주변 문맥 읽기
  4. 반복 폴링으로 게임 상태 추적

실행: 관리자 권한으로 python mem_scan.py
"""

from __future__ import annotations

import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import Optional

try:
    import frida  # type: ignore
except ImportError:
    import tkinter.messagebox as mb
    root = tk.Tk(); root.withdraw()
    mb.showerror("오류", "pip install frida"); sys.exit(1)

# ── Frida 메모리 스캔 스크립트 ──────────────────────────────────────
# 인터셉터 사용 안 함 — 순수 메모리 읽기만
_SCAN_SCRIPT = r"""
'use strict';

// 검색할 알려진 문자열 (UTF-16LE / UTF-8 둘 다 시도)
const TARGETS_UTF8 = [
    "MapOnline",
    "CharOnline",
    "ChannelOnline",
    "PetComponent",
    "StateComponent",
    "WsUserController",
];

// 한글 맵 이름 샘플 (UTF-16LE 검색)
const TARGETS_UTF16 = [
    "망가진 용의 둥지",
    "블루 와이번의 둥지",
    "리프레",
    "협곡의 동쪽길",
    "남겨진 용의 둥지",
    "마뇽의 숲",
];

function toUtf8Bytes(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

function toUtf16LEBytes(str) {
    const buf = new ArrayBuffer(str.length * 2);
    const view = new DataView(buf);
    for (let i = 0; i < str.length; i++) {
        view.setUint16(i * 2, str.charCodeAt(i), true);
    }
    return new Uint8Array(buf);
}

function scanFor(pattern, iters) {
    const results = [];
    try {
        Memory.scan(
            ptr('0x10000'), 0x7FFFFFFF,
            pattern,
            {
                onMatch(address, size) {
                    try {
                        // 주변 256바이트 읽기
                        const start = address.sub(32);
                        const len   = 64 + 32 + 32;
                        const ctx   = Memory.readByteArray(start, len);
                        results.push({
                            addr: address.toString(),
                            ctx:  Array.from(new Uint8Array(ctx)),
                        });
                    } catch(e) {}
                    if (results.length >= 20) return 'stop';
                },
                onError(reason) {},
                onComplete() {},
            }
        );
    } catch(e) {}
    return results;
}

function buildPattern(bytes_arr) {
    return bytes_arr.map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
}

function doScan() {
    const out = { found: [] };

    // UTF-8 영문 필드명 검색
    for (const target of TARGETS_UTF8) {
        const bytes   = toUtf8Bytes(target);
        const pattern = buildPattern(Array.from(bytes));
        const hits    = scanFor(pattern, 20);
        for (const h of hits) {
            out.found.push({ target, encoding: 'utf8', addr: h.addr, ctx: h.ctx });
        }
    }

    // UTF-16LE 한글 검색
    for (const target of TARGETS_UTF16) {
        const bytes   = toUtf16LEBytes(target);
        const pattern = buildPattern(Array.from(bytes));
        const hits    = scanFor(pattern, 10);
        for (const h of hits) {
            out.found.push({ target, encoding: 'utf16le', addr: h.addr, ctx: h.ctx });
        }
    }

    send({ type: 'scan_result', data: out });
}

send({ type: 'alive' });

// 즉시 1회 스캔
try { doScan(); } catch(e) { send({ type: 'error', msg: e.message }); }
"""

# 반복 폴링용 (주소 알고 나면 해당 주소만 다시 읽기)
_READ_ADDR_SCRIPT = r"""
'use strict';
function readAt(addrStr, len) {
    try {
        const p   = ptr(addrStr).sub(128);
        const buf = Memory.readByteArray(p, len + 128);
        send({ type: 'mem_read', addr: addrStr,
               data: Array.from(new Uint8Array(buf)) });
    } catch(e) {
        send({ type: 'mem_read_err', addr: addrStr, msg: e.message });
    }
}
"""


def bytes_to_text(data: list[int]) -> str:
    """바이트 배열을 hex dump 문자열로 변환."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{off:04X}  {h:<47}  {a}")
    return "\n".join(lines)


def try_decode_utf16(data: list[int]) -> str:
    """바이트를 UTF-16LE로 디코딩 시도."""
    try:
        return bytes(data).decode("utf-16-le", errors="replace")
    except Exception:
        return ""


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("메모리 직접 읽기 — msw.exe")
        self.geometry("1050x750")

        self._session: Optional[object] = None
        self._script:  Optional[object] = None
        self._lock = threading.Lock()
        self._results: list[dict] = []
        self._queue:   list[dict] = []
        self._proc_map: dict[str, int] = {}

        self._build_ui()
        self._refresh_procs()
        self._poll()

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=5)
        top.pack(fill="x")

        tk.Label(top, text="프로세스:").pack(side="left")
        self._proc_var = tk.StringVar()
        self._proc_cb = ttk.Combobox(top, textvariable=self._proc_var,
                                      width=35, state="readonly")
        self._proc_cb.pack(side="left", padx=(4, 2))
        tk.Button(top, text="↺", command=self._refresh_procs).pack(side="left", padx=(0, 8))

        self._btn_attach = tk.Button(top, text="▶ 연결 & 스캔",
                                      bg="#2d5c9e", fg="white", command=self._attach)
        self._btn_attach.pack(side="left", padx=2)
        self._btn_scan = tk.Button(top, text="🔍 다시 스캔",
                                    state="disabled", command=self._rescan)
        self._btn_scan.pack(side="left", padx=2)
        self._btn_detach = tk.Button(top, text="■ 해제",
                                      state="disabled", command=self._detach)
        self._btn_detach.pack(side="left", padx=2)
        tk.Button(top, text="결과 지우기", command=self._clear).pack(side="left", padx=(12, 2))

        self._lbl = tk.Label(top, text="대기", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 발견된 문자열 목록
        frm_top = tk.LabelFrame(self, text="발견된 문자열 위치", padx=4, pady=4)
        frm_top.pack(fill="x", padx=8, pady=(0, 4))

        cols = ("#", "문자열", "인코딩", "주소")
        self._tree = ttk.Treeview(frm_top, columns=cols, show="headings", height=8)
        for c, w in [("#", 40), ("문자열", 200), ("인코딩", 70), ("주소", 180)]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, stretch=False)
        vsb = ttk.Scrollbar(frm_top, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="x", expand=False)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 상세 탭
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self._ctx_txt  = self._make_tab(nb, "선택 위치 문맥 (hex)")
        self._utf_txt  = self._make_tab(nb, "UTF-16LE 디코딩")
        self._log_txt  = self._make_tab(nb, "로그")

    def _make_tab(self, nb, label: str) -> tk.Text:
        frm = tk.Frame(nb); nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sv  = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sh  = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y")
        sh.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    # ── 프로세스 ────────────────────────────────────────────────────

    def _refresh_procs(self) -> None:
        try:
            device = frida.get_local_device()
            procs  = sorted(device.enumerate_processes(), key=lambda p: p.name.lower())
            items  = [f"[{p.pid:6}]  {p.name}" for p in procs]
            self._proc_cb["values"] = items
            self._proc_map = {f"[{p.pid:6}]  {p.name}": p.pid for p in procs}
            # msw.exe 자동 선택
            for item in items:
                if "msw" in item.lower():
                    self._proc_var.set(item)
                    break
        except Exception as e:
            self._log(f"프로세스 목록 오류: {e}")

    # ── 연결 ────────────────────────────────────────────────────────

    def _attach(self) -> None:
        sel = self._proc_var.get().strip()
        if not sel:
            import tkinter.messagebox as mb
            mb.showwarning("선택 필요", "프로세스를 선택하세요."); return
        pid = self._proc_map.get(sel)
        if pid is None: return

        self._btn_attach.config(state="disabled")
        self._log(f"연결 중: {sel} (PID {pid})")

        def _do() -> None:
            try:
                device = frida.get_local_device()
                sess   = device.attach(pid)
                script = sess.create_script(_SCAN_SCRIPT)
                script.on("message", self._on_msg)
                script.load()
                self._session = sess
                self._script  = script
                self.after(0, lambda: (
                    self._btn_scan.config(state="normal"),
                    self._btn_detach.config(state="normal"),
                    self._lbl.config(text=f"연결됨: {sel}", fg="#2d7d2d"),
                ))
            except Exception as e:
                self.after(0, lambda: (
                    self._btn_attach.config(state="normal"),
                    self._lbl.config(text=f"연결 실패: {e}", fg="red"),
                ))
                self._log(f"연결 실패: {e}")

        threading.Thread(target=_do, daemon=True).start()

    def _rescan(self) -> None:
        """현재 연결된 스크립트에서 스캔 재실행."""
        if not self._session:
            return
        self._log("스캔 재실행...")
        try:
            script = self._session.create_script(_SCAN_SCRIPT)  # type: ignore
            script.on("message", self._on_msg)
            script.load()
            if self._script:
                try: self._script.unload()  # type: ignore
                except Exception: pass
            self._script = script
        except Exception as e:
            self._log(f"재스캔 오류: {e}")

    def _detach(self) -> None:
        for obj, m in [(self._script, "unload"), (self._session, "detach")]:
            if obj:
                try: getattr(obj, m)()
                except Exception: pass
        self._script = self._session = None
        self._btn_attach.config(state="normal")
        self._btn_scan.config(state="disabled")
        self._btn_detach.config(state="disabled")
        self._lbl.config(text="해제됨", fg="gray")

    def _clear(self) -> None:
        with self._lock: self._queue.clear()
        self._results.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._log("결과 지움")

    # ── Frida 메시지 ────────────────────────────────────────────────

    def _on_msg(self, message: dict, _data: object) -> None:
        if message.get("type") == "error":
            desc = message.get("description", "")
            self._log(f"스크립트 오류: {desc[:100]}")
            return
        payload = message.get("payload", {})
        mtype   = payload.get("type", "")

        if mtype == "alive":
            self._log("스크립트 시작 — 메모리 스캔 중...")

        elif mtype == "scan_result":
            data   = payload.get("data", {})
            found  = data.get("found", [])
            self._log(f"스캔 완료 — {len(found)}개 위치 발견")
            with self._lock:
                self._queue.extend(found)

        elif mtype == "error":
            self._log(f"오류: {payload.get('msg','')}")

    # ── 폴링 ────────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for item in batch:
            idx    = len(self._results) + 1
            target = item.get("target", "?")
            enc    = item.get("encoding", "?")
            addr   = item.get("addr", "?")
            self._results.append(item)
            self._tree.insert("", "end", iid=str(idx),
                              values=(idx, target, enc, addr))
            self._tree.see(str(idx))
        if batch:
            self._lbl.config(text=f"발견: {len(self._results)}개", fg="#2d7d2d")
        self.after(300, self._poll)

    # ── 선택 상세 ────────────────────────────────────────────────────

    def _on_select(self, _: object) -> None:
        sel = self._tree.selection()
        if not sel: return
        idx  = int(sel[0]) - 1
        if not (0 <= idx < len(self._results)): return
        item = self._results[idx]
        ctx  = item.get("ctx", [])
        enc  = item.get("encoding", "")

        # hex dump
        self._set_text(self._ctx_txt,
            f"주소: {item['addr']}\n대상: {item['target']} ({enc})\n\n"
            + bytes_to_text(ctx))

        # UTF-16LE 디코딩 (한글)
        utf16 = try_decode_utf16(ctx)
        utf8  = bytes(ctx).decode("utf-8", errors="replace")
        self._set_text(self._utf_txt,
            f"=== UTF-16LE ===\n{utf16}\n\n=== UTF-8 ===\n{utf8}")

    # ── 유틸 ────────────────────────────────────────────────────────

    def _set_text(self, w: tk.Text, text: str) -> None:
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("1.0", text)
        w.config(state="disabled")

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
        self._detach()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
