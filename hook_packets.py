"""Frida 기반 평문 패킷 후킹 GUI.

게임 프로세스의 Winsock send/recv를 후킹해서
암호화 전 / 복호화 후 데이터를 캡쳐합니다.

설치: pip install frida
실행: 관리자 권한으로 python hook_packets.py
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

import psutil

try:
    import frida  # type: ignore
except ImportError:
    pass  # handled below


class _StatusLog:
    """self._status.config(text=...) 호출을 로그 위젯으로 라우팅하는 래퍼."""
    def __init__(self) -> None:
        self._widget: Optional["tk.Text"] = None  # type: ignore[name-defined]

    def attach(self, widget: "tk.Text") -> None:  # type: ignore[name-defined]
        self._widget = widget

    def config(self, text: str = "", **_kwargs: object) -> None:
        if not text or self._widget is None:
            return
        from datetime import datetime
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}\n"
        self._widget.config(state="normal")
        self._widget.insert("end", line)
        self._widget.see("end")
        self._widget.config(state="disabled")


try:
    import frida  # type: ignore  # noqa: F811
except ImportError:
    _r = tk.Tk(); _r.withdraw()
    messagebox.showerror("오류", "frida가 설치되지 않았습니다.\npip install frida")
    sys.exit(1)


# ── Frida 인젝션 스크립트 ─────────────────────────────────────────

_SCRIPT = r"""
'use strict';

send({ type: 'alive' });   // 스크립트 시작 확인용

const ptrSize    = Process.pointerSize;
const wsabufSize = ptrSize === 8 ? 16 : 8;
const wsBufOff   = ptrSize === 8 ? 8  : 4;

// OVERLAPPED_ENTRY layout (GetQueuedCompletionStatusEx)
const ovEntrySize     = ptrSize === 8 ? 32 : 16;
const ovEntryOvOff    = ptrSize === 8 ? 8  : 4;
const ovEntryBytesOff = ptrSize === 8 ? 24 : 12;

const _hooked      = new Set();
const _pendingRecv = new Map();   // overlapped addr string → {lpBufs, nBufs, fn}

function emit(dir, fn, buf) {
    send({ dir, fn, data: Array.from(new Uint8Array(buf)) });
}

function readBufs(lpBufs, nBufs, total, fn) {
    let off = 0;
    for (let i = 0; i < nBufs && off < total; i++) {
        try {
            const e    = lpBufs.add(i * wsabufSize);
            const blen = Memory.readU32(e);
            const bptr = Memory.readPointer(e.add(wsBufOff));
            const read = Math.min(blen, total - off);
            if (read > 0) emit('RECV', fn, Memory.readByteArray(bptr, read));
            off += read;
        } catch(e) {}
    }
}

// ── ws2_32 ────────────────────────────────────────────────────────

function hookRecv(mod, fn) {
    const key = mod.name + '!' + fn;
    if (_hooked.has(key)) return;
    const ptr = mod.findExportByName(fn);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter(a) { this.buf = a[1]; },
        onLeave(rv) {
            const n = rv.toInt32();
            if (n > 0 && n < 131072)
                try { emit('RECV', fn, Memory.readByteArray(this.buf, n)); } catch(e) {}
        }
    });
    _hooked.add(key); send({ type:'hooked', fn:key });
}

function hookSend(mod, fn) {
    const key = mod.name + '!' + fn;
    if (_hooked.has(key)) return;
    const ptr = mod.findExportByName(fn);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter(a) {
            const n = a[2].toInt32();
            if (n > 0 && n < 131072)
                try { emit('SEND', fn, Memory.readByteArray(a[1], n)); } catch(e) {}
        }
    });
    _hooked.add(key); send({ type:'hooked', fn:key });
}

function hookWSARecv(mod, fn) {
    // WSARecv(sock, lpBufs, nBufs, lpBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine)
    const key = mod.name + '!' + fn;
    if (_hooked.has(key)) return;
    const ptr = mod.findExportByName(fn);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter(a) {
            this.lpBufs = a[1]; this.nBufs = a[2].toInt32();
            this.lpBytesRecvd = a[3]; this.lpOverlapped = a[5]; this.fn = fn;
        },
        onLeave(rv) {
            if (rv.toInt32() === 0) {
                // 동기 완료
                try {
                    if (this.lpBytesRecvd && !this.lpBytesRecvd.isNull()) {
                        const total = Memory.readU32(this.lpBytesRecvd);
                        if (total > 0 && total < 131072)
                            readBufs(this.lpBufs, this.nBufs, total, this.fn);
                    }
                } catch(e) {}
            } else {
                // 비동기(IOCP) → OVERLAPPED 주소로 완료 추적
                try {
                    if (this.lpOverlapped && !this.lpOverlapped.isNull())
                        _pendingRecv.set(this.lpOverlapped.toString(),
                            { lpBufs: this.lpBufs, nBufs: this.nBufs, fn: this.fn });
                } catch(e) {}
            }
        }
    });
    _hooked.add(key); send({ type:'hooked', fn:key });
}

function hookWSASend(mod, fn) {
    const key = mod.name + '!' + fn;
    if (_hooked.has(key)) return;
    const ptr = mod.findExportByName(fn);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter(a) {
            const n = a[2].toInt32();
            try {
                for (let i = 0; i < n; i++) {
                    const e    = a[1].add(i * wsabufSize);
                    const blen = Memory.readU32(e);
                    const bptr = Memory.readPointer(e.add(wsBufOff));
                    if (blen > 0 && blen < 131072) emit('SEND', fn, Memory.readByteArray(bptr, blen));
                }
            } catch(e) {}
        }
    });
    _hooked.add(key); send({ type:'hooked', fn:key });
}

// ── IOCP 완료 후킹 ───────────────────────────────────────────────

function hookGQCS(mod) {
    // GetQueuedCompletionStatus(port, lpBytes, lpKey, lpOverlapped*, ms)
    const fn = 'GetQueuedCompletionStatus';
    const key = mod.name + '!' + fn;
    if (_hooked.has(key)) return;
    const ptr = mod.findExportByName(fn);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter(a) { this.lpBytes = a[1]; this.lpOvPtr = a[3]; },
        onLeave(rv) {
            if (rv.toInt32() === 0) return;
            try {
                const ov      = Memory.readPointer(this.lpOvPtr);
                const ovKey   = ov.toString();
                const pending = _pendingRecv.get(ovKey);
                if (!pending) return;
                _pendingRecv.delete(ovKey);
                const bytes = Memory.readU32(this.lpBytes);
                if (bytes > 0 && bytes < 131072)
                    readBufs(pending.lpBufs, pending.nBufs, bytes, pending.fn);
            } catch(e) {}
        }
    });
    _hooked.add(key); send({ type:'hooked', fn:key });
}

function hookGQCSEx(mod) {
    // GetQueuedCompletionStatusEx(port, entries, count, removed*, ms, alertable)
    const fn = 'GetQueuedCompletionStatusEx';
    const key = mod.name + '!' + fn;
    if (_hooked.has(key)) return;
    const ptr = mod.findExportByName(fn);
    if (!ptr) return;
    Interceptor.attach(ptr, {
        onEnter(a) { this.lpEntries = a[1]; this.lpRemoved = a[3]; },
        onLeave(rv) {
            if (rv.toInt32() === 0) return;
            try {
                const count = Memory.readU32(this.lpRemoved);
                for (let i = 0; i < count; i++) {
                    const e       = this.lpEntries.add(i * ovEntrySize);
                    const ov      = Memory.readPointer(e.add(ovEntryOvOff));
                    const ovKey   = ov.toString();
                    const pending = _pendingRecv.get(ovKey);
                    if (!pending) continue;
                    _pendingRecv.delete(ovKey);
                    const bytes = Memory.readU32(e.add(ovEntryBytesOff));
                    if (bytes > 0 && bytes < 131072)
                        readBufs(pending.lpBufs, pending.nBufs, bytes, pending.fn);
                }
            } catch(e) {}
        }
    });
    _hooked.add(key); send({ type:'hooked', fn:key });
}

// ── WinHTTP ───────────────────────────────────────────────────────

function hookWinHTTP(mod) {
    // WinHttpReadData(hReq, lpBuf, dwToRead, lpdwRead) → BOOL
    const rfn = 'WinHttpReadData', rkey = mod.name + '!' + rfn;
    if (!_hooked.has(rkey)) {
        const ptr = mod.findExportByName(rfn);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(a) { this.buf = a[1]; this.lpRead = a[3]; },
                onLeave(rv) {
                    if (rv.toInt32() === 0) return;
                    try {
                        const n = Memory.readU32(this.lpRead);
                        if (n > 0 && n < 131072) emit('RECV', rfn, Memory.readByteArray(this.buf, n));
                    } catch(e) {}
                }
            });
            _hooked.add(rkey); send({ type:'hooked', fn:rkey });
        }
    }
    // WinHttpWriteData(hReq, lpBuf, dwToWrite, lpdwWritten) → BOOL
    const wfn = 'WinHttpWriteData', wkey = mod.name + '!' + wfn;
    if (!_hooked.has(wkey)) {
        const ptr = mod.findExportByName(wfn);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(a) {
                    const n = a[2].toInt32();
                    if (n > 0 && n < 131072)
                        try { emit('SEND', wfn, Memory.readByteArray(a[1], n)); } catch(e) {}
                }
            });
            _hooked.add(wkey); send({ type:'hooked', fn:wkey });
        }
    }
}

// ── 모듈 디스패치 ─────────────────────────────────────────────────

function applyHooks(mod) {
    const name = mod.name.toLowerCase();
    if (name === 'ws2_32.dll') {
        hookRecv(mod, 'recv');   hookSend(mod, 'send');
        hookWSARecv(mod, 'WSARecv'); hookWSASend(mod, 'WSASend');
    } else if (name === 'kernel32.dll' || name === 'kernelbase.dll') {
        hookGQCS(mod); hookGQCSEx(mod);
    } else if (name === 'winhttp.dll') {
        hookWinHTTP(mod);
    }
}

try { Process.enumerateModules().forEach(applyHooks); }
catch(e) { send({ type:'script_error', where:'enumerateModules', msg: e.message }); }

['LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW'].forEach(fn => {
    try {
        const ptr = Module.findExportByName('kernelbase.dll', fn)
                 || Module.findExportByName('kernel32.dll',   fn);
        if (!ptr) return;
        const wide = fn.endsWith('W');
        Interceptor.attach(ptr, {
            onEnter(a) {
                try { this.n = wide ? a[0].readUtf16String() : a[0].readUtf8String(); }
                catch(e) { this.n = null; }
            },
            onLeave(rv) {
                if (rv.isNull() || !this.n) return;
                try { const m = Process.findModuleByAddress(rv); if (m) applyHooks(m); }
                catch(e) {}
            }
        });
    } catch(e) {}
});

try {
    send({ type:'ready', modules: Process.enumerateModules().map(m => m.name) });
} catch(e) {
    send({ type:'script_error', where:'ready', msg: e.message });
}
"""


# ── 유틸 ──────────────────────────────────────────────────────────

def detect(data: bytes) -> str:
    if not data:
        return "EMPTY"
    _TLS = {0x14:"CCS",0x15:"Alert",0x16:"Handshake",0x17:"AppData",0x18:"HB"}
    _VER = {(3,1):"1.0",(3,2):"1.1",(3,3):"1.2",(3,4):"1.3"}
    if len(data) >= 5 and data[0] in _TLS and data[1] == 0x03:
        return f"TLS{_VER.get((data[1],data[2]),'?')} {_TLS[data[0]]}"
    for p in (b"GET ",b"POST ",b"PUT ",b"DELETE ",b"HTTP/"):
        if data.startswith(p):
            return "HTTP  " + data.split(b"\r\n")[0].decode("utf-8","replace")[:80]
    ratio = sum(1 for b in data[:64] if 32<=b<127 or b in(9,10,13)) / min(len(data),64)
    if ratio >= 0.70:
        return "TEXT  " + data[:100].decode("utf-8","replace").replace("\n"," ")
    return f"BINARY  (가독 {ratio:.0%})"


def hex_dump(data: bytes, limit: int = 512) -> str:
    shown = data[:limit]
    lines: list[str] = []
    for off in range(0, len(shown), 16):
        chunk = shown[off:off+16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32<=b<=126 else "." for b in chunk)
        lines.append(f"{off:04X}  {h:<47}  {a}")
    if len(data) > limit:
        lines.append(f"... (전체 {len(data)}B, {len(data)-limit}B 생략)")
    return "\n".join(lines)


def text_view(data: bytes) -> str:
    parts: list[str] = []
    for enc in ("utf-8", "euc-kr", "cp949"):
        try:
            t = data.decode(enc, errors="strict")
            parts.append(f"[{enc}]\n{t}")
        except (UnicodeDecodeError, LookupError):
            t = data.decode(enc, errors="replace")
            parts.append(f"[{enc} - 손실]\n{t}")
    return "\n\n".join(parts)


# ── GUI ───────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Frida 패킷 후킹")
        self.geometry("980x700")

        self._session: Optional[object] = None
        self._script:  Optional[object] = None
        self._device:  Optional[object] = None
        self._child_sessions: list[object] = []
        self._lock = threading.Lock()
        self._queue: list[dict] = []
        self._packets: list[dict] = []
        self._proc_map: dict[str, int] = {}
        self._loaded_modules: list[str] = []
        self._status = _StatusLog()

        self._build_ui()
        self._refresh_procs()
        self._poll()

    _DEFAULT_EXE = r"C:\Users\utor9\AppData\Local\Nexon\MapleStory Worlds\msw.exe"

    # ── UI 구성 ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        ctrl = tk.Frame(self, padx=8, pady=4)
        ctrl.pack(fill="x")

        # ── 1행: Spawn (게임 직접 실행) ──
        row1 = tk.Frame(ctrl)
        row1.pack(fill="x", pady=(0, 2))

        tk.Label(row1, text="게임 경로").pack(side="left")
        self._exe_var = tk.StringVar(value=self._DEFAULT_EXE)
        tk.Entry(row1, textvariable=self._exe_var, width=52).pack(side="left", padx=(4, 4))
        self._btn_spawn = tk.Button(row1, text="▶ 게임 실행 & 후킹",
                                     bg="#2d5c9e", fg="white", command=self._spawn)
        self._btn_spawn.pack(side="left", padx=2)
        tk.Button(row1, text="모듈 목록", command=self._show_modules).pack(side="left", padx=(8, 0))

        # ── 2행: Attach (이미 실행 중인 프로세스) ──
        row2 = tk.Frame(ctrl)
        row2.pack(fill="x")

        tk.Label(row2, text="실행 중인 프로세스").pack(side="left")
        self._proc_var = tk.StringVar()
        self._proc_cb = ttk.Combobox(row2, textvariable=self._proc_var,
                                      width=30, state="readonly")
        self._proc_cb.pack(side="left", padx=(4, 2))
        tk.Button(row2, text="↺", command=self._refresh_procs,
                  width=2).pack(side="left", padx=(0, 8))
        self._btn_attach = tk.Button(row2, text="▶ 연결", width=7,
                                      bg="#2d7d2d", fg="white", command=self._attach)
        self._btn_attach.pack(side="left", padx=2)
        self._btn_detach = tk.Button(row2, text="■ 해제", width=7,
                                      state="disabled", command=self._detach)
        self._btn_detach.pack(side="left", padx=2)
        tk.Button(row2, text="목록 지우기",
                  command=self._clear).pack(side="left", padx=(12, 2))

        # ── 로그 영역 ──
        log_frame = tk.Frame(ctrl)
        log_frame.pack(fill="x", pady=(4, 0))

        tk.Label(log_frame, text="로그").pack(side="left", padx=(0, 4))
        tk.Button(log_frame, text="로그 복사",
                  command=self._copy_log).pack(side="right", padx=2)
        tk.Button(log_frame, text="로그 지우기",
                  command=self._clear_log).pack(side="right", padx=2)

        self._log = tk.Text(ctrl, height=4, font=("Consolas", 9),
                            state="disabled", wrap="word")
        self._log.pack(fill="x", pady=(2, 4))
        self._status.attach(self._log)

        # 패킷 목록
        cols = ("#", "방향", "함수", "크기", "미리보기")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=15)
        self._tree.heading("#",        text="#",        anchor="e")
        self._tree.heading("방향",     text="방향")
        self._tree.heading("함수",     text="함수")
        self._tree.heading("크기",     text="크기",     anchor="e")
        self._tree.heading("미리보기", text="미리보기")
        self._tree.column("#",        width=48,  anchor="e", stretch=False)
        self._tree.column("방향",     width=55,  stretch=False)
        self._tree.column("함수",     width=130, stretch=False)
        self._tree.column("크기",     width=68,  anchor="e", stretch=False)
        self._tree.column("미리보기", width=500)
        self._tree.tag_configure("RECV", foreground="#1a6fba")
        self._tree.tag_configure("SEND", foreground="#9b2d2d")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 하단 상세 패널
        bottom = tk.Frame(self)
        bottom.pack(fill="both", expand=False, padx=8, pady=(0, 6))

        btn_row = tk.Frame(bottom)
        btn_row.pack(fill="x")
        self._view = tk.StringVar(value="hex")
        tk.Radiobutton(btn_row, text="Hex dump", variable=self._view,
                       value="hex",  command=self._refresh_detail).pack(side="left")
        tk.Radiobutton(btn_row, text="텍스트",   variable=self._view,
                       value="text", command=self._refresh_detail).pack(side="left", padx=(6, 0))
        self._btn_copy = tk.Button(btn_row, text="클립보드에 복사",
                                    state="disabled", command=self._copy)
        self._btn_copy.pack(side="right")

        self._detail = tk.Text(bottom, height=11, font=("Consolas", 9),
                               state="disabled", wrap="none")
        sb_v = ttk.Scrollbar(bottom, orient="vertical",   command=self._detail.yview)
        sb_h = ttk.Scrollbar(bottom, orient="horizontal", command=self._detail.xview)
        self._detail.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        sb_v.pack(side="right", fill="y")
        self._detail.pack(fill="both", expand=True)
        sb_h.pack(fill="x")

    # ── Spawn ────────────────────────────────────────────────────

    def _spawn(self) -> None:
        exe = self._exe_var.get().strip()
        if not exe:
            messagebox.showwarning("경로 필요", "게임 실행 파일 경로를 입력하세요.")
            return
        self._btn_spawn.config(state="disabled")
        self._status.config(text="게임 시작 중...", fg="gray")

        def _try_attach(device: object, pid: int) -> bool:
            """pid에 Frida를 붙인다. 성공 여부 반환."""
            try:
                sess   = device.attach(pid)     # type: ignore[attr-defined]
                script = sess.create_script(_SCRIPT)
                script.on("message", self._on_msg)
                script.load()
                with self._lock:
                    self._child_sessions.append(sess)
                return True
            except Exception:
                return False

        # 후킹 불필요한 프로세스 (Frida 내부 / Windows 시스템)
        _SKIP = {
            "frida-helper-x86.exe", "frida-helper-x86_64.exe",
            "conhost.exe", "svchost.exe", "runtimebroker.exe",
            "gamebarftserver.exe", "gamebar.exe", "gamebarinputredirector.exe",
            "backgroundtaskhost.exe", "dllhost.exe", "sihost.exe",
            "taskhostw.exe", "searchapp.exe", "searchhost.exe",
        }

        def _do() -> None:
            try:
                before = {p.pid for p in psutil.process_iter()}
                subprocess.Popen([exe])          # 게임 런처 실행 (일반 방식)
            except Exception as e:
                err = str(e)
                self.after(0, lambda: (
                    messagebox.showerror("실행 실패", err),
                    self._btn_spawn.config(state="normal"),
                    self._status.config(text="대기 중", fg="gray"),
                ))
                return

            self.after(0, lambda: self._status.config(
                text="런처 실행됨 — 새 프로세스 감지 중... (최대 180초)", fg="#2d5c9e"))
            self.after(0, lambda: self._btn_detach.config(state="normal"))

            try:
                device   = frida.get_local_device()
                self._device = device
            except Exception as e:
                self.after(0, lambda: self._status.config(text=f"Frida 오류: {e}", fg="red"))
                return

            seen     = set(before)
            hooked   = 0
            deadline = time.time() + 180

            while time.time() < deadline:
                time.sleep(0.5)
                try:
                    current = {p.pid for p in psutil.process_iter()}
                except Exception:
                    continue

                new_pids = current - seen
                seen |= new_pids

                for pid in new_pids:
                    try:
                        name = psutil.Process(pid).name()
                    except Exception:
                        name = str(pid)
                    if name.lower() in _SKIP:
                        continue
                    if _try_attach(device, pid):
                        hooked += 1
                        self.after(0, lambda n=name, p=pid: self._status.config(
                            text=f"후킹됨 — {n} (PID {p})  총 {hooked}개 프로세스",
                            fg="#2d7d2d"))

            if hooked == 0:
                self.after(0, lambda: self._status.config(
                    text="새 프로세스를 찾았지만 후킹 실패 (권한 문제?)", fg="#b85000"))
            else:
                self.after(0, lambda: self._status.config(
                    text=f"감시 종료 — 총 {hooked}개 프로세스 후킹됨", fg="gray"))

        threading.Thread(target=_do, daemon=True).start()

    # ── 프로세스 목록 ─────────────────────────────────────────────

    def _refresh_procs(self) -> None:
        try:
            device = frida.get_local_device()
            procs  = sorted(device.enumerate_processes(), key=lambda p: p.name.lower())
            items  = [f"[{p.pid:6}]  {p.name}" for p in procs]
            self._proc_cb["values"] = items
            self._proc_map = {f"[{p.pid:6}]  {p.name}": p.pid for p in procs}
        except Exception as e:
            messagebox.showerror("오류", f"프로세스 목록 조회 실패:\n{e}")

    # ── Attach ───────────────────────────────────────────────────

    def _attach(self) -> None:
        sel = self._proc_var.get().strip()
        if not sel:
            messagebox.showwarning("선택 필요", "프로세스를 선택하세요.")
            return
        pid = self._proc_map.get(self._proc_var.get())
        if pid is None:
            return
        device = frida.get_local_device()
        sess = script = None
        try:
            sess   = device.attach(pid)
            script = sess.create_script(_SCRIPT)
            script.on("message", self._on_msg)
            script.load()
        except frida.ProcessNotFoundError:
            messagebox.showerror("오류", "프로세스를 찾을 수 없습니다.")
            return
        except frida.PermissionDeniedError:
            messagebox.showerror("권한 오류", "관리자 권한으로 실행하세요.")
            return
        except Exception as first_err:
            err_str = str(first_err)
            if "0x00000005" in err_str or "WriteProcessMemory" in err_str:
                try:
                    if sess:
                        try: sess.detach()
                        except Exception: pass
                    sess   = device.attach(pid, realm="emulated")
                    script = sess.create_script(_SCRIPT)
                    script.on("message", self._on_msg)
                    script.load()
                except Exception:
                    messagebox.showerror("접근 거부",
                        "메모리 접근이 거부됐습니다.\n관리자 권한으로 실행하거나 Spawn 방식을 사용하세요.")
                    return
            else:
                messagebox.showerror("연결 실패", err_str)
                return
        self._session = sess
        self._script  = script
        self._btn_attach.config(state="disabled")
        self._btn_detach.config(state="normal")
        self._status.config(text=f"후킹 중: {sel}", fg="#2d7d2d")

    def _detach(self) -> None:
        self._cleanup()
        self._btn_spawn.config(state="normal")
        self._btn_attach.config(state="normal")
        self._btn_detach.config(state="disabled")
        self._status.config(text=f"해제됨 — 총 {len(self._packets)}개", fg="gray")

    def _cleanup(self) -> None:
        for obj, method in ((self._script, "unload"), (self._session, "detach")):
            if obj:
                try: getattr(obj, method)()
                except Exception: pass
        self._script = self._session = None
        for sess in self._child_sessions:
            try: sess.detach()   # type: ignore[attr-defined]
            except Exception: pass
        self._child_sessions.clear()
        self._device = None

    # ── Frida 메시지 ─────────────────────────────────────────────

    def _on_msg(self, message: dict, _data: object) -> None:
        # 스크립트 내부 예외
        if message.get("type") == "error":
            desc = message.get("description", "")
            stack = message.get("stack", "")
            self.after(0, lambda: self._status.config(
                text=f"스크립트 오류: {desc[:80]}", fg="red"))
            self.after(0, lambda: messagebox.showerror(
                "Frida 스크립트 오류", f"{desc}\n\n{stack[:500]}"))
            return

        if message.get("type") != "send":
            return
        payload  = message.get("payload", {})
        msg_type = payload.get("type")

        if msg_type == "alive":
            self.after(0, lambda: self._status.config(
                text="스크립트 실행 중 (모듈 로드 대기)...", fg="#2d5c9e"))
            return

        if msg_type == "script_error":
            where = payload.get("where", "?")
            msg   = payload.get("msg", "")
            self.after(0, lambda: self._status.config(
                text=f"스크립트 오류 [{where}]: {msg[:70]}", fg="red"))
            return

        if msg_type == "ready":
            mods    = payload.get("modules", [])
            self._loaded_modules = mods
            has_ws2 = any("ws2_32" in m.lower() for m in mods)
            note    = "ws2_32 ✓" if has_ws2 else "⚠ ws2_32 없음"
            self.after(0, lambda: self._status.config(
                text=f"스크립트 로드 완료 | {note}",
                fg="#2d7d2d" if has_ws2 else "#b85000"))
            return

        if msg_type == "hooked":
            fn = payload.get("fn", "")
            self.after(0, lambda: self._status.config(
                text=f"후킹됨: {fn}", fg="#2d7d2d"))
            return

        raw = bytes(payload.get("data", []))
        if not raw:
            return
        with self._lock:
            self._queue.append({
                "dir":   payload.get("dir", "?"),
                "fn":    payload.get("fn",  "?"),
                "size":  len(raw),
                "data":  raw,
                "proto": detect(raw),
            })

    # ── 폴링 ─────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for row in batch:
            idx = len(self._packets) + 1
            self._packets.append(row)
            self._tree.insert("", "end", iid=str(idx), tags=(row["dir"],),
                              values=(idx, row["dir"], row["fn"],
                                      f"{row['size']}B", row["proto"][:80]))
            self._tree.see(str(idx))
        if batch:
            self._status.config(text=f"후킹 중 — {len(self._packets)}개", fg="#2d7d2d")
        self.after(150, self._poll)

    # ── 선택 / 복사 ───────────────────────────────────────────────

    def _on_select(self, _: object) -> None:
        self._refresh_detail()
        self._btn_copy.config(state="normal")

    def _refresh_detail(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        row  = self._packets[int(sel[0]) - 1]
        body = hex_dump(row["data"]) if self._view.get() == "hex" else text_view(row["data"])
        self._set_detail(
            f"패킷 #{sel[0]}  [{row['dir']}]  {row['fn']}  {row['size']}B\n"
            f"  프로토콜: {row['proto']}\n\n" + body)

    def _set_detail(self, text: str) -> None:
        self._detail.config(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("1.0", text)
        self._detail.config(state="disabled")

    def _copy(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        row  = self._packets[int(sel[0]) - 1]
        text = (f"패킷 #{sel[0]}  [{row['dir']}]  {row['fn']}  {row['size']}B\n"
                f"  프로토콜: {row['proto']}\n\n"
                f"=== Hex dump (첫 512B) ===\n"
                + hex_dump(row["data"])
                + "\n\n=== 텍스트 (UTF-8) ===\n"
                + row["data"].decode("utf-8", errors="replace"))
        self.clipboard_clear()
        self.clipboard_append(text)
        running = self._session is not None
        self._status.config(text="클립보드에 복사됨!", fg="#1a6fba")
        self.after(2000, lambda: self._status.config(
            text=f"{'후킹 중' if running else '해제됨'} — {len(self._packets)}개",
            fg="#2d7d2d" if running else "gray"))

    # ── 모듈 목록 ─────────────────────────────────────────────────

    def _copy_log(self) -> None:
        text = self._log.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def _clear_log(self) -> None:
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    def _show_modules(self) -> None:
        mods = self._loaded_modules
        if not mods:
            messagebox.showinfo("모듈 목록", "아직 모듈 정보가 없습니다.\n게임을 먼저 실행 & 후킹하세요.")
            return
        NET_KW = ("ws2","winsock","winhttp","wininet","mswsock",
                  "ssl","tls","curl","http","socket","net","unity","mono","il2cpp","steam")
        net_mods = [m for m in mods if any(k in m.lower() for k in NET_KW)]

        win = tk.Toplevel(self)
        win.title(f"로드된 모듈 — 총 {len(mods)}개")
        win.geometry("560x540")

        tk.Label(win, text="★ 네트워크 관련 DLL",
                 fg="#b85000", font=("", 9, "bold")).pack(anchor="w", padx=8, pady=(8,2))
        net_box = tk.Text(win, height=8, font=("Consolas", 9), wrap="none")
        net_box.insert("1.0", "\n".join(net_mods) or "(없음)")
        net_box.config(state="disabled")
        net_box.pack(fill="x", padx=8)

        tk.Label(win, text="전체 모듈",
                 font=("", 9, "bold")).pack(anchor="w", padx=8, pady=(10,2))
        frm = tk.Frame(win)
        frm.pack(fill="both", expand=True, padx=8, pady=(0,4))
        all_box = tk.Text(frm, font=("Consolas", 9), wrap="none")
        sb = ttk.Scrollbar(frm, orient="vertical", command=all_box.yview)
        all_box.configure(yscrollcommand=sb.set)
        all_box.insert("1.0", "\n".join(sorted(mods, key=str.lower)))
        all_box.config(state="disabled")
        sb.pack(side="right", fill="y")
        all_box.pack(fill="both", expand=True)

        def copy_net() -> None:
            win.clipboard_clear()
            win.clipboard_append("\n".join(net_mods))
        tk.Button(win, text="네트워크 DLL 복사", command=copy_net).pack(pady=(0,8))

    def _clear(self) -> None:
        self._packets.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._set_detail("")
        self._btn_copy.config(state="disabled")

    def on_close(self) -> None:
        self._cleanup()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
