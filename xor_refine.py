"""XOR 키 검증 + 브루트포스 개별 바이트 정제.

현재 48B 키가 부분적으로만 맞을 수 있음.
각 키 바이트 위치별로 0x00~0xFF 시도해서
복호화 결과에 알려진 평문이 나타나는 횟수 최대화.
"""

from __future__ import annotations

import struct
import sys
import threading
import tkinter as tk
from collections import Counter
from tkinter import ttk
from typing import Optional

try:
    from scapy.all import AsyncSniffer, Raw, TCP  # type: ignore
except ImportError:
    import tkinter.messagebox as mb
    root = tk.Tk(); root.withdraw()
    mb.showerror("오류", "pip install scapy"); sys.exit(1)

TARGET_PORT = 32800
HEADER_LEN  = 25
KEY_PERIOD  = 48

# 검증용 알려진 평문
KNOWN_PLAIN: list[bytes] = [
    b"Map", b"Name", b"Profile", b"Job", b"Exp", b"Level",
    b"Attacks", b"Created", b"Buffs", b"Captcha",
    b"MapOnline", b"CharOnline", b"ChannelOnline",
    b"PetComponent", b"StateComponent", b"WsUserController",
]


def extract_payload(raw: bytes) -> bytes:
    if len(raw) < HEADER_LEN:
        return raw
    if raw[8:12] == b"\xff\xff\xff\xff":
        plen = struct.unpack_from("<I", raw, 4)[0]
        return raw[HEADER_LEN: HEADER_LEN + plen]
    return raw[HEADER_LEN:]


def xor_apply(data: bytes, key: bytes) -> bytes:
    if not key: return data
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def count_known(data: bytes) -> int:
    """복호화된 데이터에 알려진 평문이 몇 번 나타나는지."""
    total = 0
    for plain in KNOWN_PLAIN:
        idx = 0
        while True:
            idx = data.find(plain, idx)
            if idx == -1: break
            total += 1; idx += 1
    return total


def hex_dump(data: bytes, limit: int = 512) -> str:
    lines: list[str] = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{off:04X}  {h:<47}  {a}")
    if len(data) > limit:
        lines.append(f"... 전체 {len(data)}B")
    return "\n".join(lines)


def freq_recover(payloads: list[bytes]) -> bytearray:
    buckets: list[Counter] = [Counter() for _ in range(KEY_PERIOD)]
    for p in payloads:
        for i, b in enumerate(p):
            buckets[i % KEY_PERIOD][b] += 1
    return bytearray(b.most_common(1)[0][0] if b else 0 for b in buckets)


def kpa_recover(payloads: list[bytes]) -> bytearray:
    votes: list[Counter] = [Counter() for _ in range(KEY_PERIOD)]
    for payload in payloads:
        for plain in KNOWN_PLAIN:
            plen = len(plain)
            for offset in range(len(payload) - plen + 1):
                if payload[offset:offset + plen] != bytes(
                        payload[offset + j] for j in range(plen)):
                    pass
                # XOR 후보
                test_key = bytearray(KEY_PERIOD)
                ok = True
                for j, pb in enumerate(plain):
                    pos  = offset + j
                    kpos = pos % KEY_PERIOD
                    test_key[kpos] = payload[pos] ^ pb

                # 검증: plain 앞뒤 문맥도 확인
                start = max(0, offset - 3)
                end   = min(len(payload), offset + plen + 3)
                snippet = xor_apply(payload[start:end], bytes(test_key))
                readable = sum(1 for b in snippet if 32 <= b <= 126 or b == 0)
                if readable / max(len(snippet), 1) >= 0.4:
                    for j, pb in enumerate(plain):
                        pos  = offset + j
                        kpos = pos % KEY_PERIOD
                        votes[kpos][payload[pos] ^ pb] += 1

    key = bytearray(KEY_PERIOD)
    for kpos, v in enumerate(votes):
        if v:
            key[kpos] = v.most_common(1)[0][0]
    return key


def refine_key_byte(payloads: list[bytes], key: bytearray, kpos: int) -> tuple[int, int]:
    """kpos번 키 바이트를 0~255 시도해서 알려진 평문 매칭 최대화."""
    best_val, best_score = key[kpos], 0
    for candidate in range(256):
        key[kpos] = candidate
        total = 0
        for p in payloads[:100]:
            dec   = xor_apply(p, bytes(key))
            total += count_known(dec)
        if total > best_score:
            best_score = total
            best_val   = candidate
    key[kpos] = best_val
    return best_val, best_score


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"키 검증 & 브루트포스 정제 | 포트 {TARGET_PORT}")
        self.geometry("1000x750")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock    = threading.Lock()
        self._queue:    list[bytes] = []
        self._raws:     list[bytes] = []
        self._payloads: list[bytes] = []
        self._key:      bytearray   = bytearray(KEY_PERIOD)

        self._build_ui()
        self._poll()

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=4)
        top.pack(fill="x")

        self._btn_start = tk.Button(top, text="▶ 캡쳐", bg="#2d7d2d", fg="white",
                                     command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop  = tk.Button(top, text="■ 중지", state="disabled",
                                     command=self._stop)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="초기화", command=self._clear).pack(side="left", padx=(8,2))

        self._lbl = tk.Label(top, text=f"대기 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 키 입력/출력
        kf = tk.LabelFrame(self, text="키 복구 & 검증", padx=8, pady=4)
        kf.pack(fill="x", padx=8, pady=(0,4))

        r1 = tk.Frame(kf); r1.pack(fill="x")
        tk.Button(r1, text="① 빈도+KPA 초기 키 복구",
                  bg="#1a5c9e", fg="white",
                  command=self._initial_recover).pack(side="left", padx=2)
        tk.Button(r1, text="② 바이트별 브루트포스 정제 (느림, ~2분)",
                  bg="#7d2d00", fg="white",
                  command=self._refine).pack(side="left", padx=(12,2))
        tk.Button(r1, text="③ 키 검증 (알려진 평문 카운트)",
                  command=self._validate).pack(side="left", padx=(12,2))
        tk.Button(r1, text="전체 스캔",
                  command=self._scan_all).pack(side="left", padx=(12,2))

        r2 = tk.Frame(kf); r2.pack(fill="x", pady=(4,0))
        tk.Label(r2, text="키 hex:").pack(side="left")
        self._key_var = tk.StringVar()
        self._key_ent = tk.Entry(r2, textvariable=self._key_var, width=82,
                                  font=("Consolas", 9))
        self._key_ent.pack(side="left", padx=(4,6))
        tk.Button(r2, text="적용", command=self._apply_key).pack(side="left")
        tk.Button(r2, text="복사", command=self._copy_key).pack(side="left", padx=4)
        self._lbl_key = tk.Label(r2, text="", fg="#1a6fba")
        self._lbl_key.pack(side="left")

        # 패킷 목록 + 상세
        pw = tk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8, pady=(0,6))

        left = tk.Frame(pw); pw.add(left, minsize=180)
        cols = ("#", "크기", "페이로드", "매칭")
        self._tree = ttk.Treeview(left, columns=cols, show="headings", height=30)
        for c, w, anc in [("#",40,"e"),("크기",64,"e"),("페이로드",64,"e"),("매칭",50,"e")]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor=anc, stretch=False)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        right = tk.Frame(pw); pw.add(right, minsize=600)
        self._nb  = ttk.Notebook(right)
        self._nb.pack(fill="both", expand=True)
        self._raw_txt = self._make_tab("원본 hex")
        self._dec_txt = self._make_tab("복호화 hex+텍스트")
        self._fld_txt = self._make_tab("발견된 필드 / 전체스캔")
        self._log_txt = self._make_tab("로그")

    def _make_tab(self, label: str) -> tk.Text:
        frm = tk.Frame(self._nb); self._nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sv = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sh = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y")
        sh.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    # ── 캡쳐 ────────────────────────────────────────────────────────

    def _lfilter(self, pkt):
        if TCP not in pkt or Raw not in pkt: return False
        t = pkt[TCP]
        return TARGET_PORT in (t.sport, t.dport)

    def _handler(self, pkt):
        data = pkt[Raw].load
        if data:
            with self._lock: self._queue.append(data)

    def _start(self):
        self._sniffer = AsyncSniffer(store=False, prn=self._handler,
                                     lfilter=self._lfilter)
        try: self._sniffer.start()
        except PermissionError:
            import tkinter.messagebox as mb
            mb.showerror("권한 오류", "관리자 권한 필요"); self._sniffer = None; return
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._lbl.config(text=f"캡쳐 중 | 포트 {TARGET_PORT}", fg="#2d7d2d")

    def _stop(self):
        sniffer, self._sniffer = self._sniffer, None
        self._btn_stop.config(state="disabled")
        def _do():
            if sniffer:
                try: sniffer.stop(); sniffer.join(timeout=3)
                except Exception: pass
            self.after(0, lambda: (
                self._btn_start.config(state="normal"),
                self._lbl.config(text=f"중지 {len(self._raws)}개", fg="gray"),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _clear(self):
        with self._lock: self._queue.clear()
        self._raws.clear(); self._payloads.clear()
        for iid in self._tree.get_children(): self._tree.delete(iid)
        for w in (self._raw_txt, self._dec_txt, self._fld_txt):
            self._set_text(w, "")

    # ── 폴링 ────────────────────────────────────────────────────────

    def _poll(self):
        with self._lock:
            batch, self._queue = self._queue, []
        for raw in batch: self._add_raw(raw)
        if batch:
            self._lbl.config(text=f"캡쳐 중 {len(self._raws)}개", fg="#2d7d2d")
        self.after(200, self._poll)

    def _add_raw(self, raw: bytes):
        payload = extract_payload(raw)
        idx = len(self._raws) + 1
        self._raws.append(raw); self._payloads.append(payload)
        hits = count_known(xor_apply(payload, bytes(self._key))) if any(self._key) else 0
        self._tree.insert("", "end", iid=str(idx),
                          values=(idx, f"{len(raw)}B", f"{len(payload)}B", hits))
        self._tree.see(str(idx))

    # ── 키 복구 ─────────────────────────────────────────────────────

    def _initial_recover(self):
        if not self._payloads:
            self._log("패킷 없음"); return
        self._log(f"초기 키 복구 중 ({len(self._payloads)}개)...")

        def _do():
            kf = freq_recover(self._payloads)
            kk = kpa_recover(self._payloads)
            # 둘 중 KPA 우선
            key = bytearray(KEY_PERIOD)
            for i in range(KEY_PERIOD): key[i] = kk[i] or kf[i]
            total = sum(count_known(xor_apply(p, bytes(key)))
                        for p in self._payloads[:100])
            self._log(f"초기 키 복구 완료 — 알려진 평문 매칭: {total}회")
            self.after(0, lambda: self._set_key(key, f"초기 키 (매칭 {total}회)"))
        threading.Thread(target=_do, daemon=True).start()

    def _refine(self):
        if not self._payloads:
            self._log("패킷 없음"); return
        self._log(f"브루트포스 정제 시작 (키 {KEY_PERIOD}바이트 × 256 = {KEY_PERIOD*256} 시도)...")
        self._log("예상 시간: 30초~2분")

        def _do():
            key = bytearray(self._key) if self._key else bytearray(KEY_PERIOD)
            for kpos in range(KEY_PERIOD):
                best_val, best_score = refine_key_byte(self._payloads, key, kpos)
                self._log(f"  위치 {kpos:2d}/47 → 0x{best_val:02X}  (매칭 {best_score}회)")
                self.after(0, lambda k=bytearray(key): setattr(self, '_key', bytes(k)))
            total = sum(count_known(xor_apply(p, bytes(key)))
                        for p in self._payloads[:200])
            self._log(f"정제 완료 — 전체 매칭: {total}회")
            self.after(0, lambda: self._set_key(key, f"정제 완료 (총 매칭 {total}회)"))
        threading.Thread(target=_do, daemon=True).start()

    def _validate(self):
        if not self._payloads or not any(self._key):
            self._log("패킷 또는 키 없음"); return
        total = sum(count_known(xor_apply(p, bytes(self._key)))
                    for p in self._payloads)
        per_packet = total / max(len(self._payloads), 1)
        self._log(f"검증: 총 {len(self._payloads)}개 패킷에서 알려진 평문 {total}회 매칭 (평균 {per_packet:.1f}회/패킷)")
        if per_packet >= 5:
            self._log("✓ 키가 맞는 것 같음!")
        elif per_packet >= 1:
            self._log("△ 일부 매칭 — 키가 부분적으로 맞거나 헤더 길이가 다를 수 있음")
        else:
            self._log("✗ 매칭 없음 — 키가 틀리거나 암호화 방식이 다름")
        # 트리 업데이트
        for iid in self._tree.get_children():
            idx = int(iid) - 1
            if 0 <= idx < len(self._payloads):
                hits = count_known(xor_apply(self._payloads[idx], bytes(self._key)))
                self._tree.set(iid, "매칭", hits)

    def _scan_all(self):
        if not any(self._key) or not self._payloads:
            self._log("키 또는 패킷 없음"); return
        lines = [f"=== 전체 {len(self._payloads)}개 스캔 ===\n"]

        def _do():
            total = 0
            for i, p in enumerate(self._payloads, 1):
                dec = xor_apply(p, bytes(self._key))
                for plain in KNOWN_PLAIN:
                    idx = 0
                    while True:
                        idx = dec.find(plain, idx)
                        if idx == -1: break
                        ctx_start = max(0, idx - 5)
                        ctx_end   = min(len(dec), idx + len(plain) + 20)
                        ctx = dec[ctx_start:ctx_end].decode("utf-8", errors="replace")
                        ctx = repr(ctx)
                        lines.append(f"패킷#{i:3d} +{idx:4d} [{plain.decode():18s}] {ctx}")
                        total += 1; idx += 1
            lines.append(f"\n총 {total}회 매칭")
            self.after(0, lambda: (
                self._set_text(self._fld_txt, "\n".join(lines)),
                self._nb.select(2),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _apply_key(self):
        raw = self._key_var.get().replace(" ", "")
        try: self._key = bytearray(bytes.fromhex(raw))
        except ValueError:
            self._lbl_key.config(text="잘못된 hex", fg="red"); return
        self._lbl_key.config(text=f"{len(self._key)}B 적용", fg="#2d7d2d")
        self._refresh_all()

    def _copy_key(self):
        k = self._key_var.get()
        if k:
            self.clipboard_clear(); self.clipboard_append(k)
            self._lbl_key.config(text="복사됨!", fg="#1a6fba")

    def _set_key(self, key, note: str):
        self._key = bytearray(key)
        self._key_var.set(bytes(self._key).hex())
        self._lbl_key.config(text=note, fg="#1a6fba")
        self._refresh_all()

    def _refresh_all(self):
        for iid in self._tree.get_children():
            idx = int(iid) - 1
            if 0 <= idx < len(self._payloads):
                hits = count_known(xor_apply(self._payloads[idx], bytes(self._key)))
                self._tree.set(iid, "매칭", hits)
        self._refresh_detail()

    def _on_select(self, _):
        self._refresh_detail()

    def _refresh_detail(self):
        sel = self._tree.selection()
        if not sel: return
        idx = int(sel[0]) - 1
        if not (0 <= idx < len(self._raws)): return
        payload = self._payloads[idx]
        self._set_text(self._raw_txt, hex_dump(payload))

        if not any(self._key):
            self._set_text(self._dec_txt, "(키 없음)")
            return
        dec = xor_apply(payload, bytes(self._key))
        dec_str = dec.decode("utf-8", errors="replace")
        self._set_text(self._dec_txt,
                       hex_dump(dec) + "\n\n── UTF-8 텍스트 ──\n" + dec_str)

    def _set_text(self, w, text):
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("1.0", text)
        w.config(state="disabled")

    def _log(self, msg):
        from datetime import datetime
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
        self.after(0, lambda: self._append_log(line))

    def _append_log(self, line):
        self._log_txt.config(state="normal")
        self._log_txt.insert("end", line)
        self._log_txt.see("end")
        self._log_txt.config(state="disabled")

    def on_close(self):
        sniffer, self._sniffer = self._sniffer, None
        self.destroy()
        if sniffer:
            try: sniffer.stop()
            except Exception: pass


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
