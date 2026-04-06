"""Nonce 기반 키 유도 크래킹.

패킷 구조:
  bytes 0-3  : NONCE (패킷마다 다름) ← 키 유도에 사용 추정
  bytes 4-7  : 페이로드 길이 (uint32-LE)
  bytes 8-11 : FF FF FF FF (매직, 평문)
  byte  12   : 02
  bytes 13-24: 고정 헤더 (평문)
  bytes 25+  : XOR 암호화 페이로드

가설: actual_key[i] = master_key[i%K] XOR nonce_expanded[i]
각 패킷의 cipher XOR nonce_expanded → plain XOR master_key
이 변환 후 집계하면 master_key를 빈도 분석으로 복구 가능.
"""
from __future__ import annotations
import struct, sys, threading, tkinter as tk
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

KNOWN_PLAIN: list[bytes] = [
    b"Map", b"Name", b"Profile", b"Job", b"Exp", b"Level",
    b"Attacks", b"Created", b"Buffs", b"Captcha",
    b"MapOnline", b"CharOnline", b"ChannelOnline",
    b"PetComponent", b"StateComponent",
]

def extract(raw: bytes) -> tuple[bytes, bytes]:
    """(nonce_4B, payload) 반환."""
    if len(raw) < HEADER_LEN or raw[8:12] != b"\xff\xff\xff\xff":
        return b"\x00"*4, raw[HEADER_LEN:]
    plen = struct.unpack_from("<I", raw, 4)[0]
    nonce = raw[0:4]
    payload = raw[HEADER_LEN: HEADER_LEN + plen]
    return nonce, payload

def xor_apply(data: bytes, key: bytes) -> bytes:
    if not key: return data
    kl = len(key); return bytes(b ^ key[i % kl] for i, b in enumerate(data))

def count_known(data: bytes) -> int:
    total = 0
    for p in KNOWN_PLAIN:
        idx = 0
        while True:
            idx = data.find(p, idx)
            if idx == -1: break
            total += 1; idx += 1
    return total

def hex_dump(data: bytes, limit: int = 512) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off+16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32<=b<=126 else "." for b in chunk)
        lines.append(f"{off:04X}  {h:<47}  {a}")
    if len(data) > limit: lines.append(f"...{len(data)}B")
    return "\n".join(lines)

def try_derivations(raws: list[bytes], period: int) -> list[tuple[int,int,int,str]]:
    """여러 nonce 유도 방식을 시도. (매칭수, nonce_shift, period, desc) 반환."""
    results = []

    # 방법 1: cipher XOR nonce[i%4] → plain XOR master_key (nonce 4가지 shift)
    for nonce_shift in range(4):
        # nonce-adjusted payload 수집
        adjusted: list[bytes] = []
        for raw in raws:
            nonce, payload = extract(raw)
            if len(nonce) < 4 or not payload: continue
            adj = bytes(payload[i] ^ nonce[(i + nonce_shift) % 4]
                        for i in range(len(payload)))
            adjusted.append(adj)
        if not adjusted: continue

        # 빈도 분석으로 master_key 복구
        for p in [period, 4, 8, 16, 24, 32, 64]:
            buckets: list[Counter] = [Counter() for _ in range(p)]
            for a in adjusted:
                for i, b in enumerate(a): buckets[i % p][b] += 1
            master_key = bytes(bk.most_common(1)[0][0] if bk else 0
                               for bk in buckets)

            total = 0
            for raw in raws:
                nonce, payload = extract(raw)
                if not payload: continue
                # 복호화: payload XOR nonce_expanded XOR master_key
                full_key = bytes(nonce[(i+nonce_shift)%4] ^ master_key[i%p]
                                 for i in range(len(payload)))
                dec = xor_apply(payload, full_key)
                total += count_known(dec)

            desc = f"nonce_shift={nonce_shift}, period={p}"
            results.append((total, nonce_shift, p, desc, master_key))

    results.sort(key=lambda x: -x[0])
    return results

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Nonce 키 유도 크래커 | 포트 {TARGET_PORT}")
        self.geometry("1050x780")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._queue: list[bytes] = []
        self._raws:  list[bytes] = []
        self._key:   bytes = b""
        self._nonce_shift: int = 0
        self._key_period:  int = 48

        self._build_ui()
        self._poll()

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=4); top.pack(fill="x")
        self._btn_start = tk.Button(top, text="▶ 캡쳐", bg="#2d7d2d", fg="white", command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중지", state="disabled", command=self._stop)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="초기화", command=self._clear).pack(side="left", padx=8)
        self._lbl = tk.Label(top, text=f"대기 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl.pack(side="right", padx=8)

        kf = tk.LabelFrame(self, text="Nonce 기반 키 유도 크랙", padx=8, pady=4)
        kf.pack(fill="x", padx=8, pady=(0,4))

        r1 = tk.Frame(kf); r1.pack(fill="x")
        tk.Label(r1, text="XOR 주기:").pack(side="left")
        self._period_var = tk.StringVar(value="48")
        tk.Entry(r1, textvariable=self._period_var, width=5).pack(side="left", padx=(2,8))
        tk.Button(r1, text="★ 전체 유도 방식 시도 (자동 최적)",
                  bg="#7d2d00", fg="white",
                  command=self._auto_try).pack(side="left", padx=2)
        tk.Button(r1, text="전체 패킷 스캔",
                  command=self._scan_all).pack(side="left", padx=(12,2))
        tk.Button(r1, text="키 검증",
                  command=self._validate).pack(side="left", padx=4)

        r2 = tk.Frame(kf); r2.pack(fill="x", pady=(4,0))
        tk.Label(r2, text="master_key hex:").pack(side="left")
        self._key_var = tk.StringVar()
        tk.Entry(r2, textvariable=self._key_var, width=70,
                 font=("Consolas", 9)).pack(side="left", padx=(4,4))
        tk.Button(r2, text="적용", command=self._apply_key).pack(side="left")
        tk.Button(r2, text="복사", command=self._copy_key).pack(side="left", padx=4)
        self._lbl_key = tk.Label(r2, text="", fg="#1a6fba")
        self._lbl_key.pack(side="left")

        pw = tk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8, pady=(0,6))

        left = tk.Frame(pw); pw.add(left, minsize=200)
        cols = ("#", "크기", "페이로드", "매칭")
        self._tree = ttk.Treeview(left, columns=cols, show="headings", height=30)
        for c, w, a in [("#",40,"e"),("크기",60,"e"),("페이로드",70,"e"),("매칭",50,"e")]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor=a, stretch=False)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        right = tk.Frame(pw); pw.add(right, minsize=620)
        self._nb = ttk.Notebook(right); self._nb.pack(fill="both", expand=True)
        self._try_txt = self._make_tab("유도 방식 비교")
        self._dec_txt = self._make_tab("복호화 hex+텍스트")
        self._fld_txt = self._make_tab("발견된 필드")
        self._log_txt = self._make_tab("로그")

    def _make_tab(self, label: str) -> tk.Text:
        frm = tk.Frame(self._nb); self._nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sv = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sh = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y"); sh.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True); return txt

    # ── 캡쳐 ──────────────────────────────────────────────────────
    def _lfilter(self, pkt):
        if TCP not in pkt or Raw not in pkt: return False
        t = pkt[TCP]; return TARGET_PORT in (t.sport, t.dport)
    def _handler(self, pkt):
        data = pkt[Raw].load
        if data:
            with self._lock: self._queue.append(data)
    def _start(self):
        self._sniffer = AsyncSniffer(store=False, prn=self._handler, lfilter=self._lfilter)
        try: self._sniffer.start()
        except PermissionError:
            import tkinter.messagebox as mb
            mb.showerror("권한 오류", "관리자 권한 필요"); self._sniffer = None; return
        self._btn_start.config(state="disabled"); self._btn_stop.config(state="normal")
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
        self._raws.clear()
        for iid in self._tree.get_children(): self._tree.delete(iid)
        self._lbl.config(text="초기화", fg="gray")

    # ── 폴링 ──────────────────────────────────────────────────────
    def _poll(self):
        with self._lock:
            batch, self._queue = self._queue, []
        for raw in batch:
            nonce, payload = extract(raw)
            idx = len(self._raws) + 1; self._raws.append(raw)
            hits = self._decode_hits(nonce, payload)
            self._tree.insert("", "end", iid=str(idx),
                              values=(idx, f"{len(raw)}B", f"{len(payload)}B", hits))
            self._tree.see(str(idx))
        if batch:
            self._lbl.config(text=f"캡쳐 중 {len(self._raws)}개", fg="#2d7d2d")
        self.after(200, self._poll)

    def _decode_hits(self, nonce: bytes, payload: bytes) -> int:
        if not self._key or not payload: return 0
        full_key = bytes(nonce[(i+self._nonce_shift)%4] ^ self._key[i%self._key_period]
                         for i in range(len(payload)))
        dec = xor_apply(payload, full_key)
        return count_known(dec)

    # ── 자동 시도 ──────────────────────────────────────────────────
    def _auto_try(self):
        if len(self._raws) < 5:
            self._log("패킷 5개 이상 필요"); return
        try: period = max(1, int(self._period_var.get()))
        except ValueError: period = 48
        self._log(f"전체 유도 방식 시도 중... ({len(self._raws)}개 패킷, 주기 {period}B)")

        def _do():
            results = try_derivations(self._raws, period)
            lines = ["=== 유도 방식 비교 (매칭 많을수록 좋음) ===\n"]
            for i, item in enumerate(results[:20]):
                total, ns, p, desc, mkey = item
                lines.append(f"  #{i+1:2d}  매칭={total:5d}  {desc}")
            self.after(0, lambda: self._set_text(self._try_txt, "\n".join(lines)))
            self.after(0, lambda: self._nb.select(0))

            # 최고 방식 자동 적용
            if results and results[0][0] > 0:
                best = results[0]
                total, ns, p, desc, mkey = best
                self._log(f"최고: {desc} → 매칭 {total}회")
                self.after(0, lambda: self._apply_best(mkey, ns, p,
                    f"최고 유도 (shift={ns}, period={p}, 매칭={total})"))
            else:
                self._log("유효한 매칭 없음 — 암호화 방식이 다를 수 있음")
        threading.Thread(target=_do, daemon=True).start()

    def _apply_best(self, master_key: bytes, nonce_shift: int,
                    key_period: int, note: str) -> None:
        self._key = master_key
        self._nonce_shift = nonce_shift
        self._key_period  = key_period
        self._key_var.set(master_key.hex())
        self._lbl_key.config(text=note, fg="#1a6fba")
        self._refresh_tree()
        self._refresh_detail()

    def _refresh_tree(self) -> None:
        for iid in self._tree.get_children():
            idx = int(iid) - 1
            if 0 <= idx < len(self._raws):
                nonce, payload = extract(self._raws[idx])
                hits = self._decode_hits(nonce, payload)
                self._tree.set(iid, "매칭", hits)

    def _validate(self) -> None:
        if not self._raws or not self._key:
            self._log("패킷 또는 키 없음"); return
        total = sum(self._decode_hits(*extract(r)) for r in self._raws)
        avg = total / max(len(self._raws), 1)
        self._log(f"검증: {total}회 매칭 / {len(self._raws)}개 패킷 (평균 {avg:.1f}회)")
        if avg >= 3:   self._log("✓ 키 맞음!")
        elif avg >= 1: self._log("△ 부분 매칭")
        else:          self._log("✗ 매칭 없음")

    def _scan_all(self) -> None:
        if not self._key or not self._raws: return
        lines = [f"=== 전체 {len(self._raws)}개 패킷 스캔 ===\n"]
        def _do():
            total = 0
            for i, raw in enumerate(self._raws, 1):
                nonce, payload = extract(raw)
                if not payload: continue
                full_key = bytes(nonce[(j+self._nonce_shift)%4] ^ self._key[j%self._key_period]
                                 for j in range(len(payload)))
                dec = xor_apply(payload, full_key)
                for plain in KNOWN_PLAIN:
                    idx = 0
                    while True:
                        idx = dec.find(plain, idx)
                        if idx == -1: break
                        ctx = dec[max(0,idx-3):idx+len(plain)+20].decode("utf-8","replace")
                        lines.append(f"패킷#{i:3d} +{idx:4d} [{plain.decode():16s}] {repr(ctx)}")
                        total += 1; idx += 1
            lines.append(f"\n총 {total}회 매칭")
            self.after(0, lambda: (self._set_text(self._fld_txt, "\n".join(lines)),
                                    self._nb.select(2)))
        threading.Thread(target=_do, daemon=True).start()

    def _apply_key(self) -> None:
        raw = self._key_var.get().replace(" ", "")
        try: self._key = bytes.fromhex(raw)
        except ValueError:
            self._lbl_key.config(text="잘못된 hex", fg="red"); return
        self._lbl_key.config(text=f"{len(self._key)}B 적용", fg="#2d7d2d")
        self._refresh_tree(); self._refresh_detail()

    def _copy_key(self) -> None:
        k = self._key_var.get()
        if k:
            self.clipboard_clear(); self.clipboard_append(k)
            self._lbl_key.config(text="복사됨!", fg="#1a6fba")

    def _on_select(self, _): self._refresh_detail()

    def _refresh_detail(self) -> None:
        sel = self._tree.selection()
        if not sel: return
        idx = int(sel[0]) - 1
        if not (0 <= idx < len(self._raws)): return
        nonce, payload = extract(self._raws[idx])
        if not self._key:
            self._set_text(self._dec_txt, f"nonce={nonce.hex()}\n\n" + hex_dump(payload))
            return
        full_key = bytes(nonce[(i+self._nonce_shift)%4] ^ self._key[i%self._key_period]
                         for i in range(len(payload)))
        dec = xor_apply(payload, full_key)
        dec_str = dec.decode("utf-8", errors="replace")
        self._set_text(self._dec_txt,
            f"nonce={nonce.hex()}  shift={self._nonce_shift}  period={self._key_period}\n\n"
            + hex_dump(dec) + "\n\n── UTF-8 텍스트 ──\n" + dec_str)

        fields = []
        for p in KNOWN_PLAIN:
            i = 0
            while True:
                i = dec.find(p, i)
                if i == -1: break
                ctx = dec[max(0,i-3):i+len(p)+20].decode("utf-8","replace")
                fields.append(f"[{p.decode():16s}] +{i:4d}  {repr(ctx)}")
                i += 1
        self._set_text(self._fld_txt, "\n".join(fields) if fields else "(없음)")
        if fields: self._nb.select(2)

    def _set_text(self, w, text):
        w.config(state="normal"); w.delete("1.0", "end")
        w.insert("1.0", text); w.config(state="disabled")

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
        sniffer, self._sniffer = self._sniffer, None; self.destroy()
        if sniffer:
            try: sniffer.stop()
            except Exception: pass

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
