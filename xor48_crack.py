"""포트 32800 XOR-48 복호화 도구.

분석 결과 확인된 패킷 구조:
  Bytes  0- 3  : 패킷 ID (변동)
  Bytes  4- 7  : 페이로드 길이 uint32-LE
  Bytes  8-11  : FF FF FF FF (매직)
  Byte   12    : 02 (커맨드 타입)
  Bytes 13-15  : 페이로드 길이 uint24-LE (반복)
  Byte   16    : 00
  Bytes 17-24  : 61 35 F0 7D 00 00 00 00 (세션 ID, 고정)
  Bytes 25+    : XOR 암호화 페이로드 (주기 48B)

전략: 헤더(25B)를 완전히 스킵하고, 페이로드만으로
      주기-48 빈도 분석 + 알려진 평문 공격
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
    mb.showerror("오류", "pip install scapy")
    sys.exit(1)

TARGET_PORT = 32800
HEADER_LEN  = 25          # 평문 헤더 크기
KEY_PERIOD  = 48          # 자기상관으로 확인된 XOR 주기

# ex3/ex4에서 관찰된 알려진 평문 (UTF-8 bytes)
KNOWN_PLAIN: list[bytes] = [
    b"Map",
    b"Name",
    b"Profile",
    b"Job",
    b"Exp",
    b"Level",
    b"Attacks",
    b"Created",
    b"Buffs",
    b"Captcha",
    b"MapOnline",
    b"CharOnline",
    b"ChannelOnline",
    b"PetComponent",
    b"StateComponent",
    b"WsUserController",
    b"MOVE",
]


# ── 헤더 파서 ───────────────────────────────────────────────────────

def parse_header(data: bytes) -> dict | None:
    """25바이트 헤더 파싱. 매직 확인 실패시 None."""
    if len(data) < HEADER_LEN:
        return None
    magic = data[8:12]
    if magic != b"\xff\xff\xff\xff":
        return None
    plen = struct.unpack_from("<I", data, 4)[0]
    return {
        "pkt_id":   data[0:4].hex(),
        "pay_len":  plen,
        "cmd":      data[12],
        "session":  data[17:25].hex(),
        "payload":  data[HEADER_LEN: HEADER_LEN + plen],
    }


def extract_payload(raw: bytes) -> bytes:
    """헤더 파싱 성공 시 페이로드 반환, 실패 시 전체 반환."""
    h = parse_header(raw)
    if h:
        return h["payload"]
    # 매직 없는 패킷 — 헤더 길이를 모르므로 25B 스킵만
    return raw[HEADER_LEN:] if len(raw) > HEADER_LEN else raw


# ── XOR 도우미 ──────────────────────────────────────────────────────

def xor_apply(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def read_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    n = sum(1 for b in data if 0x20 <= b <= 0x7e or 0xac00 <= b)
    return n / len(data)


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


# ── 키 복구 알고리즘 ─────────────────────────────────────────────────

def freq_recover(payloads: list[bytes], period: int) -> bytearray:
    """빈도 분석: 가장 자주 나오는 암호 바이트 = key ^ 0x00."""
    buckets: list[Counter] = [Counter() for _ in range(period)]
    for p in payloads:
        for i, b in enumerate(p):
            buckets[i % period][b] += 1
    return bytearray(b.most_common(1)[0][0] if b else 0 for b in buckets)


def kpa_recover(payloads: list[bytes], period: int,
                log_fn=None) -> tuple[bytearray, list[int]]:
    """알려진 평문 공격. 신뢰 있는 키 위치 목록도 반환."""
    votes: list[Counter] = [Counter() for _ in range(period)]
    matched = 0

    for payload in payloads:
        for plain in KNOWN_PLAIN:
            plen = len(plain)
            for offset in range(len(payload) - plen + 1):
                # 후보 키 바이트 계산
                cands: dict[int, int] = {}
                for j, pb in enumerate(plain):
                    pos  = offset + j
                    kpos = pos % period
                    cands[kpos] = payload[pos] ^ pb

                # 빠른 검증: 이 오프셋에서 평문이 나타나는지
                # → 주변 4바이트도 ASCII/한글이면 가산점
                test_key = bytearray(period)
                for kpos, kb in cands.items():
                    test_key[kpos] = kb
                start = max(0, offset - 4)
                end   = min(len(payload), offset + plen + 4)
                snippet = xor_apply(payload[start:end], bytes(test_key))
                rr = read_ratio(snippet)
                if rr >= 0.35:
                    matched += 1
                    for kpos, kb in cands.items():
                        votes[kpos][kb] += 1

    if log_fn:
        log_fn(f"KPA: {matched}회 매칭 (알려진 평문 {len(KNOWN_PLAIN)}종)")

    key = bytearray(period)
    confident: list[int] = []
    for kpos, v in enumerate(votes):
        if v:
            best, cnt = v.most_common(1)[0]
            key[kpos] = best
            if cnt >= 2:
                confident.append(kpos)

    if log_fn:
        log_fn(f"KPA: {len(confident)}/{period} 바이트 신뢰")
    return key, confident


def merge_keys(kf: bytearray, kk: bytearray,
               confident: list[int]) -> bytearray:
    """KPA 신뢰 바이트는 KPA 우선, 나머지는 빈도 분석."""
    merged = bytearray(len(kf))
    conf_set = set(confident)
    for i in range(len(kf)):
        merged[i] = kk[i] if i in conf_set else kf[i]
    return merged


def score_key(key: bytes, payloads: list[bytes]) -> float:
    """키로 복호화 했을 때 평균 가독률."""
    if not payloads:
        return 0.0
    total = sum(read_ratio(xor_apply(p, key))
                for p in payloads[:50])
    return total / min(len(payloads), 50)


def parse_fields(data: bytes) -> list[str]:
    text = data.decode("utf-8", errors="replace")
    results: list[str] = []
    for kw in KNOWN_PLAIN:
        kws = kw.decode()
        idx = text.find(kws)
        while idx != -1:
            snippet = repr(text[idx:idx + 50])
            results.append(f"  [{kws:18s}] @ {idx:4d}  {snippet}")
            idx = text.find(kws, idx + 1)
    return results


# ── GUI ─────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"XOR-48 복호화 | 포트 {TARGET_PORT} | 헤더 {HEADER_LEN}B 스킵")
        self.geometry("1120x800")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock    = threading.Lock()
        self._queue:    list[bytes] = []
        self._raws:     list[bytes] = []   # 원본 전체 패킷
        self._payloads: list[bytes] = []   # 헤더 제거 페이로드
        self._key:      bytes       = b""

        self._build_ui()
        self._poll()

    # ── UI ──────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=4)
        top.pack(fill="x")

        self._btn_start = tk.Button(top, text="▶ 캡쳐 시작",
                                     bg="#2d7d2d", fg="white", command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중지",
                                    state="disabled", command=self._stop)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="목록 초기화", command=self._clear).pack(side="left", padx=(8, 2))

        self._lbl = tk.Label(top, text=f"대기 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 키 복구 패널
        kf = tk.LabelFrame(self, text=f"XOR 키 복구 (주기 {KEY_PERIOD}B, 헤더 {HEADER_LEN}B 제외)", padx=8, pady=4)
        kf.pack(fill="x", padx=8, pady=(0, 4))

        r1 = tk.Frame(kf); r1.pack(fill="x")
        tk.Button(r1, text="① 빈도 분석",
                  bg="#1a5c9e", fg="white",
                  command=self._freq).pack(side="left", padx=2)
        tk.Button(r1, text="② 알려진 평문 공격 (KPA)",
                  bg="#5c2d7d", fg="white",
                  command=self._kpa).pack(side="left", padx=(8, 2))
        tk.Button(r1, text="③ 자동 크랙 (빈도+KPA 병합)",
                  bg="#7d2d2d", fg="white",
                  command=self._auto_crack).pack(side="left", padx=(8, 2))
        tk.Button(r1, text="전체 패턴 스캔",
                  command=self._scan_all).pack(side="left", padx=(16, 2))

        r2 = tk.Frame(kf); r2.pack(fill="x", pady=(4, 0))
        tk.Label(r2, text="키 hex:").pack(side="left")
        self._key_var = tk.StringVar()
        tk.Entry(r2, textvariable=self._key_var, width=82,
                 font=("Consolas", 9)).pack(side="left", padx=(4, 6))
        tk.Button(r2, text="적용", command=self._apply_key).pack(side="left")
        tk.Button(r2, text="복사", command=self._copy_key).pack(side="left", padx=4)
        self._lbl_key = tk.Label(r2, text="", fg="#1a6fba")
        self._lbl_key.pack(side="left", padx=4)

        # 본문
        pw = tk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        # 좌: 패킷 목록
        left = tk.Frame(pw)
        pw.add(left, minsize=230)
        cols = ("#", "크기", "페이로드", "원본%", "복호%")
        self._tree = ttk.Treeview(left, columns=cols, show="headings", height=30)
        for c, w, anc in [("#", 40, "e"), ("크기", 64, "e"), ("페이로드", 64, "e"),
                          ("원본%", 52, "e"), ("복호%", 52, "e")]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor=anc, stretch=False)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 우: 탭
        right = tk.Frame(pw)
        pw.add(right, minsize=600)
        self._nb = ttk.Notebook(right)
        self._nb.pack(fill="both", expand=True)
        self._hdr_txt = self._make_tab("헤더 파싱")
        self._raw_txt = self._make_tab("원본 payload hex")
        self._dec_txt = self._make_tab("복호화 hex+텍스트")
        self._fld_txt = self._make_tab("파싱된 필드")
        self._log_txt = self._make_tab("로그")

    def _make_tab(self, label: str) -> tk.Text:
        frm = tk.Frame(self._nb)
        self._nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sv  = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sh  = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y")
        sh.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    # ── 캡쳐 ────────────────────────────────────────────────────────

    def _lfilter(self, pkt: object) -> bool:
        if TCP not in pkt or Raw not in pkt:  # type: ignore
            return False
        t = pkt[TCP]  # type: ignore
        return TARGET_PORT in (t.sport, t.dport)

    def _handler(self, pkt: object) -> None:
        data: bytes = pkt[Raw].load  # type: ignore
        if data:
            with self._lock:
                self._queue.append(data)

    def _start(self) -> None:
        self._sniffer = AsyncSniffer(store=False, prn=self._handler,
                                     lfilter=self._lfilter)
        try:
            self._sniffer.start()
        except PermissionError:
            import tkinter.messagebox as mb
            mb.showerror("권한 오류", "관리자 권한으로 실행하세요.")
            self._sniffer = None
            return
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._lbl.config(text=f"캡쳐 중... | 포트 {TARGET_PORT}", fg="#2d7d2d")

    def _stop(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        self._btn_stop.config(state="disabled")

        def _do() -> None:
            if sniffer:
                try:
                    sniffer.stop(); sniffer.join(timeout=3)
                except Exception:
                    pass
            self.after(0, lambda: (
                self._btn_start.config(state="normal"),
                self._lbl.config(text=f"중지 — {len(self._raws)}개", fg="gray"),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _clear(self) -> None:
        with self._lock: self._queue.clear()
        self._raws.clear(); self._payloads.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for w in (self._hdr_txt, self._raw_txt, self._dec_txt,
                  self._fld_txt):
            self._set_text(w, "")
        self._lbl.config(text=f"초기화 | 포트 {TARGET_PORT}", fg="gray")

    # ── 폴링 ────────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for raw in batch:
            self._add_raw(raw)
        if batch:
            n = len(self._raws)
            self._lbl.config(text=f"캡쳐 중 {n}개 | 포트 {TARGET_PORT}",
                              fg="#2d7d2d")
        self.after(200, self._poll)

    def _add_raw(self, raw: bytes) -> None:
        payload = extract_payload(raw)
        idx     = len(self._raws) + 1
        self._raws.append(raw)
        self._payloads.append(payload)
        r_raw = f"{read_ratio(payload):.0%}"
        r_dec = (f"{read_ratio(xor_apply(payload, self._key)):.0%}"
                 if self._key else "-")
        self._tree.insert("", "end", iid=str(idx),
                          values=(idx, f"{len(raw)}B", f"{len(payload)}B",
                                  r_raw, r_dec))
        self._tree.see(str(idx))

    # ── 키 복구 ─────────────────────────────────────────────────────

    def _freq(self) -> None:
        if not self._payloads:
            return
        key = freq_recover(self._payloads, KEY_PERIOD)
        sc  = score_key(bytes(key), self._payloads)
        self._set_key(key, f"빈도 분석 가독률={sc:.1%}")

    def _kpa(self) -> None:
        if len(self._payloads) < 2:
            self._log("패킷 2개 이상 필요"); return
        self._log(f"KPA 시작 ({len(self._payloads)}개 패킷, 주기 {KEY_PERIOD}B)...")

        def _do() -> None:
            key, conf = kpa_recover(self._payloads, KEY_PERIOD, log_fn=self._log)
            sc = score_key(bytes(key), self._payloads)
            self.after(0, lambda: self._set_key(key, f"KPA 가독률={sc:.1%} ({len(conf)}/{KEY_PERIOD}B 신뢰)"))
        threading.Thread(target=_do, daemon=True).start()

    def _auto_crack(self) -> None:
        if len(self._payloads) < 3:
            self._log("패킷 3개 이상 필요"); return
        self._log(f"=== 자동 크랙 시작 ({len(self._payloads)}개, 주기 {KEY_PERIOD}B) ===")

        def _do() -> None:
            # 빈도 분석
            kf  = freq_recover(self._payloads, KEY_PERIOD)
            sf  = score_key(bytes(kf), self._payloads)
            self._log(f"빈도 분석 가독률: {sf:.1%}")

            # KPA
            kk, conf = kpa_recover(self._payloads, KEY_PERIOD, log_fn=self._log)
            sk = score_key(bytes(kk), self._payloads)
            self._log(f"KPA 가독률: {sk:.1%} ({len(conf)}/{KEY_PERIOD}B 신뢰)")

            # 병합
            km = merge_keys(kf, kk, conf)
            sm = score_key(bytes(km), self._payloads)
            self._log(f"병합 가독률: {sm:.1%}")

            best, bs = max(
                [(kf, sf), (kk, sk), (km, sm)],
                key=lambda x: x[1])
            self._log(f"=== 최종 가독률: {bs:.1%} ===")
            self.after(0, lambda: self._set_key(
                bytearray(best), f"자동 크랙 가독률={bs:.1%}"))
        threading.Thread(target=_do, daemon=True).start()

    def _apply_key(self) -> None:
        raw = self._key_var.get().replace(" ", "")
        try:
            self._key = bytes.fromhex(raw)
        except ValueError:
            self._lbl_key.config(text="잘못된 hex", fg="red")
            return
        self._lbl_key.config(text=f"{len(self._key)}B 적용", fg="#2d7d2d")
        self._refresh_all()

    def _copy_key(self) -> None:
        k = self._key_var.get()
        if k:
            self.clipboard_clear(); self.clipboard_append(k)
            self._lbl_key.config(text="복사됨!", fg="#1a6fba")

    def _set_key(self, key, note: str) -> None:
        self._key = bytes(key)
        self._key_var.set(self._key.hex())
        self._lbl_key.config(text=note, fg="#1a6fba")
        self._refresh_all()

    def _refresh_all(self) -> None:
        for iid in self._tree.get_children():
            idx = int(iid) - 1
            if 0 <= idx < len(self._payloads):
                r = f"{read_ratio(xor_apply(self._payloads[idx], self._key)):.0%}"
                self._tree.set(iid, "복호%", r)
        self._refresh_detail()

    def _scan_all(self) -> None:
        if not self._key or not self._payloads:
            return
        lines: list[str] = [f"=== 전체 {len(self._payloads)}개 패킷 패턴 스캔 ===\n"]

        def _do() -> None:
            total_fields = 0
            for i, payload in enumerate(self._payloads, 1):
                dec    = xor_apply(payload, self._key)
                fields = parse_fields(dec)
                if fields:
                    lines.append(f"\n패킷 #{i} ({len(payload)}B):")
                    lines.extend(fields)
                    total_fields += len(fields)
            lines.append(f"\n\n총 {total_fields}개 필드 발견")
            def _show() -> None:
                self._set_text(self._fld_txt, "\n".join(lines))
                self._nb.select(3)
            self.after(0, _show)
        threading.Thread(target=_do, daemon=True).start()

    # ── 선택 상세 ────────────────────────────────────────────────────

    def _on_select(self, _: object) -> None:
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(sel[0]) - 1
        if not (0 <= idx < len(self._raws)):
            return

        raw     = self._raws[idx]
        payload = self._payloads[idx]
        h       = parse_header(raw)

        # 헤더 탭
        if h:
            hdr_txt = (
                f"=== 패킷 #{idx+1} 헤더 파싱 ===\n"
                f"  패킷 ID  : {h['pkt_id']}\n"
                f"  커맨드   : 0x{h['cmd']:02X}\n"
                f"  페이로드 : {h['pay_len']}B\n"
                f"  세션 ID  : {h['session']}\n"
                f"\n원본 헤더 (25B):\n"
                + hex_dump(raw[:HEADER_LEN])
            )
        else:
            hdr_txt = f"헤더 파싱 실패 (매직 없음)\n\n" + hex_dump(raw[:HEADER_LEN])
        self._set_text(self._hdr_txt, hdr_txt)

        # 원본 payload
        self._set_text(self._raw_txt, hex_dump(payload))

        if not self._key:
            self._set_text(self._dec_txt, "(키를 복구하세요)")
            self._set_text(self._fld_txt, "")
            return

        dec     = xor_apply(payload, self._key)
        dec_str = dec.decode("utf-8", errors="replace")
        self._set_text(
            self._dec_txt,
            hex_dump(dec) + "\n\n── UTF-8 텍스트 ──\n" + dec_str)

        fields = parse_fields(dec)
        if fields:
            body = "\n".join(fields)
            self._set_text(self._fld_txt,
                           f"패킷 #{idx+1} 필드:\n" + body)
            self._nb.select(3)
        else:
            self._set_text(self._fld_txt, "(필드 없음)")

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
        sniffer, self._sniffer = self._sniffer, None
        self.destroy()
        if sniffer:
            try: sniffer.stop()
            except Exception: pass


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
