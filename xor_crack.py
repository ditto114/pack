"""XOR 키 크래킹 도구 — 알려진 평문 공격 + Scapy 실시간 캡쳐.

전략:
  1. Scapy로 포트 32800 패킷 실시간 캡쳐
  2. ex3.txt/ex4.txt에서 관찰된 키워드(Map, Name, Profile 등)를
     알려진 평문으로 사용해 XOR 키 바이트를 복구
  3. 자동상관으로 키 주기 검출
  4. 복호화 결과 실시간 표시

사용: 관리자 권한 PowerShell에서
    python xor_crack.py

캡쳐 없이 파일에서 분석할 때:
    python xor_crack.py --file some.bin
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional

try:
    from scapy.all import AsyncSniffer, Raw, TCP  # type: ignore
except ImportError:
    import tkinter.messagebox as mb
    root = tk.Tk(); root.withdraw()
    mb.showerror("오류", "scapy 없음. pip install scapy")
    sys.exit(1)

TARGET_PORT = 32800

# ── 알려진 평문 패턴 (ex3/ex4에서 관찰된 키워드) ────────────────────
# 이 문자열들이 복호화된 패킷 안에 반드시 나타난다고 가정
KNOWN_PLAINTEXTS: list[bytes] = [
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


# ── XOR 도우미 ───────────────────────────────────────────────────────

def xor_apply(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def read_ratio(data: bytes) -> float:
    """가독률: ASCII 출력 가능 + 한글 비율."""
    if not data:
        return 0.0
    n = sum(1 for b in data if 0x20 <= b <= 0x7e or 0xac <= b)
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


# ── 알려진 평문 공격 ─────────────────────────────────────────────────

def kpa_single(cipher: bytes, plain: bytes, offset: int, period: int
               ) -> dict[int, int]:
    """cipher[offset:offset+len(plain)] XOR plain → 키 바이트 후보 반환."""
    result: dict[int, int] = {}
    for i, pb in enumerate(plain):
        pos = offset + i
        if pos < len(cipher):
            result[pos % period] = cipher[pos] ^ pb
    return result


def kpa_search(payloads: list[bytes], period: int,
               log_fn=None) -> bytearray:
    """모든 페이로드에서 알려진 평문을 찾아 키 바이트 복구."""
    votes: list[Counter] = [Counter() for _ in range(period)]
    found = 0

    for payload in payloads:
        for plain in KNOWN_PLAINTEXTS:
            plen = len(plain)
            # 슬라이딩 윈도우로 매칭 위치 탐색
            for offset in range(len(payload) - plen + 1):
                candidate = kpa_single(payload, plain, offset, period)
                # 후보 키로 이 평문 주변을 복호화해서 유효한지 검증
                test_key = bytearray(period)
                for kpos, kb in candidate.items():
                    test_key[kpos] = kb
                # 검증: plain 앞뒤 문자들도 어느 정도 가독성 있어야 함
                start = max(0, offset - 4)
                end   = min(len(payload), offset + plen + 4)
                snippet = xor_apply(payload[start:end], bytes(test_key))
                ratio = read_ratio(snippet)
                if ratio > 0.4:
                    found += 1
                    for kpos, kb in candidate.items():
                        votes[kpos][kb] += 1

    if log_fn:
        log_fn(f"KPA: 알려진 평문 매칭 {found}회")

    key = bytearray(period)
    confident = 0
    for kpos, v in enumerate(votes):
        if v:
            best, cnt = v.most_common(1)[0]
            key[kpos] = best
            if cnt >= 2:
                confident += 1

    if log_fn:
        log_fn(f"KPA: {period}바이트 키 중 {confident}바이트 신뢰")
    return key


def find_period_autocorr(payloads: list[bytes]) -> int:
    """자동상관 함수로 XOR 주기 탐색 (8~256)."""
    combined = b"".join(payloads)[:8000]
    if len(combined) < 200:
        return 32
    best_p, best_s = 32, float("inf")
    for p in range(8, 257):
        total = sum(bin(combined[i] ^ combined[i + p]).count("1")
                    for i in range(min(len(combined) - p, 4000)))
        avg = total / min(len(combined) - p, 4000)
        if avg < best_s:
            best_s, best_p = avg, p
    return best_p


def freq_attack(payloads: list[bytes], period: int) -> bytearray:
    """빈도 분석: 가장 많이 나오는 암호 바이트 = key ^ 0x00."""
    buckets: list[Counter] = [Counter() for _ in range(period)]
    for p in payloads:
        for i, b in enumerate(p):
            buckets[i % period][b] += 1
    return bytearray(b.most_common(1)[0][0] if b else 0 for b in buckets)


# ── 구조체 파서 ──────────────────────────────────────────────────────

def parse_fields(data: bytes) -> list[tuple[str, str]]:
    """복호화된 데이터에서 키워드=값 패턴 추출."""
    text = data.decode("utf-8", errors="replace")
    results: list[tuple[str, str]] = []

    keywords = [kw.decode() for kw in KNOWN_PLAINTEXTS]
    for kw in keywords:
        idx = text.find(kw)
        while idx != -1:
            # 키워드 뒤 30자 발췌
            snippet = text[idx:idx + 40].replace("\n", "↵").replace("\r", "")
            results.append((kw, snippet))
            idx = text.find(kw, idx + 1)
    return results


# ── GUI ──────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self, preload: Optional[bytes] = None) -> None:
        super().__init__()
        self.title(f"XOR 크래커 — 포트 {TARGET_PORT}")
        self.geometry("1100x780")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._queue: list[bytes] = []
        self._payloads: list[bytes] = []
        self._key: bytes = b""
        self._period: int = 32

        self._build_ui()
        self._poll()

        if preload:
            self._add_payload(preload)

    # ── UI ──────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # 상단 컨트롤
        top = tk.Frame(self, padx=8, pady=5)
        top.pack(fill="x")

        # 캡쳐 버튼
        self._btn_start = tk.Button(top, text="▶ 캡쳐 시작",
                                     bg="#2d7d2d", fg="white", command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중지", state="disabled",
                                    command=self._stop)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="파일 열기", command=self._open_file).pack(side="left", padx=(8, 2))
        tk.Button(top, text="목록 초기화", command=self._clear).pack(side="left", padx=2)

        self._lbl_status = tk.Label(top, text=f"대기 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl_status.pack(side="right", padx=8)

        # 키 복구 패널
        kf = tk.LabelFrame(self, text="XOR 키 복구", padx=8, pady=4)
        kf.pack(fill="x", padx=8, pady=(0, 4))

        r1 = tk.Frame(kf); r1.pack(fill="x")
        tk.Label(r1, text="주기:").pack(side="left")
        self._period_var = tk.StringVar(value="32")
        tk.Entry(r1, textvariable=self._period_var, width=5).pack(side="left", padx=(2, 8))
        tk.Button(r1, text="① 자동상관 주기 탐지",
                  command=self._auto_period).pack(side="left", padx=2)
        tk.Button(r1, text="② 빈도 분석 (null=0x00)",
                  command=self._freq_attack).pack(side="left", padx=(8, 2))
        tk.Button(r1, text="③ 알려진 평문 공격 (KPA)",
                  bg="#5c2d7d", fg="white",
                  command=self._kpa).pack(side="left", padx=(8, 2))
        tk.Button(r1, text="④ 조합 자동 크랙",
                  bg="#7d2d2d", fg="white",
                  command=self._auto_crack).pack(side="left", padx=(8, 2))

        r2 = tk.Frame(kf); r2.pack(fill="x", pady=(4, 0))
        tk.Label(r2, text="키 (hex):").pack(side="left")
        self._key_var = tk.StringVar()
        tk.Entry(r2, textvariable=self._key_var, width=80,
                 font=("Consolas", 9)).pack(side="left", padx=(4, 6))
        tk.Button(r2, text="적용", command=self._apply_key).pack(side="left")
        tk.Button(r2, text="복사", command=self._copy_key).pack(side="left", padx=4)
        self._lbl_key = tk.Label(r2, text="", fg="#1a6fba")
        self._lbl_key.pack(side="left", padx=8)

        # 본문
        pw = tk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        # 좌: 패킷 목록
        left = tk.Frame(pw)
        pw.add(left, minsize=230)
        cols = ("#", "크기", "원본%", "복호%")
        self._tree = ttk.Treeview(left, columns=cols, show="headings", height=28)
        for c, w, anc in [("#", 44, "e"), ("크기", 72, "e"),
                          ("원본%", 64, "e"), ("복호%", 64, "e")]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor=anc, stretch=False)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 우: 탭
        right = tk.Frame(pw)
        pw.add(right, minsize=550)
        self._nb = ttk.Notebook(right)
        self._nb.pack(fill="both", expand=True)
        self._raw_txt  = self._make_tab("원본 hex")
        self._dec_txt  = self._make_tab("복호화 hex+텍스트")
        self._fld_txt  = self._make_tab("파싱된 필드")
        self._log_txt  = self._make_tab("분석 로그")

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
        self._lbl_status.config(text=f"캡쳐 중... | 포트 {TARGET_PORT}", fg="#2d7d2d")

    def _stop(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        self._btn_stop.config(state="disabled")

        def _do() -> None:
            if sniffer:
                try:
                    sniffer.stop()
                    sniffer.join(timeout=3)
                except Exception:
                    pass
            self.after(0, lambda: (
                self._btn_start.config(state="normal"),
                self._lbl_status.config(
                    text=f"중지 — {len(self._payloads)}개 패킷", fg="gray"),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="바이너리 파일 열기",
            filetypes=[("바이너리/텍스트", "*.bin *.dat *.raw *.txt *"), ("전체", "*")])
        if path:
            data = Path(path).read_bytes()
            self._add_payload(data)
            self._log(f"파일 로드: {path} ({len(data)}B)")

    def _clear(self) -> None:
        with self._lock:
            self._queue.clear()
        self._payloads.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for w in (self._raw_txt, self._dec_txt, self._fld_txt):
            self._set_text(w, "")
        self._lbl_status.config(text=f"초기화 | 포트 {TARGET_PORT}", fg="gray")

    # ── 폴링 ────────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for data in batch:
            self._add_payload(data)
        if batch:
            n = len(self._payloads)
            self._lbl_status.config(text=f"캡쳐 중... {n}개 | 포트 {TARGET_PORT}",
                                     fg="#2d7d2d")
        self.after(200, self._poll)

    def _add_payload(self, data: bytes) -> None:
        idx = len(self._payloads) + 1
        self._payloads.append(data)
        r_raw = f"{read_ratio(data):.0%}"
        r_dec = f"{read_ratio(xor_apply(data, self._key)):.0%}" if self._key else "-"
        self._tree.insert("", "end", iid=str(idx),
                          values=(idx, f"{len(data)}B", r_raw, r_dec))
        self._tree.see(str(idx))

    # ── 키 복구 ─────────────────────────────────────────────────────

    def _get_period(self) -> int:
        try:
            v = int(self._period_var.get())
            return max(1, v)
        except ValueError:
            return 32

    def _auto_period(self) -> None:
        if len(self._payloads) < 3:
            self._log("패킷 3개 이상 필요"); return
        self._log("자동상관 분석 중...")

        def _do() -> None:
            p = find_period_autocorr(self._payloads)
            self.after(0, lambda: (
                self._period_var.set(str(p)),
                self._log(f"탐지된 주기: {p}B"),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _freq_attack(self) -> None:
        if not self._payloads:
            self._log("패킷 없음"); return
        p = self._get_period()
        key = freq_attack(self._payloads, p)
        self._set_key(key, f"빈도 분석 (주기 {p}B)")

    def _kpa(self) -> None:
        if len(self._payloads) < 2:
            self._log("패킷 2개 이상 필요"); return
        p = self._get_period()
        self._log(f"알려진 평문 공격 시작 (주기 {p}B, {len(self._payloads)}개 패킷)...")

        def _do() -> None:
            key = kpa_search(self._payloads, p, log_fn=self._log)
            self.after(0, lambda: self._set_key(key, f"KPA 복구 (주기 {p}B)"))
        threading.Thread(target=_do, daemon=True).start()

    def _auto_crack(self) -> None:
        """주기 자동탐지 → 빈도 분석 → KPA 순서로 자동 실행."""
        if len(self._payloads) < 3:
            self._log("패킷 3개 이상 필요"); return
        self._log("=== 자동 크랙 시작 ===")

        def _do() -> None:
            # 1단계: 주기 탐지
            p = find_period_autocorr(self._payloads)
            self.after(0, lambda: self._period_var.set(str(p)))
            self._log(f"1) 주기 탐지: {p}B")

            # 2단계: 빈도 분석 초기 키
            key_freq = freq_attack(self._payloads, p)
            score_freq = self._score_key(key_freq, p)
            self._log(f"2) 빈도 분석 키 가독률: {score_freq:.1%}")

            # 3단계: KPA 보완
            key_kpa = kpa_search(self._payloads, p, log_fn=self._log)
            score_kpa = self._score_key(key_kpa, p)
            self._log(f"3) KPA 키 가독률: {score_kpa:.1%}")

            # 두 키 중 더 나은 것 선택 (또는 결합)
            key_merged = bytearray(p)
            for i in range(p):
                # KPA 신뢰도가 높으면 KPA 우선, 아니면 빈도 분석
                key_merged[i] = key_kpa[i] if score_kpa >= score_freq else key_freq[i]

            score_merged = self._score_key(bytes(key_merged), p)
            self._log(f"4) 병합 키 가독률: {score_merged:.1%}")

            best_key = max(
                [(key_freq, score_freq), (key_kpa, score_kpa), (key_merged, score_merged)],
                key=lambda x: x[1]
            )[0]
            best_score = self._score_key(bytes(best_key), p)
            self._log(f"=== 최종 키 가독률: {best_score:.1%} ===")
            self.after(0, lambda: self._set_key(bytearray(best_key), f"자동 크랙 (주기 {p}B, 가독률 {best_score:.1%})"))

        threading.Thread(target=_do, daemon=True).start()

    def _score_key(self, key, period: int) -> float:
        """현재 키로 복호화했을 때 평균 가독률."""
        if not self._payloads:
            return 0.0
        total = sum(read_ratio(xor_apply(p, bytes(key) if not isinstance(key, bytes) else key))
                    for p in self._payloads[:50])
        return total / min(len(self._payloads), 50)

    def _apply_key(self) -> None:
        raw = self._key_var.get().replace(" ", "")
        try:
            self._key = bytes.fromhex(raw)
        except ValueError:
            self._lbl_key.config(text="잘못된 hex", fg="red")
            return
        self._lbl_key.config(text=f"키 {len(self._key)}B 적용됨", fg="#2d7d2d")
        self._refresh_all()

    def _copy_key(self) -> None:
        k = self._key_var.get()
        if k:
            self.clipboard_clear()
            self.clipboard_append(k)
            self._lbl_key.config(text="복사됨!", fg="#1a6fba")

    def _set_key(self, key: bytearray, note: str) -> None:
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

    # ── 상세 보기 ────────────────────────────────────────────────────

    def _on_select(self, _: object) -> None:
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx  = int(sel[0]) - 1
        if not (0 <= idx < len(self._payloads)):
            return
        data = self._payloads[idx]
        self._set_text(self._raw_txt, hex_dump(data))

        if not self._key:
            self._set_text(self._dec_txt, "(키를 복구하세요)")
            self._set_text(self._fld_txt, "")
            return

        dec = xor_apply(data, self._key)
        dec_str = dec.decode("utf-8", errors="replace")
        self._set_text(self._dec_txt,
                       hex_dump(dec) + "\n\n── UTF-8 텍스트 ──\n" + dec_str)

        fields = parse_fields(dec)
        if fields:
            lines = [f"[{kw:20s}] {snippet}" for kw, snippet in fields]
            self._set_text(self._fld_txt, "\n".join(lines))
            self._nb.select(2)
        else:
            self._set_text(self._fld_txt, "(파싱된 필드 없음)")

    # ── 유틸 ────────────────────────────────────────────────────────

    def _set_text(self, w: tk.Text, text: str) -> None:
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("1.0", text)
        w.config(state="disabled")

    def _log(self, msg: str) -> None:
        from datetime import datetime
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
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
            try:
                sniffer.stop()
            except Exception:
                pass


# ── 진입점 ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="XOR 크래커")
    parser.add_argument("--file", help="분석할 바이너리 파일")
    args = parser.parse_args()

    preload: Optional[bytes] = None
    if args.file:
        preload = Path(args.file).read_bytes()
        print(f"파일 로드: {args.file} ({len(preload)}B)")

    app = App(preload=preload)
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
