"""포트 32800 패킷 XOR 복호화 분석 GUI.

전략:
1. 키 주기 자동 탐지 (자동상관)
2. 알려진 평문 공격: 이전 분석에서 offset 8에 FF FF FF FF (매직 바이트)
3. 빈도 분석: null 패딩이 많은 바이너리 프로토콜 특성 이용
4. 수동 키 입력 (hex)
"""

from __future__ import annotations

import re
import sys
import threading
import tkinter as tk
from collections import Counter
from tkinter import ttk
from typing import Optional

try:
    from scapy.all import AsyncSniffer, Raw, TCP, rdpcap  # type: ignore
except ImportError:
    import tkinter.messagebox as mb
    root = tk.Tk(); root.withdraw()
    mb.showerror("오류", "scapy 없음. pip install scapy")
    sys.exit(1)

TARGET_PORT  = 32800
MAGIC_OFFSET = 8           # 이전 프로토콜 분석: FF FF FF FF 위치
MAGIC_BYTES  = b"\xff\xff\xff\xff"
DEFAULT_PERIOD = 48

WORLD_ID_RE = re.compile(r"\d{17}")
CHANNEL_RE  = re.compile(r"[\uAC00-\uD7A3]+\d+")


# ── XOR 분석 헬퍼 ──────────────────────────────────────────────────

def find_period(payloads: list[bytes]) -> int:
    """자동상관으로 키 주기 추정 (16~64 탐색)."""
    combined = b"".join(payloads)
    if len(combined) < 200:
        return DEFAULT_PERIOD
    best_p, best_s = DEFAULT_PERIOD, float("inf")
    for p in range(16, 65):
        total = sum(bin(combined[i] ^ combined[i + p]).count("1")
                    for i in range(len(combined) - p))
        avg = total / (len(combined) - p)
        if avg < best_s:
            best_s, best_p = avg, p
    return best_p


def recover_magic(payloads: list[bytes], period: int) -> tuple[bytearray, list[bool]]:
    """offset 8~11 = FF FF FF FF 가정으로 키 바이트 복구."""
    key = bytearray(period)
    known = [False] * period
    votes: list[Counter] = [Counter() for _ in range(period)]

    for payload in payloads:
        if len(payload) < MAGIC_OFFSET + 4:
            continue
        for i, kb in enumerate(MAGIC_BYTES):
            pos  = MAGIC_OFFSET + i
            kpos = pos % period
            votes[kpos][payload[pos] ^ kb] += 1

    for kpos, v in enumerate(votes):
        if v:
            key[kpos] = v.most_common(1)[0][0]
            known[kpos] = True

    return key, known


def recover_frequency(payloads: list[bytes], period: int) -> tuple[bytearray, list[bool]]:
    """빈도 분석: 가장 자주 나오는 암호 바이트 = key[k] ^ 0x00 (null 패딩 가정)."""
    buckets: list[Counter] = [Counter() for _ in range(period)]
    for p in payloads:
        for i, b in enumerate(p):
            buckets[i % period][b] += 1
    key   = bytearray(b.most_common(1)[0][0] if b else 0 for b in buckets)
    known = [bool(b) for b in buckets]
    return key, known


def xor_apply(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    kl = len(key)
    return bytes(b ^ key[i % kl] for i, b in enumerate(data))


def read_ratio(data: bytes) -> float:
    """가독률 (UTF-8 유효 문자 비율)."""
    if not data:
        return 0.0
    text = data.decode("utf-8", errors="replace")
    n = sum(1 for c in text
            if (32 <= ord(c) <= 126 or "\uAC00" <= c <= "\uD7A3") and c != "\uFFFD")
    return n / max(len(text), 1)


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


def search_magic_offset(payloads: list[bytes], period: int,
                        magic: bytes = MAGIC_BYTES,
                        max_offset: int = 60) -> list[tuple[int, float, bytearray]]:
    """magic 바이트가 있을 수 있는 offset을 0~max_offset 전수 탐색.

    각 offset에서 패킷들이 같은 키 바이트에 동의하는 비율(일관성)을 측정.
    반환: [(offset, consistency_0~1, partial_key), ...] 내림차순 정렬
    """
    results: list[tuple[int, float, bytearray]] = []
    mlen = len(magic)

    for offset in range(max_offset + 1):
        votes: list[Counter] = [Counter() for _ in range(period)]
        n_eligible = 0

        for payload in payloads:
            if len(payload) < offset + mlen:
                continue
            n_eligible += 1
            for i, kb in enumerate(magic):
                kpos = (offset + i) % period
                votes[kpos][payload[offset + i] ^ kb] += 1

        if n_eligible == 0:
            continue

        # 일관성 = 각 키 위치에서 1등 바이트가 전체 투표 중 차지하는 비율 평균
        consistency_scores: list[float] = []
        for i in range(mlen):
            kpos = (offset + i) % period
            v = votes[kpos]
            if v:
                top, total = v.most_common(1)[0][1], sum(v.values())
                consistency_scores.append(top / total)

        if not consistency_scores:
            continue
        consistency = sum(consistency_scores) / len(consistency_scores)

        # 이 offset으로 부분 키 복구
        partial_key = bytearray(period)
        for i, kb in enumerate(magic):
            kpos = (offset + i) % period
            v = votes[kpos]
            if v:
                partial_key[kpos] = v.most_common(1)[0][0]

        results.append((offset, consistency, partial_key))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def analyze_byte_map(payloads: list[bytes], max_pos: int = 80) -> str:
    """키 없이 각 바이트 위치의 출현 분포를 분석해 프로토콜 고정 필드를 찾는다."""
    pos_counters: list[Counter] = [Counter() for _ in range(max_pos)]
    n = 0
    for payload in payloads:
        n += 1
        for i, b in enumerate(payload[:max_pos]):
            pos_counters[i][b] += 1

    lines = [
        f"바이트 맵 분석 — {n}개 패킷",
        "pos | 출현값수 | 최다값  | 빈도  | 비고",
        "─" * 52,
    ]
    for pos, ctr in enumerate(pos_counters):
        if not ctr:
            break
        total  = sum(ctr.values())
        val, cnt = ctr.most_common(1)[0]
        freq   = cnt / total
        ndist  = len(ctr)
        if ndist == 1:
            note = "★ 완전 고정"
        elif freq >= 0.95:
            note = "◆ 거의 고정 (95%+)"
        elif freq >= 0.80:
            note = "◇ 자주 반복 (80%+)"
        else:
            note = ""
        lines.append(f"{pos:3d} | {ndist:6d}   | 0x{val:02X}={val:3d}  | {freq:5.1%} | {note}")

    # 고정 필드 구간 요약
    fixed_runs: list[str] = []
    run_start = -1
    for pos, ctr in enumerate(pos_counters):
        if not ctr:
            break
        total = sum(ctr.values())
        _, cnt = ctr.most_common(1)[0]
        if cnt / total >= 0.95:
            if run_start < 0:
                run_start = pos
        else:
            if run_start >= 0:
                fixed_runs.append(f"  offset {run_start}~{pos-1} ({pos-run_start}바이트 고정)")
                run_start = -1
    if run_start >= 0:
        fixed_runs.append(f"  offset {run_start}~ (고정)")

    if fixed_runs:
        lines += ["", "── 고정 구간 요약 (알려진 평문 후보) ──"] + fixed_runs
    else:
        lines.append("\n(95% 이상 일관된 고정 구간 없음 — 키가 패킷마다 달라질 수 있음)")

    return "\n".join(lines)


def find_patterns(text: str) -> list[str]:
    out: list[str] = []
    for m in WORLD_ID_RE.finditer(text):
        out.append(f"[WorldID]  {m.group()}  @ char {m.start()}")
    for m in CHANNEL_RE.finditer(text):
        out.append(f"[Channel]  {m.group()}  @ char {m.start()}")
    return out


# ── GUI ───────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"XOR 복호화 분석 — 포트 {TARGET_PORT}")
        self.geometry("1060x740")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._queue:    list[bytes] = []
        self._payloads: list[bytes] = []
        self._key: bytes = b""

        self._build_ui()
        self._poll()

    # ── UI 구성 ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── 1행: 캡쳐 컨트롤 ──
        ctrl = tk.Frame(self, padx=8, pady=5)
        ctrl.pack(fill="x")

        self._btn_start = tk.Button(ctrl, text="▶ 캡쳐 시작",
                                     bg="#2d7d2d", fg="white", command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop = tk.Button(ctrl, text="■ 중지",
                                    state="disabled", command=self._stop)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(ctrl, text="📂 pcap 열기",
                  command=self._load_pcap).pack(side="left", padx=(12, 2))
        tk.Button(ctrl, text="목록 지우기", command=self._clear).pack(side="left", padx=2)
        tk.Button(ctrl, text="전체 패턴 스캔", bg="#5c2d7d", fg="white",
                  command=self._scan_all).pack(side="left", padx=(12, 2))

        self._lbl_status = tk.Label(ctrl, text=f"대기 중 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl_status.pack(side="right", padx=8)

        # ── 2행: 키 분석 패널 ──
        kf = tk.LabelFrame(self, text="XOR 키 복구", padx=8, pady=4)
        kf.pack(fill="x", padx=8, pady=(0, 4))

        row1 = tk.Frame(kf)
        row1.pack(fill="x")
        tk.Label(row1, text="키 주기:").pack(side="left")
        self._period_var = tk.StringVar(value=str(DEFAULT_PERIOD))
        tk.Entry(row1, textvariable=self._period_var, width=5).pack(side="left", padx=(2, 8))
        tk.Button(row1, text="자동 탐지", command=self._auto_period).pack(side="left", padx=2)
        tk.Button(row1, text="FF FF FF FF 가정 (offset 8)",
                  command=self._recover_magic).pack(side="left", padx=(12, 2))
        tk.Button(row1, text="매직 오프셋 자동 탐색",
                  bg="#7d4d00", fg="white",
                  command=self._search_magic_offset).pack(side="left", padx=2)
        tk.Button(row1, text="빈도 분석 (null 기준)",
                  command=self._recover_freq).pack(side="left", padx=2)
        tk.Button(row1, text="바이트 맵 분석",
                  bg="#003d5c", fg="white",
                  command=self._show_byte_map).pack(side="left", padx=(12, 2))

        row2 = tk.Frame(kf)
        row2.pack(fill="x", pady=(4, 0))
        tk.Label(row2, text="키 (hex):").pack(side="left")
        self._key_var = tk.StringVar()
        tk.Entry(row2, textvariable=self._key_var, width=72,
                 font=("Consolas", 9)).pack(side="left", padx=(4, 6))
        tk.Button(row2, text="적용", command=self._apply_key).pack(side="left")
        tk.Button(row2, text="복사", command=self._copy_key).pack(side="left", padx=4)
        self._lbl_key = tk.Label(row2, text="", fg="#1a6fba")
        self._lbl_key.pack(side="left", padx=8)

        # ── 본문: 좌(패킷 목록) + 우(상세) ──
        pw = tk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8, pady=(0, 6))

        # 좌: 패킷 목록
        left = tk.Frame(pw)
        pw.add(left, minsize=240)
        cols = ("#", "크기", "원본%", "복호%")
        self._tree = ttk.Treeview(left, columns=cols, show="headings", height=24)
        for c, w, anchor in [("#", 44, "e"), ("크기", 72, "e"),
                              ("원본%", 64, "e"), ("복호%", 64, "e")]:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor=anchor, stretch=False)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 우: 탭 상세
        right = tk.Frame(pw)
        pw.add(right, minsize=500)
        self._nb = ttk.Notebook(right)
        self._nb.pack(fill="both", expand=True)

        self._raw_text  = self._make_tab("원본 hex")
        self._dec_text  = self._make_tab("복호화 hex + 텍스트")
        self._pat_text  = self._make_tab("발견된 패턴")
        self._all_text  = self._make_tab("전체 스캔 결과")
        self._off_text  = self._make_tab("오프셋 탐색 결과")
        self._map_text  = self._make_tab("바이트 맵")

    def _make_tab(self, label: str) -> tk.Text:
        frm = tk.Frame(self._nb)
        self._nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sb_v = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sb_h = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        sb_v.pack(side="right", fill="y")
        sb_h.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    # ── 캡쳐 ──────────────────────────────────────────────────────

    def _lfilter(self, pkt: object) -> bool:
        if TCP not in pkt or Raw not in pkt:  # type: ignore[operator]
            return False
        t = pkt[TCP]  # type: ignore[index]
        return TARGET_PORT in (t.sport, t.dport)

    def _handler(self, pkt: object) -> None:
        data: bytes = pkt[Raw].load  # type: ignore[index]
        if data:
            with self._lock:
                self._queue.append(data)

    def _start(self) -> None:
        self._sniffer = AsyncSniffer(store=False, prn=self._handler, lfilter=self._lfilter)
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
        self._lbl_status.config(text="중지 중...", fg="gray")

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
                    text=f"중지 — {len(self._payloads)}개 | 포트 {TARGET_PORT}",
                    fg="gray"),
            ))

        threading.Thread(target=_do, daemon=True).start()

    def _load_pcap(self) -> None:
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="pcap 파일 선택",
            filetypes=[("pcap/pcapng 파일", "*.pcap *.pcapng *.cap"), ("모든 파일", "*.*")],
        )
        if not path:
            return

        def _do() -> None:
            self.after(0, lambda: self._lbl_status.config(
                text=f"읽는 중: {path}", fg="gray"))
            try:
                pkts = rdpcap(path)
            except Exception as e:
                self.after(0, lambda: self._lbl_status.config(
                    text=f"읽기 실패: {e}", fg="red"))
                return

            loaded = 0
            for pkt in pkts:
                if TCP not in pkt or Raw not in pkt:
                    continue
                t = pkt[TCP]
                if TARGET_PORT not in (t.sport, t.dport):
                    continue
                data: bytes = pkt[Raw].load
                if not data:
                    continue
                with self._lock:
                    self._queue.append(data)
                loaded += 1

            self.after(0, lambda: self._lbl_status.config(
                text=f"pcap 로드 완료 — 포트 {TARGET_PORT} 패킷 {loaded}개",
                fg="#2d7d2d"))

        threading.Thread(target=_do, daemon=True).start()

    def _clear(self) -> None:
        with self._lock:
            self._queue.clear()
        self._payloads.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for w in (self._raw_text, self._dec_text, self._pat_text, self._all_text):
            self._set_text(w, "")
        self._lbl_status.config(text=f"지워짐 | 포트 {TARGET_PORT}", fg="gray")

    # ── 폴링 ──────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []

        for data in batch:
            idx = len(self._payloads) + 1
            self._payloads.append(data)
            r_raw = f"{read_ratio(data):.0%}"
            r_dec = f"{read_ratio(xor_apply(data, self._key)):.0%}" if self._key else "-"
            self._tree.insert("", "end", iid=str(idx),
                              values=(idx, f"{len(data)}B", r_raw, r_dec))
            self._tree.see(str(idx))

        if batch:
            self._lbl_status.config(
                text=f"캡쳐 중... {len(self._payloads)}개 | 포트 {TARGET_PORT}",
                fg="#2d7d2d")

        self.after(200, self._poll)

    # ── 키 복구 ───────────────────────────────────────────────────

    def _period(self) -> int:
        try:
            return max(1, int(self._period_var.get()))
        except ValueError:
            return DEFAULT_PERIOD

    def _auto_period(self) -> None:
        n = len(self._payloads)
        if n < 5:
            self._lbl_key.config(text="패킷 5개 이상 필요", fg="red")
            return
        self._lbl_key.config(text="분석 중...", fg="gray")

        def _do() -> None:
            p = find_period(self._payloads)
            self.after(0, lambda: (
                self._period_var.set(str(p)),
                self._lbl_key.config(text=f"탐지된 주기: {p}B", fg="#2d7d2d"),
            ))

        threading.Thread(target=_do, daemon=True).start()

    def _show_byte_map(self) -> None:
        if not self._payloads:
            self._lbl_key.config(text="패킷 없음", fg="red")
            return

        def _do() -> None:
            report = analyze_byte_map(self._payloads)
            self.after(0, lambda: (
                self._set_text(self._map_text, report),
                self._nb.select(5),
            ))

        threading.Thread(target=_do, daemon=True).start()
        self._lbl_key.config(text="바이트 맵 분석 중...", fg="gray")

    def _search_magic_offset(self) -> None:
        if not self._payloads:
            self._lbl_key.config(text="패킷 없음", fg="red")
            return
        period = self._period()
        self._lbl_key.config(text="오프셋 탐색 중...", fg="gray")

        def _do() -> None:
            results = search_magic_offset(self._payloads, period)
            lines = ["FF FF FF FF 위치 탐색 결과 (상위 15개)\n"
                     f"총 {len(self._payloads)}개 패킷, 키 주기 {period}B\n"
                     + "─" * 55]
            for i, (offset, score, _) in enumerate(results[:15]):
                star = " ◀ 유력" if i == 0 else ""
                lines.append(f"  offset {offset:3d}  |  일관성 {score:.1%}{star}")

            # 가장 유력한 offset으로 키 세팅
            best_offset, best_score, best_key = results[0]
            summary = "\n".join(lines)

            def _apply() -> None:
                self._set_text(self._off_text, summary)
                self._nb.select(4)  # 오프셋 탐색 탭
                if best_score >= 0.8:
                    # offset 업데이트 후 키 적용
                    self._set_key(best_key,
                                  f"offset {best_offset} | 일관성 {best_score:.1%}")
                else:
                    self._lbl_key.config(
                        text=f"최고 일관성 {best_score:.1%} (낮음 — 매직 바이트 가정 재검토 필요)",
                        fg="#b85000")

            self.after(0, _apply)

        threading.Thread(target=_do, daemon=True).start()

    def _recover_magic(self) -> None:
        period = self._period()
        key, known = recover_magic(self._payloads, period)
        n_known = sum(known)
        self._set_key(key, f"매직 복구: {n_known}/{period}바이트 알려짐")

    def _recover_freq(self) -> None:
        if len(self._payloads) < 10:
            self._lbl_key.config(text="패킷 10개 이상 필요", fg="red")
            return
        period = self._period()
        key, _ = recover_frequency(self._payloads, period)
        self._set_key(key, f"빈도 분석 복구 (주기 {period}B)")

    def _apply_key(self) -> None:
        raw = self._key_var.get().replace(" ", "")
        try:
            self._key = bytes.fromhex(raw)
        except ValueError:
            self._lbl_key.config(text="잘못된 hex", fg="red")
            return
        self._lbl_key.config(text=f"키 적용 ({len(self._key)}B)", fg="#2d7d2d")
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

    # ── 전체 새로고침 ─────────────────────────────────────────────

    def _refresh_all(self) -> None:
        for iid in self._tree.get_children():
            idx = int(iid) - 1
            if 0 <= idx < len(self._payloads):
                r = f"{read_ratio(xor_apply(self._payloads[idx], self._key)):.0%}"
                self._tree.set(iid, "복호%", r)
        self._refresh_detail()

    # ── 선택 상세 ─────────────────────────────────────────────────

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

        # 원본 hex
        self._set_text(self._raw_text, hex_dump(data))

        if not self._key:
            self._set_text(self._dec_text, "(키를 복구하세요)")
            self._set_text(self._pat_text, "")
            return

        dec = xor_apply(data, self._key)
        dec_txt = dec.decode("utf-8", errors="replace")
        self._set_text(self._dec_text,
                       hex_dump(dec) + "\n\n── UTF-8 텍스트 ──\n" + dec_txt)

        patterns = find_patterns(dec_txt)
        if patterns:
            self._set_text(self._pat_text, "\n".join(patterns))
            self._nb.select(2)  # 패턴 탭 자동 포커스
        else:
            self._set_text(self._pat_text, "(이 패킷에서 패턴 없음)")

    # ── 전체 패턴 스캔 ────────────────────────────────────────────

    def _scan_all(self) -> None:
        if not self._key:
            self._lbl_key.config(text="키 없음 — 먼저 키 복구", fg="red")
            return
        if not self._payloads:
            return

        def _do() -> None:
            results: list[str] = []
            for i, payload in enumerate(self._payloads, 1):
                dec  = xor_apply(payload, self._key)
                text = dec.decode("utf-8", errors="replace")
                pats = find_patterns(text)
                for p in pats:
                    results.append(f"패킷 #{i}: {p}")

            summary = (f"총 {len(self._payloads)}개 패킷 스캔\n"
                       f"패턴 {len(results)}개 발견\n"
                       + "─" * 50 + "\n"
                       + ("\n".join(results) if results else "(없음)"))
            self.after(0, lambda: (
                self._set_text(self._all_text, summary),
                self._nb.select(3),  # 전체 스캔 탭
            ))

        threading.Thread(target=_do, daemon=True).start()
        self._lbl_status.config(text="전체 스캔 중...", fg="#5c2d7d")

    # ── 유틸 ──────────────────────────────────────────────────────

    def _set_text(self, w: tk.Text, text: str) -> None:
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("1.0", text)
        w.config(state="disabled")

    def on_close(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
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
