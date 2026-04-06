"""암호화 방식 자동 진단 — 포트 32800 패킷 분석.

출력 항목:
  - 엔트로피 (7.9~8.0 → AES/고품질 암호, 낮으면 XOR/스트림)
  - 바이트 빈도 분포 (균일하면 강한 암호)
  - 패킷 간 앞 N바이트가 같은지 (헤더 추측)
  - TLS 레코드 감지
  - IV 후보 탐색 (앞 16/12/8 바이트)
  - XOR 자기상관 점수
"""

from __future__ import annotations

import math
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


# ── 분석 함수들 ───────────────────────────────────────────────────────

def entropy(data: bytes) -> float:
    """Shannon 엔트로피 (bits/byte). 최대 8.0 = 완전 랜덤."""
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def byte_uniformity(data: bytes) -> float:
    """0~255 바이트가 얼마나 균일한지 (1.0 = 완전 균일 = 강한 암호)."""
    if not data:
        return 0.0
    c = Counter(data)
    expected = len(data) / 256
    chi2 = sum((c.get(b, 0) - expected) ** 2 / expected for b in range(256))
    # chi2 낮을수록 균일
    # 정규화: 0(최악) ~ 1(균일)
    max_chi2 = len(data) * 255  # 최악의 경우
    return max(0.0, 1.0 - chi2 / max_chi2)


def common_prefix_len(payloads: list[bytes]) -> int:
    """패킷들 사이의 공통 앞부분 바이트 수 (헤더 길이 추측)."""
    if len(payloads) < 2:
        return 0
    ref = payloads[0]
    n = 0
    for i in range(min(32, len(ref))):
        if all(len(p) > i and p[i] == ref[i] for p in payloads[1:]):
            n = i + 1
        else:
            break
    return n


def xor_autocorr_score(data: bytes, period: int) -> float:
    """주기 p에 대한 XOR 자기상관 점수 (낮을수록 XOR 가능성 높음)."""
    if len(data) < period * 2:
        return 4.0
    total = sum(bin(data[i] ^ data[i + period]).count("1")
                for i in range(min(len(data) - period, 2000)))
    return total / min(len(data) - period, 2000)


def detect_tls(data: bytes) -> str:
    _CT  = {0x14: "ChangeCipherSpec", 0x15: "Alert",
            0x16: "Handshake", 0x17: "AppData", 0x18: "Heartbeat"}
    _VER = {(3, 1): "TLS1.0", (3, 2): "TLS1.1",
            (3, 3): "TLS1.2", (3, 4): "TLS1.3"}
    if len(data) >= 5 and data[0] in _CT and data[1] == 0x03:
        ct  = _CT[data[0]]
        ver = _VER.get((data[1], data[2]), f"TLS?({data[2]})")
        length = (data[3] << 8) | data[4]
        return f"TLS  {ver} / {ct}  payload_len={length}"
    return ""


def analyze_packets(payloads: list[bytes]) -> str:
    """전체 패킷 분석 리포트 생성."""
    if not payloads:
        return "패킷 없음"

    lines: list[str] = []
    lines.append(f"=== 패킷 분석 리포트 ({len(payloads)}개) ===\n")

    # 1. 크기 분포
    sizes = [len(p) for p in payloads]
    lines.append(f"[1] 패킷 크기")
    lines.append(f"    최소={min(sizes)}B  최대={max(sizes)}B  평균={sum(sizes)/len(sizes):.0f}B")
    size_dist = Counter(sizes)
    common = size_dist.most_common(5)
    lines.append(f"    자주 나오는 크기: {common}\n")

    # 2. 엔트로피
    ents = [entropy(p) for p in payloads]
    avg_ent = sum(ents) / len(ents)
    lines.append(f"[2] 엔트로피 (bits/byte)")
    lines.append(f"    평균={avg_ent:.3f}  (7.9~8.0=AES급 강암호, 4~6=XOR/약암호, <4=평문)")
    if avg_ent > 7.8:
        lines.append("    ⚠ 엔트로피가 매우 높음 → AES 또는 동급 블록 암호 가능성")
    elif avg_ent > 6.0:
        lines.append("    ✓ 중간 엔트로피 → 스트림 암호(RC4/XOR) 가능성")
    else:
        lines.append("    ✓ 낮은 엔트로피 → 단순 XOR 또는 평문에 가까움")
    lines.append("")

    # 3. TLS 감지
    lines.append(f"[3] TLS 레코드 감지")
    tls_count = 0
    for p in payloads:
        r = detect_tls(p)
        if r:
            tls_count += 1
            lines.append(f"    → {r}")
    if tls_count == 0:
        lines.append("    없음 (TLS 아님)")
    lines.append("")

    # 4. 공통 헤더
    prefix_len = common_prefix_len(payloads)
    lines.append(f"[4] 공통 앞부분 (헤더 추측)")
    lines.append(f"    공통 바이트 수: {prefix_len}B")
    if prefix_len > 0:
        hdr = payloads[0][:prefix_len]
        lines.append(f"    헤더값: {hdr.hex()}")
    lines.append("")

    # 5. XOR 자기상관 (주기 탐색)
    lines.append(f"[5] XOR 자기상관 점수 (낮을수록 XOR 가능)")
    combined = b"".join(payloads)[:4000]
    best_scores: list[tuple[float, int]] = []
    for p in [8, 16, 24, 32, 48, 64, 128, 256]:
        sc = xor_autocorr_score(combined, p)
        best_scores.append((sc, p))
    best_scores.sort()
    for sc, p in best_scores[:5]:
        lines.append(f"    주기 {p:3d}B → 점수 {sc:.4f}")
    min_score = best_scores[0][0]
    if min_score < 3.5:
        lines.append(f"    ✓ XOR/스트림 암호 가능성 있음 (최저={min_score:.3f})")
    else:
        lines.append(f"    ⚠ XOR 패턴 없음 (최저={min_score:.3f}) → 블록 암호 의심")
    lines.append("")

    # 6. 앞 32바이트 변화 분석 (IV 탐색)
    lines.append(f"[6] 앞 16바이트 패킷간 변화 (IV/Nonce 탐색)")
    if len(payloads) >= 4:
        hdrs = [p[:16] for p in payloads if len(p) >= 16]
        if hdrs:
            # 각 바이트 위치에서 값이 얼마나 변하는지
            variable_positions = []
            fixed_positions    = []
            for i in range(16):
                vals = set(h[i] for h in hdrs)
                if len(vals) == 1:
                    fixed_positions.append((i, list(vals)[0]))
                else:
                    variable_positions.append(i)
            lines.append(f"    고정 바이트 위치: {[p for p, _ in fixed_positions]}")
            lines.append(f"    변하는 바이트 위치: {variable_positions}")
            if len(variable_positions) >= 8:
                lines.append("    ⚠ 앞 16바이트 대부분이 변함 → 패킷마다 IV/Nonce 포함 가능")
            elif len(variable_positions) == 0:
                lines.append("    ✓ 앞 16바이트 고정 → IV 없이 고정 키 암호화")
    lines.append("")

    # 7. 연속 패킷 XOR (같은 키라면 패킷 A XOR 패킷 B = PA XOR PB)
    lines.append(f"[7] 연속 패킷 XOR 엔트로피 (낮으면 같은 키 스트림)")
    if len(payloads) >= 4:
        xored_ents: list[float] = []
        for i in range(min(len(payloads) - 1, 10)):
            a, b = payloads[i], payloads[i + 1]
            mn = min(len(a), len(b))
            xb = bytes(a[j] ^ b[j] for j in range(mn))
            xored_ents.append(entropy(xb))
        avg_x = sum(xored_ents) / len(xored_ents)
        lines.append(f"    평균 XOR 엔트로피: {avg_x:.3f}")
        if avg_x < 6.5:
            lines.append("    ✓ 낮음 → 패킷간 키 스트림이 같을 가능성 (XOR 공격 가능)")
        else:
            lines.append("    ⚠ 높음 → 패킷마다 다른 키/IV 사용")
    lines.append("")

    # 8. 헥스 덤프 샘플 (첫 3패킷)
    lines.append(f"[8] 첫 3패킷 hex dump (앞 64B)")
    for i, p in enumerate(payloads[:3], 1):
        lines.append(f"  패킷 #{i} ({len(p)}B):")
        for off in range(0, min(64, len(p)), 16):
            chunk = p[off:off + 16]
            h = " ".join(f"{b:02X}" for b in chunk)
            a = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"    {off:04X}  {h:<47}  {a}")
        lines.append("")

    return "\n".join(lines)


# ── GUI ───────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"암호화 방식 진단 — 포트 {TARGET_PORT}")
        self.geometry("860x700")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._queue: list[bytes] = []
        self._payloads: list[bytes] = []

        self._build_ui()
        self._poll()

    def _build_ui(self) -> None:
        top = tk.Frame(self, padx=8, pady=5)
        top.pack(fill="x")

        self._btn_start = tk.Button(top, text="▶ 캡쳐 시작",
                                     bg="#2d7d2d", fg="white", command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중지", state="disabled",
                                    command=self._stop)
        self._btn_stop.pack(side="left", padx=2)

        self._btn_analyze = tk.Button(top, text="🔍 암호화 방식 분석",
                                       bg="#7d4d00", fg="white",
                                       command=self._analyze)
        self._btn_analyze.pack(side="left", padx=(16, 2))

        tk.Button(top, text="결과 복사", command=self._copy_result).pack(side="left", padx=4)
        tk.Button(top, text="초기화",    command=self._clear).pack(side="left", padx=2)

        self._lbl = tk.Label(top, text=f"대기 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 패킷 수 표시
        self._cnt_lbl = tk.Label(self, text="수집: 0개", font=("Consolas", 10))
        self._cnt_lbl.pack(pady=(4, 0))

        # 결과 텍스트
        frm = tk.Frame(self)
        frm.pack(fill="both", expand=True, padx=8, pady=6)

        self._result = tk.Text(frm, font=("Consolas", 9), state="disabled", wrap="none")
        sv = ttk.Scrollbar(frm, orient="vertical",   command=self._result.yview)
        sh = ttk.Scrollbar(frm, orient="horizontal", command=self._result.xview)
        self._result.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y")
        sh.pack(side="bottom", fill="x")
        self._result.pack(fill="both", expand=True)

        # 안내
        self._set_result(
            f"[안내]\n"
            f"1. '캡쳐 시작' 클릭\n"
            f"2. 게임에서 캐릭터 이동 / 채널 이동 등 활동\n"
            f"3. 패킷 20개 이상 수집 후 '암호화 방식 분석' 클릭\n"
            f"4. 결과를 복사해서 채팅에 붙여넣기\n\n"
            f"포트: {TARGET_PORT}\n"
        )

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
                self._lbl.config(text=f"중지 — {len(self._payloads)}개", fg="gray"),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _clear(self) -> None:
        with self._lock:
            self._queue.clear()
        self._payloads.clear()
        self._cnt_lbl.config(text="수집: 0개")
        self._set_result("초기화됨")

    # ── 폴링 ────────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for data in batch:
            self._payloads.append(data)
        if batch:
            n = len(self._payloads)
            self._cnt_lbl.config(text=f"수집: {n}개")
            self._lbl.config(text=f"캡쳐 중... {n}개 | 포트 {TARGET_PORT}", fg="#2d7d2d")
        self.after(200, self._poll)

    # ── 분석 ────────────────────────────────────────────────────────

    def _analyze(self) -> None:
        if not self._payloads:
            self._set_result("패킷이 없습니다. 먼저 캡쳐하세요.")
            return
        self._set_result(f"분석 중... ({len(self._payloads)}개 패킷)")

        def _do() -> None:
            report = analyze_packets(self._payloads)
            self.after(0, lambda: self._set_result(report))
        threading.Thread(target=_do, daemon=True).start()

    def _copy_result(self) -> None:
        text = self._result.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._lbl.config(text="복사됨!", fg="#1a6fba")
            self.after(2000, lambda: self._lbl.config(
                text=f"{'캡쳐 중' if self._sniffer else '중지'} — {len(self._payloads)}개",
                fg="#2d7d2d" if self._sniffer else "gray"))

    # ── 유틸 ────────────────────────────────────────────────────────

    def _set_result(self, text: str) -> None:
        self._result.config(state="normal")
        self._result.delete("1.0", "end")
        self._result.insert("1.0", text)
        self._result.config(state="disabled")

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
