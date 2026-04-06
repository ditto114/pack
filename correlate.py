"""패킷 패턴 상관분석 도구.

복호화 없이 암호화된 패킷의 외형적 특징으로 패킷 유형 분류:
  - 크기 (payload length)
  - 비암호화 헤더의 커맨드 바이트 (byte 12)
  - 도착 타이밍

사용법:
  1. 캡쳐 시작
  2. 게임에서 특정 행동 직전 "이벤트 마킹" 버튼 클릭
      (채널 이동, 맵 이동, 로그인/아웃, 일반 이동 등)
  3. 행동 후 다시 마킹
  4. 이벤트 전후 패킷 패턴 비교
  5. 특정 크기 범위나 유형이 이벤트와 상관관계 있으면 → 해당 패킷 유형 식별
"""

from __future__ import annotations

import struct
import sys
import threading
import time
import tkinter as tk
from collections import Counter, defaultdict
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

# ── 패킷 파서 ────────────────────────────────────────────────────────

def parse_pkt(raw: bytes, ts: float) -> Optional[dict]:
    """패킷 헤더 파싱 → dict. 매직 없으면 None."""
    if len(raw) < HEADER_LEN:
        return None
    # 매직 확인 (byte 8-11 = FF FF FF FF)
    has_magic = raw[8:12] == b"\xff\xff\xff\xff"
    if not has_magic:
        return None
    pay_len = struct.unpack_from("<I", raw, 4)[0]
    cmd     = raw[12]
    pkt_id  = raw[0:4].hex()
    session = raw[17:25].hex()
    payload = raw[HEADER_LEN: HEADER_LEN + pay_len]
    # 방향 추정: 서버→클라이언트 or 클라이언트→서버 구분 어려움
    return {
        "ts":      ts,
        "raw_len": len(raw),
        "pay_len": pay_len,
        "cmd":     cmd,
        "pkt_id":  pkt_id,
        "session": session,
        "payload": payload,
        # 페이로드 첫 8바이트 hex (암호화됐지만 패턴 비교용)
        "pay_head": payload[:8].hex() if len(payload) >= 8 else "",
    }

# ── 이벤트 타임라인 ──────────────────────────────────────────────────

class Event:
    def __init__(self, ts: float, label: str) -> None:
        self.ts    = ts
        self.label = label

# ── GUI ──────────────────────────────────────────────────────────────

PRESET_EVENTS = [
    "채널 이동 직전",
    "채널 이동 완료",
    "맵 이동 직전",
    "맵 이동 완료",
    "채팅 전송",
    "스킬 사용",
    "몬스터 처치",
    "아이템 획득",
    "다른 플레이어 입장",
    "다른 플레이어 퇴장",
    "기타",
]

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"패킷 패턴 상관분석 | 포트 {TARGET_PORT}")
        self.geometry("1200x820")

        self._sniffer: Optional[AsyncSniffer] = None
        self._lock     = threading.Lock()
        self._queue:   list[dict] = []
        self._packets: list[dict] = []
        self._events:  list[Event] = []
        self._t0 = time.time()

        self._build_ui()
        self._poll()

    # ── UI ──────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # 상단
        top = tk.Frame(self, padx=8, pady=4)
        top.pack(fill="x")

        self._btn_start = tk.Button(top, text="▶ 캡쳐 시작",
                                     bg="#2d7d2d", fg="white", command=self._start)
        self._btn_start.pack(side="left", padx=2)
        self._btn_stop = tk.Button(top, text="■ 중지", state="disabled",
                                    command=self._stop)
        self._btn_stop.pack(side="left", padx=2)
        tk.Button(top, text="초기화", command=self._clear).pack(side="left", padx=(8,2))

        self._lbl = tk.Label(top, text=f"대기 | 포트 {TARGET_PORT}", fg="gray")
        self._lbl.pack(side="right", padx=8)

        # 이벤트 마킹 패널
        ef = tk.LabelFrame(self, text="★ 이벤트 마킹 (게임에서 행동 직전/후에 클릭)", padx=6, pady=4)
        ef.pack(fill="x", padx=8, pady=(0, 4))

        ev_top = tk.Frame(ef); ev_top.pack(fill="x")
        tk.Label(ev_top, text="이벤트 종류:").pack(side="left")
        self._ev_var = tk.StringVar(value=PRESET_EVENTS[0])
        ev_cb = ttk.Combobox(ev_top, textvariable=self._ev_var,
                             values=PRESET_EVENTS, width=20, state="readonly")
        ev_cb.pack(side="left", padx=(4,8))
        tk.Label(ev_top, text="메모:").pack(side="left")
        self._ev_note = tk.StringVar()
        tk.Entry(ev_top, textvariable=self._ev_note, width=20).pack(side="left", padx=(4,8))
        tk.Button(ev_top, text="📌 이벤트 마킹", bg="#b85000", fg="white",
                  font=("", 10, "bold"), command=self._mark_event).pack(side="left")

        # 이벤트 목록
        ev_row = tk.Frame(ef); ev_row.pack(fill="x", pady=(4,0))
        ev_cols = ("시각", "이벤트", "메모", "직후10초 패킷수")
        self._ev_tree = ttk.Treeview(ev_row, columns=ev_cols,
                                      show="headings", height=3)
        for c, w in [("시각",80),("이벤트",160),("메모",140),("직후10초 패킷수",110)]:
            self._ev_tree.heading(c, text=c)
            self._ev_tree.column(c, width=w, stretch=False)
        ev_sb = ttk.Scrollbar(ev_row, orient="vertical", command=self._ev_tree.yview)
        self._ev_tree.configure(yscrollcommand=ev_sb.set)
        ev_sb.pack(side="right", fill="y")
        self._ev_tree.pack(fill="x")
        self._ev_tree.bind("<<TreeviewSelect>>", self._on_ev_select)

        # 본문: 좌(타임라인) + 우(분석)
        pw = tk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8, pady=(0,6))

        # 좌: 패킷 타임라인
        left = tk.Frame(pw); pw.add(left, minsize=380)
        lbl_frame = tk.Frame(left); lbl_frame.pack(fill="x")
        tk.Label(lbl_frame, text="패킷 타임라인", font=("", 9, "bold")).pack(side="left")
        tk.Button(lbl_frame, text="선택 이벤트 ±20초 필터",
                  command=self._filter_event_window).pack(side="right")
        tk.Button(lbl_frame, text="전체 보기",
                  command=self._show_all).pack(side="right", padx=4)

        p_cols = ("T+s", "크기", "페이로드", "CMD", "세션", "payload_head")
        self._pkt_tree = ttk.Treeview(left, columns=p_cols,
                                       show="headings", height=28)
        for c, w, a in [("T+s",70,"e"),("크기",60,"e"),("페이로드",64,"e"),
                        ("CMD",40,"c"),("세션",80,"c"),("payload_head",140,"w")]:
            self._pkt_tree.heading(c, text=c)
            self._pkt_tree.column(c, width=w, anchor=a, stretch=False)
        # 이벤트 태그 색상
        self._pkt_tree.tag_configure("event", background="#ffe0b0")
        self._pkt_tree.tag_configure("small",  foreground="#888888")
        self._pkt_tree.tag_configure("large",  foreground="#1a6fba", font=("","8","bold"))

        psb = ttk.Scrollbar(left, orient="vertical", command=self._pkt_tree.yview)
        self._pkt_tree.configure(yscrollcommand=psb.set)
        psb.pack(side="right", fill="y")
        self._pkt_tree.pack(fill="both", expand=True)

        # 우: 분석 탭
        right = tk.Frame(pw); pw.add(right, minsize=480)
        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True)
        self._stat_txt = self._make_tab(nb, "전체 통계")
        self._cmp_txt  = self._make_tab(nb, "이벤트 전후 비교")
        self._grp_txt  = self._make_tab(nb, "크기별 그룹")
        self._cmd_txt  = self._make_tab(nb, "CMD별 통계")
        self._hint_txt = self._make_tab(nb, "💡 해석 힌트")
        self._nb = nb

        self._set_text(self._hint_txt, HINT_TEXT)

        # 분석 버튼
        btn_row = tk.Frame(right); btn_row.pack(fill="x", pady=(4,0))
        tk.Button(btn_row, text="전체 통계 갱신",
                  command=self._update_stats).pack(side="left", padx=2)
        tk.Button(btn_row, text="CMD별 통계",
                  command=self._update_cmd).pack(side="left", padx=2)
        tk.Button(btn_row, text="크기 그룹화",
                  command=self._update_groups).pack(side="left", padx=2)

    def _make_tab(self, nb: ttk.Notebook, label: str) -> tk.Text:
        frm = tk.Frame(nb); nb.add(frm, text=label)
        txt = tk.Text(frm, font=("Consolas", 8), state="disabled", wrap="none")
        sv  = ttk.Scrollbar(frm, orient="vertical",   command=txt.yview)
        sh  = ttk.Scrollbar(frm, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sv.set, xscrollcommand=sh.set)
        sv.pack(side="right", fill="y")
        sh.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        return txt

    # ── 캡쳐 ────────────────────────────────────────────────────────

    def _lfilter(self, pkt) -> bool:
        if TCP not in pkt or Raw not in pkt: return False
        t = pkt[TCP]; return TARGET_PORT in (t.sport, t.dport)

    def _handler(self, pkt) -> None:
        raw = bytes(pkt[Raw].load)
        ts  = time.time()
        with self._lock:
            self._queue.append((raw, ts))

    def _start(self) -> None:
        self._t0 = time.time()
        self._sniffer = AsyncSniffer(store=False, prn=self._handler,
                                     lfilter=self._lfilter)
        try:
            self._sniffer.start()
        except PermissionError:
            import tkinter.messagebox as mb
            mb.showerror("권한 오류", "관리자 권한 필요"); self._sniffer = None; return
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._lbl.config(text=f"캡쳐 중 | 포트 {TARGET_PORT}", fg="#2d7d2d")

    def _stop(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        self._btn_stop.config(state="disabled")
        def _do():
            if sniffer:
                try: sniffer.stop(); sniffer.join(timeout=3)
                except Exception: pass
            self.after(0, lambda: (
                self._btn_start.config(state="normal"),
                self._lbl.config(text=f"중지 — {len(self._packets)}개", fg="gray"),
            ))
        threading.Thread(target=_do, daemon=True).start()

    def _clear(self) -> None:
        with self._lock: self._queue.clear()
        self._packets.clear(); self._events.clear()
        self._t0 = time.time()
        for t in (self._pkt_tree, self._ev_tree):
            for iid in t.get_children(): t.delete(iid)
        for w in (self._stat_txt, self._cmp_txt, self._grp_txt, self._cmd_txt):
            self._set_text(w, "")

    # ── 폴링 ────────────────────────────────────────────────────────

    def _poll(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for raw, ts in batch:
            p = parse_pkt(raw, ts)
            if p is None:
                continue
            idx = len(self._packets)
            self._packets.append(p)
            dt  = p["ts"] - self._t0
            tag = "large" if p["pay_len"] > 400 else ("small" if p["pay_len"] < 80 else "")
            self._pkt_tree.insert("", "end", iid=str(idx), tags=(tag,),
                values=(f"{dt:+.2f}", f"{p['raw_len']}B",
                        f"{p['pay_len']}B", f"{p['cmd']:02X}",
                        p["session"][:6], p["pay_head"]))
            self._pkt_tree.see(str(idx))
        if batch:
            n = len(self._packets)
            self._lbl.config(text=f"캡쳐 중 {n}개", fg="#2d7d2d")
        self.after(150, self._poll)

    # ── 이벤트 마킹 ──────────────────────────────────────────────────

    def _mark_event(self) -> None:
        ts    = time.time()
        label = self._ev_var.get()
        note  = self._ev_note.get().strip()
        ev    = Event(ts, label)
        self._events.append(ev)
        dt    = ts - self._t0

        # 타임라인에 이벤트 구분선 삽입
        sep_id = f"ev_{len(self._events)}"
        self._pkt_tree.insert("", "end", iid=sep_id, tags=("event",),
            values=(f"{dt:+.2f}", "── 이벤트 ──",
                    label + (f" [{note}]" if note else ""),
                    "", "", ""))

        # 이벤트 목록에 추가
        ev_id = str(len(self._events))
        self._ev_tree.insert("", "end", iid=ev_id,
            values=(f"{dt:.1f}s", label, note, "..."))

        self._lbl.config(text=f"이벤트 마킹: {label} @ T+{dt:.1f}s", fg="#b85000")
        # 5초 후 이벤트 직후 패킷수 업데이트
        self.after(10000, lambda: self._update_ev_count(ev_id, ev))

    def _update_ev_count(self, ev_id: str, ev: Event) -> None:
        count = sum(1 for p in self._packets
                    if ev.ts <= p["ts"] <= ev.ts + 10)
        try:
            self._ev_tree.set(ev_id, "직후10초 패킷수", str(count))
        except Exception:
            pass

    def _on_ev_select(self, _: object) -> None:
        sel = self._ev_tree.selection()
        if not sel: return
        idx = int(sel[0]) - 1
        if not (0 <= idx < len(self._events)): return
        ev  = self._events[idx]
        self._analyze_event(ev)

    def _filter_event_window(self) -> None:
        sel = self._ev_tree.selection()
        if not sel: return
        idx = int(sel[0]) - 1
        if not (0 <= idx < len(self._events)): return
        ev  = self._events[idx]
        win_start = ev.ts - 20
        win_end   = ev.ts + 20
        # 필터: 이 창의 패킷만 표시
        for iid in self._pkt_tree.get_children():
            self._pkt_tree.delete(iid)
        for i, p in enumerate(self._packets):
            if win_start <= p["ts"] <= win_end:
                dt  = p["ts"] - self._t0
                tag = "large" if p["pay_len"] > 400 else ("small" if p["pay_len"] < 80 else "")
                self._pkt_tree.insert("", "end", iid=str(i), tags=(tag,),
                    values=(f"{dt:+.2f}", f"{p['raw_len']}B",
                            f"{p['pay_len']}B", f"{p['cmd']:02X}",
                            p["session"][:6], p["pay_head"]))
        # 이벤트 선 표시
        ev_dt = ev.ts - self._t0
        self._pkt_tree.insert("", "end", tags=("event",),
            values=(f"{ev_dt:+.2f}", "── ★ 이벤트 ──", ev.label, "", "", ""))

    def _show_all(self) -> None:
        for iid in self._pkt_tree.get_children():
            self._pkt_tree.delete(iid)
        for i, p in enumerate(self._packets):
            dt  = p["ts"] - self._t0
            tag = "large" if p["pay_len"] > 400 else ("small" if p["pay_len"] < 80 else "")
            self._pkt_tree.insert("", "end", iid=str(i), tags=(tag,),
                values=(f"{dt:+.2f}", f"{p['raw_len']}B",
                        f"{p['pay_len']}B", f"{p['cmd']:02X}",
                        p["session"][:6], p["pay_head"]))
        for j, ev in enumerate(self._events):
            ev_dt = ev.ts - self._t0
            sep_id = f"ev_{j+1}"
            self._pkt_tree.insert("", "end", iid=sep_id, tags=("event",),
                values=(f"{ev_dt:+.2f}", "── 이벤트 ──", ev.label, "", "", ""))

    # ── 분석 ────────────────────────────────────────────────────────

    def _analyze_event(self, ev: Event) -> None:
        """이벤트 기준 전 30초 / 후 30초 패킷 분포 비교."""
        before = [p for p in self._packets if ev.ts - 30 <= p["ts"] < ev.ts]
        after  = [p for p in self._packets if ev.ts <= p["ts"] < ev.ts + 30]

        def stats(pkts: list[dict]) -> str:
            if not pkts:
                return "  없음"
            sizes   = [p["pay_len"] for p in pkts]
            cmds    = Counter(p["cmd"] for p in pkts)
            rate    = len(pkts) / 30.0
            lines   = [
                f"  패킷수: {len(pkts)} ({rate:.1f}/초)",
                f"  크기: min={min(sizes)} max={max(sizes)} avg={sum(sizes)/len(sizes):.0f}B",
                f"  CMD 분포: {dict(cmds.most_common(5))}",
                f"  크기 분포:",
            ]
            buckets = Counter()
            for s in sizes:
                b = (s // 100) * 100
                buckets[b] += 1
            for b in sorted(buckets):
                lines.append(f"    {b:4d}~{b+99}B : {'█'*buckets[b]} ({buckets[b]}개)")
            return "\n".join(lines)

        # 새로 등장한 크기
        before_sizes = set(p["pay_len"] for p in before)
        after_sizes  = set(p["pay_len"] for p in after)
        new_sizes    = after_sizes - before_sizes
        gone_sizes   = before_sizes - after_sizes

        lines = [
            f"=== 이벤트 분석: {ev.label} @ T+{ev.ts-self._t0:.1f}s ===\n",
            f"[이벤트 전 30초]",
            stats(before),
            f"\n[이벤트 후 30초]",
            stats(after),
            f"\n[변화 분석]",
            f"  이벤트 후 새로 등장한 크기: {sorted(new_sizes)}",
            f"  이벤트 후 사라진 크기:     {sorted(gone_sizes)}",
        ]

        # 이벤트 직후 급등 패킷 탐지 (처음 5초)
        burst = [p for p in self._packets if ev.ts <= p["ts"] < ev.ts + 5]
        if burst:
            lines.append(f"\n[이벤트 직후 5초 버스트: {len(burst)}개 패킷]")
            for p in burst:
                dt = p["ts"] - ev.ts
                lines.append(f"  +{dt:.2f}s  {p['pay_len']:4d}B  CMD={p['cmd']:02X}  {p['pay_head']}")

        self._set_text(self._cmp_txt, "\n".join(lines))
        self._nb.select(1)

    def _update_stats(self) -> None:
        if not self._packets:
            self._set_text(self._stat_txt, "패킷 없음"); return
        total   = len(self._packets)
        sizes   = [p["pay_len"] for p in self._packets]
        dur     = self._packets[-1]["ts"] - self._packets[0]["ts"] if total > 1 else 1
        rate    = total / max(dur, 1)
        lines   = [
            f"=== 전체 통계 ({total}개 패킷, {dur:.0f}초) ===\n",
            f"평균 속도: {rate:.1f} 패킷/초",
            f"크기 범위: {min(sizes)} ~ {max(sizes)}B",
            f"평균 크기: {sum(sizes)/total:.0f}B",
            f"\n[CMD 바이트 분포]",
        ]
        cmd_cnt = Counter(p["cmd"] for p in self._packets)
        for cmd, cnt in cmd_cnt.most_common():
            lines.append(f"  CMD 0x{cmd:02X}: {cnt:4d}개 ({cnt/total:.1%})")
        lines.append("\n[페이로드 크기 히스토그램 (50B 단위)]")
        buckets: Counter = Counter()
        for s in sizes:
            b = (s // 50) * 50
            buckets[b] += 1
        for b in sorted(buckets):
            bar = "█" * min(buckets[b], 40)
            lines.append(f"  {b:5d}~{b+49}B: {bar} ({buckets[b]})")
        lines.append("\n[세션별 패킷 수]")
        sess_cnt = Counter(p["session"][:6] for p in self._packets)
        for s, c in sess_cnt.most_common():
            lines.append(f"  {s}: {c}개")
        self._set_text(self._stat_txt, "\n".join(lines))
        self._nb.select(0)

    def _update_cmd(self) -> None:
        if not self._packets:
            return
        lines = ["=== CMD 바이트별 상세 통계 ===\n"]
        cmd_pkts: dict[int, list[dict]] = defaultdict(list)
        for p in self._packets:
            cmd_pkts[p["cmd"]].append(p)
        for cmd in sorted(cmd_pkts):
            pkts   = cmd_pkts[cmd]
            sizes  = [p["pay_len"] for p in pkts]
            lines.append(f"CMD 0x{cmd:02X}  ({len(pkts)}개)")
            lines.append(f"  크기: min={min(sizes)} max={max(sizes)} avg={sum(sizes)/len(sizes):.0f}B")
            size_dist = Counter(sizes)
            for s, c in size_dist.most_common(5):
                lines.append(f"    {s}B × {c}")
            # 고유 payload_head 수
            heads = set(p["pay_head"] for p in pkts)
            lines.append(f"  고유 payload_head: {len(heads)}종")
            if len(heads) <= 5:
                for h in sorted(heads):
                    lines.append(f"    {h}")
            lines.append("")
        self._set_text(self._cmd_txt, "\n".join(lines))
        self._nb.select(3)

    def _update_groups(self) -> None:
        if not self._packets:
            return
        # 크기를 근접 클러스터로 묶기
        lines = ["=== 크기별 그룹 (정확한 크기 기준) ===\n"]
        size_groups: dict[int, list[dict]] = defaultdict(list)
        for p in self._packets:
            size_groups[p["pay_len"]].append(p)
        lines.append(f"{'크기':>6}  {'개수':>5}  {'CMD분포':30}  payload_head 샘플")
        lines.append("─" * 90)
        for sz in sorted(size_groups, key=lambda s: -len(size_groups[s])):
            pkts    = size_groups[sz]
            cmd_d   = Counter(p["cmd"] for p in pkts)
            cmd_str = " ".join(f"{c:02X}×{n}" for c, n in cmd_d.most_common(3))
            head_ex = pkts[0]["pay_head"]
            lines.append(f"{sz:6d}B  {len(pkts):5d}  {cmd_str:30}  {head_ex}")
        self._set_text(self._grp_txt, "\n".join(lines))
        self._nb.select(2)

    # ── 유틸 ────────────────────────────────────────────────────────

    def _set_text(self, w: tk.Text, text: str) -> None:
        w.config(state="normal"); w.delete("1.0","end")
        w.insert("1.0", text); w.config(state="disabled")

    def on_close(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        self.destroy()
        if sniffer:
            try: sniffer.stop()
            except Exception: pass


# ── 힌트 텍스트 ──────────────────────────────────────────────────────

HINT_TEXT = """
💡 패킷 상관분석 해석 가이드
══════════════════════════════════════════════════════════

【채널/맵 이동 이벤트】
  기대 패턴:
  - 이동 직후 큰 패킷(>500B) 1~3개 폭발적 등장
    → 새 채널/맵의 플레이어 목록 일괄 전송으로 추정
  - 이동 전: 작은 패킷들(상태 업데이트, 위치 등)
  - 이동 후: 큰 패킷 → 플레이어 수만큼 이어지는 중간 패킷들

  ★ ex3.txt/ex4.txt와 연결:
    - 이전 데이터에서 가장 큰 패킷: 여러 플레이어 정보 포함
    - 각 플레이어 → ~100~150B 정도의 레코드
    - 20명 채널 = ~2000~3000B 패킷 (여러 TCP 세그먼트로 분할될 수 있음)

【일반 이동/행동 이벤트】
  기대 패턴:
  - 소형 패킷 연속 (위치/상태 업데이트)
  - 크기 40~120B, CMD가 일정

【다른 플레이어 입장/퇴장】
  기대 패턴:
  - 특정 고유 크기의 패킷 1개 등장
  - 입장: 해당 플레이어 전체 상태 (이름+맵+레벨 등)
  - 퇴장: 짧은 패킷 (ID만 포함)

【채팅 전송】
  기대 패턴:
  - 채팅 텍스트 길이에 비례하는 패킷 1개
  - 같은 CMD 바이트이지만 크기가 메시지 길이만큼 가변

══════════════════════════════════════════════════════════
【분석 전략】
  1. 채널 이동을 여러 번 반복하면서 이벤트 마킹
  2. "이벤트 전후 비교" 탭에서 매번 새로 등장하는 크기 파악
  3. 그 크기가 항상 같다면 → "플레이어 목록" 패킷 유형 확정
  4. "크기별 그룹" 탭에서 해당 크기의 CMD 바이트 확인
  5. CMD 바이트가 다른 패킷과 다르다면 → 패킷 유형 분류 성공

  분류 성공 후: 해당 크기/CMD 조합을 hook_packets.py 필터에 추가해서
  해당 유형만 캡쳐 → 복호화 집중 공격 가능
"""


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
