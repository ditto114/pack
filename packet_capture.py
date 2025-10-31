"""패킷 캡쳐 UI 애플리케이션.

이 모듈은 Tkinter 기반의 간단한 사용자 인터페이스를 제공하여
네트워크 패킷을 캡쳐하고, 특정 IP 주소 기준 필터링 및 UTF-8 텍스트
디코딩 결과를 확인할 수 있도록 한다.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Optional

try:
    from scapy.all import IP, Raw, sniff  # type: ignore
except ImportError as exc:  # pragma: no cover - scapy 미설치 환경 대비
    raise SystemExit(
        "Scapy가 설치되어 있지 않습니다. 'pip install scapy' 명령으로 설치 후 다시 실행하세요."
    ) from exc


class PacketCaptureApp:
    """패킷 캡쳐 애플리케이션.

    Tkinter 위젯을 기반으로 캡쳐 시작/중지, IP 필터링, UTF-8 디코딩 결과
    확인 기능을 제공한다.
    """

    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        self.master.title("패킷 캡쳐 도구")
        self.packet_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None

        self._build_widgets()
        self._poll_queue()

    # ------------------------------------------------------------------
    # UI 구성
    def _build_widgets(self) -> None:
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # 필터 입력
        filter_frame = ttk.LabelFrame(main_frame, text="필터")
        filter_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        filter_frame.columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="대상 IP").grid(row=0, column=0, padx=(8, 4), pady=8)
        self.ip_entry = ttk.Entry(filter_frame)
        self.ip_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=8)
        ttk.Label(filter_frame, text="(비워두면 모든 패킷 캡쳐)").grid(row=0, column=2, padx=(0, 8))

        # 제어 버튼
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        button_frame.columnconfigure((0, 1), weight=1)

        self.start_button = ttk.Button(button_frame, text="캡쳐 시작", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=4, sticky="ew")
        self.stop_button = ttk.Button(button_frame, text="캡쳐 중지", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=4, sticky="ew")

        # 패킷 리스트
        packet_frame = ttk.LabelFrame(main_frame, text="캡쳐된 패킷")
        packet_frame.grid(row=2, column=0, sticky="nsew")
        packet_frame.columnconfigure(0, weight=1)
        packet_frame.rowconfigure(0, weight=1)

        self.packet_list = tk.Listbox(packet_frame, height=12)
        self.packet_list.grid(row=0, column=0, sticky="nsew")
        self.packet_list.bind("<<ListboxSelect>>", self._on_select_packet)

        scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_list.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.packet_list.configure(yscrollcommand=scrollbar.set)

        # 패킷 상세
        detail_frame = ttk.LabelFrame(main_frame, text="패킷 상세 및 UTF-8 내용")
        detail_frame.grid(row=3, column=0, sticky="nsew", pady=(8, 0))
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(0, weight=1)

        self.detail_text = tk.Text(detail_frame, height=10, wrap="word")
        self.detail_text.grid(row=0, column=0, sticky="nsew")
        detail_scroll = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.detail_text.yview)
        detail_scroll.grid(row=0, column=1, sticky="ns")
        self.detail_text.configure(yscrollcommand=detail_scroll.set, state=tk.DISABLED)

    # ------------------------------------------------------------------
    # 이벤트 핸들러
    def start_capture(self) -> None:
        if self.capture_thread and self.capture_thread.is_alive():
            messagebox.showinfo("알림", "이미 캡쳐가 진행 중입니다.")
            return

        self.stop_event.clear()
        ip_filter = self.ip_entry.get().strip()
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(ip_filter,),
            daemon=True,
        )
        self.capture_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_capture(self) -> None:
        if not self.capture_thread:
            return
        self.stop_event.set()
        self.capture_thread.join(timeout=1.0)
        self.capture_thread = None

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def _on_select_packet(self, _: tk.Event) -> None:
        selection = self.packet_list.curselection()
        if not selection:
            return
        index = selection[0]
        try:
            summary, payload = self.packet_list_data[index]
        except IndexError:  # pragma: no cover - 리스트 동기화 문제 방지용
            return

        self._set_detail_text(f"요약:\n{summary}\n\nUTF-8 내용:\n{payload}")

    # ------------------------------------------------------------------
    # 캡쳐 로직
    def _capture_packets(self, ip_filter: str) -> None:
        self.packet_list_data: list[tuple[str, str]] = []

        def packet_handler(packet) -> None:
            if self.stop_event.is_set():
                return
            if ip_filter and not self._packet_matches_ip(packet, ip_filter):
                return

            summary = packet.summary()
            payload = self._extract_payload(packet)
            self.packet_queue.put((summary, payload))

        try:
            sniff(  # type: ignore[call-arg]
                prn=packet_handler,
                stop_filter=lambda _: self.stop_event.is_set(),
                store=False,
            )
        except PermissionError:
            self.packet_queue.put(("[오류] 캡쳐 권한이 필요합니다. 관리자 권한으로 실행하세요.", ""))
        except OSError as exc:
            self.packet_queue.put((f"[오류] 캡쳐 도중 문제가 발생했습니다: {exc}", ""))

    def _packet_matches_ip(self, packet, ip_filter: str) -> bool:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            return ip_filter in (src, dst)
        return False

    @staticmethod
    def _extract_payload(packet) -> str:
        if Raw in packet:
            data = packet[Raw].load
            if isinstance(data, bytes):
                return data.decode("utf-8", errors="replace")
            return str(data)
        return "(페이로드 없음)"

    # ------------------------------------------------------------------
    # UI 보조 메서드
    def _poll_queue(self) -> None:
        while True:
            try:
                summary, payload = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            else:
                if not hasattr(self, "packet_list_data"):
                    self.packet_list_data = []
                self.packet_list_data.append((summary, payload))
                self.packet_list.insert(tk.END, summary)

        self.master.after(200, self._poll_queue)

    def _set_detail_text(self, text: str) -> None:
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, text)
        self.detail_text.config(state=tk.DISABLED)


def main() -> None:
    root = tk.Tk()
    app = PacketCaptureApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
