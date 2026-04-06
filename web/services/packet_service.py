"""패킷 캡쳐 서비스 — Scapy AsyncSniffer 래핑."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import psutil

from scapy.all import (  # type: ignore
    AsyncSniffer,
    Ether,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    send,
    sendp,
)

from capture_app.models import FilterConfig, PacketDisplay

from ..db import create_session, insert_packets, stop_session


class PacketCaptureService:
    """Scapy 기반 패킷 캡쳐를 관리한다."""

    DEFAULT_MAX_PACKETS = 500

    def __init__(self) -> None:
        self.sniffer: Optional[AsyncSniffer] = None
        self.stop_event = threading.Event()
        self.packet_counter = 0
        self.packet_list: list[PacketDisplay] = []
        self.local_addresses = self._detect_local_addresses()
        self.session_id: Optional[str] = None
        # asyncio queue for WebSocket broadcast
        self._ws_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        # batch buffer for DB inserts
        self._db_buffer: list[dict[str, Any]] = []
        self._db_lock = threading.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        # PID-based client identification
        self._port_pid_cache: dict[int, Optional[int]] = {}
        self._pid_client_map: dict[int, int] = {}
        self._client_counter = 0
        # 전체 port→pid 매핑 (주기적 갱신)
        self._global_port_map: dict[int, int] = {}
        self._global_port_map_time: float = 0.0
        self._GLOBAL_PORT_MAP_TTL: float = 5.0  # 초
        # PID capture filter (None = no filter)
        self._filter_pid: Optional[int] = None

    @property
    def is_running(self) -> bool:
        return self.sniffer is not None and self.sniffer.running

    # ── public API ────────────────────────────────────────────────

    async def start(
        self,
        ip_text: str = "",
        port_text: str = "",
        text_filter: str = "",
        max_packets: int = 500,
        pid_text: str = "",
    ) -> dict[str, Any]:
        if self.is_running:
            return {"error": "이미 캡쳐가 진행 중입니다."}

        # PID 필터 파싱
        if pid_text:
            if not pid_text.strip().isdigit():
                return {"error": "PID는 양의 정수여야 합니다."}
            self._filter_pid = int(pid_text.strip())
        else:
            self._filter_pid = None

        filter_config = self._build_filter_config(ip_text, port_text)

        # create DB session
        port_int = filter_config.port
        session = create_session(
            filter_ip=ip_text,
            filter_port=port_int,
            filter_text=text_filter,
            max_packets=max_packets,
        )
        self.session_id = session["id"]

        self.packet_list.clear()
        self.packet_counter = 0
        self.stop_event.clear()
        self._port_pid_cache.clear()
        self._pid_client_map.clear()
        self._client_counter = 0
        # _filter_pid는 위에서 이미 설정됨

        self.sniffer = AsyncSniffer(
            store=False,
            prn=self._packet_handler,
            lfilter=lambda pkt: self._packet_matches_filter(pkt, filter_config),
        )

        try:
            self.sniffer.start()
        except PermissionError:
            self.sniffer = None
            return {"error": "캡쳐 권한이 필요합니다. 관리자 권한으로 실행하세요."}
        except OSError as exc:
            self.sniffer = None
            return {"error": f"캡쳐 시작 실패: {exc}"}

        # start periodic DB flush
        loop = asyncio.get_event_loop()
        self._flush_task = loop.create_task(self._periodic_flush())

        return {"status": "started", "session_id": self.session_id}

    async def stop(self) -> dict[str, Any]:
        if not self.sniffer:
            return {"status": "not_running"}
        self.stop_event.set()
        try:
            self.sniffer.stop()
            self.sniffer.join()
        except Exception:
            pass
        finally:
            self.sniffer = None
            self.stop_event.clear()
        if self._flush_task:
            self._flush_task.cancel()
            self._flush_task = None
        # flush remaining
        self._flush_db_buffer()
        if self.session_id:
            stop_session(self.session_id)
        return {"status": "stopped", "session_id": self.session_id}

    def get_status(self) -> dict[str, Any]:
        return {
            "running": self.is_running,
            "session_id": self.session_id,
            "packet_count": self.packet_counter,
        }

    async def get_ws_packet(self) -> dict[str, Any]:
        return await self._ws_queue.get()

    def resend_packet(self, packet_display: PacketDisplay) -> dict[str, str]:
        raw = packet_display.raw_packet
        if raw is None:
            return {"error": "원본 패킷 데이터가 없어 다시 보낼 수 없습니다."}
        try:
            pkt = raw.copy()
        except Exception:
            pkt = raw
        try:
            if hasattr(pkt, "haslayer") and pkt.haslayer(Ether):
                sendp(pkt, verbose=False)
            else:
                send(pkt, verbose=False)
        except PermissionError:
            return {"error": "패킷을 송신하려면 관리자 권한이 필요합니다."}
        except Exception as exc:
            return {"error": f"패킷 다시 보내기에 실패했습니다: {exc}"}
        return {"status": "sent"}

    # ── packet handler (runs in sniffer thread) ───────────────────

    def _packet_handler(self, packet: Any) -> None:
        if self.stop_event.is_set():
            return

        payload = self._extract_payload_bytes(packet)
        summary = packet.summary()
        direction = self._determine_direction(packet)
        local_port = self._extract_local_port(packet, direction)
        client_id, client_pid = self._resolve_client(local_port)

        # PID 필터 적용
        if self._filter_pid is not None and client_pid != self._filter_pid:
            return

        utf8_text = None
        if payload:
            try:
                utf8_text = payload.decode("utf-8")
            except UnicodeDecodeError:
                utf8_text = payload.decode("utf-8", errors="replace")
        preview = self._extract_hangul_preview(utf8_text)

        self.packet_counter += 1
        captured_at = time.time()

        pkt = PacketDisplay(
            summary=summary,
            payload=payload,
            utf8_text=utf8_text,
            preview=preview,
            direction=direction,
            identifier=self.packet_counter,
            captured_at=captured_at,
            raw_packet=packet.copy(),
        )
        self.packet_list.insert(0, pkt)

        # trim in-memory list
        while len(self.packet_list) > self.DEFAULT_MAX_PACKETS:
            self.packet_list.pop()

        # build JSON-safe dict for WS broadcast
        ws_data = {
            "id": pkt.identifier,
            "summary": summary,
            "direction": direction,
            "preview": preview,
            "captured_at": captured_at,
            "utf8_text": (utf8_text or "")[:2000],
            "payload_hex": payload.hex() if payload else None,
            "client_id": client_id,
            "client_pid": client_pid,
        }
        try:
            self._ws_queue.put_nowait(ws_data)
        except asyncio.QueueFull:
            pass

        # buffer for DB batch insert
        db_row = {
            "session_id": self.session_id,
            "captured_at": datetime.fromtimestamp(captured_at, tz=timezone.utc).isoformat(),
            "summary": summary,
            "direction": direction,
            "preview": preview,
            "utf8_text": (utf8_text or "")[:4000],
            "payload_hex": payload.hex() if payload else None,
            "client_id": client_id,
            "client_pid": client_pid,
        }
        with self._db_lock:
            self._db_buffer.append(db_row)

    # ── DB flush ──────────────────────────────────────────────────

    async def _periodic_flush(self) -> None:
        try:
            while True:
                await asyncio.sleep(1.0)
                self._flush_db_buffer()
        except asyncio.CancelledError:
            pass

    def _flush_db_buffer(self) -> None:
        with self._db_lock:
            if not self._db_buffer:
                return
            batch = list(self._db_buffer)
            self._db_buffer.clear()
        try:
            insert_packets(batch)
        except Exception:
            pass  # best-effort

    # ── filter / direction helpers ────────────────────────────────

    @staticmethod
    def _build_filter_config(ip_text: str, port_text: str) -> FilterConfig:
        networks = []
        if ip_text:
            try:
                networks.append(ipaddress.ip_network(ip_text, strict=False))
            except ValueError:
                raise ValueError("유효한 IP 주소 또는 CIDR 표기법이 아닙니다.")
        port = None
        if port_text:
            if not port_text.isdigit():
                raise ValueError("포트 값은 0~65535 범위의 숫자여야 합니다.")
            port = int(port_text)
            if not 0 <= port <= 65535:
                raise ValueError("포트 값은 0~65535 범위여야 합니다.")
        return FilterConfig(networks=networks, port=port)

    @staticmethod
    def _packet_matches_filter(packet: Any, fc: FilterConfig) -> bool:
        network_ok = True
        if fc.networks:
            addrs: list[str] = []
            if IP in packet:
                addrs = [packet[IP].src, packet[IP].dst]
            if not addrs and IPv6 in packet:
                addrs = [packet[IPv6].src, packet[IPv6].dst]
            if not addrs:
                network_ok = False
            else:
                network_ok = False
                for net in fc.networks:
                    for a in addrs:
                        try:
                            if ipaddress.ip_address(a) in net:
                                network_ok = True
                                break
                        except ValueError:
                            continue
                    if network_ok:
                        break

        port_ok = True
        if fc.port is not None:
            port_ok = False
            if TCP in packet:
                t = packet[TCP]
                port_ok = fc.port in (t.sport, t.dport)
            if not port_ok and UDP in packet:
                u = packet[UDP]
                port_ok = fc.port in (u.sport, u.dport)

        return network_ok and port_ok

    @staticmethod
    def _extract_payload_bytes(packet: Any) -> Optional[bytes]:
        if Raw in packet:
            data = packet[Raw].load
            if isinstance(data, bytes):
                return data
            if data is None:
                return None
            return bytes(str(data), "utf-8", "replace")
        return None

    def _determine_direction(self, packet: Any) -> str:
        src = dst = None
        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        elif IPv6 in packet:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        if not src or not dst:
            return "unknown"
        src = self._normalize_ip(src)
        dst = self._normalize_ip(dst)
        if src in self.local_addresses and dst not in self.local_addresses:
            return "outgoing"
        if dst in self.local_addresses and src not in self.local_addresses:
            return "incoming"
        if src in self.local_addresses and dst in self.local_addresses:
            return "internal"
        return "unknown"

    def _extract_local_port(self, packet: Any, direction: str) -> Optional[int]:
        """패킷에서 로컬 측 포트를 추출한다.

        outgoing → src port, incoming → dst port.
        """
        sport = dport = None
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
        if sport is None:
            return None
        if direction == "outgoing":
            return sport
        if direction == "incoming":
            return dport
        # internal / unknown: src 기본
        return sport

    def _resolve_client(
        self, local_port: Optional[int]
    ) -> tuple[Optional[int], Optional[int]]:
        """로컬 포트로부터 (client_id, pid)를 반환한다.

        새 포트가 발견되면 psutil로 PID를 조회하고 캐싱한다.
        같은 PID면 포트가 바뀌어도 동일한 client_id를 유지한다.
        """
        if local_port is None:
            return None, None

        # 포트 → PID 캐시 조회, 없으면 psutil로 조회
        if local_port not in self._port_pid_cache:
            self._port_pid_cache[local_port] = self._lookup_pid_by_port(local_port)

        pid = self._port_pid_cache[local_port]
        if pid is None:
            return None, None

        # PID → 클라이언트 번호 매핑
        if pid not in self._pid_client_map:
            self._client_counter += 1
            self._pid_client_map[pid] = self._client_counter

        return self._pid_client_map[pid], pid

    def _refresh_global_port_map(self) -> None:
        """psutil.net_connections()를 한 번 호출하여 전체 port→pid 매핑을 갱신한다."""
        now = time.time()
        if now - self._global_port_map_time < self._GLOBAL_PORT_MAP_TTL:
            return
        try:
            mapping: dict[int, int] = {}
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr and conn.pid:
                    mapping[conn.laddr.port] = conn.pid
            self._global_port_map = mapping
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
        self._global_port_map_time = now

    def _lookup_pid_by_port(self, port: int) -> Optional[int]:
        """캐싱된 매핑에서 포트→PID를 조회한다."""
        self._refresh_global_port_map()
        return self._global_port_map.get(port)

    @staticmethod
    def _normalize_ip(addr: str) -> str:
        return addr.split("%", 1)[0] if "%" in addr else addr

    @staticmethod
    def _detect_local_addresses() -> set[str]:
        addresses: set[str] = {"127.0.0.1", "::1"}
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                normalized = addr.split("%", 1)[0] if "%" in addr else addr
                if normalized:
                    addresses.add(normalized)
        except OSError:
            pass
        for family, target in [
            (socket.AF_INET, ("8.8.8.8", 80)),
            (socket.AF_INET6, ("2001:4860:4860::8888", 80)),
        ]:
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.2)
                    s.connect(target)
                    addr = s.getsockname()[0]
                    addresses.add(addr.split("%", 1)[0] if "%" in addr else addr)
            except OSError:
                pass
        return addresses

    @staticmethod
    def _extract_hangul_preview(text: Optional[str], limit: int = 10) -> str:
        if not text:
            return ""
        preview_chars: list[str] = []
        for ch in text:
            if "\uAC00" <= ch <= "\uD7A3":
                preview_chars.append(ch)
                if len(preview_chars) >= limit:
                    break
        return "".join(preview_chars)

    @staticmethod
    def hex_dump(data: bytes, max_length: int = 2048) -> tuple[str, bool]:
        if not data:
            return "(데이터 없음)", False
        shown = data[:max_length]
        lines = []
        for offset in range(0, len(shown), 16):
            chunk = shown[offset : offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{offset:08X}  {hex_part:<47}  {ascii_part}")
        return "\n".join(lines), len(data) > max_length


# singleton
packet_service = PacketCaptureService()
