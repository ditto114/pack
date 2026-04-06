/**
 * 메인 앱 초기화 및 캡쳐 제어
 */
const App = (() => {
  let capturing = false;

  function init() {
    Packets.init();
    World.init();
    UserList.init();
    UserDB.init();
  }

  async function startCapture() {
    if (capturing) return;
    const ip = document.getElementById('filter-ip').value.trim();
    const port = document.getElementById('filter-port').value.trim();
    const pid = document.getElementById('filter-pid').value.trim();
    const textFilter = document.getElementById('filter-text').value.trim();
    const maxPackets = parseInt(document.getElementById('filter-max').value) || 500;

    try {
      const res = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, port, pid, text_filter: textFilter, max_packets: maxPackets }),
      });
      const data = await res.json();
      if (data.error) {
        alert(data.error);
        return;
      }
    } catch (err) {
      alert('캡쳐 시작 실패: ' + err);
      return;
    }

    capturing = true;
    Packets.clear();
    setCaptureUI(true);

    // connect packet stream WS
    WS.connect('/ws/packets', {
      onMessage(data) {
        // 배치 전송 지원
        const packets = (data.type === 'batch' && Array.isArray(data.packets))
          ? data.packets : [data];
        for (const pkt of packets) {
          Packets.addPacket(pkt);
          World.processPacketForExperiment(pkt.utf8_text);
          UserList.processPacket(pkt.utf8_text);
        }
      },
    });
  }

  async function stopCapture() {
    if (!capturing) return;
    try {
      await fetch('/api/capture/stop', { method: 'POST' });
    } catch (err) {
      console.error('stop error:', err);
    }
    capturing = false;
    setCaptureUI(false);
    WS.close('/ws/packets');
  }

  function setCaptureUI(running) {
    document.getElementById('btn-start').disabled = running;
    document.getElementById('btn-stop').disabled = !running;
  }

  function togglePacketModal() {
    document.getElementById('packet-modal').classList.toggle('hidden');
  }

  function toggleWorld() {
    const panel = document.getElementById('world-panel');
    panel.classList.toggle('hidden');
    const btn = document.getElementById('btn-world');
    btn.textContent = panel.classList.contains('hidden') ? '월드 매칭' : '월드 매칭 닫기';
  }

  function toggleFriend() {
    const panel = document.getElementById('friend-panel');
    panel.classList.toggle('hidden');
    const btn = document.getElementById('btn-friend');
    btn.textContent = panel.classList.contains('hidden') ? '친구검색' : '친구검색 닫기';
  }

  // init on load
  document.addEventListener('DOMContentLoaded', init);

  return { startCapture, stopCapture, togglePacketModal, toggleWorld, toggleFriend };
})();
