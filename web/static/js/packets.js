/**
 * 패킷 캡쳐 UI 로직 — 단일 텍스트 출력 방식
 */
const Packets = (() => {
  const packetData = [];

  function init() {
    document.getElementById('filter-text').addEventListener('input', refreshOutput);
    document.getElementById('filter-direction').addEventListener('change', refreshOutput);
  }

  function addPacket(data) {
    packetData.push(data);
    const max = parseInt(document.getElementById('filter-max').value) || 500;
    while (packetData.length > max) packetData.shift();

    if (matchesFilter(data)) {
      appendToOutput(data);
    }
  }

  function formatPacket(pkt) {
    return sanitizeText(pkt.utf8_text);
  }

  function appendToOutput(pkt) {
    const el = document.getElementById('packet-output');
    // 첫 패킷이면 placeholder 제거
    if (packetData.length === 1 || el.textContent === '캡쳐를 시작하면 패킷이 여기에 표시됩니다.') {
      el.textContent = '';
    }
    el.textContent += formatPacket(pkt);

    // 자동 스크롤
    const autoScroll = document.getElementById('auto-scroll');
    if (autoScroll && autoScroll.checked) {
      el.scrollTop = el.scrollHeight;
    }
  }

  function refreshOutput() {
    const el = document.getElementById('packet-output');
    const filtered = packetData.filter(matchesFilter);
    if (filtered.length === 0) {
      el.textContent = '캡쳐를 시작하면 패킷이 여기에 표시됩니다.';
      return;
    }
    el.textContent = filtered.map(formatPacket).join('');

    const autoScroll = document.getElementById('auto-scroll');
    if (autoScroll && autoScroll.checked) {
      el.scrollTop = el.scrollHeight;
    }
  }

  function matchesFilter(pkt) {
    const textFilter = document.getElementById('filter-text').value.trim().toLowerCase();
    if (textFilter && !(pkt.utf8_text || '').toLowerCase().includes(textFilter)) return false;

    const dirFilter = document.getElementById('filter-direction').value;
    if (dirFilter !== 'all') {
      if (dirFilter === 'incoming' && pkt.direction !== 'incoming') return false;
      if (dirFilter === 'outgoing' && pkt.direction !== 'outgoing') return false;
      if (dirFilter === 'unknown' && (pkt.direction === 'incoming' || pkt.direction === 'outgoing')) return false;
    }
    return true;
  }

  function exportAll() {
    const text = document.getElementById('packet-output').textContent;
    if (!text || text === '캡쳐를 시작하면 패킷이 여기에 표시됩니다.') {
      alert('내보낼 패킷 데이터가 없습니다.');
      return;
    }
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `packets_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function clear() {
    packetData.length = 0;
    document.getElementById('packet-output').textContent = '캡쳐를 시작하면 패킷이 여기에 표시됩니다.';
  }

  // helpers
  function sanitizeText(text) {
    if (!text) return '';
    return text.replace(/[\s\n\r]+/g, '').replace(/[^\uAC00-\uD7A3a-zA-Z0-9]/g, '-');
  }

  function formatTime(ts) {
    if (!ts || ts <= 0) return '--:--:--';
    const d = new Date(ts * 1000);
    return d.toTimeString().slice(0, 8);
  }

  function formatDirection(dir) {
    if (dir === 'incoming') return '수신';
    if (dir === 'outgoing') return '송신';
    return '미확인';
  }

  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  return { init, addPacket, refreshOutput, exportAll, clear, formatTime, escapeHtml };
})();
