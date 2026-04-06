/**
 * 패킷 캡쳐 UI 로직 — 클라이언트(PID) 별 탭 분리
 */
const Packets = (() => {
  /** client_id(number|null) → packet[] */
  const packetsByClient = new Map();
  /** client_id → { pid } */
  const clientInfo = new Map();
  /** 현재 선택된 탭 (client_id, null 이면 "전체") */
  let activeClient = null;
  /** 렌더링 버퍼: requestAnimationFrame으로 모아서 처리 */
  let pendingTexts = [];
  let rafId = null;

  function init() {
    document.getElementById('filter-text').addEventListener('input', refreshOutput);
    document.getElementById('filter-direction').addEventListener('change', refreshOutput);
  }

  function addPacket(data) {
    const cid = data.client_id ?? null;

    // "전체" 목록에 추가
    if (!packetsByClient.has(null)) packetsByClient.set(null, []);
    packetsByClient.get(null).push(data);

    // 클라이언트별 목록에 추가
    if (cid !== null) {
      const isNew = !packetsByClient.has(cid);
      if (isNew) {
        packetsByClient.set(cid, []);
        clientInfo.set(cid, { pid: data.client_pid });
        renderTabs();
      }
      packetsByClient.get(cid).push(data);
    }

    // max 제한
    const max = parseInt(document.getElementById('filter-max').value) || 500;
    for (const [, arr] of packetsByClient) {
      while (arr.length > max) arr.shift();
    }

    // 활성 탭에 해당하는 패킷이면 출력
    if (activeClient === null || activeClient === cid) {
      if (matchesFilter(data)) {
        appendToOutput(data);
      }
    }
  }

  function renderTabs() {
    const container = document.getElementById('packet-tabs');
    container.innerHTML = '';

    // 클라이언트가 1개뿐이면 탭을 표시하지 않음
    const clients = [...packetsByClient.keys()].filter(k => k !== null);
    if (clients.length <= 1) return;

    // "전체" 탭
    container.appendChild(createTabButton('전체', null));

    // 클라이언트별 탭 (번호 순)
    clients.sort((a, b) => a - b);
    for (const cid of clients) {
      const info = clientInfo.get(cid);
      const label = `클라이언트 ${cid} (PID: ${info?.pid ?? '?'})`;
      container.appendChild(createTabButton(label, cid));
    }
  }

  function createTabButton(label, cid) {
    const btn = document.createElement('button');
    btn.className = 'packet-tab' + (activeClient === cid ? ' active' : '');
    btn.textContent = label;
    btn.addEventListener('click', () => switchTab(cid));
    return btn;
  }

  function switchTab(cid) {
    activeClient = cid;
    // 탭 active 상태 갱신
    const container = document.getElementById('packet-tabs');
    const clients = [null, ...[...packetsByClient.keys()].filter(k => k !== null).sort((a, b) => a - b)];
    const tabs = [...container.children];
    const idx = clients.indexOf(cid);
    for (let i = 0; i < tabs.length; i++) {
      tabs[i].classList.toggle('active', i === idx);
    }
    refreshOutput();
  }

  function formatPacket(pkt) {
    return sanitizeText(pkt.utf8_text);
  }

  function appendToOutput(pkt) {
    pendingTexts.push(formatPacket(pkt));
    if (!rafId) {
      rafId = requestAnimationFrame(flushPendingTexts);
    }
  }

  function flushPendingTexts() {
    rafId = null;
    if (!pendingTexts.length) return;
    const el = document.getElementById('packet-output');
    if (el.textContent === '캡쳐를 시작하면 패킷이 여기에 표시됩니다.') {
      el.textContent = '';
    }
    el.textContent += pendingTexts.join('');
    pendingTexts = [];
    // 최대 표시 길이 제한 (100만 자 초과 시 뒤쪽만 유지)
    if (el.textContent.length > 1_000_000) {
      el.textContent = el.textContent.slice(-500_000);
    }
    const autoScroll = document.getElementById('auto-scroll');
    if (autoScroll && autoScroll.checked) {
      el.scrollTop = el.scrollHeight;
    }
  }

  function refreshOutput() {
    const el = document.getElementById('packet-output');
    const packets = packetsByClient.get(activeClient) || [];
    const filtered = packets.filter(matchesFilter);
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
    const suffix = activeClient !== null ? `_client${activeClient}` : '';
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `packets${suffix}_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function clear() {
    packetsByClient.clear();
    clientInfo.clear();
    activeClient = null;
    pendingTexts = [];
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    document.getElementById('packet-tabs').innerHTML = '';
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
