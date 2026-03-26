/**
 * 친구 채널 모니터링 UI 로직
 */
const Monitor = (() => {
  const MAX_LOG = 200;
  const logs = [];
  let friends = {};   // ppsn → entry
  let running = false;

  function open() {
    document.getElementById('monitor-modal').classList.remove('hidden');
  }

  function close() {
    stop();
    document.getElementById('monitor-modal').classList.add('hidden');
  }

  function start() {
    if (running) return;
    const ppsn = document.getElementById('monitor-ppsn').value.trim();
    const interval = parseFloat(document.getElementById('monitor-interval').value) || 5;

    if (!/^\d{15,20}$/.test(ppsn)) {
      return alert('PPSN을 올바르게 입력하세요.\n(예: 20372100005861109)');
    }

    clearLog();
    friends = {};
    renderTable();
    setRunning(true);
    setStatus('[정보] 연결 중...');

    WS.connect('/ws/monitor', {
      onOpen(socket) {
        socket.send(JSON.stringify({ ppsn, interval }));
      },
      onMessage(data) {
        handleMessage(data);
      },
      onClose() {
        setRunning(false);
      },
    });
  }

  function stop() {
    WS.close('/ws/monitor');
    setRunning(false);
  }

  function handleMessage(data) {
    switch (data.type) {
      case 'init':
        for (const f of data.friends) friends[f.ppsn] = f;
        renderTable();
        break;

      case 'online': {
        friends[data.entry.ppsn] = data.entry;
        const cameOnline = data.prevOnline === 0;
        const icon = cameOnline ? '🟢' : '⛔';
        const label = cameOnline ? '온라인' : '오프라인';
        const loc = cameOnline
          ? ` (${World.getChannelName(data.entry.gameInstanceId) || data.entry.worldName || ''})`
          : '';
        appendLog(`${icon} ${label}: ${esc(data.entry.profileName)} #${esc(data.entry.profileCode)}${loc}`,
          cameOnline ? 'mon-log-online' : 'mon-log-offline');
        renderTable();
        break;
      }

      case 'channel': {
        friends[data.entry.ppsn] = data.entry;
        const from = World.getChannelName(data.prevGameInstanceId) || data.prevWorldName || '?';
        const to   = World.getChannelName(data.entry.gameInstanceId) || data.entry.worldName || '?';
        appendLog(`🔄 채널이동: ${esc(data.entry.profileName)} #${esc(data.entry.profileCode)} — ${from} → ${to}`,
          'mon-log-channel');
        renderTable();
        break;
      }

      case 'status':
        setStatus(data.text || '');
        break;

      case 'error':
        setStatus(data.text || '');
        appendLog(`⚠️ ${data.text || ''}`, 'mon-log-error');
        break;
    }
  }

  // ── 로그 ────────────────────────────────────────────────────────
  function appendLog(text, className) {
    const now = new Date().toLocaleTimeString('ko-KR');
    logs.unshift({ text: `[${now}] ${text}`, className });
    if (logs.length > MAX_LOG) logs.pop();
    renderLog();
  }

  function renderLog() {
    const el = document.getElementById('monitor-log');
    el.innerHTML = '';
    for (const entry of logs) {
      const div = document.createElement('div');
      div.className = 'mon-log-entry' + (entry.className ? ' ' + entry.className : '');
      div.textContent = entry.text;
      el.appendChild(div);
    }
  }

  function clearLog() {
    logs.length = 0;
    document.getElementById('monitor-log').innerHTML = '';
  }

  // ── 친구 테이블 ──────────────────────────────────────────────────
  function renderTable() {
    const tbody = document.getElementById('monitor-tbody');
    tbody.innerHTML = '';

    const all = Object.values(friends);
    const online  = all.filter(f => f.isOnline).sort((a, b) =>
      (a.worldName || '').localeCompare(b.worldName || ''));
    const offline = all.filter(f => !f.isOnline);

    document.getElementById('monitor-online-count').textContent = online.length;
    document.getElementById('monitor-total-count').textContent = all.length;

    for (const f of online) {
      const channelName = World.getChannelName(f.gameInstanceId) || f.worldName || '';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>🟢</td>
        <td>${esc(f.profileName)}</td>
        <td>#${esc(f.profileCode)}</td>
        <td>${esc(channelName)}</td>
        <td style="color:var(--text-dim);font-size:11px">${esc(f.gameInstanceId || '')}</td>
      `;
      tbody.appendChild(tr);
    }
    for (const f of offline) {
      const tr = document.createElement('tr');
      tr.className = 'mon-offline-row';
      tr.innerHTML = `
        <td>⛔</td>
        <td>${esc(f.profileName)}</td>
        <td>#${esc(f.profileCode)}</td>
        <td></td>
        <td></td>
      `;
      tbody.appendChild(tr);
    }
  }

  // ── 헬퍼 ────────────────────────────────────────────────────────
  function setStatus(text) {
    document.getElementById('monitor-status').textContent = text;
  }

  function setRunning(r) {
    running = r;
    document.getElementById('monitor-start-btn').disabled = r;
    document.getElementById('monitor-stop-btn').disabled = !r;
  }

  function esc(s) { return Packets.escapeHtml(s || ''); }

  return { open, close, start, stop };
})();
