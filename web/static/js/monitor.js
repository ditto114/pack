/**
 * 친구 채널 모니터링 UI 로직
 */
const Monitor = (() => {
  const MAX_LOG = 200;
  const logs = [];
  let friends = {};   // ppsn → entry
  let running = false;
  let worldFilter = '';
  let targetFilter = new Set();
  let additionalPpsns = [];
  let monitorSortKey = 'channelName';
  let monitorSortAsc = false;

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

    const ppsns = [ppsn, ...additionalPpsns].filter((p, i, a) => a.indexOf(p) === i);
    additionalPpsns = [];

    clearLog();
    friends = {};
    targetFilter.clear();
    updateTargetFilterUI();
    renderTable();
    setRunning(true);
    setStatus('[정보] 연결 중...');

    WS.connect('/ws/monitor', {
      onOpen(socket) {
        socket.send(JSON.stringify({ ppsns, interval }));
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
        const cameOnline = data.prevOnline === 0;
        const prevWorldName = friends[data.entry.ppsn]?.worldName || '';
        friends[data.entry.ppsn] = data.entry;
        const relevantWorld = cameOnline ? data.entry.worldName : prevWorldName;
        if (passesWorldFilter(relevantWorld) && passesTargetFilter(data.entry.profileCode)) {
          const icon = cameOnline ? '🟢' : '⛔';
          const label = cameOnline ? '온라인' : '오프라인';
          const loc = cameOnline
            ? ` (${resolveChannel(data.entry.gameInstanceId)})`
            : '';
          appendLog(`${icon} ${label}: ${esc(getDisplayNick(data.entry))} #${esc(data.entry.profileCode)}${loc}`,
            cameOnline ? 'mon-log-online' : 'mon-log-offline');
        }
        renderTable();
        break;
      }

      case 'channel': {
        friends[data.entry.ppsn] = data.entry;
        if (passesWorldFilter(data.entry.worldName) && passesTargetFilter(data.entry.profileCode)) {
          const from = resolveChannel(data.prevGameInstanceId);
          const to   = resolveChannel(data.entry.gameInstanceId);
          let logLabel, logClass;
          if (to === '로비') {
            logLabel = '[퇴장]';
            logClass = 'mon-log-exit';
          } else if (from === '로비') {
            logLabel = '[입장]';
            logClass = 'mon-log-enter';
          } else {
            logLabel = '🔄 채널이동:';
            logClass = 'mon-log-channel';
          }
          appendLog(`${logLabel} ${esc(getDisplayNick(data.entry))} #${esc(data.entry.profileCode)} — ${to}`,
            logClass);
        }
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
    const filterLower = worldFilter.toLowerCase();
    let online = all.filter(f => f.isOnline);
    online = monitorSortKey ? applyMonitorSort(online) : online.sort((a, b) =>
      (a.worldName || '').localeCompare(b.worldName || ''));
    if (filterLower) {
      online = online.filter(f => (f.worldName || '').toLowerCase().includes(filterLower));
    }
    if (targetFilter.size > 0) {
      online = online.filter(f => passesTargetFilter(f.profileCode));
    }
    let offline = all.filter(f => !f.isOnline);
    if (targetFilter.size > 0) {
      offline = offline.filter(f => passesTargetFilter(f.profileCode));
    }
    if (monitorSortKey) offline = applyMonitorSort(offline);

    document.getElementById('monitor-online-count').textContent = online.length;
    document.getElementById('monitor-total-count').textContent = all.length;

    // 같은 채널 유저 묶음 기호 사전 계산
    const channelGroups = {};
    for (const f of online) {
      const ch = resolveChannel(f.gameInstanceId);
      if (!channelGroups[ch]) channelGroups[ch] = [];
      channelGroups[ch].push(f.ppsn);
    }
    const bracketMap = {};
    for (const [, ppsns] of Object.entries(channelGroups)) {
      if (ppsns.length < 2) continue;
      ppsns.forEach((ppsn, idx) => {
        if (idx === 0) bracketMap[ppsn] = '┌';
        else if (idx === ppsns.length - 1) bracketMap[ppsn] = '└';
        else bracketMap[ppsn] = '│';
      });
    }

    for (const f of online) {
      const ch = resolveChannel(f.gameInstanceId);
      const bracket = bracketMap[f.ppsn] || '';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mon-bracket-cell">${bracket}</td>
        <td>🟢</td>
        <td>${esc(f.profileName)}</td>
        <td>${esc(UserDB.getIngameNick(f.profileCode))}</td>
        <td>${esc(UserDB.getGuild(f.profileCode))}</td>
        <td>${esc(UserDB.getMemo(f.profileCode))}</td>
        <td>#${esc(f.profileCode)}</td>
        <td>${esc(ch)}</td>
        <td>${esc(f.worldName || '')}</td>
        <td style="color:var(--text-dim);font-size:11px">${esc(f.gameInstanceId || '')}</td>
      `;
      tbody.appendChild(tr);
    }
    if (filterLower && targetFilter.size === 0) return;
    for (const f of offline) {
      const tr = document.createElement('tr');
      tr.className = 'mon-offline-row';
      tr.innerHTML = `
        <td class="mon-bracket-cell"></td>
        <td>⛔</td>
        <td>${esc(f.profileName)}</td>
        <td>${esc(UserDB.getIngameNick(f.profileCode))}</td>
        <td>${esc(UserDB.getGuild(f.profileCode))}</td>
        <td>${esc(UserDB.getMemo(f.profileCode))}</td>
        <td>#${esc(f.profileCode)}</td>
        <td></td>
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

  function setWorldFilter(value) {
    worldFilter = value.trim();
    renderTable();
  }

  function passesWorldFilter(worldName) {
    if (!worldFilter) return true;
    return (worldName || '').toLowerCase().includes(worldFilter.toLowerCase());
  }

  function passesTargetFilter(profileCode) {
    if (targetFilter.size === 0) return true;
    return targetFilter.has((profileCode || '').toUpperCase());
  }

  function setTargetFilter(codes) {
    targetFilter = new Set(codes.map(c => c.toUpperCase()));
    updateTargetFilterUI();
    renderTable();
  }

  function clearTargetFilter() {
    targetFilter.clear();
    updateTargetFilterUI();
    renderTable();
  }

  function updateTargetFilterUI() {
    const row = document.getElementById('monitor-target-row');
    const count = document.getElementById('monitor-target-count');
    if (targetFilter.size > 0) {
      row.classList.remove('hidden');
      count.textContent = targetFilter.size;
    } else {
      row.classList.add('hidden');
    }
  }

  function getDisplayNick(entry) {
    const ingame = UserDB.getIngameNick(entry.profileCode);
    if (ingame) return ingame.split(',')[0].trim() || entry.profileName || '';
    return entry.profileName || '';
  }

  function resolveChannel(gameInstanceId) {
    if (!gameInstanceId) return '로비';
    return World.getChannelName(gameInstanceId) || '???';
  }

  function getMonitorSortValue(f, key) {
    switch (key) {
      case 'profileName':  return (f.profileName || '').toLowerCase();
      case 'ingameNick':   return UserDB.getIngameNick(f.profileCode).split(',')[0].trim().toLowerCase();
      case 'guild':        return UserDB.getGuild(f.profileCode).toLowerCase();
      case 'memo':         return UserDB.getMemo(f.profileCode).toLowerCase();
      case 'profileCode':  return (f.profileCode || '').toLowerCase();
      case 'channelName':  return resolveChannel(f.gameInstanceId).toLowerCase();
      case 'worldName':    return (f.worldName || '').toLowerCase();
      case 'gameInstanceId': return (f.gameInstanceId || '').toLowerCase();
      default: return '';
    }
  }

  function applyMonitorSort(arr) {
    return [...arr].sort((a, b) => {
      const va = getMonitorSortValue(a, monitorSortKey);
      const vb = getMonitorSortValue(b, monitorSortKey);
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return monitorSortAsc ? cmp : -cmp;
    });
  }

  function setupMonitorSort() {
    document.querySelectorAll('#monitor-table thead th[data-sort-key]').forEach(th => {
      th.classList.add('sortable');
      th.addEventListener('click', () => {
        const key = th.dataset.sortKey;
        if (monitorSortKey === key) {
          monitorSortAsc = !monitorSortAsc;
        } else {
          monitorSortKey = key;
          monitorSortAsc = true;
        }
        updateMonitorSortIndicators();
        renderTable();
      });
    });
    updateMonitorSortIndicators();
  }

  function updateMonitorSortIndicators() {
    document.querySelectorAll('#monitor-table thead th').forEach(th => {
      const base = th.textContent.replace(/[ ▲▼]/g, '').trim();
      if (th.dataset.sortKey === monitorSortKey) {
        th.textContent = base + (monitorSortAsc ? ' ▲' : ' ▼');
      } else {
        th.textContent = base;
      }
    });
  }

  function esc(s) { return Packets.escapeHtml(s || ''); }

  function openWithPpsn(ppsn, targetCodes, allPpsns) {
    open();
    document.getElementById('monitor-ppsn').value = ppsn;
    setTimeout(() => {
      additionalPpsns = (allPpsns || []).filter(p => p !== ppsn);
      start();
      if (targetCodes && targetCodes.length > 0) setTargetFilter(targetCodes);
    }, 150);
  }

  document.addEventListener('DOMContentLoaded', setupMonitorSort);

  return { open, close, start, stop, setWorldFilter, openWithPpsn, clearTargetFilter };
})();
