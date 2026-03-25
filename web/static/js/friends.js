/**
 * 친구 검색 UI 로직
 */
const Friends = (() => {
  let ws = null;
  let running = false;
  const entries = [];
  const entryKeys = new Set();
  let sortKey = null;
  let sortAsc = true;
  let lastSearchCode = '';

  const COLUMNS = [
    { key: 'status',           label: '상태' },
    { key: 'profile_code',     label: '프로필 코드' },
    { key: '_channel_name',    label: '채널명' },
    { key: '_ingame_nick',     label: '인겜닉' },
    { key: 'world_name',       label: '월드명' },
    { key: 'display_name',     label: '메월닉' },
    { key: 'game_instance_id', label: '채널 코드' },
    { key: 'ppsn',             label: 'PPSN' },
  ];

  let headerSortInit = false;

  function search() {
    if (running) return alert('친구 검색이 이미 진행 중입니다.');

    const code = document.getElementById('friend-code').value.trim();
    if (!/^[A-Za-z0-9]{5,6}$/.test(code)) {
      return alert('프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다.');
    }

    if (!headerSortInit) { setupHeaderSort(); headerSortInit = true; }
    clearTable();
    lastSearchCode = code;
    setRunning(true);
    document.getElementById('friend-status').textContent = '[정보] 친구 목록 검색을 시작합니다.';

    ws = WS.connect('/ws/friends', {
      onOpen(socket) {
        socket.send(JSON.stringify({ action: 'search', codes: [code], phase: 1, code }));
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
    fetch('/api/friends/search', { method: 'DELETE' });
    document.getElementById('friend-status').textContent = '[정보] 검색 중지 요청을 전달했습니다.';
    document.getElementById('friend-stop-btn').disabled = true;
  }

  function handleMessage(data) {
    switch (data.type) {
      case 'status':
        document.getElementById('friend-status').textContent = data.text || '';
        break;
      case 'progress':
        document.getElementById('friend-count-val').textContent = data.count || 0;
        break;
      case 'result':
        if (data.entries) {
          for (const e of data.entries) {
            addEntry(e);
          }
          document.getElementById('friend-count-val').textContent = entries.length;
        }
        break;
      case 'error':
        document.getElementById('friend-status').textContent = data.text || '';
        break;
      case 'finished':
        setRunning(false);
        WS.close('/ws/friends');
        break;
    }
  }

  function addEntry(e) {
    const key = `${(e.ppsn || '').toUpperCase()}_${(e.profile_code || '').toUpperCase()}`;
    if (entryKeys.has(key)) return;
    entryKeys.add(key);
    e._channel_name = World.getChannelName(e.game_instance_id);
    entries.push(e);
    render();
  }

  function getSorted() {
    if (!sortKey) return entries;
    return [...entries].sort((a, b) => {
      const va = (a[sortKey] || '').toLowerCase();
      const vb = (b[sortKey] || '').toLowerCase();
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return sortAsc ? cmp : -cmp;
    });
  }

  function render() {
    const tbody = document.getElementById('friend-tbody');
    tbody.innerHTML = '';
    document.getElementById('friend-count-val').textContent = entries.length;
    for (const e of getSorted()) {
      e._ingame_nick = UserDB.getIngameNick(e.profile_code);
      const statusIcon = e.status === '온라인' ? '🟢' : '⛔';
      const isNew = e.profile_code && !UserDB.has(e.profile_code);
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${statusIcon}</td>
        <td style="color:${isNew ? '#ffff00' : ''}">${e.profile_code ? '#' + esc(e.profile_code) : ''}</td>
        <td>${esc(e._channel_name)}</td>
        <td>${esc(e._ingame_nick)}</td>
        <td>${esc(e.world_name)}</td>
        <td>${esc(e.display_name)}</td>
        <td>${esc(e.game_instance_id)}</td>
        <td>${esc(e.ppsn)}</td>
      `;
      tbody.appendChild(tr);
    }
  }

  function setupHeaderSort() {
    const ths = document.querySelectorAll('#friend-table thead th');
    ths.forEach((th, i) => {
      th.style.cursor = 'pointer';
      th.style.userSelect = 'none';
      th.addEventListener('click', () => {
        const key = COLUMNS[i].key;
        if (sortKey === key) {
          sortAsc = !sortAsc;
        } else {
          sortKey = key;
          sortAsc = true;
        }
        updateHeaderIndicators();
        render();
      });
    });
  }

  function updateHeaderIndicators() {
    const ths = document.querySelectorAll('#friend-table thead th');
    ths.forEach((th, i) => {
      const base = COLUMNS[i].label;
      th.textContent = COLUMNS[i].key === sortKey ? base + (sortAsc ? ' ▲' : ' ▼') : base;
    });
  }

  function clearTable() {
    entries.length = 0;
    entryKeys.clear();
    sortKey = null;
    sortAsc = true;
    updateHeaderIndicators();
    document.getElementById('friend-tbody').innerHTML = '';
    document.getElementById('friend-count-val').textContent = '0';
  }

  function setRunning(r) {
    running = r;
    document.getElementById('friend-search-btn').disabled = r;
    document.getElementById('friend-stop-btn').disabled = !r;
  }

  function saveToUserDB() {
    const data = entries
      .filter(e => e.profile_code)
      .map(e => ({ profile_code: e.profile_code, mw_nick: e.display_name || '' }));
    if (!data.length) {
      alert('저장할 데이터가 없습니다.');
      return;
    }
    UserDB.saveEntries(data);
  }

  async function saveFriendList() {
    if (!lastSearchCode) {
      alert('먼저 친구 검색을 실행하세요.');
      return;
    }
    const codes = entries.map(e => e.profile_code).filter(c => c);
    if (!codes.length) {
      alert('저장할 친구 목록이 없습니다.');
      return;
    }
    const friendListVal = codes.join(',');
    try {
      const res = await fetch(`/api/user-db/${encodeURIComponent(lastSearchCode)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ field: 'friend_list', value: friendListVal }),
      });
      const data = await res.json();
      if (data.status === 'ok') {
        alert(`친구목록 ${codes.length}명이 저장되었습니다.`);
        await UserDB.load();
      } else {
        alert('저장 실패: ' + (data.error || ''));
      }
    } catch (err) {
      alert('저장 실패: ' + err);
    }
  }

  function esc(s) { return Packets.escapeHtml(s || ''); }

  return { search, stop, saveToUserDB, saveFriendList };
})();


/**
 * 프로필 검색 모달 로직
 */
const PPSN = (() => {
  function search() {
    const code = document.getElementById('ppsn-code').value.trim();
    if (!/^[A-Za-z0-9]{5,6}$/.test(code)) {
      return alert('프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다.');
    }
    const delay = parseFloat(document.getElementById('ppsn-delay').value) || 0.5;

    clearLog();
    clearResult();
    appendLog('[정보] 프로필 검색을 시작합니다.');
    setSearching(true);

    WS.connect('/ws/ppsn', {
      onOpen(socket) {
        socket.send(JSON.stringify({ action: 'profile_search', code, delay }));
      },
      onMessage(data) {
        handleMsg(data);
      },
      onClose() {
        setSearching(false);
      },
    });
  }

  function handleMsg(data) {
    if (data.type === 'log') {
      appendLog(data.text || '');
    } else if (data.type === 'done') {
      if (data.text) appendLog(data.text);
      if (data.success && data.entry) renderResult(data.entry);
      setSearching(false);
      WS.close('/ws/ppsn');
    }
  }

  function renderResult(e) {
    const tbody = document.getElementById('ppsn-result-tbody');
    tbody.innerHTML = '';
    const channelName = World.getChannelName(e.game_instance_id);
    const ingameNick = UserDB.getIngameNick(e.profile_code);
    const statusIcon = e.status === '온라인' ? '🟢' : '⛔';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${statusIcon}</td>
      <td>${e.profile_code ? '#' + esc(e.profile_code) : ''}</td>
      <td>${esc(channelName)}</td>
      <td>${esc(ingameNick)}</td>
      <td>${esc(e.world_name)}</td>
      <td>${esc(e.display_name)}</td>
      <td>${esc(e.game_instance_id)}</td>
      <td>${esc(e.ppsn)}</td>
    `;
    tbody.appendChild(tr);
  }

  function clearLog() {
    document.getElementById('ppsn-log').textContent = '';
  }

  function clearResult() {
    document.getElementById('ppsn-result-tbody').innerHTML = '';
  }

  function appendLog(msg) {
    const el = document.getElementById('ppsn-log');
    el.textContent += msg + '\n';
    el.scrollTop = el.scrollHeight;
  }

  function setSearching(busy) {
    document.getElementById('ppsn-search-btn').disabled = busy;
  }

  function esc(s) { return Packets.escapeHtml(s || ''); }

  return { search };
})();
