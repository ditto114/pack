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

  const COLUMNS = [
    { key: 'status',           label: '상태' },
    { key: 'profile_code',     label: '프로필 코드' },
    { key: '_channel_name',    label: '채널명' },
    { key: 'display_name',     label: '메월닉' },
    { key: 'world_name',       label: '월드명' },
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
      const statusIcon = e.status === '온라인' ? '🟢' : '⛔';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${statusIcon}</td>
        <td>${e.profile_code ? '#' + esc(e.profile_code) : ''}</td>
        <td>${esc(e._channel_name)}</td>
        <td>${esc(e.display_name)}</td>
        <td>${esc(e.world_name)}</td>
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

  function esc(s) { return Packets.escapeHtml(s || ''); }

  return { search, stop, saveToUserDB };
})();


/**
 * PPSN / 채널 검색 모달 로직
 */
const PPSN = (() => {
  let ws = null;

  function search() {
    const code = document.getElementById('ppsn-code').value.trim();
    if (!/^[A-Za-z0-9]{5,6}$/.test(code)) {
      return alert('프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다.');
    }
    const delay = parseFloat(document.getElementById('ppsn-delay').value) || 0.5;

    clearLog();
    appendLog('[정보] PPSN 검색을 시작합니다.');
    document.getElementById('ppsn-result').value = '';
    setSearching(true);

    ws = WS.connect('/ws/ppsn', {
      onOpen(socket) {
        socket.send(JSON.stringify({ action: 'ppsn_search', code, delay }));
      },
      onMessage(data) {
        handleMsg(data);
      },
      onClose() {
        setSearching(false);
      },
    });
  }

  function channelSearch() {
    const code = document.getElementById('ppsn-code').value.trim();
    if (!/^[A-Za-z0-9]{5,6}$/.test(code)) {
      return alert('프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다.');
    }
    const worldCode = document.getElementById('ppsn-world-code').value.trim();
    if (!/^\d{17}$/.test(worldCode)) {
      return alert('월드 코드는 숫자 17자리여야 합니다.');
    }
    const delay = parseFloat(document.getElementById('ppsn-delay').value) || 0.5;

    clearLog();
    appendLog('[정보] 채널 검색을 시작합니다.');
    document.getElementById('channel-result').value = '';
    document.getElementById('channel-count').value = '0';
    setSearching(true);

    ws = WS.connect('/ws/ppsn', {
      onOpen(socket) {
        socket.send(JSON.stringify({ action: 'channel_search', code, world_code: worldCode, delay }));
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
    } else if (data.type === 'progress') {
      document.getElementById('channel-count').value = data.count || 0;
    } else if (data.type === 'done') {
      appendLog(data.text || '');
      if (data.ppsn) document.getElementById('ppsn-result').value = data.ppsn;
      if (data.channel_result) document.getElementById('channel-result').value = data.channel_result;
      setSearching(false);
      WS.close('/ws/ppsn');
    }
  }

  function clearLog() {
    document.getElementById('ppsn-log').textContent = '';
  }

  function appendLog(msg) {
    const el = document.getElementById('ppsn-log');
    el.textContent += msg + '\n';
    el.scrollTop = el.scrollHeight;
  }

  function setSearching(busy) {
    document.getElementById('ppsn-search-btn').disabled = busy;
    document.getElementById('channel-search-btn').disabled = busy;
  }

  function copyResult() {
    const val = document.getElementById('ppsn-result').value;
    if (!val) return alert('복사할 PPSN 결과가 없습니다.');
    navigator.clipboard.writeText(val).then(() => alert('PPSN이 클립보드에 복사되었습니다.'));
  }

  return { search, channelSearch, copyResult };
})();
