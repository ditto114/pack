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
  let lastSearchCodes = [];
  const collapsedGroups = new Set();

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
    _startSearch(false);
  }

  function searchSelf(codesStr) {
    const panel = document.getElementById('friend-panel');
    if (panel.classList.contains('hidden')) {
      panel.classList.remove('hidden');
      document.getElementById('btn-friend').textContent = '친구검색 닫기';
    }
    if (codesStr !== undefined) {
      document.getElementById('friend-code').value = codesStr;
    }
    _startSearch(true);
  }

  // targets: string[], friendMap: { [code: string]: string[] }
  function searchSelfOptimized(targets, friendMap) {
    if (running) return alert('친구 검색이 이미 진행 중입니다.');

    const panel = document.getElementById('friend-panel');
    if (panel.classList.contains('hidden')) {
      panel.classList.remove('hidden');
      document.getElementById('btn-friend').textContent = '친구검색 닫기';
    }
    document.getElementById('friend-code').value = targets.join(', ');

    if (!headerSortInit) { setupHeaderSort(); headerSortInit = true; }
    clearTable();
    lastSearchCodes = targets;
    targets.forEach(c => collapsedGroups.add(c));
    setRunning(true);
    document.getElementById('friend-status').textContent =
      `[정보] ${targets.length}명의 본인 프로필을 최적화 탐색합니다.`;

    ws = WS.connect('/ws/friends', {
      onOpen(socket) {
        socket.send(JSON.stringify({ action: 'search_self', targets, friend_map: friendMap }));
      },
      onMessage(data) { handleMessage(data); },
      onClose() { setRunning(false); },
    });
  }

  function _startSearch(selfOnly) {
    if (running) return alert('친구 검색이 이미 진행 중입니다.');

    const raw = document.getElementById('friend-code').value.trim();
    const codes = raw.split(',').map(s => s.trim()).filter(s => s);

    if (codes.length === 0) return alert('프로필 코드를 입력하세요.');

    const invalid = codes.filter(c => !/^[A-Za-z0-9]{5,6}$/.test(c));
    if (invalid.length > 0) {
      return alert(`올바르지 않은 프로필 코드: ${invalid.join(', ')}\n영문 대소문자/숫자 5~6글자여야 합니다.`);
    }

    if (!headerSortInit) { setupHeaderSort(); headerSortInit = true; }
    clearTable();
    lastSearchCodes = codes;
    if (codes.length > 1) codes.forEach(c => collapsedGroups.add(c));
    setRunning(true);
    document.getElementById('friend-status').textContent =
      selfOnly
        ? (codes.length > 1 ? `[정보] ${codes.length}명의 본인 프로필을 검색합니다.` : '[정보] 본인 프로필을 검색합니다.')
        : (codes.length > 1 ? `[정보] ${codes.length}개 코드 검색을 시작합니다.` : '[정보] 친구 목록 검색을 시작합니다.');

    ws = WS.connect('/ws/friends', {
      onOpen(socket) {
        socket.send(JSON.stringify({ action: 'search', codes, phase: 1, code: codes[0], self_only: selfOnly }));
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
            e.search_code = data.search_code || (lastSearchCodes[0] || '');
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
    // 단일 검색만 중복 제거 적용
    if (lastSearchCodes.length <= 1) {
      const key = `${(e.ppsn || '').toUpperCase()}_${(e.profile_code || '').toUpperCase()}`;
      if (entryKeys.has(key)) return;
      entryKeys.add(key);
    }
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

  function makeRow(e) {
    e._ingame_nick = UserDB.getIngameNick(e.profile_code);
    const statusIcon = e.status === '온라인' ? '🟢' : '⛔';
    const isNew = e.profile_code && !UserDB.has(e.profile_code);
    const isSelf = !!e.is_self;
    const tr = document.createElement('tr');
    if (isSelf) tr.classList.add('friend-self-row');
    tr.innerHTML = `
      <td>${statusIcon}${isSelf ? ' <span class="self-badge">본인</span>' : ''}</td>
      <td style="color:${isNew ? '#ffff00' : ''}">${e.profile_code ? '#' + esc(e.profile_code) : ''}</td>
      <td>${esc(e._channel_name)}</td>
      <td>${esc(e._ingame_nick)}</td>
      <td>${esc(e.world_name)}</td>
      <td>${esc(e.display_name)}</td>
      <td>${esc(e.game_instance_id)}</td>
      <td>${esc(e.ppsn)}</td>
    `;
    return tr;
  }

  function makeGroupHeaderRow(code, selfEntry, friendCount, isCollapsed) {
    const tr = document.createElement('tr');
    tr.className = 'friend-group-header';
    const btn = `<button class="group-toggle-btn" onclick="Friends.toggleGroup('${code}')">${isCollapsed ? '+' : '−'}</button>`;
    const countBadge = `<span class="group-friend-count">(친구 ${friendCount}명)</span>`;
    if (selfEntry) {
      selfEntry._ingame_nick = UserDB.getIngameNick(selfEntry.profile_code);
      const icon = selfEntry.status === '온라인' ? '🟢' : '⛔';
      const isNew = selfEntry.profile_code && !UserDB.has(selfEntry.profile_code);
      tr.innerHTML = `
        <td>${btn} ${icon} <span class="self-badge">본인</span></td>
        <td style="color:${isNew ? '#ffff00' : ''};font-weight:bold">#${esc(selfEntry.profile_code)} ${countBadge}</td>
        <td>${esc(selfEntry._channel_name)}</td>
        <td>${esc(selfEntry._ingame_nick)}</td>
        <td>${esc(selfEntry.world_name)}</td>
        <td>${esc(selfEntry.display_name)}</td>
        <td>${esc(selfEntry.game_instance_id)}</td>
        <td>${esc(selfEntry.ppsn)}</td>
      `;
    } else {
      tr.innerHTML = `
        <td>${btn}</td>
        <td style="font-weight:bold;color:var(--text-dim)">#${esc(code)} ${countBadge}</td>
        <td colspan="6" style="color:var(--text-dim)">본인 정보 없음</td>
      `;
    }
    return tr;
  }

  function toggleGroup(code) {
    if (collapsedGroups.has(code)) collapsedGroups.delete(code);
    else collapsedGroups.add(code);
    render();
  }

  function render() {
    const tbody = document.getElementById('friend-tbody');
    tbody.innerHTML = '';
    document.getElementById('friend-count-val').textContent = entries.length;

    if (lastSearchCodes.length <= 1) {
      // 단일 코드: 기존 방식
      for (const e of getSorted()) tbody.appendChild(makeRow(e));
      return;
    }

    // 다중 코드: 검색 코드별 그룹 표시
    for (const code of lastSearchCodes) {
      const group = entries.filter(e => e.search_code === code);
      // is_self 항목이 중복 제거로 걸러진 경우, 전체 entries에서 해당 코드 항목을 폴백으로 사용
      const selfEntry = group.find(e => e.is_self)
        || entries.find(e => e.profile_code.toUpperCase() === code.toUpperCase())
        || null;
      const friendEntries = group.filter(e => !e.is_self);
      const isCollapsed = collapsedGroups.has(code);
      tbody.appendChild(makeGroupHeaderRow(code, selfEntry, friendEntries.length, isCollapsed));
      if (!isCollapsed) friendEntries.forEach(e => tbody.appendChild(makeRow(e)));
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
    lastSearchCodes = [];
    collapsedGroups.clear();
    sortKey = null;
    sortAsc = true;
    updateHeaderIndicators();
    document.getElementById('friend-tbody').innerHTML = '';
    document.getElementById('friend-count-val').textContent = '0';
  }

  function setRunning(r) {
    running = r;
    document.getElementById('friend-search-btn').disabled = r;
    document.getElementById('friend-self-btn').disabled = r;
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

  async function _doSave(searchCode, friendCodes) {
    try {
      const res = await fetch('/api/user-db/save-friend-list', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ search_code: searchCode, friend_codes: friendCodes }),
      });
      const data = await res.json();
      if (data.status === 'ok') return data.updated || 0;
      console.error('친구목록 저장 실패:', searchCode, data.error);
      return 0;
    } catch (err) {
      console.error('친구목록 저장 오류:', searchCode, err);
      return 0;
    }
  }

  async function saveFriendList() {
    if (!lastSearchCodes.length) {
      alert('먼저 친구 검색을 실행하세요.');
      return;
    }

    if (lastSearchCodes.length === 1) {
      // 단일 코드: 기존 동작
      const code = lastSearchCodes[0];
      const friendCodes = entries.filter(e => !e.is_self).map(e => e.profile_code).filter(c => c);
      if (!friendCodes.length) { alert('저장할 친구 목록이 없습니다.'); return; }
      try {
        const res = await fetch('/api/user-db/save-friend-list', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ search_code: code, friend_codes: friendCodes }),
        });
        const data = await res.json();
        if (data.status === 'ok') {
          alert(`친구목록 저장 완료 (${data.updated}건 업데이트)`);
          await UserDB.load();
        } else {
          alert('저장 실패: ' + (data.error || ''));
        }
      } catch (err) { alert('저장 실패: ' + err); }
      return;
    }

    // 다중 코드: 코드별로 각각의 친구목록 저장
    let totalUpdated = 0;
    let savedCount = 0;
    for (const code of lastSearchCodes) {
      const friendCodes = entries
        .filter(e => e.search_code === code && !e.is_self)
        .map(e => e.profile_code)
        .filter(c => c);
      if (!friendCodes.length) continue;
      totalUpdated += await _doSave(code, friendCodes);
      savedCount++;
    }
    if (!savedCount) { alert('저장할 친구 목록이 없습니다.'); return; }
    alert(`친구목록 저장 완료 — ${lastSearchCodes.length}개 코드, ${totalUpdated}건 업데이트`);
    await UserDB.load();
  }

  function searchCode(code) {
    const panel = document.getElementById('friend-panel');
    if (panel.classList.contains('hidden')) {
      panel.classList.remove('hidden');
      document.getElementById('btn-friend').textContent = '친구검색 닫기';
    }
    document.getElementById('friend-code').value = code;
    _startSearch(false);
  }

  function esc(s) { return Packets.escapeHtml(s || ''); }

  return { search, searchSelf, searchSelfOptimized, stop, saveToUserDB, saveFriendList, searchCode, toggleGroup };
})();
