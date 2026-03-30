/**
 * 유저 DB — Supabase 연동, 우클릭 수정/삭제, 헤더 정렬, 다중 행 선택
 */
const UserDB = (() => {
  let entries = [];
  let filterText = '';
  let ctxMenu = null;
  let sortKey = null;
  let sortAsc = true;

  // ── 다중 행 선택 / 텍스트 선택 상태 ────────────────────────
  let selectedCodes = new Set();
  let isDragging = false;
  let dragStartIdx = -1;
  let anchorCode = null;
  let lastSorted = [];


  // ── 겹지인 테이블 선택 상태 ─────────────────────────────────
  let cfSelectedCodes = new Set();
  let cfCtxMenu = null;
  let cfIsDragging = false;
  let cfDragStartIdx = -1;
  let cfAnchorCode = null;
  let cfLastRanked = [];

  const COLUMNS = [
    { key: 'profile_code', label: '프로필 코드' },
    { key: 'ingame_nick', label: '인겜닉' },
    { key: 'mw_nick', label: '메월닉' },
    { key: 'guild', label: '길드' },
    { key: 'main_map', label: '주 사냥터' },
    { key: 'memo', label: '메모' },
    { key: 'friend_list', label: '친구목록' },
    { key: 'ppsn', label: 'PPSN' },
  ];

  const TAG_FIELDS = new Set(['ingame_nick', 'friend_list']);

  function isDirectSearched(profileCode) {
    const entry = entries.find(e => e.profile_code === profileCode);
    return !!(entry && entry.friend_list_direct);
  }

  async function init() {
    setupHeaderSort();
    setupSelectionListeners();
    setupCfSelectionListeners();
    await load();
  }

  // ── 다중 선택 이벤트 리스너 (tbody에 위임) ──────────────────
  function setupSelectionListeners() {
    const tbody = document.getElementById('userdb-tbody');

    tbody.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      const td = e.target.closest('td');

      const tr = e.target.closest('tr');
      if (!tr || !tr.dataset.profileCode) return;

      const idx = parseInt(tr.dataset.rowIdx);
      const code = tr.dataset.profileCode;

      if (e.shiftKey && anchorCode !== null) {
        // Shift+클릭: 앵커~현재 범위 선택
        e.preventDefault(); // 브라우저 텍스트 범위 선택 방지
        const anchorIdx = lastSorted.findIndex(e => e.profile_code === anchorCode);
        if (anchorIdx !== -1) {
          clearSelection();
          const lo = Math.min(anchorIdx, idx);
          const hi = Math.max(anchorIdx, idx);
          for (let i = lo; i <= hi; i++) {
            if (lastSorted[i]) selectedCodes.add(lastSorted[i].profile_code);
          }
          updateSelectionVisuals();
        }
        // anchorCode는 유지 (연속 Shift+Click 지원)
      } else if (e.ctrlKey || e.metaKey) {
        // Ctrl+클릭: 토글
        if (selectedCodes.has(code)) {
          selectedCodes.delete(code);
          tr.classList.remove('selected');
        } else {
          selectedCodes.add(code);
          tr.classList.add('selected');
        }
        anchorCode = code;
      } else {
        // 일반 클릭 혹은 드래그 시작
        clearSelection();
        selectedCodes.add(code);
        tr.classList.add('selected');
        isDragging = true;
        dragStartIdx = idx;
        anchorCode = code;
      }
    });

    tbody.addEventListener('dblclick', (e) => {
      const td = e.target.closest('td');
      if (!td) return;
      if (td.querySelector('input, .nick-tag-editor')) return;
      const profileCode = td.dataset.profileCode;
      const field = td.dataset.field;
      if (!profileCode || !field) return;

      if (field === 'profile_code' || TAG_FIELDS.has(field)) {
        td.style.userSelect = 'text';
        const range = document.createRange();
        range.selectNodeContents(td);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.addEventListener('mousedown', () => { td.style.userSelect = ''; }, { once: true });
        return;
      }

      editCell(profileCode, field, td);
    });

    tbody.addEventListener('mouseover', (e) => {
      if (!isDragging) return;
      const tr = e.target.closest('tr');
      if (!tr || !tr.dataset.rowIdx) return;

      const currentIdx = parseInt(tr.dataset.rowIdx);
      const lo = Math.min(dragStartIdx, currentIdx);
      const hi = Math.max(dragStartIdx, currentIdx);

      clearSelection();
      for (let i = lo; i <= hi; i++) {
        if (lastSorted[i]) selectedCodes.add(lastSorted[i].profile_code);
      }
      updateSelectionVisuals();
    });

    document.addEventListener('mouseup', () => { isDragging = false; });
  }

  function clearSelection() {
    selectedCodes.clear();
    document.querySelectorAll('#userdb-tbody tr.selected')
      .forEach(tr => tr.classList.remove('selected'));
  }

  function updateSelectionVisuals() {
    document.querySelectorAll('#userdb-tbody tr').forEach(tr => {
      if (selectedCodes.has(tr.dataset.profileCode)) {
        tr.classList.add('selected');
      } else {
        tr.classList.remove('selected');
      }
    });
  }

  function setupHeaderSort() {
    const ths = document.querySelectorAll('#userdb-table thead th');
    ths.forEach((th, i) => {
      if (i < COLUMNS.length) {
        th.dataset.sortKey = COLUMNS[i].key;
        th.classList.add('sortable');
        th.addEventListener('click', () => onHeaderClick(COLUMNS[i].key));
      }
    });
  }

  function onHeaderClick(key) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      sortAsc = true;
    }
    updateHeaderIndicators();
    render();
  }

  function updateHeaderIndicators() {
    const ths = document.querySelectorAll('#userdb-table thead th');
    ths.forEach(th => {
      const base = th.textContent.replace(/[ ▲▼]/g, '').trim();
      if (th.dataset.sortKey === sortKey) {
        th.textContent = base + (sortAsc ? ' ▲' : ' ▼');
      } else {
        th.textContent = base;
      }
    });
  }

  function getTerms() {
    return filterText.split(',').map(s => s.trim().toLowerCase()).filter(s => s);
  }

  function getFiltered() {
    const terms = getTerms();
    if (!terms.length) return entries;
    return entries.filter(e =>
      terms.some(q =>
        COLUMNS.some(col => (e[col.key] || '').toLowerCase().includes(q))
      )
    );
  }

  function getSorted() {
    const base = getFiltered();
    const terms = getTerms();

    // 검색어가 있으면: 프로필 코드 매칭을 최우선, 동순위는 정렬 키로 2차 정렬
    if (terms.length) {
      const priority = (e) => {
        if (terms.some(q => (e.profile_code || '').toLowerCase().includes(q))) return 0;
        if (terms.some(q => (e.ingame_nick  || '').toLowerCase().includes(q))) return 1;
        if (terms.some(q => (e.guild        || '').toLowerCase().includes(q))) return 2;
        if (terms.some(q => (e.memo         || '').toLowerCase().includes(q))) return 3;
        if (terms.some(q => (e.friend_list  || '').toLowerCase().includes(q))) return 4;
        return 5;
      };
      return [...base].sort((a, b) => {
        const pd = priority(a) - priority(b);
        if (pd !== 0) return pd;
        if (sortKey) {
          const va = (a[sortKey] || '').toLowerCase();
          const vb = (b[sortKey] || '').toLowerCase();
          const cmp = va < vb ? -1 : va > vb ? 1 : 0;
          return sortAsc ? cmp : -cmp;
        }
        return 0;
      });
    }

    // 검색어 없음: 헤더 클릭 정렬만 적용
    if (sortKey) {
      return [...base].sort((a, b) => {
        const va = (a[sortKey] || '').toLowerCase();
        const vb = (b[sortKey] || '').toLowerCase();
        const cmp = va < vb ? -1 : va > vb ? 1 : 0;
        return sortAsc ? cmp : -cmp;
      });
    }

    return base;
  }

  function setFilter(value) {
    filterText = value.trim();
    render();
  }

  async function load() {
    try {
      const res = await fetch('/api/user-db');
      if (!res.ok) return;
      entries = await res.json();
      render();
    } catch (err) {
      console.error('유저 DB 로드 실패:', err);
    }
  }

  function render() {
    const tbody = document.getElementById('userdb-tbody');
    tbody.innerHTML = '';
    const sorted = getSorted();
    lastSorted = sorted;
    const total = entries.length;
    const shown = sorted.length;
    document.getElementById('userdb-count').textContent =
      filterText ? `${shown}/${total}` : String(total);
    for (let i = 0; i < sorted.length; i++) {
      const entry = sorted[i];
      const tr = document.createElement('tr');
      tr.dataset.profileCode = entry.profile_code;
      tr.dataset.rowIdx = String(i);
      if (selectedCodes.has(entry.profile_code)) tr.classList.add('selected');
      const terms = getTerms();
      for (const col of COLUMNS) {
        const td = document.createElement('td');
        td.dataset.profileCode = entry.profile_code;
        td.dataset.field = col.key;
        if (TAG_FIELDS.has(col.key)) {
          const directSearched = col.key === 'friend_list' && isDirectSearched(entry.profile_code);
          renderNickTags(td, entry[col.key] || '', terms, col.key === 'friend_list', directSearched);
        } else if (terms.length) {
          td.innerHTML = highlightText(entry[col.key] || '', terms);
        } else {
          td.textContent = entry[col.key] || '';
        }
        td.addEventListener('contextmenu', onCellContextMenu);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  // ── 인겜닉 태그 렌더링 ──────────────────────────────────────
  function parseTags(value) {
    return (value || '').split(',').map(s => s.trim()).filter(s => s);
  }

  function renderNickTags(td, value, terms = [], showCount = false, directSearched = false) {
    td.innerHTML = '';
    const tags = parseTags(value);
    if (showCount) {
      const countSpan = document.createElement('span');
      countSpan.className = directSearched ? 'friend-count friend-count-direct' : 'friend-count';
      countSpan.textContent = `(${tags.length})`;
      td.appendChild(countSpan);
    }
    for (const tag of tags) {
      td.appendChild(makeTagEl(tag, terms));
    }
  }

  function makeTagEl(text, terms = []) {
    const span = document.createElement('span');
    span.className = 'nick-tag';
    if (terms.length && terms.some(t => text.toLowerCase().includes(t))) {
      span.classList.add('search-highlight-tag');
    }
    span.textContent = text;
    return span;
  }

  function highlightText(text, terms) {
    if (!terms.length || !text) return Packets.escapeHtml(text || '');
    const reEscaped = terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const re = new RegExp(`(${reEscaped.join('|')})`, 'gi');
    const parts = [];
    let last = 0, match;
    re.lastIndex = 0;
    while ((match = re.exec(text)) !== null) {
      if (match.index > last) parts.push(Packets.escapeHtml(text.slice(last, match.index)));
      parts.push(`<span class="search-highlight">${Packets.escapeHtml(match[0])}</span>`);
      last = match.index + match[0].length;
    }
    if (last < text.length) parts.push(Packets.escapeHtml(text.slice(last)));
    return parts.join('');
  }

  // ── 인겜닉 태그 편집기 ───────────────────────────────────────
  function editIngameNickCell(profileCode, field, td) {
    const current = td.dataset.rawValue || [...td.querySelectorAll('.nick-tag')]
      .map(s => s.textContent).join(',');

    const tags = parseTags(current);
    let committed = false;

    const editor = document.createElement('div');
    editor.className = 'nick-tag-editor';

    function buildEditor() {
      editor.innerHTML = '';
      for (const tag of tags) {
        const span = document.createElement('span');
        span.className = 'nick-tag';
        span.textContent = tag;
        const rm = document.createElement('span');
        rm.className = 'nick-tag-remove';
        rm.textContent = '×';
        rm.addEventListener('mousedown', (e) => {
          e.preventDefault();
          tags.splice(tags.indexOf(tag), 1);
          buildEditor();
        });
        span.appendChild(rm);
        editor.appendChild(span);
      }
      const maxTags = field === 'ingame_nick' ? 3 : Infinity;
      const inp = document.createElement('input');
      inp.className = 'nick-tag-input';
      inp.placeholder = field === 'ingame_nick'
        ? (tags.length >= 3 ? '최대 3개' : `닉네임 입력 (${tags.length}/3)`)
        : `코드 입력 (${tags.length})`;
      inp.disabled = tags.length >= maxTags;
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ',') {
          e.preventDefault();
          if (tags.length >= maxTags) return;
          const val = inp.value.trim().replace(/,/g, '');
          if (val && !tags.includes(val)) tags.push(val);
          buildEditor();
          editor.querySelector('.nick-tag-input').focus();
        }
        if (e.key === 'Escape') {
          committed = true;
          restoreCell();
        }
        if (e.key === 'Backspace' && inp.value === '' && tags.length) {
          tags.pop();
          buildEditor();
          editor.querySelector('.nick-tag-input').focus();
        }
      });
      inp.addEventListener('blur', () => setTimeout(commit, 150));
      editor.appendChild(inp);
      inp.focus();
    }

    function commit() {
      if (committed) return;
      if (editor.contains(document.activeElement)) return;
      committed = true;
      const newVal = tags.join(',');
      td.innerHTML = '';
      renderNickTags(td, newVal);
      if (newVal !== current) saveField(profileCode, field, newVal);
    }

    function restoreCell() {
      td.innerHTML = '';
      renderNickTags(td, current);
    }

    editor.addEventListener('mousedown', (e) => {
      if (e.target === editor) {
        setTimeout(() => editor.querySelector('.nick-tag-input')?.focus(), 0);
      }
    });

    td.innerHTML = '';
    td.appendChild(editor);
    buildEditor();
  }

  // ── 우클릭 컨텍스트 메뉴 ────────────────────────────────────
  function onCellContextMenu(e) {
    e.preventDefault();
    closeCtxMenu();
    const td = e.target.closest('td');
    if (!td) return;

    const profileCode = td.dataset.profileCode;
    const field = td.dataset.field;

    ctxMenu = document.createElement('div');
    ctxMenu.className = 'context-menu';
    ctxMenu.style.left = e.clientX + 'px';
    ctxMenu.style.top = e.clientY + 'px';

    // 다중 행 선택 시: 다중 친구 검색 / 본인 검색
    if (selectedCodes.size > 1 && selectedCodes.has(profileCode)) {
      const multiBtn = document.createElement('div');
      multiBtn.textContent = `다중 친구 검색 (${selectedCodes.size}명)`;
      multiBtn.addEventListener('click', () => {
        closeCtxMenu();
        const codes = [...selectedCodes].join(',');
        Friends.searchCode(codes);
      });
      ctxMenu.appendChild(multiBtn);

      const multiSelfBtn = document.createElement('div');
      multiSelfBtn.textContent = `본인 검색 (${selectedCodes.size}명)`;
      multiSelfBtn.addEventListener('click', () => {
        closeCtxMenu();
        const targetCodes = [...selectedCodes];
        const friendMap = {};
        for (const entry of entries.filter(e => selectedCodes.has(e.profile_code))) {
          const friends = (entry.friend_list || '').split(',').map(s => s.trim()).filter(s => s);
          if (friends.length > 0) friendMap[entry.profile_code] = friends;
        }
        Friends.searchSelfOptimized(targetCodes, friendMap);
      });
      ctxMenu.appendChild(multiSelfBtn);
    } else {
      const selfBtn = document.createElement('div');
      selfBtn.textContent = '본인 검색';
      selfBtn.addEventListener('click', () => {
        closeCtxMenu();
        Friends.searchSelf(profileCode);
      });
      ctxMenu.appendChild(selfBtn);
    }

    const friendBtn = document.createElement('div');
    friendBtn.textContent = '친구 검색';
    friendBtn.addEventListener('click', () => {
      closeCtxMenu();
      Friends.searchCode(profileCode);
    });
    ctxMenu.appendChild(friendBtn);

    const monitorBtn = document.createElement('div');
    monitorBtn.textContent = '채널 모니터';
    monitorBtn.addEventListener('click', () => {
      closeCtxMenu();
      startMonitorForSelected(profileCode);
    });
    ctxMenu.appendChild(monitorBtn);

    const removeDataBtn = document.createElement('div');
    removeDataBtn.textContent = '데이터 제거';
    removeDataBtn.addEventListener('click', () => {
      closeCtxMenu();
      const value = prompt('제거할 값을 입력하세요 (대소문자 구분):');
      if (value === null || value === '') return;
      removeDataFromSelected(value);
    });
    ctxMenu.appendChild(removeDataBtn);

    const editBtn = document.createElement('div');
    editBtn.textContent = '수정';
    editBtn.addEventListener('click', () => {
      closeCtxMenu();
      editCell(profileCode, field, td);
    });
    ctxMenu.appendChild(editBtn);

    const delBtn = document.createElement('div');
    delBtn.textContent = field === 'profile_code' ? '행 삭제' : '삭제';
    delBtn.addEventListener('click', () => {
      closeCtxMenu();
      if (field === 'profile_code') {
        deleteRow(profileCode);
      } else {
        clearCell(profileCode, field, td);
      }
    });
    ctxMenu.appendChild(delBtn);

    document.body.appendChild(ctxMenu);
    setTimeout(() => document.addEventListener('click', closeCtxMenu, { once: true }), 0);
  }

  async function removeDataFromSelected(value) {
    const codes = selectedCodes.size > 0 ? [...selectedCodes] : null;
    if (!codes || codes.length === 0) return;

    const FIELDS = ['ingame_nick', 'mw_nick', 'guild', 'main_map', 'memo', 'ppsn', 'friend_list'];
    let changeCount = 0;
    const saves = [];

    for (const pc of codes) {
      const entry = entries.find(e => e.profile_code === pc);
      if (!entry) continue;
      for (const field of FIELDS) {
        const current = entry[field] || '';
        let newVal;
        if (TAG_FIELDS.has(field)) {
          const tags = current.split(',').map(t => t.trim()).filter(t => t !== '');
          const filtered = tags.filter(t => t !== value);
          if (filtered.length === tags.length) continue;
          newVal = filtered.join(',');
        } else {
          if (current !== value) continue;
          newVal = '';
        }
        changeCount++;
        saves.push(saveField(pc, field, newVal));
      }
    }

    await Promise.all(saves);
    if (changeCount === 0) {
      alert('일치하는 값이 없습니다.');
    } else {
      render();
    }
  }

  function closeCtxMenu() {
    if (ctxMenu) {
      ctxMenu.remove();
      ctxMenu = null;
    }
  }

  // ── 인라인 편집 ─────────────────────────────────────────────
  function editCell(profileCode, field, td) {
    if (field === 'profile_code') return;
    if (TAG_FIELDS.has(field)) return editIngameNickCell(profileCode, field, td);
    const current = td.textContent;
    const input = document.createElement('input');
    input.type = 'text';
    input.value = current;
    input.className = 'userdb-edit-input';
    td.textContent = '';
    td.appendChild(input);
    input.focus();
    input.select();

    let committed = false;
    function commit() {
      if (committed) return;
      committed = true;
      const newVal = input.value.trim();
      td.textContent = newVal;
      if (newVal !== current) {
        saveField(profileCode, field, newVal);
      }
    }

    input.addEventListener('blur', commit);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') input.blur();
      if (e.key === 'Escape') { committed = true; td.textContent = current; }
    });
  }

  async function saveField(profileCode, field, value) {
    try {
      await fetch(`/api/user-db/${encodeURIComponent(profileCode)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ field, value }),
      });
      const entry = entries.find(e => e.profile_code === profileCode);
      if (entry) entry[field] = value;
    } catch (err) {
      console.error('유저 DB 수정 실패:', err);
    }
  }

  async function clearCell(profileCode, field, td) {
    td.innerHTML = '';
    await saveField(profileCode, field, '');
  }

  async function deleteRow(profileCode) {
    try {
      await fetch(`/api/user-db/${encodeURIComponent(profileCode)}`, { method: 'DELETE' });
      entries = entries.filter(e => e.profile_code !== profileCode);
      render();
    } catch (err) {
      console.error('유저 DB 삭제 실패:', err);
    }
  }

  // ── 겹지인찾기 ───────────────────────────────────────────────
  function findCommonFriends() {
    if (selectedCodes.size === 0) {
      alert('먼저 행을 선택해주세요.\n(클릭 또는 드래그로 여러 행 선택 가능)');
      return;
    }
    const selectedEntries = entries.filter(e => selectedCodes.has(e.profile_code));
    const total = selectedEntries.length;

    // 각 친구 코드가 몇 명의 선택된 유저와 연결되어 있는지 카운트
    const freq = {};
    for (const entry of selectedEntries) {
      const friends = parseTags(entry.friend_list || '');
      for (const code of friends) {
        if (!code) continue;
        freq[code] = (freq[code] || 0) + 1;
      }
    }

    // 빈도 순 정렬
    const ranked = Object.entries(freq).sort((a, b) => b[1] - a[1]);

    renderCommonFriendsModal(ranked, total, selectedEntries);
  }

  function renderCommonFriendsModal(ranked, total, selectedEntries) {
    const modal = document.getElementById('common-friends-modal');
    const titleEl = document.getElementById('cf-title');
    const tbody = document.getElementById('cf-tbody');
    const searchedCodes = new Set(selectedEntries.map(e => e.profile_code));

    titleEl.textContent = `겹지인찾기 — ${total}명 선택`;
    tbody.innerHTML = '';
    cfSelectedCodes.clear();
    cfLastRanked = ranked;

    if (ranked.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = '공통 친구가 없습니다.';
      td.style.textAlign = 'center';
      td.style.color = 'var(--text-dim)';
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      ranked.forEach(([code, count], idx) => {
        const tr = document.createElement('tr');
        tr.dataset.profileCode = code;
        tr.dataset.rowIdx = String(idx);
        const entry = entries.find(e => e.profile_code === code);
        const nick = getIngameNick(code);
        const guild = entry ? (entry.guild || '') : '';
        const memo = entry ? (entry.memo || '') : '';
        const pct = Math.round((count / total) * 100);

        const rankTd = document.createElement('td');
        rankTd.textContent = String(idx + 1);
        rankTd.style.color = 'var(--text-dim)';
        rankTd.style.textAlign = 'center';

        const codeTd = document.createElement('td');
        codeTd.textContent = code;
        codeTd.style.fontFamily = 'monospace';
        codeTd.style.color = has(code) ? 'var(--text)' : '#ffff00';
        if (searchedCodes.has(code)) codeTd.style.fontWeight = 'bold';

        const nickTd = document.createElement('td');
        nickTd.textContent = nick;
        nickTd.style.color = nick ? 'var(--text)' : 'var(--text-dim)';

        const guildTd = document.createElement('td');
        guildTd.textContent = guild;
        guildTd.style.color = guild ? 'var(--text)' : 'var(--text-dim)';

        const memoTd = document.createElement('td');
        memoTd.textContent = memo;
        memoTd.style.color = memo ? 'var(--text)' : 'var(--text-dim)';

        const countTd = document.createElement('td');
        countTd.style.textAlign = 'center';
        const bar = document.createElement('div');
        bar.className = 'cf-bar-wrap';
        const fill = document.createElement('div');
        fill.className = 'cf-bar-fill';
        fill.style.width = pct + '%';
        bar.appendChild(fill);
        const label = document.createElement('span');
        label.className = 'cf-bar-label';
        label.textContent = `${count}/${total}`;
        countTd.appendChild(bar);
        countTd.appendChild(label);

        tr.appendChild(rankTd);
        tr.appendChild(codeTd);
        tr.appendChild(nickTd);
        tr.appendChild(guildTd);
        tr.appendChild(memoTd);
        tr.appendChild(countTd);
        tbody.appendChild(tr);
      });
    }

    modal.classList.remove('hidden');
  }

  function setupCfSelectionListeners() {
    const tbody = document.getElementById('cf-tbody');

    tbody.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      const tr = e.target.closest('tr');
      if (!tr || !tr.dataset.profileCode) return;
      const idx = parseInt(tr.dataset.rowIdx);
      const code = tr.dataset.profileCode;

      if (e.shiftKey && cfAnchorCode !== null) {
        e.preventDefault();
        const anchorIdx = cfLastRanked.findIndex(([c]) => c === cfAnchorCode);
        if (anchorIdx !== -1) {
          cfSelectedCodes.clear();
          const lo = Math.min(anchorIdx, idx);
          const hi = Math.max(anchorIdx, idx);
          for (let i = lo; i <= hi; i++) {
            if (cfLastRanked[i]) cfSelectedCodes.add(cfLastRanked[i][0]);
          }
          updateCfSelectionVisuals();
        }
      } else if (e.ctrlKey || e.metaKey) {
        if (cfSelectedCodes.has(code)) {
          cfSelectedCodes.delete(code);
          tr.classList.remove('selected');
        } else {
          cfSelectedCodes.add(code);
          tr.classList.add('selected');
        }
        cfAnchorCode = code;
      } else {
        cfSelectedCodes.clear();
        updateCfSelectionVisuals();
        cfSelectedCodes.add(code);
        tr.classList.add('selected');
        cfIsDragging = true;
        cfDragStartIdx = idx;
        cfAnchorCode = code;
      }
    });

    tbody.addEventListener('mouseover', (e) => {
      if (!cfIsDragging) return;
      const tr = e.target.closest('tr');
      if (!tr || !tr.dataset.rowIdx) return;
      const currentIdx = parseInt(tr.dataset.rowIdx);
      const lo = Math.min(cfDragStartIdx, currentIdx);
      const hi = Math.max(cfDragStartIdx, currentIdx);
      cfSelectedCodes.clear();
      for (let i = lo; i <= hi; i++) {
        if (cfLastRanked[i]) cfSelectedCodes.add(cfLastRanked[i][0]);
      }
      updateCfSelectionVisuals();
    });

    document.addEventListener('mouseup', () => { cfIsDragging = false; });

    tbody.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const tr = e.target.closest('tr');
      if (!tr || !tr.dataset.profileCode) return;
      const code = tr.dataset.profileCode;
      // 우클릭한 행이 선택 안 돼 있으면 단독 선택
      if (!cfSelectedCodes.has(code)) {
        cfSelectedCodes.clear();
        updateCfSelectionVisuals();
        cfSelectedCodes.add(code);
        tr.classList.add('selected');
        cfAnchorCode = code;
      }
      onCfContextMenu(e, code);
    });
  }

  function updateCfSelectionVisuals() {
    document.querySelectorAll('#cf-tbody tr').forEach(tr => {
      tr.classList.toggle('selected', cfSelectedCodes.has(tr.dataset.profileCode));
    });
  }

  function closeCfCtxMenu() {
    if (cfCtxMenu) { cfCtxMenu.remove(); cfCtxMenu = null; }
  }

  function onCfContextMenu(e, code) {
    closeCfCtxMenu();
    cfCtxMenu = document.createElement('div');
    cfCtxMenu.className = 'context-menu';
    cfCtxMenu.style.left = e.clientX + 'px';
    cfCtxMenu.style.top  = e.clientY + 'px';

    const isMulti = cfSelectedCodes.size > 1;
    const codes = [...cfSelectedCodes];

    if (isMulti) {
      const multiBtn = document.createElement('div');
      multiBtn.textContent = `다중 친구 검색 (${codes.length}명)`;
      multiBtn.addEventListener('click', () => {
        closeCfCtxMenu();
        Friends.searchCode(codes.join(','));
      });
      cfCtxMenu.appendChild(multiBtn);

      const multiSelfBtn = document.createElement('div');
      multiSelfBtn.textContent = `본인 검색 (${codes.length}명)`;
      multiSelfBtn.addEventListener('click', () => {
        closeCfCtxMenu();
        const friendMap = {};
        for (const c of codes) {
          const entry = entries.find(en => en.profile_code === c);
          const fl = (entry?.friend_list || '').split(',').map(s => s.trim()).filter(s => s);
          if (fl.length) friendMap[c] = fl;
        }
        Friends.searchSelfOptimized(codes, friendMap);
      });
      cfCtxMenu.appendChild(multiSelfBtn);

      const dbFilterBtn = document.createElement('div');
      dbFilterBtn.textContent = `유저DB에서 검색 (${codes.length}명)`;
      dbFilterBtn.addEventListener('click', () => {
        closeCfCtxMenu();
        const val = codes.join(', ');
        document.getElementById('userdb-search').value = val;
        setFilter(val);
      });
      const cfMonitorBtn = document.createElement('div');
      cfMonitorBtn.textContent = `채널 모니터 (${codes.length}명)`;
      cfMonitorBtn.addEventListener('click', () => {
        closeCfCtxMenu();
        startMonitorForCodes(codes);
      });
      cfCtxMenu.appendChild(cfMonitorBtn);

      cfCtxMenu.appendChild(dbFilterBtn);
    } else {
      const friendBtn = document.createElement('div');
      friendBtn.textContent = '친구 검색';
      friendBtn.addEventListener('click', () => { closeCfCtxMenu(); Friends.searchCode(code); });
      cfCtxMenu.appendChild(friendBtn);

      const selfBtn = document.createElement('div');
      selfBtn.textContent = '본인 검색';
      selfBtn.addEventListener('click', () => { closeCfCtxMenu(); Friends.searchSelf(code); });
      cfCtxMenu.appendChild(selfBtn);

      const cfMonitorBtn = document.createElement('div');
      cfMonitorBtn.textContent = '채널 모니터';
      cfMonitorBtn.addEventListener('click', () => {
        closeCfCtxMenu();
        startMonitorForCodes([code]);
      });
      cfCtxMenu.appendChild(cfMonitorBtn);

      const dbFilterBtn = document.createElement('div');
      dbFilterBtn.textContent = '유저DB에서 검색';
      dbFilterBtn.addEventListener('click', () => {
        closeCfCtxMenu();
        document.getElementById('userdb-search').value = code;
        setFilter(code);
      });
      cfCtxMenu.appendChild(dbFilterBtn);
    }

    document.body.appendChild(cfCtxMenu);
    setTimeout(() => document.addEventListener('click', closeCfCtxMenu, { once: true }), 0);
  }

  function closeCommonFriendsModal() {
    document.getElementById('common-friends-modal').classList.add('hidden');
  }

  // ── 전체 초기화 ──────────────────────────────────────────────
  async function clearAll() {
    if (!confirm('유저 DB의 모든 데이터를 삭제하시겠습니까?\n이 작업은 되돌릴 수 없습니다.')) return;
    try {
      await fetch('/api/user-db', { method: 'DELETE' });
      entries = [];
      render();
    } catch (err) {
      console.error('유저 DB 초기화 실패:', err);
      alert('초기화 실패: ' + err);
    }
  }

  // ── 중복 프로필 제거 ─────────────────────────────────────────
  async function deduplicate() {
    try {
      const res = await fetch('/api/user-db/deduplicate', { method: 'POST' });
      const data = await res.json();
      alert(`중복 제거 완료: ${data.removed}건 삭제되었습니다.`);
      await load();
    } catch (err) {
      console.error('중복 제거 실패:', err);
      alert('중복 제거 실패: ' + err);
    }
  }

  // ── 외부 호출: 친구검색 / 유저리스트에서 저장 ──────────────
  async function saveEntries(newEntries) {
    if (!newEntries.length) return;
    try {
      const res = await fetch('/api/user-db/bulk-save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entries: newEntries }),
      });
      const data = await res.json();
      if (data.status === 'saved') {
        alert(`${data.count}건의 데이터가 유저 DB에 저장되었습니다.`);
        await load();
      } else {
        alert('저장 실패: ' + (data.error || ''));
      }
    } catch (err) {
      alert('저장 실패: ' + err);
    }
  }

  function getIngameNick(profileCode) {
    if (!profileCode) return '';
    const entry = entries.find(e => e.profile_code === profileCode);
    return entry ? (entry.ingame_nick || '') : '';
  }

  function getGuild(profileCode) {
    if (!profileCode) return '';
    const entry = entries.find(e => e.profile_code === profileCode);
    return entry ? (entry.guild || '') : '';
  }

  function getMemo(profileCode) {
    if (!profileCode) return '';
    const entry = entries.find(e => e.profile_code === profileCode);
    return entry ? (entry.memo || '') : '';
  }

  function has(profileCode) {
    if (!profileCode) return false;
    return entries.some(e => e.profile_code === profileCode);
  }

  // ── 채널 모니터 연동 ─────────────────────────────────────────
  async function startMonitorForSelected(clickedCode) {
    const targetCodes = (selectedCodes.size > 0 && selectedCodes.has(clickedCode))
      ? [...selectedCodes]
      : [clickedCode];
    return startMonitorForCodes(targetCodes);
  }

  async function startMonitorForCodes(targetCodes) {

    // 커버리지 맵 구성: 친구코드(upper) → 커버 가능한 타겟 코드(upper) 집합
    const coverageMap = new Map();
    const origCodeMap = new Map(); // upper → 원본 케이스
    for (const code of targetCodes) {
      const entry = entries.find(e => e.profile_code === code);
      if (!entry?.friend_list) continue;
      for (const f of parseTags(entry.friend_list)) {
        const fUp = f.toUpperCase();
        if (!coverageMap.has(fUp)) {
          coverageMap.set(fUp, new Set());
          origCodeMap.set(fUp, f);
        }
        coverageMap.get(fUp).add(code.toUpperCase());
      }
    }

    if (coverageMap.size === 0) {
      alert('선택된 유저의 친구목록 데이터가 없습니다.\n먼저 친구목록을 저장해주세요.');
      return;
    }

    // UserDB에서 PPSN 조회
    const ppsnMap = new Map(); // upper → ppsn
    const missingUpper = new Set();
    for (const [fUp] of coverageMap) {
      const e = entries.find(en => en.profile_code.toUpperCase() === fUp);
      if (e?.ppsn) {
        ppsnMap.set(fUp, e.ppsn);
      } else {
        missingUpper.add(fUp);
      }
    }

    // 탐욕적 집합 피복
    function runGreedy(currentPpsnMap) {
      const remaining = new Set(targetCodes.map(c => c.toUpperCase()));
      const available = new Map(currentPpsnMap);
      const result = [];
      while (remaining.size > 0 && available.size > 0) {
        let bestCode = null, bestPpsn = null, bestCov = [], bestCount = 0;
        for (const [fUp, ppsn] of available) {
          const cov = coverageMap.get(fUp) || new Set();
          const overlap = [...cov].filter(t => remaining.has(t));
          if (overlap.length > bestCount) {
            bestCount = overlap.length;
            bestCode = fUp;
            bestPpsn = ppsn;
            bestCov = overlap;
          }
        }
        if (!bestCode) break;
        result.push({ ppsn: bestPpsn, friendCode: bestCode, coveredTargets: bestCov });
        bestCov.forEach(t => remaining.delete(t));
        available.delete(bestCode);
      }
      return { result, uncovered: remaining };
    }

    let { result: greedyResult, uncovered } = runGreedy(ppsnMap);

    // 아직 커버 안 된 타겟이 있고, PPSN 미탐색 친구가 있으면 검색 시도
    if (uncovered.size > 0 && missingUpper.size > 0) {
      const neededUpper = [...missingUpper].filter(fUp => {
        const cov = coverageMap.get(fUp) || new Set();
        return [...cov].some(t => uncovered.has(t));
      });

      if (neededUpper.length > 0) {
        const origNeeded = neededUpper.map(fUp => origCodeMap.get(fUp) || fUp);
        const confirmed = confirm(
          `${uncovered.size}명 모니터링을 위해 ${origNeeded.length}개 코드의 PPSN 탐색이 필요합니다.\n탐색을 진행할까요?\n(탐색 후 유저DB에 자동 저장됩니다)`
        );
        if (confirmed) {
          const discovered = await _searchPpsnsForCodes(origNeeded);
          if (discovered.length > 0) {
            await _saveEntriesSilent(discovered);
            await load();
            for (const d of discovered) {
              if (d.ppsn) ppsnMap.set(d.profile_code.toUpperCase(), d.ppsn);
            }
            const second = runGreedy(ppsnMap);
            greedyResult = second.result;
            uncovered = second.uncovered;
          }
        }
      }
    }

    if (greedyResult.length === 0) {
      alert('채널 모니터를 시작할 PPSN을 찾지 못했습니다.');
      return;
    }

    const allPpsns = greedyResult.map(r => r.ppsn);
    const coveredCount = targetCodes.length - uncovered.size;
    if (uncovered.size > 0) {
      alert(
        `${targetCodes.length}명 중 ${coveredCount}명을 ${allPpsns.length}개 PPSN으로 모니터링합니다.\n` +
        `(나머지 ${uncovered.size}명은 커버할 수 있는 PPSN이 없습니다)`
      );
    }
    Monitor.openWithPpsn(allPpsns[0], targetCodes, allPpsns);
  }

  // 프로필 코드 목록 → PPSN 탐색 (백그라운드 WS, self_only)
  function _searchPpsnsForCodes(codes) {
    return new Promise((resolve) => {
      const results = [];
      const ws = new WebSocket(`ws://${location.host}/ws/friends`);
      ws.onopen = () => {
        ws.send(JSON.stringify({ action: 'search', codes, phase: 1, self_only: true }));
      };
      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data);
          if (data.type === 'result') {
            for (const e of data.entries || []) {
              if (e.is_self && e.ppsn && e.profile_code) {
                results.push({ profile_code: e.profile_code, ppsn: e.ppsn, mw_nick: e.display_name || '' });
              }
            }
          }
          if (data.type === 'finished') {
            ws.onclose = null;
            ws.close();
            resolve(results);
          }
        } catch (err) {
          console.error('[PPSN lookup]', err);
        }
      };
      ws.onerror = () => { ws.close(); resolve(results); };
      ws.onclose = () => resolve(results);
    });
  }

  // 유저DB 저장 (알림 없는 버전)
  async function _saveEntriesSilent(newEntries) {
    if (!newEntries.length) return;
    try {
      await fetch('/api/user-db/bulk-save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entries: newEntries }),
      });
    } catch (err) {
      console.error('PPSN 저장 실패:', err);
    }
  }

  return { init, load, render, saveEntries, clearAll, deduplicate, getIngameNick, getGuild, getMemo, has, setFilter, findCommonFriends, closeCommonFriendsModal };
})();
