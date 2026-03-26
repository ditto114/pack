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
  let anchorCode = null; // Shift+Click 범위 선택의 기준 코드
  let lastSorted = [];
  let textSelTd = null; // 더블클릭으로 텍스트 선택 중인 td

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

  async function init() {
    setupHeaderSort();
    setupSelectionListeners();
    await load();
  }

  // ── 다중 선택 이벤트 리스너 (tbody에 위임) ──────────────────
  function setupSelectionListeners() {
    const tbody = document.getElementById('userdb-tbody');

    tbody.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      const td = e.target.closest('td');

      // 텍스트 선택 모드: 같은 td 내부 클릭이면 행 선택 건드리지 않음 (드래그 텍스트 선택 허용)
      if (textSelTd) {
        if (td === textSelTd) return;
        // 다른 곳 클릭 → 텍스트 선택 모드 해제
        exitTextSelMode();
      }

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
      // 편집 중인 셀(input/editor 포함)은 제외
      if (td.querySelector('input, .nick-tag-editor')) return;

      if (textSelTd && textSelTd !== td) exitTextSelMode();

      textSelTd = td;
      td.style.userSelect = 'text';

      // 셀 전체 텍스트 선택
      const range = document.createRange();
      range.selectNodeContents(td);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
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

  function exitTextSelMode() {
    if (!textSelTd) return;
    textSelTd.style.userSelect = '';
    textSelTd = null;
    window.getSelection().removeAllRanges();
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

  function getFiltered() {
    if (!filterText) return entries;
    const q = filterText.toLowerCase();
    return entries.filter(e =>
      COLUMNS.some(col => (e[col.key] || '').toLowerCase().includes(q))
    );
  }

  function getSorted() {
    const base = getFiltered();

    // 헤더 클릭 정렬이 있으면 그대로 적용
    if (sortKey) {
      return [...base].sort((a, b) => {
        const va = (a[sortKey] || '').toLowerCase();
        const vb = (b[sortKey] || '').toLowerCase();
        const cmp = va < vb ? -1 : va > vb ? 1 : 0;
        return sortAsc ? cmp : -cmp;
      });
    }

    // 검색어가 있으면 프로필 코드 → 길드 → 메모 순으로 우선 표시
    if (filterText) {
      const q = filterText.toLowerCase();
      const priority = (e) => {
        if ((e.profile_code || '').toLowerCase().includes(q)) return 0;
        if ((e.guild      || '').toLowerCase().includes(q)) return 1;
        if ((e.memo       || '').toLowerCase().includes(q)) return 2;
        return 3;
      };
      return [...base].sort((a, b) => priority(a) - priority(b));
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
    textSelTd = null; // 재렌더링 시 텍스트 선택 모드 해제
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
      for (const col of COLUMNS) {
        const td = document.createElement('td');
        td.dataset.profileCode = entry.profile_code;
        td.dataset.field = col.key;
        if (TAG_FIELDS.has(col.key)) {
          renderNickTags(td, entry[col.key] || '');
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

  function renderNickTags(td, value) {
    td.innerHTML = '';
    const tags = parseTags(value);
    for (const tag of tags) {
      td.appendChild(makeTagEl(tag));
    }
  }

  function makeTagEl(text) {
    const span = document.createElement('span');
    span.className = 'nick-tag';
    span.textContent = text;
    return span;
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
      const inp = document.createElement('input');
      inp.className = 'nick-tag-input';
      inp.placeholder = '닉네임 입력';
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ',') {
          e.preventDefault();
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

  function has(profileCode) {
    if (!profileCode) return false;
    return entries.some(e => e.profile_code === profileCode);
  }

  return { init, load, render, saveEntries, clearAll, deduplicate, getIngameNick, has, setFilter, findCommonFriends, closeCommonFriendsModal };
})();
