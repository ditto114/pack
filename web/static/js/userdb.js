/**
 * 유저 DB — Supabase 연동, 우클릭 수정/삭제, 헤더 정렬
 */
const UserDB = (() => {
  let entries = [];
  let filterText = '';
  let ctxMenu = null;
  let sortKey = null;
  let sortAsc = true;

  const COLUMNS = [
    { key: 'profile_code', label: '프로필 코드' },
    { key: 'ingame_nick', label: '인겜닉' },
    { key: 'mw_nick', label: '메월닉' },
    { key: 'guild', label: '길드' },
    { key: 'main_map', label: '주 사냥터' },
    { key: 'ppsn', label: 'PPSN' },
    { key: 'friend_list', label: '친구목록' },
  ];

  const TAG_FIELDS = new Set(['ingame_nick', 'friend_list']);

  async function init() {
    setupHeaderSort();
    await load();
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
    if (!sortKey) return base;
    return [...base].sort((a, b) => {
      const va = (a[sortKey] || '').toLowerCase();
      const vb = (b[sortKey] || '').toLowerCase();
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return sortAsc ? cmp : -cmp;
    });
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
    const total = entries.length;
    const shown = sorted.length;
    document.getElementById('userdb-count').textContent =
      filterText ? `${shown}/${total}` : String(total);
    for (const entry of sorted) {
      const tr = document.createElement('tr');
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

  return { init, load, render, saveEntries, clearAll, deduplicate, getIngameNick, has, setFilter };
})();
