/**
 * 유저 DB — Supabase 연동, 우클릭 수정/삭제, 헤더 정렬
 */
const UserDB = (() => {
  let entries = [];
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
  ];

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

  function getSorted() {
    if (!sortKey) return entries;
    return [...entries].sort((a, b) => {
      const va = (a[sortKey] || '').toLowerCase();
      const vb = (b[sortKey] || '').toLowerCase();
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return sortAsc ? cmp : -cmp;
    });
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
    document.getElementById('userdb-count').textContent = String(entries.length);
    const sorted = getSorted();
    for (const entry of sorted) {
      const tr = document.createElement('tr');
      for (const col of COLUMNS) {
        const td = document.createElement('td');
        td.textContent = entry[col.key] || '';
        td.dataset.profileCode = entry.profile_code;
        td.dataset.field = col.key;
        td.addEventListener('contextmenu', onCellContextMenu);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
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
    if (field === 'profile_code') return; // 기준 열은 수정 불가
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
    td.textContent = '';
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

  return { init, load, render, saveEntries, clearAll };
})();
