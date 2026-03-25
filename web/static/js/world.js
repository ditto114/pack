/**
 * 월드 매칭 UI 로직
 */
const World = (() => {
  let lastClickedRow = null;
  const codeToName = new Map();
  const worldRows = []; // { channel_name, world_code } — 현재 테이블 데이터

  // 실험 기능: WorldId / ChannelName 추출
  const WORLD_ID_RE = /w\s*o\s*r\s*l\s*d\s*i\s*d[\s:="'\x00-\x1F]*(\d{1,17})/gi;
  const CHANNEL_NAME_RE = /c\s*h\s*a\s*n\s*n\s*e\s*l\s*n\s*a\s*m\s*e[\s:="'\x00-\x1F]*([A-Za-z]-[\uAC00-\uD7A3]\d{2,3})/gi;
  const EXPERIMENT_COLS = 6;
  const experimentIds = [];
  const experimentIdSet = new Set();
  const experimentChannels = [];
  const experimentChannelSet = new Set();
  let currentExpTab = 'world';
  let dragSrcIdx = -1;
  let ctxMenu = null;

  function init() {
    document.getElementById('world-tbody').addEventListener('click', onRowClick);
    load(); // DB에서 저장된 데이터 불러오기
  }

  async function load() {
    document.getElementById('world-tbody').innerHTML = '';
    lastClickedRow = null;
    codeToName.clear();
    worldRows.length = 0;
    try {
      const res = await fetch('/api/world-match');
      if (!res.ok) {
        console.error('월드 매칭 데이터 로드 실패:', res.status);
        return;
      }
      const rows = await res.json();
      for (const item of rows) {
        addRow(item);
      }
    } catch (err) {
      console.error('월드 매칭 데이터 로드 실패:', err);
    }
  }

  function addRow(data) {
    if (data.world_code && data.channel_name) {
      codeToName.set(data.world_code, data.channel_name);
      worldRows.push({ channel_name: data.channel_name, world_code: data.world_code });
    }
    const tbody = document.getElementById('world-tbody');
    const tr = document.createElement('tr');
    tr.dataset.worldCode = data.world_code;
    tr.innerHTML = `
      <td>${Packets.escapeHtml(data.channel_name)}</td>
      <td>${Packets.escapeHtml(data.world_code)}</td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
  }

  function getChannelName(code) {
    return codeToName.get(code) || '';
  }

  function onRowClick(e) {
    const tr = e.target.closest('tr');
    if (!tr) return;
    if (lastClickedRow === tr) {
      const code = tr.dataset.worldCode;
      if (code) {
        navigator.clipboard.writeText(code).catch(() => {});
      }
      lastClickedRow = null;
    } else {
      lastClickedRow = tr;
    }
  }

  function toggleOrder(type) {
    const wfEl = document.getElementById('world-order-wf');
    const cfEl = document.getElementById('world-order-cf');

    if (type === 'world-first') {
      if (wfEl.checked) {
        cfEl.checked = false;
        setOrder('world-first', true);
      } else {
        setOrder(null, false);
      }
    } else {
      if (cfEl.checked) {
        wfEl.checked = false;
        setOrder('channel-first', true);
      } else {
        setOrder(null, false);
      }
    }
  }

  async function setOrder(order, locked) {
    await fetch('/api/world-match/order', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ order, locked }),
    });
  }

  async function save() {
    if (worldRows.length === 0) {
      alert('저장할 데이터가 없습니다.');
      return;
    }
    try {
      const res = await fetch('/api/world-match/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entries: worldRows }),
      });
      if (!res.ok) {
        alert('저장 실패: 서버 오류 (' + res.status + ')');
        return;
      }
      const data = await res.json();
      if (data.error) {
        alert('저장 실패: ' + data.error);
      } else {
        alert(`${data.count}건의 데이터가 DB에 저장되었습니다.`);
      }
    } catch (err) {
      alert('저장 실패: ' + err);
    }
  }

  async function clear() {
    await fetch('/api/world-match', { method: 'DELETE' });
    document.getElementById('world-tbody').innerHTML = '';
    lastClickedRow = null;
    codeToName.clear();
    worldRows.length = 0;
  }

  // ── 실험 기능 ───────────────────────────────────────────────
  function openExperiment() {
    document.getElementById('experiment-modal').classList.remove('hidden');
  }

  function closeExperiment() {
    document.getElementById('experiment-modal').classList.add('hidden');
  }

  function switchExpTab(tab) {
    currentExpTab = tab;
    document.getElementById('exp-tab-world').classList.toggle('active', tab === 'world');
    document.getElementById('exp-tab-channel').classList.toggle('active', tab === 'channel');
    document.getElementById('exp-world-view').classList.toggle('hidden', tab !== 'world');
    document.getElementById('exp-channel-view').classList.toggle('hidden', tab !== 'channel');
  }

  function clearExperiment() {
    experimentIds.length = 0;
    experimentIdSet.clear();
    experimentChannels.length = 0;
    experimentChannelSet.clear();
    document.getElementById('experiment-tbody').innerHTML = '';
    document.getElementById('experiment-ch-tbody').innerHTML = '';
  }

  function processPacketForExperiment(text) {
    if (!text) return;
    let worldChanged = false;
    let channelChanged = false;

    WORLD_ID_RE.lastIndex = 0;
    let match;
    while ((match = WORLD_ID_RE.exec(text)) !== null) {
      const id = match[1];
      if (id.length === 17 && !experimentIdSet.has(id)) {
        experimentIdSet.add(id);
        experimentIds.push(id);
        worldChanged = true;
      }
    }

    CHANNEL_NAME_RE.lastIndex = 0;
    while ((match = CHANNEL_NAME_RE.exec(text)) !== null) {
      const ch = match[1];
      const normalized = ch.toUpperCase();
      if (!experimentChannelSet.has(normalized)) {
        experimentChannelSet.add(normalized);
        experimentChannels.push(normalized);
        channelChanged = true;
      }
    }

    if (worldChanged) {
      experimentIds.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      renderGrid('experiment-tbody', experimentIds);
    }
    if (channelChanged) {
      renderGrid('experiment-ch-tbody', experimentChannels);
    }
  }

  function compareChannel(a, b) {
    const letterA = a[0];
    const letterB = b[0];
    if (letterA !== letterB) return letterA < letterB ? -1 : 1;
    const numA = parseInt(a.match(/\d+$/)[0], 10);
    const numB = parseInt(b.match(/\d+$/)[0], 10);
    return numA - numB;
  }

  function renderGrid(tbodyId, items) {
    const tbody = document.getElementById(tbodyId);
    const isDraggable = (tbodyId === 'experiment-ch-tbody');
    tbody.innerHTML = '';
    for (let i = 0; i < items.length; i += EXPERIMENT_COLS) {
      const tr = document.createElement('tr');
      for (let j = 0; j < EXPERIMENT_COLS; j++) {
        const td = document.createElement('td');
        const idx = i + j;
        td.textContent = items[idx] || '';
        if (idx < items.length) {
          td.dataset.idx = idx;
          td.dataset.grid = tbodyId;
          td.addEventListener('contextmenu', onGridContextMenu);
          if (isDraggable) {
            td.draggable = true;
            td.addEventListener('dragstart', onChDragStart);
            td.addEventListener('dragover', onChDragOver);
            td.addEventListener('drop', onChDrop);
            td.addEventListener('dragend', onChDragEnd);
          }
        }
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  }

  // ── 우클릭 삭제 컨텍스트 메뉴 ──────────────────────────────
  function onGridContextMenu(e) {
    e.preventDefault();
    closeCtxMenu();
    const td = e.target.closest('td');
    if (!td || td.dataset.idx === undefined || !td.textContent) return;

    const idx = parseInt(td.dataset.idx, 10);
    const gridId = td.dataset.grid;

    ctxMenu = document.createElement('div');
    ctxMenu.className = 'context-menu';
    ctxMenu.style.left = e.clientX + 'px';
    ctxMenu.style.top = e.clientY + 'px';

    const delBtn = document.createElement('div');
    delBtn.textContent = '삭제';
    delBtn.addEventListener('click', () => {
      deleteGridItem(gridId, idx);
      closeCtxMenu();
    });
    ctxMenu.appendChild(delBtn);
    document.body.appendChild(ctxMenu);

    // 바깥 클릭 시 닫기
    setTimeout(() => document.addEventListener('click', closeCtxMenu, { once: true }), 0);
  }

  function closeCtxMenu() {
    if (ctxMenu) {
      ctxMenu.remove();
      ctxMenu = null;
    }
  }

  function deleteGridItem(gridId, idx) {
    if (gridId === 'experiment-tbody') {
      const removed = experimentIds.splice(idx, 1)[0];
      if (removed) experimentIdSet.delete(removed);
      renderGrid('experiment-tbody', experimentIds);
    } else if (gridId === 'experiment-ch-tbody') {
      const removed = experimentChannels.splice(idx, 1)[0];
      if (removed) experimentChannelSet.delete(removed);
      renderGrid('experiment-ch-tbody', experimentChannels);
    }
  }

  // ── 채널 테이블 드래그 앤 드롭 ─────────────────────────────
  function onChDragStart(e) {
    dragSrcIdx = parseInt(e.target.dataset.idx, 10);
    e.target.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
  }

  function onChDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const td = e.target.closest('td');
    if (td && td.dataset.idx !== undefined) {
      // 드롭 대상 표시
      document.querySelectorAll('#experiment-ch-tbody td.drag-over').forEach(
        el => el.classList.remove('drag-over')
      );
      td.classList.add('drag-over');
    }
  }

  function onChDrop(e) {
    e.preventDefault();
    const td = e.target.closest('td');
    if (!td || td.dataset.idx === undefined) return;
    const destIdx = parseInt(td.dataset.idx, 10);
    if (dragSrcIdx < 0 || dragSrcIdx === destIdx) return;

    // 배열에서 아이템을 빼서 새 위치에 삽입
    const [moved] = experimentChannels.splice(dragSrcIdx, 1);
    experimentChannels.splice(destIdx, 0, moved);
    renderGrid('experiment-ch-tbody', experimentChannels);
    dragSrcIdx = -1;
  }

  function onChDragEnd() {
    dragSrcIdx = -1;
    document.querySelectorAll('#experiment-ch-tbody td.dragging, #experiment-ch-tbody td.drag-over').forEach(
      el => { el.classList.remove('dragging'); el.classList.remove('drag-over'); }
    );
  }

  function saveExpToWorldMatch() {
    const count = Math.min(experimentIds.length, experimentChannels.length);
    if (count === 0) {
      alert('매칭할 데이터가 없습니다. 월드매칭과 채널매칭 데이터가 모두 필요합니다.');
      return;
    }

    // 기존 월드 매칭 테이블 초기화
    document.getElementById('world-tbody').innerHTML = '';
    lastClickedRow = null;
    codeToName.clear();
    worldRows.length = 0;

    // 같은 인덱스끼리 매칭하여 추가
    for (let i = 0; i < count; i++) {
      addRow({
        world_code: experimentIds[i],
        channel_name: experimentChannels[i],
      });
    }

    alert(`${count}건의 데이터가 월드 매칭 테이블에 반영되었습니다. '저장' 버튼을 눌러 DB에 영구 저장하세요.`);
  }

  return {
    init, load, toggleOrder, save, clear, getChannelName,
    openExperiment, closeExperiment, switchExpTab, clearExperiment,
    processPacketForExperiment, saveExpToWorldMatch,
  };
})();
