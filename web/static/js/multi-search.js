/**
 * 다중 검색 (1촌 → 2촌 자동 순회) 모달 로직
 */
const MultiSearch = (() => {
  let running = false;
  let phase = 0; // 0=idle, 1=phase1, 2=phase2
  let currentWs = null;

  const phase1Entries = [];
  const phase2Entries = [];
  const allProfileCodes = new Set(); // 1촌·2촌 전체 중복 방지

  let phase2Queue = [];
  let phase2QueueIdx = 0;

  // ── 모달 열기/닫기 ──────────────────────────────────────────
  function open() {
    document.getElementById('multi-search-modal').classList.remove('hidden');
  }

  function close() {
    stop();
    document.getElementById('multi-search-modal').classList.add('hidden');
  }

  // ── 검색 시작 ────────────────────────────────────────────────
  function search() {
    if (running) return alert('다중 검색이 이미 진행 중입니다.');

    const code = document.getElementById('ms-code').value.trim();
    if (!/^[A-Za-z0-9]{5,6}$/.test(code)) {
      return alert('프로필 코드는 영문 대소문자/숫자의 5~6글자여야 합니다.');
    }

    clearAll();
    setRunning(true);
    setStatus('[1촌] 친구 목록 검색을 시작합니다...');
    startPhase1(code);
  }

  // ── 검색 중지 ────────────────────────────────────────────────
  function stop() {
    if (!running && !currentWs) return;
    running = false;
    phase = 0;
    closeCurrentWs();
    setRunning(false);
    setStatus('검색이 중지되었습니다.');
  }

  function closeCurrentWs() {
    if (currentWs) {
      currentWs.onclose = null;
      currentWs.onerror = null;
      currentWs.onmessage = null;
      currentWs.close();
      currentWs = null;
    }
  }

  // ── Phase 1: 입력 코드 검색 → 1촌 수집 ─────────────────────
  function startPhase1(code) {
    phase = 1;
    const ws = new WebSocket(`ws://${location.host}/ws/friends`);
    currentWs = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ action: 'search', codes: [code], phase: 1, code }));
    };

    ws.onmessage = (e) => {
      try { handlePhase1Message(JSON.parse(e.data)); }
      catch (err) { console.error('[MultiSearch] parse error:', err); }
    };

    ws.onclose = () => { currentWs = null; };

    ws.onerror = () => {
      setStatus('[오류] 1촌 검색 중 연결 오류가 발생했습니다.');
      setRunning(false);
    };
  }

  function handlePhase1Message(data) {
    switch (data.type) {
      case 'status':
        setStatus('[1촌] ' + (data.text || ''));
        break;
      case 'result':
        if (data.entries) {
          for (const e of data.entries) addPhase1Entry(e);
        }
        break;
      case 'error':
        setStatus('[1촌 오류] ' + (data.text || ''));
        break;
      case 'finished':
        closeCurrentWs();
        if (running) startPhase2();
        break;
    }
  }

  function addPhase1Entry(e) {
    const pc = (e.profile_code || '').toUpperCase();
    if (!pc || allProfileCodes.has(pc)) return;
    allProfileCodes.add(pc);
    e._channel_name = World.getChannelName(e.game_instance_id);
    phase1Entries.push(e);
    renderTable(1);
  }

  // ── Phase 2: 1촌 코드 순회 → 2촌 수집 ──────────────────────
  function startPhase2() {
    phase2Queue = phase1Entries
      .map(e => (e.profile_code || '').toUpperCase())
      .filter(pc => pc);
    phase2QueueIdx = 0;
    phase = 2;

    if (phase2Queue.length === 0) {
      setStatus('1촌 검색 결과가 없어 2촌 검색을 건너뜁니다.');
      setRunning(false);
      return;
    }

    setStatus(`2촌 검색 시작 (0/${phase2Queue.length})...`);
    processNextPhase2();
  }

  function processNextPhase2() {
    if (!running || phase2QueueIdx >= phase2Queue.length) {
      setStatus(`검색 완료 — 1촌: ${phase1Entries.length}명 / 2촌: ${phase2Entries.length}명`);
      setRunning(false);
      return;
    }

    const code = phase2Queue[phase2QueueIdx];
    const cur = phase2QueueIdx + 1;
    const tot = phase2Queue.length;
    setStatus(`2촌 검색 중 (${cur}/${tot}): ${code}`);

    const ws = new WebSocket(`ws://${location.host}/ws/friends`);
    currentWs = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ action: 'search', codes: [code], phase: 1, code }));
    };

    ws.onmessage = (e) => {
      try { handlePhase2Message(JSON.parse(e.data)); }
      catch (err) { console.error('[MultiSearch] parse error:', err); }
    };

    ws.onclose = () => { currentWs = null; };

    ws.onerror = () => {
      // 오류 발생 시 해당 코드 스킵 후 다음으로
      phase2QueueIdx++;
      if (running) processNextPhase2();
    };
  }

  function handlePhase2Message(data) {
    switch (data.type) {
      case 'result':
        if (data.entries) {
          for (const e of data.entries) addPhase2Entry(e);
        }
        break;
      case 'finished':
        closeCurrentWs();
        phase2QueueIdx++;
        if (running) processNextPhase2();
        break;
    }
  }

  function addPhase2Entry(e) {
    const pc = (e.profile_code || '').toUpperCase();
    if (!pc || allProfileCodes.has(pc)) return;
    allProfileCodes.add(pc);
    e._channel_name = World.getChannelName(e.game_instance_id);
    phase2Entries.push(e);
    renderTable(2);
  }

  // ── 렌더링 ──────────────────────────────────────────────────
  function renderTable(phaseNum) {
    const arr     = phaseNum === 1 ? phase1Entries : phase2Entries;
    const tbodyId = phaseNum === 1 ? 'ms-phase1-tbody' : 'ms-phase2-tbody';
    const countId = phaseNum === 1 ? 'ms-phase1-count' : 'ms-phase2-count';

    const tbody = document.getElementById(tbodyId);
    tbody.innerHTML = '';
    document.getElementById(countId).textContent = arr.length;

    for (const e of arr) {
      e._ingame_nick = UserDB.getIngameNick(e.profile_code);
      const statusIcon = e.status === '온라인' ? '🟢' : '⛔';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${statusIcon}</td>
        <td>${e.profile_code ? '#' + esc(e.profile_code) : ''}</td>
        <td>${esc(e._channel_name)}</td>
        <td>${esc(e.display_name)}</td>
        <td>${esc(e._ingame_nick)}</td>
        <td>${esc(e.world_name)}</td>
        <td>${esc(e.game_instance_id)}</td>
        <td>${esc(e.ppsn)}</td>
      `;
      tbody.appendChild(tr);
    }
  }

  // ── 초기화 ──────────────────────────────────────────────────
  function clearAll() {
    phase1Entries.length = 0;
    phase2Entries.length = 0;
    allProfileCodes.clear();
    phase2Queue = [];
    phase2QueueIdx = 0;
    renderTable(1);
    renderTable(2);
    setStatus('');
  }

  // ── 유저 DB에 저장 ───────────────────────────────────────────
  function saveToUserDB() {
    const all = [...phase1Entries, ...phase2Entries].filter(e => e.profile_code);
    if (!all.length) { alert('저장할 데이터가 없습니다.'); return; }
    const data = all.map(e => ({ profile_code: e.profile_code, mw_nick: e.display_name || '' }));
    UserDB.saveEntries(data);
  }

  // ── 헬퍼 ────────────────────────────────────────────────────
  function setRunning(r) {
    running = r;
    document.getElementById('ms-search-btn').disabled = r;
    document.getElementById('ms-stop-btn').disabled = !r;
  }

  function setStatus(text) {
    document.getElementById('ms-status').textContent = text;
  }

  function esc(s) { return Packets.escapeHtml(s || ''); }

  return { open, close, search, stop, saveToUserDB };
})();
