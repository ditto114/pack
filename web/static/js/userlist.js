/**
 * 유저리스트 — 패킷에서 접속 유저 정보(닉네임, 맵, 프로필 코드) 추출
 *
 * 지원 포맷 (필드 순서가 달라도 동작):
 *   ex1/ex2: Exp → Name → Created → MapOnline → Map → CharOnline → Profile → Attacks
 *   ex3:     Map → Profile → MapOnline → ... → Name → Attacks → Level
 *   ex4:     Level → Name → Exp → Attacks → Created → Profile → ... → Map → Captcha
 *
 * 전략: 키워드(Profile, Name, Map 등)의 위치를 모두 수집한 뒤,
 *        같은 키워드가 반복되면 블록 경계로 판단.
 *        각 블록에서 Profile·Name·Map을 추출하여 매칭.
 *        필드 순서에 의존하지 않으므로 어떤 순서든 정확히 매칭됨.
 */
const UserList = (() => {
  let buffer = '';
  const users = [];
  const profileSet = new Set();

  // 정렬 상태
  const SORT_KEYS = ['name', 'map', 'profile'];
  let sortKey = null;
  let sortAsc = true;

  // 값 추출 정규식
  const PROFILE_VAL_RE = /Profile[-\s]+([A-Za-z0-9]{5,6})(?![A-Za-z0-9])/;
  const NAME_VAL_RE = /(?<!Channel)Name[-\s]+([\uAC00-\uD7A3a-zA-Z0-9]+)/;
  const MAP_VAL_RE = /Map(?!Online)[-\s]+([\s\S]+?)(?:[-\s]{4,}(?:Profile|Captcha|Cha)|[-\s]*$)/;

  /* ── 키워드 위치 탐색 ─────────────────────────────────────── */

  function findKeywordPositions(text) {
    const positions = [];
    let m;

    // 대상 필드 (P, N, M)
    const profRe = /Profile[-\s]+[A-Za-z0-9]{5,6}(?![A-Za-z0-9])/g;
    while ((m = profRe.exec(text)) !== null)
      positions.push({ type: 'P', pos: m.index });

    const nameRe = /(?<!Channel)Name[-\s]+[\uAC00-\uD7A3a-zA-Z0-9]/g;
    while ((m = nameRe.exec(text)) !== null)
      positions.push({ type: 'N', pos: m.index });

    const mapRe = /Map(?!Online)[-\s]{4,}/g;
    while ((m = mapRe.exec(text)) !== null)
      positions.push({ type: 'M', pos: m.index });

    // 보조 키워드 — 블록 경계 감지용 (각 키워드를 고유 타입으로 등록)
    const helperRe = /Created|Attacks|Buffs|CharOnline|Captcha|MapOnline|ChannelOnline/g;
    while ((m = helperRe.exec(text)) !== null)
      positions.push({ type: m[0], pos: m.index });

    positions.sort((a, b) => a.pos - b.pos);
    return positions;
  }

  /* ── 블록 감지 & 추출 ─────────────────────────────────────── */

  function processPacket(text) {
    if (!text) return;
    const sanitized = text.replace(/[^\uAC00-\uD7A3a-zA-Z0-9\s\n\r]/g, '-');
    buffer += sanitized;

    if (buffer.length > 65536) {
      buffer = buffer.slice(-65536);
    }

    const positions = findKeywordPositions(buffer);

    // 키워드 반복 시 블록 경계로 판단
    const blocks = [];
    let seen = new Set();
    let blockItems = [];
    let trimPos = 0;

    for (const kw of positions) {
      if (seen.has(kw.type)) {
        // 블록 완성 여부 확인 (P, N, M 모두 존재)
        if (seen.has('P') && seen.has('N') && seen.has('M')) {
          blocks.push({ items: blockItems, endPos: kw.pos });
        }
        trimPos = kw.pos;
        seen = new Set();
        blockItems = [];
      }
      seen.add(kw.type);
      blockItems.push(kw);
    }

    let changed = false;
    for (const block of blocks) {
      const user = extractFromBlock(block.items, block.endPos);
      if (user && !profileSet.has(user.profile)) {
        profileSet.add(user.profile);
        users.push(user);
        changed = true;
      }
    }

    if (trimPos > 0) {
      buffer = buffer.substring(trimPos);
    }

    if (changed) {
      document.getElementById('userlist-count').textContent = String(users.length);
      render();
    }
  }

  function extractFromBlock(items, endPos) {
    const profItem = items.find(k => k.type === 'P');
    if (!profItem) return null;

    const blockStart = items[0].pos;
    const blockText = buffer.substring(blockStart, endPos);

    // Profile
    const profMatch = PROFILE_VAL_RE.exec(blockText.substring(profItem.pos - blockStart));
    if (!profMatch) return null;

    // Name
    let name = null;
    const nameItem = items.find(k => k.type === 'N');
    if (nameItem) {
      const nameMatch = NAME_VAL_RE.exec(blockText.substring(nameItem.pos - blockStart));
      if (nameMatch) name = nameMatch[1];
    }

    // Map
    let map = null;
    const mapItem = items.find(k => k.type === 'M');
    if (mapItem) {
      const mapSub = blockText.substring(mapItem.pos - blockStart);
      const mapMatch = MAP_VAL_RE.exec(mapSub);
      if (mapMatch) {
        const cleaned = mapMatch[1]
          .replace(/-+/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();
        const mapRun = cleaned.match(/([\uAC00-\uD7A3][\uAC00-\uD7A3a-zA-Z0-9 ]*)/);
        if (mapRun) map = mapRun[1].trim();
      }
    }

    return { name: name || '?', map: map || '?', profile: profMatch[1] };
  }

  /* ── 정렬 ──────────────────────────────────────────────────── */

  function init() {
    const ths = document.querySelectorAll('#userlist-table thead th');
    ths.forEach((th, i) => {
      if (i < SORT_KEYS.length) {
        th.dataset.sortKey = SORT_KEYS[i];
        th.classList.add('sortable');
        th.addEventListener('click', () => onHeaderClick(SORT_KEYS[i]));
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
    const ths = document.querySelectorAll('#userlist-table thead th');
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
    if (!sortKey) return users;
    return [...users].sort((a, b) => {
      const va = (a[sortKey] || '').toLowerCase();
      const vb = (b[sortKey] || '').toLowerCase();
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return sortAsc ? cmp : -cmp;
    });
  }

  /* ── UI ─────────────────────────────────────────────────────── */

  function open() {
    document.getElementById('userlist-modal').classList.remove('hidden');
  }

  function close() {
    document.getElementById('userlist-modal').classList.add('hidden');
  }

  function clear() {
    buffer = '';
    users.length = 0;
    profileSet.clear();
    sortKey = null;
    sortAsc = true;
    updateHeaderIndicators();
    document.getElementById('userlist-count').textContent = '0';
    render();
  }

  function render() {
    const tbody = document.getElementById('userlist-tbody');
    tbody.innerHTML = '';
    const sorted = getSorted();
    for (const user of sorted) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td>' + esc(user.name) + '</td>' +
        '<td>' + esc(user.map) + '</td>' +
        '<td>' + esc(user.profile) + '</td>';
      tbody.appendChild(tr);
    }
  }

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function saveToUserDB() {
    const data = users
      .filter(u => u.profile)
      .map(u => ({
        profile_code: u.profile,
        ingame_nick: u.name !== '?' ? u.name : '',
        main_map: u.map !== '?' ? u.map : '',
      }));
    if (!data.length) {
      alert('저장할 데이터가 없습니다.');
      return;
    }
    UserDB.saveEntries(data);
  }

  return { init, open, close, clear, processPacket, saveToUserDB };
})();
