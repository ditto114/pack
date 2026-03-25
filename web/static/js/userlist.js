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
  const rawChunks = [];   // { bufStart, bufLen, raw }
  let bufferOffset = 0;   // 트림으로 잘려나간 누적 길이
  const users = [];
  const debugBlocks = [];
  const profileSet = new Set();

  // 정렬 상태
  const SORT_KEYS = ['name', 'map', 'profile'];
  let sortKey = null;
  let sortAsc = true;

  // 블록 내 연속 키워드 간 최대 허용 간격
  const MAX_KEYWORD_GAP = 50;

  // 값 추출 정규식
  const PROFILE_VAL_RE = /Profile[- ]+([A-Za-z0-9]{5,6})(?![A-Za-z0-9])/;
  const NAME_VAL_RE = /(?<!Channel)Name[- ]+([\uAC00-\uD7A3a-zA-Z0-9]+)/;
  const MAP_VAL_RE = /Map(?!Online)[- ]+([^-]+)/;

  /* ── 키워드 위치 탐색 ─────────────────────────────────────── */

  function findKeywordPositions(text) {
    const positions = [];
    let m;

    // 대상 필드 (P, N, M)
    const profRe = /Profile[- ]+[A-Za-z0-9]{5,6}(?![A-Za-z0-9])/g;
    while ((m = profRe.exec(text)) !== null)
      positions.push({ type: 'P', pos: m.index });

    const nameRe = /(?<!Channel)Name[- ]+[\uAC00-\uD7A3a-zA-Z0-9]/g;
    while ((m = nameRe.exec(text)) !== null)
      positions.push({ type: 'N', pos: m.index });

    const mapRe = /Map(?!Online)[- ]{4,}/g;
    while ((m = mapRe.exec(text)) !== null)
      positions.push({ type: 'M', pos: m.index });

    // 보조 키워드 — 블록 경계 감지용 (각 키워드를 고유 타입으로 등록)
    const helperRe = /Created|Attacks|Buffs|CharOnline|Captcha|MapOnline|ChannelOnline|Level|Exp|Job/g;
    while ((m = helperRe.exec(text)) !== null)
      positions.push({ type: m[0], pos: m.index });

    positions.sort((a, b) => a.pos - b.pos);
    return positions;
  }

  /* ── 블록 감지 & 추출 ─────────────────────────────────────── */

  function processPacket(text) {
    if (!text) return;
    // 전처리: 줄바꿈·탭·넓은공백 등 제거(일반 스페이스만 유지) → 나머지 특수문자를 -로 치환
    const cleaned = text.replace(/[^\S ]/g, '');
    const sanitized = cleaned.replace(/[^\uAC00-\uD7A3a-zA-Z0-9 ]/g, '-');

    const bufStart = bufferOffset + buffer.length;
    rawChunks.push({ bufStart, bufLen: sanitized.length, raw: text });
    buffer += sanitized;

    if (buffer.length > 65536) {
      const excess = buffer.length - 65536;
      buffer = buffer.slice(excess);
      bufferOffset += excess;
      // 오래된 rawChunks 제거
      while (rawChunks.length && rawChunks[0].bufStart + rawChunks[0].bufLen <= bufferOffset) {
        rawChunks.shift();
      }
    }

    const positions = findKeywordPositions(buffer);

    // 키워드 반복 시 블록 경계로 판단
    const blocks = [];
    let seen = new Set();
    let blockItems = [];
    let trimPos = 0;

    for (const kw of positions) {
      if (seen.has(kw.type)) {
        const isValid = seen.has('P') && seen.has('N') && seen.has('M') && isBlockCompact(blockItems);
        if (isValid) {
          // 유효한 블록: 그대로 저장하고 새 블록은 kw 부터 시작
          blocks.push({ items: blockItems, endPos: kw.pos });
          trimPos = kw.pos;
          seen = new Set();
          blockItems = [];
        } else {
          // 유효하지 않은 블록: kw와 가까운 항목들을 새 블록으로 이월
          const tail = getCompactTail(blockItems, kw.pos);
          trimPos = tail.length > 0 ? tail[0].pos : kw.pos;
          seen = new Set();
          blockItems = [];
          for (const item of tail) {
            // kw와 동일 타입은 kw 자체가 추가되므로 제외 (중복 방지)
            if (!seen.has(item.type) && item.type !== kw.type) {
              seen.add(item.type);
              blockItems.push(item);
            }
          }
        }
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
        const blockStart = block.items[0].pos;
        debugBlocks.push({
          profile: user.profile,
          raw: getRawForRange(blockStart, block.endPos),
          sanitized: buffer.substring(blockStart, block.endPos),
        });
        changed = true;
      }
    }

    if (trimPos > 0) {
      buffer = buffer.substring(trimPos);
      bufferOffset += trimPos;
      while (rawChunks.length && rawChunks[0].bufStart + rawChunks[0].bufLen <= bufferOffset) {
        rawChunks.shift();
      }
    }

    if (changed) {
      document.getElementById('userlist-count').textContent = String(users.length);
      render();
    }
  }

  function isBlockCompact(items) {
    for (let i = 1; i < items.length; i++) {
      if (items[i].pos - items[i - 1].pos > MAX_KEYWORD_GAP) {
        return false;
      }
    }
    return true;
  }

  /**
   * kw.pos 에서 거꾸로 items를 탐색하여 MAX_KEYWORD_GAP 이내로 연속된
   * 항목들을 반환한다. 유효하지 않은 블록이 감지됐을 때 새 블록의 시작
   * 후보를 구출하는 데 사용한다.
   */
  function getCompactTail(items, kwPos) {
    let prevPos = kwPos;
    let start = items.length;
    for (let i = items.length - 1; i >= 0; i--) {
      if (prevPos - items[i].pos <= MAX_KEYWORD_GAP) {
        start = i;
        prevPos = items[i].pos;
      } else {
        break;
      }
    }
    return items.slice(start);
  }

  function getRawForRange(start, end) {
    // buffer 내 [start, end) 범위에 해당하는 원본 텍스트를 rawChunks에서 합산
    const absStart = bufferOffset + start;
    const absEnd = bufferOffset + end;
    let result = '';
    for (const chunk of rawChunks) {
      const cEnd = chunk.bufStart + chunk.bufLen;
      if (cEnd <= absStart) continue;
      if (chunk.bufStart >= absEnd) break;
      result += chunk.raw;
    }
    return result;
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
        map = mapMatch[1].trim() || null;
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
    rawChunks.length = 0;
    bufferOffset = 0;
    users.length = 0;
    debugBlocks.length = 0;
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

  function openDebug() {
    document.getElementById('userlist-debug-modal').classList.remove('hidden');
    if (!debugBlocks.length) {
      document.getElementById('debug-raw').textContent = '(데이터 없음)';
      document.getElementById('debug-sanitized').textContent = '(데이터 없음)';
      return;
    }
    const divider = '\n' + '='.repeat(60) + '\n';
    document.getElementById('debug-raw').textContent = debugBlocks
      .map((b, i) => `[${i + 1}] ${b.profile}\n${b.raw}`)
      .join(divider);
    document.getElementById('debug-sanitized').textContent = debugBlocks
      .map((b, i) => `[${i + 1}] ${b.profile}\n${b.sanitized}`)
      .join(divider);
  }

  function closeDebug() {
    document.getElementById('userlist-debug-modal').classList.add('hidden');
  }

  return { init, open, close, clear, processPacket, saveToUserDB, openDebug, closeDebug };
})();
