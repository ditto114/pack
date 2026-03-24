# 웹 애플리케이션 마이그레이션 계획서

## 1. 코드베이스 분석

### 1.1 프로젝트 개요

MapleStory Worlds 패킷 캡쳐 도구 — Tkinter 기반 데스크톱 앱으로, 네트워크 패킷 캡쳐/분석, 친구 검색, 월드/채널 매칭 기능을 제공한다.

### 1.2 현재 파일 구조

```
pack/
├── packet_capture.py              # 진입점 (Tk 루트 생성 → PacketCaptureApp)
└── capture_app/
    ├── __init__.py                # 패키지 export
    ├── constants.py               # 상수, 정규식 패턴, URL 템플릿
    ├── models.py                  # 데이터 모델 (dataclass 6개)
    ├── network.py                 # HTTP fetch 유틸리티 (fetch_html)
    ├── parsers.py                 # HTML 파서 3종 (FriendList/FriendStatus/ChannelSearch)
    ├── friend_services.py         # 친구 탐색 비즈니스 로직 (PPSN 찾기, 월드코드 탐색 등)
    └── ui.py                      # Tkinter GUI (약 2,700줄) — 모든 UI + 일부 로직 혼재
```

### 1.3 GUI와 비즈니스 로직 결합 분석

#### 이미 분리되어 있는 모듈 (재사용 가능)

| 모듈 | 역할 | 의존성 |
|------|------|--------|
| `constants.py` | 정규식 패턴, URL 템플릿, HTTP 헤더 | 없음 |
| `models.py` | 6개 dataclass (PacketDisplay, FilterConfig 등) | ipaddress (표준 라이브러리) |
| `network.py` | `fetch_html()` — 재시도, 타임아웃 포함 HTTP 요청 | constants |
| `parsers.py` | 3종 HTMLParser (FriendList, FriendStatus, ChannelSearch) | constants, models |
| `friend_services.py` | PPSN 탐색, 친구 BFS 검색, 월드코드 매칭 | network, parsers, models, constants |

#### ui.py에 혼재된 비즈니스 로직 (분리 필요)

| 로직 | 설명 | 분리 방향 |
|------|------|-----------|
| **패킷 캡쳐 엔진** | Scapy AsyncSniffer 생성/시작/중지, 패킷 핸들러, 필터 적용 | → `packet_service.py` |
| **월드 매칭 처리** | 패킷 페이로드에서 worldId·channelName 정규식 추출, 순서 감지, 매칭 버퍼 관리 | → `world_match_service.py` |
| **설정 관리** | JSON 로드/저장 → **Supabase DB로 전환** | → `db.py` + 각 서비스 |
| **패킷 재전송** | Scapy send/sendp를 이용한 패킷 리플레이 | → `packet_service.py` |
| **CSV/TXT 내보내기** | 월드 매칭 결과 CSV 및 패킷 TXT 내보내기 | → `export_service.py` |

> **제외 항목**: 알림 스트림 처리(`_process_notification_stream`), 매크로 자동화(`_run_notification_macro`, pyautogui/pynput)는 웹 마이그레이션 대상에서 제외한다.

#### 스레딩 & 큐 구조

```
[메인 UI 스레드]
  ├── _poll_queue()        (200ms) ← packet_queue      ← [패킷 캡쳐 스레드]
  ├── _poll_ppsn_queue()   (200ms) ← ppsn_queue        ← [PPSN 검색 스레드]
  └── _poll_friend_queue() (200ms) ← friend_queue      ← [친구 검색 스레드]
```

웹 전환 시 Tkinter의 `after()` 폴링 → **WebSocket 푸시**로 대체해야 한다.

---

## 2. 웹 스택 제안

### 2.1 추천 스택: FastAPI + WebSocket + Supabase + 바닐라 JS (+ 선택적 React)

```
┌─────────────────────────────────────────────┐
│                 브라우저                      │
│  ┌───────────────────────────────────────┐  │
│  │  프론트엔드 (HTML/CSS/JS 또는 React)   │  │
│  │  - 패킷 리스트 테이블                  │  │
│  │  - 필터 패널                           │  │
│  │  - 친구 검색 / PPSN 찾기 패널         │  │
│  │  - 월드 매칭 패널                      │  │
│  └──────────────┬────────────────────────┘  │
│                 │ WebSocket + REST API        │
└─────────────────┼───────────────────────────┘
                  │
┌─────────────────┼───────────────────────────┐
│  백엔드 (FastAPI + uvicorn)                  │
│  ┌──────────────┴────────────────────────┐  │
│  │  API 레이어 (routes/)                  │  │
│  │  - REST: 필터 설정, 내보내기, 설정     │  │
│  │  - WebSocket: 패킷 스트림, 검색 결과   │  │
│  ├───────────────────────────────────────┤  │
│  │  서비스 레이어 (services/)             │  │
│  │  - packet_service     (Scapy 캡쳐)    │  │
│  │  - friend_services    (기존 모듈 활용) │  │
│  │  - world_match_service                │  │
│  │  - export_service                     │  │
│  ├───────────────────────────────────────┤  │
│  │  데이터 레이어                         │  │
│  │  - db.py (Supabase 클라이언트)        │  │
│  │  - models.py (Pydantic + DB 스키마)   │  │
│  ├───────────────────────────────────────┤  │
│  │  코어 (기존 모듈 재사용)               │  │
│  │  - constants.py, models.py            │  │
│  │  - network.py, parsers.py             │  │
│  └───────────────────────────────────────┘  │
└─────────────────┼───────────────────────────┘
                  │
┌─────────────────┼───────────────────────────┐
│           Supabase (PostgreSQL)              │
│  ┌───────────────────────────────────────┐  │
│  │  packets          캡쳐된 패킷 저장     │  │
│  │  world_matches    월드-채널 매칭 결과  │  │
│  │  friend_searches  친구 검색 결과       │  │
│  │  settings         앱 설정              │  │
│  │  capture_sessions 캡쳐 세션 이력       │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### 2.2 스택 선정 이유

| 선택 | 이유 |
|------|------|
| **FastAPI** | 비동기(async) 네이티브 지원 → 패킷 스트리밍과 WebSocket에 최적. 기존 Python 코드 그대로 통합 가능. 타입 힌트 기반 자동 API 문서화. |
| **WebSocket** | 패킷 캡쳐 데이터는 실시간 스트림 — HTTP 폴링으로는 지연이 불가피. WebSocket으로 서버→클라이언트 실시간 푸시 구현. |
| **Supabase** | PostgreSQL 기반 BaaS. REST API/Realtime 구독 기본 제공. 인증·RLS 내장. `supabase-py` SDK로 Python 통합 용이. JSON 파일 대비 동시성·영속성·쿼리 능력 월등. |
| **바닐라 JS (1차)** | 현재 앱이 테이블 + 폼 + 버튼 중심의 단순 UI. React 없이도 충분히 구현 가능하며, 의존성 최소화. |
| **React (선택적 2차)** | UI가 복잡해질 경우 부분적으로 도입. 처음부터 React를 적용하면 학습·빌드 비용이 과다. |
| **uvicorn** | ASGI 서버로 FastAPI + WebSocket 동시 서빙. |

### 2.3 대안 검토 및 기각 이유

| 대안 | 기각 이유 |
|------|-----------|
| **Streamlit / Gradio** | 실시간 패킷 스트리밍에 부적합. WebSocket 직접 제어 불가. 커스텀 UI 한계. |
| **Django + Channels** | 이 규모에 비해 과도한 프레임워크. ORM/미들웨어 불필요. |
| **Flask + SocketIO** | 가능하지만 비동기 지원이 FastAPI보다 약하고, 타입 힌트 지원 미흡. |
| **Reflex / NiceGUI** | Python 풀스택이라 매력적이나, Scapy 통합 및 저수준 WebSocket 제어가 제한적. |
| **SQLite / 로컬 JSON** | 단일 파일 DB는 동시 접근·원격 공유 불가. Supabase는 클라우드 호스팅 + Realtime 구독까지 제공. |

---

## 3. Supabase DB 스키마 설계

### 3.1 테이블 정의

```sql
-- 캡쳐 세션 이력
CREATE TABLE capture_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at  TIMESTAMPTZ,
    filter_ip   TEXT,
    filter_port INTEGER,
    filter_text TEXT,
    max_packets INTEGER DEFAULT 500,
    status      TEXT NOT NULL DEFAULT 'running'  -- running | stopped
);

-- 캡쳐된 패킷
CREATE TABLE packets (
    id            BIGSERIAL PRIMARY KEY,
    session_id    UUID REFERENCES capture_sessions(id) ON DELETE CASCADE,
    captured_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    summary       TEXT NOT NULL,
    direction     TEXT NOT NULL DEFAULT 'unknown',  -- incoming | outgoing | internal | unknown
    preview       TEXT,
    utf8_text     TEXT,
    payload_hex   TEXT,                              -- hex-encoded raw payload
    raw_packet    BYTEA,                             -- 재전송용 원본 패킷
    note          TEXT
);

-- 월드-채널 매칭 결과
CREATE TABLE world_matches (
    id            BIGSERIAL PRIMARY KEY,
    session_id    UUID REFERENCES capture_sessions(id) ON DELETE SET NULL,
    channel_name  TEXT NOT NULL,
    world_code    TEXT NOT NULL,
    captured_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (channel_name, world_code)
);

-- 친구 검색 결과
CREATE TABLE friend_searches (
    id              BIGSERIAL PRIMARY KEY,
    search_code     TEXT NOT NULL,                   -- 검색 대상 친구 코드
    status          TEXT NOT NULL,                   -- 온라인/접속 중
    ppsn            TEXT,
    profile_code    TEXT,
    display_name    TEXT,
    world_name      TEXT,
    game_instance_id TEXT,
    searched_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 앱 설정
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 3.2 기존 JSON 설정과의 매핑

| 기존 JSON 키 | DB 저장 방식 |
|---------------|-------------|
| `ip`, `port`, `text_filter`, `max_packets` | `settings` 테이블 또는 `capture_sessions` 레코드 |
| `alpha3_filter` | `settings` 테이블 (`key='alpha3_filter'`) |
| `packet_list_data` (인메모리) | `packets` 테이블 |
| `world_match_entries` (인메모리) | `world_matches` 테이블 |
| `friend_entries` (인메모리) | `friend_searches` 테이블 |

---

## 4. 단계별 마이그레이션 계획

### Phase 0: 사전 준비 (코드 변경 없음)

**목표**: 웹 프로젝트 골격 생성, 의존성 정의, Supabase 프로젝트 셋업

- [ ] Supabase 프로젝트 생성 및 DB 스키마 적용 (섹션 3의 SQL)
- [ ] 환경 변수 설정 (`SUPABASE_URL`, `SUPABASE_KEY`)
- [ ] 웹 프로젝트 디렉토리 구조 생성
- [ ] `requirements.txt` 작성 (fastapi, uvicorn, websockets, scapy, supabase)
- [ ] FastAPI 앱 진입점 (`main.py`) 및 기본 라우터 설정
- [ ] Supabase 클라이언트 초기화 모듈 (`db.py`)
- [ ] 정적 파일 서빙 설정 (`/static`)
- [ ] 기본 HTML 페이지 (빈 대시보드 레이아웃)

**결과물 디렉토리 구조**:
```
pack/
├── capture_app/            # 기존 코드 (수정 없이 유지)
├── web/                    # 새 웹 앱
│   ├── main.py             # FastAPI 앱 진입점
│   ├── db.py               # Supabase 클라이언트 초기화
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── packets.py      # 패킷 관련 API/WS 엔드포인트
│   │   ├── friends.py      # 친구 검색 API
│   │   ├── world_match.py  # 월드 매칭 API
│   │   └── settings.py     # 설정 API
│   ├── services/
│   │   ├── __init__.py
│   │   ├── packet_service.py
│   │   ├── world_match_service.py
│   │   └── export_service.py
│   └── static/
│       ├── index.html
│       ├── css/
│       │   └── style.css
│       └── js/
│           ├── app.js       # 메인 앱 초기화
│           ├── packets.js   # 패킷 UI
│           ├── friends.js   # 친구 검색 UI
│           ├── world.js     # 월드 매칭 UI
│           └── ws.js        # WebSocket 클라이언트
├── .env                    # SUPABASE_URL, SUPABASE_KEY (gitignore)
├── packet_capture.py       # 기존 데스크톱 진입점 (유지)
└── requirements.txt
```

---

### Phase 1: 비즈니스 로직 추출

**목표**: `ui.py`에 혼재된 비즈니스 로직을 독립 서비스 모듈로 분리

#### Step 1-1: Supabase 데이터 레이어 (`web/db.py`)
- `supabase-py` 클라이언트 싱글턴 초기화
- 환경 변수에서 URL/Key 로드
- 테이블별 CRUD 헬퍼 함수:
  - `insert_packet()`, `get_packets()`, `get_packet_by_id()`
  - `insert_world_match()`, `get_world_matches()`, `clear_world_matches()`
  - `insert_friend_search()`, `get_friend_searches()`
  - `upsert_setting()`, `get_setting()`, `get_all_settings()`
  - `create_session()`, `update_session()`, `get_active_session()`

#### Step 1-2: 패킷 캡쳐 서비스 (`services/packet_service.py`)
- `ui.py`의 `start_capture()`, `stop_capture()`, `_packet_handler()`, `_packet_matches_filter()` 로직 추출
- Scapy AsyncSniffer 래핑 클래스 생성
- 콜백 기반 → `asyncio.Queue` 기반으로 전환
- 로컬 IP 감지 (`_detect_local_addresses`) 포함
- 패킷 방향 판별 로직 포함
- 캡쳐된 패킷을 Supabase `packets` 테이블에 저장
- 캡쳐 시작/중지 시 `capture_sessions` 테이블 업데이트

#### Step 1-3: 월드 매칭 서비스 (`services/world_match_service.py`)
- `_process_world_matching()` 로직 추출
- 월드ID/채널명 정규식 매칭 버퍼 관리
- 순서 감지(world-first / channel-first) 상태 머신
- 중복 제거 후 Supabase `world_matches` 테이블에 저장

#### Step 1-4: 내보내기 서비스 (`services/export_service.py`)
- CSV 내보내기 — Supabase에서 `world_matches` 조회 → CSV 응답
- TXT 내보내기 — Supabase에서 `packets` 조회 → TXT 응답
- 웹에서는 파일 다운로드 응답으로 제공

---

### Phase 2: FastAPI 백엔드 구축

**목표**: REST API + WebSocket 엔드포인트 구현 (모든 영속 데이터는 Supabase 경유)

#### Step 2-1: 패킷 캡쳐 API
- `POST /api/capture/start` — 필터 설정과 함께 캡쳐 시작, `capture_sessions` 레코드 생성
- `POST /api/capture/stop` — 캡쳐 중지, 세션 상태 업데이트
- `GET /api/capture/status` — 캡쳐 상태 조회
- `GET /api/capture/packets` — 저장된 패킷 목록 조회 (페이지네이션)
- `GET /api/capture/packets/{id}` — 패킷 상세 조회
- `WS /ws/packets` — 실시간 패킷 스트림 (JSON)
- `POST /api/capture/resend/{id}` — 패킷 재전송
- `GET /api/capture/export` — TXT 다운로드

#### Step 2-2: 친구 검색 API
- `POST /api/friends/search` — 친구 검색 시작 (백그라운드 태스크), 결과를 `friend_searches`에 저장
- `DELETE /api/friends/search` — 검색 취소
- `GET /api/friends/results` — 검색 결과 조회 (Supabase에서)
- `WS /ws/friends` — 검색 진행 상황 + 결과 실시간 스트림
- `POST /api/ppsn/search` — PPSN 검색 시작
- `WS /ws/ppsn` — PPSN 검색 로그 실시간 스트림
- `POST /api/channel/search` — 채널 검색

#### Step 2-3: 월드 매칭 API
- `GET /api/world-match` — Supabase에서 매칭 결과 조회
- `DELETE /api/world-match` — 매칭 결과 초기화 (DB 레코드 삭제)
- `GET /api/world-match/export` — CSV 다운로드
- `WS /ws/world-match` — 실시간 매칭 결과 스트림

#### Step 2-4: 설정 API
- `GET /api/settings` — Supabase `settings` 테이블에서 전체 설정 조회
- `PUT /api/settings` — 설정 upsert
- `GET /api/settings/{key}` — 개별 설정 조회

---

### Phase 3: 프론트엔드 구축

**목표**: 패킷 캡쳐, 친구 검색, 월드 매칭 기능을 브라우저에서 재현

#### Step 3-1: 기본 레이아웃
- 상단: 필터 패널 (IP, 포트, 텍스트 필터, 최대 패킷 수, 방향 필터)
- 중단: 제어 버튼 바 (캡쳐 시작/중지, PPSN 찾기, 월드 매칭, 친구 검색)
- 하단 좌: 패킷 리스트 테이블 (시간, 요약, 방향, 미리보기)
- 하단 우: 패킷 상세 뷰 (HEX 덤프, 인코딩 선택, 텍스트 뷰)

#### Step 3-2: WebSocket 클라이언트
- 패킷 스트림, 친구 검색, PPSN, 월드 매칭용 WebSocket 연결 관리
- 자동 재연결 로직
- 메시지 타입별 라우팅

#### Step 3-3: 패킷 캡쳐 UI
- 실시간 패킷 테이블 (가상 스크롤 적용 — 500개 이상 표시 시 성능)
- 패킷 클릭 시 상세 뷰 (HEX + 텍스트)
- 인코딩 선택 드롭다운 (UTF-8, EUC-KR, CP949, Latin-1, Shift-JIS)
- 우클릭 컨텍스트 메뉴 → 패킷 재전송
- 내보내기 버튼
- 이전 세션 패킷 조회 (Supabase에서 로드)

#### Step 3-4: 친구 검색 패널
- 접이식(collapsible) 패널
- 친구 코드 입력 + 검색/중지 버튼
- 결과 테이블 (상태, PPSN, 프로필 코드, 이름, 월드, 채널)
- 진행 상황 표시
- 이전 검색 결과 조회 (Supabase에서 로드)

#### Step 3-5: PPSN 찾기 모달
- 친구 코드 입력, 요청 딜레이 설정
- 검색 로그 실시간 출력
- 결과 표시 및 복사 버튼
- 채널 검색 (월드 코드 입력 → 결과)

#### Step 3-6: 월드 매칭 패널
- 접이식 패널
- 매칭 결과 테이블 (채널명, 월드코드, 캡쳐 시간)
- 순서 감지 표시 (월드 우선 / 채널 우선)
- CSV 내보내기 버튼
- 클릭 시 월드 코드 복사
- 이전 매칭 이력 조회 (Supabase에서 로드)

---

### Phase 4: 통합 테스트 및 마무리

#### Step 4-1: 기능 통합 테스트
- 패킷 캡쳐 시작/중지 → WebSocket 스트림 수신 + DB 저장 확인
- 필터 변경 → 실시간 반영 확인
- 친구 검색, PPSN 검색 → 진행 로그 + 결과 + DB 저장 확인
- 월드 매칭 → 실시간 업데이트 + DB 저장 확인
- 내보내기 (CSV, TXT) 다운로드 확인
- 설정 저장/로드 (Supabase 경유)
- 브라우저 새로고침 후 DB에서 이전 데이터 복원 확인

#### Step 4-2: 성능 최적화
- 패킷 테이블 가상 스크롤 (대량 데이터)
- WebSocket 메시지 배치 전송 (고빈도 패킷 대응)
- Supabase 쿼리 최적화 (인덱스, 페이지네이션)
- 백엔드 비동기 처리 최적화

#### Step 4-3: 기존 데스크톱 앱과의 호환
- 기존 `packet_capture.py` (Tkinter 앱)는 그대로 유지
- 웹 앱은 `web/main.py`로 별도 실행
- 동일한 `capture_app/` 코어 모듈 공유

---

## 5. 마이그레이션 시 주의사항

### 5.1 기술적 제약

| 항목 | 제약 | 대응 |
|------|------|------|
| **Scapy 패킷 캡쳐** | 관리자 권한 필요, OS 의존 | 웹 서버도 관리자 권한으로 실행 필요. 원격 사용 시 보안 주의. |
| **패킷 재전송** | Raw 소켓 필요 | 서버 사이드에서만 실행. |
| **Supabase 네트워크** | DB 접근에 인터넷 필요 | 오프라인 폴백 미지원. 고빈도 패킷 시 배치 insert로 API 호출 최소화. |
| **패킷 데이터 크기** | raw_packet(BYTEA)이 클 수 있음 | payload_hex(TEXT)는 요약용, raw_packet은 재전송 필요 시에만 저장. |

### 5.2 Supabase 관련 고려

- **배치 INSERT**: 패킷은 초당 수십~수백 건 발생 가능 → 개별 insert 대신 배치로 묶어서 저장 (예: 1초 버퍼)
- **데이터 보존 정책**: `packets` 테이블은 무한 증가 → 세션 단위로 TTL 설정하거나 자동 정리 정책 필요
- **RLS(Row Level Security)**: 멀티 유저 환경이라면 Supabase RLS로 사용자별 데이터 격리
- **Realtime 구독**: Supabase Realtime을 활용하면 프론트엔드에서 DB 변경을 직접 구독 가능 (WebSocket 보완/대체 가능)

### 5.3 보안 고려

- 패킷 캡쳐는 강력한 권한이 필요 → **로컬 네트워크 전용** 또는 인증 추가
- WebSocket 연결에 토큰 기반 인증 검토
- Supabase `anon` key는 프론트엔드 노출 가능하지만, `service_role` key는 백엔드에서만 사용
- `.env` 파일을 `.gitignore`에 추가

### 5.4 알려진 코드 이슈 (마이그레이션 시 수정)

- `ALPHA_TRIPLET_PATTERN` 미정의 → 사용처 확인 후 정의하거나 제거
- `fetch_friend_statuses()` 호출 시그니처 불일치 가능 → 검증 필요

---

## 6. 예상 작업 순서 요약

```
Phase 0  사전 준비 (프로젝트 골격 + Supabase 셋업)
  ↓
Phase 1  비즈니스 로직 추출 (ui.py 분리)
  │  Step 1-1  Supabase 데이터 레이어 (db.py)
  │  Step 1-2  패킷 캡쳐 서비스
  │  Step 1-3  월드 매칭 서비스
  │  Step 1-4  내보내기 서비스
  ↓
Phase 2  FastAPI 백엔드 (API + WebSocket)
  │  Step 2-1  패킷 캡쳐 API
  │  Step 2-2  친구 검색 API
  │  Step 2-3  월드 매칭 API
  │  Step 2-4  설정 API
  ↓
Phase 3  프론트엔드 (브라우저 UI)
  │  Step 3-1  기본 레이아웃
  │  Step 3-2  WebSocket 클라이언트
  │  Step 3-3  패킷 캡쳐 UI
  │  Step 3-4  친구 검색 패널
  │  Step 3-5  PPSN 찾기 모달
  │  Step 3-6  월드 매칭 패널
  ↓
Phase 4  통합 테스트 및 마무리
```

각 Phase는 독립적으로 검증 가능하며, Phase 1 완료 후 기존 데스크톱 앱이 정상 동작하는지 반드시 확인한다.
