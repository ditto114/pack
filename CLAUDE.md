# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pack is a MapleStory Worlds packet capture and analysis tool for finding friends, discovering world/channel information, and resending network packets. It has two frontends:

- **Desktop app** (`packet_capture.py` → `capture_app/ui.py`) — Tkinter GUI, feature-complete monolith
- **Web app** (`web/main.py`) — FastAPI + Supabase replacement, actively being built

The web app reuses core business logic from `capture_app/` while adding a REST+WebSocket API layer and Supabase persistence.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run desktop app (requires admin/root for packet capture)
python packet_capture.py

# Run web app
uvicorn web.main:app --reload
# or: python -m web.main
# Serves at http://localhost:8000
```

No test framework is currently configured.

## Architecture

### Core logic (`capture_app/`)

Shared between desktop and web:

- `constants.py` — MapleStory Worlds URLs, regex patterns (worldId: 17 digits, channelName: Korean+numbers, friend codes: 5 alphanumeric), HTTP headers
- `models.py` — Dataclasses: `PacketDisplay`, `WorldMatchEntry`, `FriendEntry`, `FriendStatusEntry`, `FilterConfig`
- `network.py` — `fetch_html()` with exponential backoff retry on 403/429
- `parsers.py` — `HTMLParser` subclasses for friend lists, friend status, and channel search pages
- `friend_services.py` — PPSN lookup via BFS friend traversal, channel search by world code

### Web backend (`web/`)

- `main.py` — FastAPI app, route registration, static file mount
- `db.py` — Supabase client init + CRUD helpers for 5 tables: `capture_sessions`, `packets`, `world_matches`, `friend_searches`, `settings`
- `routes/` — REST + WebSocket endpoints for packets, friends, world matching, settings
- `services/packet_service.py` — Scapy `AsyncSniffer` wrapper with direction detection, DB batching (1s flush), WebSocket queue, packet resend via `sendp()`
- `services/world_match_service.py` — Regex extraction from packet payloads with 8KB sliding buffer, state machine for world-first vs channel-first ordering, deduplication
- `services/export_service.py` — CSV/TXT export with hex dump formatting

### Web frontend (`web/static/`)

Vanilla HTML/CSS/JS (no framework). Dark theme. JS is modular:

- `app.js` — Main controller, capture start/stop
- `ws.js` — WebSocket client wrapper
- `packets.js` — Packet table + detail view with multi-encoding support (UTF-8, EUC-KR, CP949, Latin-1, Shift-JIS)
- `friends.js` — Friend/PPSN search panel
- `world.js` — World matching table + CSV export

### Desktop-only features (not migrating to web)

Notification macro automation (`pyautogui`/`pynput` keyboard/mouse automation) lives only in `capture_app/ui.py`.

## Environment Setup

Requires a `.env` file (git-ignored) with:
```
SUPABASE_URL=...
SUPABASE_KEY=...
```

Supabase database must have the 5 tables created before running the web app.

## Key Constraints

- Scapy packet capture requires admin/root privileges
- `PacketCaptureService` uses thread locks for its DB buffer (thread-safe batching)
- World match deduplication uses normalized uppercase comparison on `channel_name`
- The migration plan is documented in `migration_plan.md` (Korean)
