"""FastAPI 앱 진입점."""

from __future__ import annotations

import sys
from pathlib import Path

# capture_app 패키지를 import할 수 있도록 프로젝트 루트를 path에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .routes.packets import router as packets_router, ws_router as packets_ws
from .routes.friends import router as friends_router, ws_router as friends_ws
from .routes.world_match import router as world_match_router, ws_router as world_match_ws
from .routes.monitor import ws_router as monitor_ws
from .routes.settings import router as settings_router
from .routes.user_db import router as user_db_router

app = FastAPI(title="패킷 캡쳐 웹 도구")


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """정적 파일에 no-cache 헤더를 추가하여 브라우저 캐싱을 방지한다."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response: Response = await call_next(request)
        if request.url.path.endswith((".js", ".css", ".html")) or request.url.path == "/":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response


app.add_middleware(NoCacheStaticMiddleware)

# REST API routers
app.include_router(packets_router)
app.include_router(friends_router)
app.include_router(world_match_router)
app.include_router(settings_router)
app.include_router(user_db_router)

# WebSocket routers
app.include_router(packets_ws)
app.include_router(friends_ws)
app.include_router(world_match_ws)
app.include_router(monitor_ws)

# Static files (HTML/CSS/JS)
static_dir = Path(__file__).resolve().parent / "static"
app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.main:app", host="0.0.0.0", port=8000, reload=True)
