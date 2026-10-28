"""VibeSec API — REST для списка модулей и WebSocket для живого запуска.

Запуск:
    cd backend && uvicorn app.main:app --reload --port 8787

Протокол WebSocket (/ws/run):
    клиент → {"action": "start", "module": "recon",
              "target": "example.com", "scope_confirmed": true}
    клиент → {"action": "stop"}
    сервер → поток событий (см. app/core/events.py)
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from app.config import settings
from app.core import events
from app.core.orchestrator import Orchestrator
from app.core.scope import ScopeError
from app.modules import registry

app = FastAPI(title="VibeSec", version="0.1.0")


@app.get("/api/modules")
async def get_modules() -> JSONResponse:
    return JSONResponse(registry.list_modules())


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": app.version}


@app.websocket("/ws/run")
async def ws_run(ws: WebSocket) -> None:
    await ws.accept()
    orch: Orchestrator | None = None
    task: asyncio.Task | None = None

    async def emit(ev: dict) -> None:
        await ws.send_json(ev)

    try:
        while True:
            msg = await ws.receive_json()
            action = msg.get("action")

            if action == "start":
                if task and not task.done():
                    await emit(events.error("проверка уже выполняется"))
                    continue
                orch = Orchestrator(emit)
                try:
                    orch.prepare(
                        module_id=msg.get("module", ""),
                        target=msg.get("target", ""),
                        confirmed=bool(msg.get("scope_confirmed", False)),
                    )
                except (ScopeError, KeyError) as exc:
                    await emit(events.error(str(exc)))
                    orch = None
                    continue
                task = asyncio.create_task(orch.run())

            elif action == "stop":
                if orch:
                    orch.stop()

            else:
                await emit(events.error(f"неизвестное действие: {action}"))

    except WebSocketDisconnect:
        if orch:
            orch.stop()
        if task:
            await asyncio.gather(task, return_exceptions=True)


# Статический фронтенд (если собран). Регистрируется последним, чтобы не
# перехватывать /api и /ws.
@app.get("/")
async def index() -> FileResponse | JSONResponse:
    idx = settings.frontend_dir / "index.html"
    if idx.exists():
        return FileResponse(idx)
    return JSONResponse(
        {"message": "VibeSec API запущен. Фронтенд не найден — откройте frontend/static/index.html."}
    )
