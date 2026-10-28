"""Модель событий, которые оркестратор транслирует в GUI по WebSocket.

Каждое событие — dict с полем ``type`` и меткой времени ``ts``.
Фронтенд подписан на поток: логи → терминал, stage/progress → этапы и прогресс,
finding → живая панель находок, report → карточка готового отчёта.
"""
from __future__ import annotations

import time
from typing import Any, Awaitable, Callable, Dict

Event = Dict[str, Any]
Emit = Callable[[Event], Awaitable[None]]


def _ev(type_: str, **fields: Any) -> Event:
    fields["type"] = type_
    fields["ts"] = round(time.time(), 3)
    return fields


def status(state: str, message: str = "") -> Event:
    """state: 'running' | 'stopped' | 'done' | 'error'."""
    return _ev("status", state=state, message=message)


def stage(index: int, name: str, state: str, total: int) -> Event:
    """Граница этапа. state: 'start' | 'done'."""
    return _ev("stage", index=index, name=name, state=state, total=total)


def log(stage_name: str, stream: str, line: str) -> Event:
    """Строка вывода. stream: 'stdout' | 'stderr' | 'system'."""
    return _ev("log", stage=stage_name, stream=stream, line=line)


def progress(value: int) -> Event:
    return _ev("progress", value=value)


def finding(data: dict) -> Event:
    """Структурная находка (новая или обновлённая — по полю id)."""
    return _ev("finding", finding=data)


def report(run_id: str, summary: str, formats: list[str], preview: str) -> Event:
    """Готовый отчёт: id запуска, сводка, доступные форматы, превью Markdown."""
    return _ev("report", run_id=run_id, summary=summary, formats=formats, preview=preview)


def done(summary: str) -> Event:
    return _ev("done", summary=summary)


def error(message: str) -> Event:
    return _ev("error", message=message)
