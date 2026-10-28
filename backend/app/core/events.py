"""Модель событий, которые оркестратор транслирует в GUI по WebSocket.

Каждое событие — это dict с полем ``type`` и меткой времени ``ts``.
Фронтенд подписан на поток и рендерит события: логи в терминал,
stage/progress — в список этапов и прогресс-бар.
"""
from __future__ import annotations

import time
from typing import Any, Dict

Event = Dict[str, Any]


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
    """Строка вывода инструмента. stream: 'stdout' | 'stderr' | 'system'."""
    return _ev("log", stage=stage_name, stream=stream, line=line)


def progress(value: int) -> Event:
    """Общий прогресс в процентах (0..100)."""
    return _ev("progress", value=value)


def done(summary: str) -> Event:
    return _ev("done", summary=summary)


def error(message: str) -> Event:
    return _ev("error", message=message)
