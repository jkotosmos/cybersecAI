"""Исполнитель шагов: запуск CLI-инструмента с живым стримингом вывода.

Каждая строка stdout/stderr немедленно уходит в GUI через callback ``emit``.
Поддерживается остановка: при установке ``cancel`` процесс (и вся его
process group на Linux) получает SIGTERM, затем SIGKILL.

Если инструмент не установлен, шаг выполняет безопасный демо-вывод —
так каркас работает «из коробки», а реальные инструменты подключаются
по мере установки.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import signal
from typing import Awaitable, Callable

from app.agents.base import Step
from app.core.events import Event, log
from app.config import settings

Emit = Callable[[Event], Awaitable[None]]
IS_POSIX = os.name == "posix"


def _render(argv: list[str], target: str) -> list[str]:
    return [part.replace("{target}", target) for part in argv]


def _terminate(proc: asyncio.subprocess.Process) -> None:
    """Снять процесс и его дочерние (на Linux — через process group)."""
    try:
        if IS_POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError):
        pass


async def _run_demo(step: Step, emit: Emit, cancel: asyncio.Event) -> str:
    await emit(log(step.name, "system",
                   f"[vibesec] «{step.argv[0]}» не установлен — демо-вывод "
                   f"(подключите инструмент, чтобы получить реальные данные)"))
    for line in step.demo_lines:
        if cancel.is_set():
            return "stopped"
        await asyncio.sleep(settings.demo_line_delay)
        await emit(log(step.name, "stdout", line))
    return "ok"


async def run_step(step: Step, target: str, emit: Emit, cancel: asyncio.Event) -> str:
    """Выполнить один шаг. Вернуть 'ok' | 'error' | 'stopped'."""
    argv = _render(step.argv, target)
    await emit(log(step.name, "system", "$ " + " ".join(argv)))

    if shutil.which(argv[0]) is None:
        return await _run_demo(step, emit, cancel)

    kwargs: dict = {}
    if IS_POSIX:
        kwargs["preexec_fn"] = os.setsid  # своя process group → снимаем всё дерево
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        **kwargs,
    )

    async def watch_cancel() -> None:
        await cancel.wait()
        _terminate(proc)

    watcher = asyncio.create_task(watch_cancel())
    assert proc.stdout is not None
    try:
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            await emit(log(step.name, "stdout", raw.decode(errors="replace").rstrip("\n")))
        rc = await proc.wait()
    finally:
        watcher.cancel()

    if cancel.is_set():
        return "stopped"
    return "ok" if rc == 0 else "error"
