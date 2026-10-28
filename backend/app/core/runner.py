"""Исполнитель tool-шагов: запуск CLI-инструмента с живым стримингом вывода.

Каждая строка stdout/stderr немедленно уходит в GUI через ``emit`` и попадает
в буфер ``lines`` для последующего парсинга в находки. Остановка: при установке
``cancel`` процесс (и вся process group на Linux) получает SIGTERM.

Перед реальным запуском argv проверяется политикой безопасности. Если инструмент
не установлен — выполняется безопасный демо-вывод, а находки берутся из
demo_findings шага.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import signal

from app.agents.base import Step
from app.core.events import Emit, log
from app.core.safety import UnsafeCommand, assert_safe
from app.config import settings

IS_POSIX = os.name == "posix"


def _render(argv: list[str], target: str) -> list[str]:
    return [part.replace("{target}", target) for part in argv]


def _terminate(proc: asyncio.subprocess.Process) -> None:
    try:
        if IS_POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError):
        pass


async def _run_demo(step: Step, emit: Emit, cancel: asyncio.Event) -> tuple[str, list[str], bool]:
    await emit(log(step.name, "system",
                   f"[vibesec] «{step.argv[0]}» не установлен — демо-режим "
                   f"(подключите инструмент для реальных данных)"))
    lines: list[str] = []
    for line in step.demo_lines:
        if cancel.is_set():
            return "stopped", lines, True
        await asyncio.sleep(settings.demo_line_delay)
        await emit(log(step.name, "stdout", line))
        lines.append(line)
    return "ok", lines, True


async def run_step(step: Step, target: str, emit: Emit,
                   cancel: asyncio.Event) -> tuple[str, list[str], bool]:
    """Выполнить tool-шаг. Вернуть (status, captured_lines, used_demo).

    status: 'ok' | 'error' | 'stopped' | 'unsafe'.
    """
    argv = _render(step.argv, target)

    try:
        assert_safe(argv)
    except UnsafeCommand as exc:
        await emit(log(step.name, "stderr", f"[vibesec] шаг заблокирован политикой безопасности: {exc}"))
        return "unsafe", [], False

    await emit(log(step.name, "system", "$ " + " ".join(argv)))

    if shutil.which(argv[0]) is None:
        return await _run_demo(step, emit, cancel)

    kwargs: dict = {}
    if IS_POSIX:
        kwargs["preexec_fn"] = os.setsid
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
    lines: list[str] = []
    assert proc.stdout is not None
    try:
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode(errors="replace").rstrip("\n")
            await emit(log(step.name, "stdout", line))
            lines.append(line)
        rc = await proc.wait()
    finally:
        watcher.cancel()

    if cancel.is_set():
        return "stopped", lines, False
    return ("ok" if rc == 0 else "error"), lines, False
