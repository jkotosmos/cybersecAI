"""Оркестратор — управляет последовательностью этапов и агентов.

Получает модуль + цель, проверяет scope, затем последовательно прогоняет
шаги всех агентов пайплайна, транслируя события в GUI. Любой шаг можно
прервать через stop().
"""
from __future__ import annotations

import asyncio

from app.core import events
from app.core.runner import run_step
from app.core.scope import Scope, ScopeError
from app.core.events import Emit
from app.modules import registry


class Orchestrator:
    def __init__(self, emit: Emit, scope: Scope | None = None) -> None:
        self.emit = emit
        self.scope = scope or Scope()
        self.cancel = asyncio.Event()
        self._module_id: str = ""
        self._target: str = ""

    def prepare(self, module_id: str, target: str, confirmed: bool) -> None:
        """Проверить вход и scope. Бросает ScopeError / KeyError при проблеме."""
        if module_id not in registry.MODULES:
            raise ScopeError(f"неизвестный модуль: {module_id}")
        self._target = self.scope.check(target, confirmed)  # may raise ScopeError
        self.scope.permit(self._target)
        self._module_id = module_id

    def stop(self) -> None:
        self.cancel.set()

    async def run(self) -> None:
        agents = registry.pipeline(self._module_id)
        steps = [s for agent in agents for s in agent.steps]
        total = len(steps)

        await self.emit(events.status("running", f"цель: {self._target}"))

        for index, step in enumerate(steps):
            if self.cancel.is_set():
                break
            await self.emit(events.stage(index, step.name, "start", total))
            result = await run_step(step, self._target, self.emit, self.cancel)

            if result == "stopped":
                await self.emit(events.status("stopped", "остановлено пользователем"))
                return
            if result == "error":
                await self.emit(events.log(step.name, "stderr",
                                           f"[vibesec] шаг завершился с ошибкой: {step.name}"))

            await self.emit(events.stage(index, step.name, "done", total))
            await self.emit(events.progress(round((index + 1) / total * 100)))

        if self.cancel.is_set():
            await self.emit(events.status("stopped", "остановлено пользователем"))
            return

        await self.emit(events.done(f"модуль «{registry.MODULES[self._module_id]['title']}» завершён"))
        await self.emit(events.status("done", ""))
