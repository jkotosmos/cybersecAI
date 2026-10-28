"""Оркестратор — управляет фазами, агентами и слоем находок.

Фазы: Recon → Surface → Hunt → Validate → Report. Tool-шаги гоняют инструменты
и наполняют FindingStore (через парсеры или demo_findings). Action-шаги
('validate' | 'report' | 'collect') выполняют внутренние фазы. Все события
(логи, этапы, прогресс, находки, отчёт) транслируются в GUI.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import time
from pathlib import Path

from app.agents.base import Step
from app.config import settings
from app.core import events
from app.core.events import Emit
from app.core.poc import generate as generate_poc
from app.core.runner import run_step
from app.core.scope import Scope, ScopeError
from app.core.validate import validate_findings
from app.evidence import screenshot
from app.findings.model import Finding, FindingStore
from app.flows import account
from app.modules import registry
from app.parsers import PARSERS
from app.report.compiler import compile_report


def _run_id(module: str, target: str) -> str:
    raw = f"{module}-{target}-{time.strftime('%Y%m%d-%H%M%S')}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", raw)


class Orchestrator:
    def __init__(self, emit: Emit, scope: Scope | None = None) -> None:
        self.emit = emit
        self.scope = scope or Scope()
        self.cancel = asyncio.Event()
        self._module_id = ""
        self._target = ""
        self._creds: dict = {}
        self.store: FindingStore | None = None

    def prepare(self, module_id: str, target: str, confirmed: bool,
                credentials: dict | None = None) -> None:
        if module_id not in registry.MODULES:
            raise ScopeError(f"неизвестный модуль: {module_id}")
        self._target = self.scope.check(target, confirmed)   # may raise ScopeError
        self.scope.permit(self._target)
        self._module_id = module_id
        # Тестовые учётные данные для сценариев: переданные пользователем или сгенерированные.
        creds = credentials or {}
        self._creds = {
            "username": creds.get("username") or "vibesec_tester",
            "password": creds.get("password") or secrets.token_urlsafe(9),
        }

    def stop(self) -> None:
        self.cancel.set()

    async def _emit_finding(self, f: Finding) -> None:
        d = f.to_dict()
        if f.screenshot and self.store is not None:
            d["screenshot_url"] = f"/api/screenshot/{self.store.run_id}/{Path(f.screenshot).name}"
        await self.emit(events.finding(d))

    async def _handle_tool_step(self, step: Step) -> str:
        status, lines, used_demo = await run_step(step, self._target, self.emit, self.cancel)
        if status == "stopped":
            return "stopped"

        # Собрать находки: из demo_findings (демо) или через парсер (реальный вывод).
        new: list[Finding] = []
        if used_demo and step.demo_findings:
            for d in step.demo_findings:
                rendered = _render_finding(d, self._target)
                new.append(Finding.from_dict(rendered))
        elif step.parser and step.parser in PARSERS and lines:
            new = PARSERS[step.parser](lines, self._target)

        assert self.store is not None
        for f in new:
            self.store.add(f)
            await self._emit_finding(f)
        if new:
            await self.emit(events.log(step.name, "system",
                                       f"[vibesec] находок на этапе: {len(new)}"))
        return status

    async def _handle_task(self, step: Step) -> None:
        """Сценарий подготовки доступа (регистрация/вход) с живым выводом и скриншотом."""
        assert self.store is not None
        fn = account.register if step.action == "task_register" else account.login
        log_lines, shot = fn(self._target, self._creds, self.store.run_dir)
        for stream, line in log_lines:
            await self.emit(events.log(step.name, stream, line))
        self.store.add_task(step.name, screenshot=shot,
                            note=f"тест-профиль {self._creds['username']}")
        await self.emit(events.log(step.name, "system", f"[vibesec] скриншот-доказательство сохранён: {shot}"))

    async def _handle_action_step(self, step: Step) -> str:
        assert self.store is not None
        if step.action in ("task_register", "task_login"):
            await self._handle_task(step)
            return "ok"
        if step.action == "collect":
            loaded = FindingStore.load_latest_for(settings.reports_dir, self._target)
            for f in loaded:
                self.store.add(f)
                await self._emit_finding(f)
            await self.emit(events.log(step.name, "system",
                                       f"[vibesec] подгружено находок: {len(loaded)}"))
        elif step.action == "validate":
            confirmed, rejected = validate_findings(self.store)
            for f in self.store.validated():
                generate_poc(f, self._target)
                f.screenshot = screenshot.capture(
                    name=f"finding-{f.id}", title=f.title,
                    subtitle=f.endpoint or self._target, sev_label=f.severity.label,
                    url=f.endpoint or f"https://{self._target}", run_dir=self.store.run_dir,
                    lines=[f"class: {f.vuln_class}",
                           f"severity: {f.severity.label} ({f.severity.score})",
                           f"tool: {f.tool}"],
                )
                await self._emit_finding(f)
            self.store.update_all()
            await self.emit(events.log(step.name, "system",
                                       f"[vibesec] подтверждено: {confirmed}, отброшено: {rejected}; "
                                       f"скриншоты-доказательства приложены"))
        elif step.action == "report":
            title = registry.MODULES[self._module_id]["title"]
            md, summary = compile_report(self.store, self._target, title)
            await self.emit(events.report(
                run_id=self.store.run_id,
                summary=summary["summary"],
                formats=summary.get("formats", ["md", "json"]),
                preview=md[:4000],
            ))
            await self.emit(events.log(step.name, "system",
                                       f"[vibesec] отчёт собран: {summary['summary']}"))
        return "ok"

    async def run(self) -> None:
        self.store = FindingStore(settings.reports_dir / _run_id(self._module_id, self._target))
        agents = registry.pipeline(self._module_id)
        steps = [s for agent in agents for s in agent.steps]
        total = len(steps)

        await self.emit(events.status("running", f"цель: {self._target}"))

        for index, step in enumerate(steps):
            if self.cancel.is_set():
                break
            await self.emit(events.stage(index, step.name, "start", total))

            if step.is_action:
                await self._handle_action_step(step)
            else:
                result = await self._handle_tool_step(step)
                if result == "stopped":
                    await self.emit(events.status("stopped", "остановлено пользователем"))
                    return

            await self.emit(events.stage(index, step.name, "done", total))
            await self.emit(events.progress(round((index + 1) / total * 100)))

        if self.cancel.is_set():
            await self.emit(events.status("stopped", "остановлено пользователем"))
            return

        title = registry.MODULES[self._module_id]["title"]
        await self.emit(events.done(f"модуль «{title}» завершён"))
        await self.emit(events.status("done", ""))


def _render_finding(d: dict, target: str) -> dict:
    """Подставить {target} в строковые поля демо-находки."""
    def sub(v):
        if isinstance(v, str):
            return v.replace("{target}", target)
        if isinstance(v, list):
            return [sub(x) for x in v]
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        return v
    return {k: sub(v) for k, v in d.items()}
