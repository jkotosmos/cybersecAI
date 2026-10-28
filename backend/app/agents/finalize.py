"""Финальные фазы: валидация находок и сборка отчёта (action-шаги)."""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="finalize",
    title="Валидация и отчёт",
    steps=[
        Step(name="Валидация находок", action="validate"),
        Step(name="Сборка отчёта", action="report"),
    ],
)
