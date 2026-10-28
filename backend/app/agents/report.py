"""Агент сборки отчёта: подгружает находки прошлых запусков и компилирует отчёт."""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="report",
    title="Сборка отчёта",
    steps=[
        Step(name="Сбор находок по цели", action="collect"),
        Step(name="Сборка отчёта", action="report"),
    ],
)
