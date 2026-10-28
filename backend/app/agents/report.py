"""Агент генерации отчёта: собирает результаты запусков в читаемый отчёт."""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="report",
    title="Отчёт",
    steps=[
        Step(
            name="Сбор данных",
            argv=["vibesec-report", "collect", "{target}"],
            demo_lines=["[+] загружены результаты последних запусков"],
        ),
        Step(
            name="Приоритизация",
            argv=["vibesec-report", "rank", "{target}"],
            demo_lines=["[+] находки отсортированы по CVSS"],
        ),
        Step(
            name="Формирование отчёта",
            argv=["vibesec-report", "build", "{target}"],
            demo_lines=["[+] отчёт сохранён: reports/{target}.md"],
        ),
    ],
)
