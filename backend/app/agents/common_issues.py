"""Агент поиска типовых проблем безопасности по проверенным шаблонам."""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="common_issues",
    title="Типовые проблемы",
    steps=[
        Step(
            name="Подготовка целей",
            argv=["vibesec-prep", "{target}"],
            demo_lines=["[+] 9 эндпоинтов поставлено в очередь"],
        ),
        Step(
            name="Запуск шаблонов",
            argv=["nuclei", "-silent", "-u", "{target}"],
            demo_lines=["[medium] открытый редирект на /go",
                        "[low] утечка версии сервера в заголовке",
                        "[+] выполнено 312 шаблонов"],
        ),
        Step(
            name="Верификация находок",
            argv=["vibesec-verify", "{target}"],
            demo_lines=["[+] подтверждено: 2", "[-] ложное срабатывание отброшено: 1"],
        ),
        Step(
            name="Приоритизация",
            argv=["vibesec-triage", "{target}"],
            demo_lines=["[+] итог: 1 medium, 1 low"],
        ),
    ],
)
