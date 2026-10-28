"""Агент анализа поверхности атаки: обход контента, сбор эндпоинтов."""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="surface",
    title="Поверхность атаки",
    steps=[
        Step(
            name="Обход контента",
            argv=["katana", "-silent", "-u", "{target}"],
            demo_lines=["https://{target}/login", "https://{target}/api/v1/users",
                        "https://{target}/admin", "[+] найдено 142 URL"],
        ),
        Step(
            name="Сбор эндпоинтов",
            argv=["gau", "{target}"],
            demo_lines=["https://{target}/api/v1/search?q=", "https://{target}/upload",
                        "[+] 38 уникальных эндпоинтов"],
        ),
        Step(
            name="Карта поверхности",
            argv=["vibesec-surface-map", "{target}"],
            demo_lines=["[+] точек входа: 12", "[+] форм: 7", "[+] API-маршрутов: 19"],
        ),
    ],
)
