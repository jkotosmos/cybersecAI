"""Агент авторизованного тестирования.

Сначала выполняет сценарии подготовки доступа (регистрация тест-профиля, вход),
затем ищет уязвимости, видимые только под аутентификацией: IDOR, Broken Access
Control, горизонтальное/вертикальное повышение привилегий.
"""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="auth",
    title="Авторизованный доступ",
    steps=[
        Step(name="Регистрация тест-профиля", action="task_register"),
        Step(name="Вход под тест-профилем", action="task_login"),
        Step(
            name="Authenticated IDOR / BAC",
            argv=["vibesec-authed", "{target}"],
            demo_lines=["[auth] GET /api/v1/orders/8842 под чужой сессией",
                        "[!] доступ к чужому заказу без проверки владения"],
            demo_findings=[{
                "vuln_class": "BAC", "title": "Broken Access Control: чужой заказ под тест-сессией",
                "endpoint": "https://{target}/api/v1/orders/8842", "target": "{target}", "tool": "vibesec-authed",
                "description": "Под сессией обычного пользователя доступен заказ другого аккаунта: нет серверной проверки владения объектом.",
                "severity": {"label": "high", "score": 8.2,
                             "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"},
                "evidence": ["GET /api/v1/orders/8842 (сессия user A) → 200 с данными user B"],
            }],
        ),
    ],
)
