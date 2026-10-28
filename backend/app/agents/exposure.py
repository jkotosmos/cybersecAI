"""Агент охоты в AI-сгенерированном коде (vibe-coding).

Ищет частые ошибки AI-генераторов: утёкшие секреты, debug-эндпоинты,
дефолтные креды, открытые .env/конфиги, небезопасные дефолты.
"""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="exposure",
    title="Охота в AI-коде",
    steps=[
        Step(
            name="Утёкшие секреты и ключи",
            argv=["gitleaks", "detect", "--no-git", "-s", "{target}", "-f", "json"],
            demo_lines=["[!] generic-api-key в .env.example:12", "[!] supabase service_role в config.ts:34"],
            demo_findings=[{
                "vuln_class": "InfoDisclosure", "title": "Утёкший сервисный ключ Supabase",
                "endpoint": "{target}/config.ts", "target": "{target}", "tool": "gitleaks",
                "description": "В публично доступном файле обнаружен service_role-ключ, дающий полный доступ к БД.",
                "severity": {"label": "critical", "score": 9.1},
                "evidence": ["config.ts:34  SUPABASE_SERVICE_ROLE=eyJ... (демо)"],
            }],
        ),
        Step(
            name="Открытые debug-эндпоинты",
            argv=["vibesec-expose", "{target}"],
            demo_lines=["200  /__debug__", "200  /api/dev/seed"],
            demo_findings=[{
                "vuln_class": "Misconfig", "title": "Открытый debug-эндпоинт в продакшене",
                "endpoint": "https://{target}/__debug__", "target": "{target}", "tool": "vibesec-expose",
                "description": "Debug-маршрут доступен без аутентификации и раскрывает внутреннее состояние.",
                "severity": {"label": "high", "score": 7.5},
                "evidence": ["GET /__debug__ → 200 со стеком и переменными окружения"],
            }],
        ),
        Step(
            name="Дефолтные креды и небезопасные дефолты",
            argv=["vibesec-defaults", "{target}"],
            demo_lines=["[~] admin/admin принят на /login", "[~] CSRF отключён на /api/admin"],
            demo_findings=[{
                "vuln_class": "AuthBypass", "title": "Приняты дефолтные учётные данные admin/admin",
                "endpoint": "https://{target}/login", "target": "{target}", "tool": "vibesec-defaults",
                "description": "Форма входа принимает неизменённые дефолтные креды, оставленные генератором.",
                "severity": {"label": "high", "score": 8.3},
                "evidence": ["POST /login admin/admin → 302 на /dashboard"],
            }],
        ),
    ],
)
