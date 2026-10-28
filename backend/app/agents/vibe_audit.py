"""Агент проверки AI-сгенерированного кода (vibe-coding).

Ищет частые проблемы приложений, собранных AI-генераторами: забытые секреты,
небезопасные дефолты (CORS, отключённый CSRF), уязвимые зависимости.
"""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="vibe_audit",
    title="Аудит AI-кода",
    steps=[
        Step(
            name="Анализ стека",
            argv=["vibesec-stack", "{target}"],
            demo_lines=["[+] обнаружен: Next.js + Supabase", "[+] карта стека построена"],
        ),
        Step(
            name="Поиск секретов",
            argv=["gitleaks", "detect", "--no-git", "-s", "{target}"],
            demo_lines=["[!] возможный API-ключ в .env.example:12",
                        "[~] hardcoded токен в config.ts:34",
                        "[+] сканирование секретов завершено"],
        ),
        Step(
            name="Небезопасные дефолты",
            argv=["vibesec-defaults", "{target}"],
            demo_lines=["[!] CORS: Access-Control-Allow-Origin: *",
                        "[~] проверка CSRF отключена на /api/admin",
                        "[+] паттерны проверены"],
        ),
        Step(
            name="Аудит зависимостей",
            argv=["osv-scanner", "--format", "json", "-r", "{target}"],
            demo_lines=["[~] 2 пакета с известными CVE", "[+] 48 зависимостей проверено"],
        ),
    ],
)
