"""Реестр модулей — связывает кнопки GUI с пайплайнами агентов.

Каждый модуль — это упорядоченный список агентов. Метаданные (название,
описание, глубина, оценка времени) отдаются во фронтенд для карточек,
а список этапов собирается автоматически из шагов агентов.
"""
from __future__ import annotations

from app.agents import recon, surface, common_issues, vibe_audit, report
from app.agents.base import Agent

MODULES: dict[str, dict] = {
    "recon": {
        "title": "Быстрая разведка",
        "desc": "Поддомены, живые хосты, открытые порты и технологии за минуты.",
        "depth": "light",
        "eta": "~2–4 мин",
        "agents": [recon.agent],
    },
    "surface": {
        "title": "Полный анализ поверхности",
        "desc": "Глубокое картирование точек входа, эндпоинтов и скрытых путей.",
        "depth": "light",
        "eta": "~10–20 мин",
        "agents": [recon.agent, surface.agent],
    },
    "common_issues": {
        "title": "Типовые проблемы безопасности",
        "desc": "Проверка на распространённые уязвимости по проверенным шаблонам.",
        "depth": "light",
        "eta": "~15–30 мин",
        "agents": [common_issues.agent],
    },
    "vibe_audit": {
        "title": "Проверка AI-кода (vibe-coding)",
        "desc": "Спец-проверка приложений, сгенерированных AI: секреты, небезопасные дефолты.",
        "depth": "deep",
        "eta": "~10–25 мин",
        "agents": [vibe_audit.agent],
    },
    "full": {
        "title": "Комплексная проверка",
        "desc": "Полный цикл: разведка → поверхность → уязвимости → аудит AI-кода.",
        "depth": "deep",
        "eta": "~40–90 мин",
        "agents": [recon.agent, surface.agent, common_issues.agent, vibe_audit.agent],
    },
    "report": {
        "title": "Генерация отчёта",
        "desc": "Собрать результаты прошлых запусков в читаемый отчёт для bug bounty.",
        "depth": "light",
        "eta": "~1–2 мин",
        "agents": [report.agent],
    },
}


def pipeline(module_id: str) -> list[Agent]:
    return MODULES[module_id]["agents"]


def stages_of(module_id: str) -> list[str]:
    return [step.name for agent in pipeline(module_id) for step in agent.steps]


def list_modules() -> list[dict]:
    """Описание модулей для фронтенда (карточки + список этапов)."""
    out = []
    for mid, m in MODULES.items():
        out.append({
            "id": mid,
            "title": m["title"],
            "desc": m["desc"],
            "depth": m["depth"],
            "eta": m["eta"],
            "stages": stages_of(mid),
        })
    return out
