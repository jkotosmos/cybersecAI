"""Реестр модулей — связывает карточки GUI с пайплайнами агентов.

Каждый модуль — упорядоченный список агентов. Метаданные (название, описание,
глубина, классы уязвимостей, потенциальная severity) отдаются во фронтенд для
карточек; список этапов собирается автоматически из шагов агентов.
"""
from __future__ import annotations

from app.agents import recon, surface, hunt, exposure, auth, finalize, report
from app.agents.base import Agent

MODULES: dict[str, dict] = {
    "recon": {
        "title": "Recon Sweep · Быстрая разведка",
        "desc": "Поддомены, живые хосты, открытые порты и технологии за минуты.",
        "depth": "light", "eta": "~2–4 мин", "sev": "info", "classes": [],
        "agents": [recon.agent],
    },
    "surface": {
        "title": "Attack Surface Mapping · Поверхность атаки",
        "desc": "Обход контента, поиск параметров и скрытых путей, карта поверхности.",
        "depth": "light", "eta": "~10–20 мин", "sev": "low", "classes": [],
        "agents": [recon.agent, surface.agent],
    },
    "vuln_hunt": {
        "title": "Vulnerability Hunt · Охота на уязвимости",
        "desc": "Активный поиск: XSS, SQLi, SSRF, IDOR, Broken Access Control, misconfig — с валидацией и отчётом.",
        "depth": "deep", "eta": "~30–60 мин", "sev": "critical",
        "classes": ["IDOR", "XSS", "SQLi", "SSRF", "BAC"],
        "agents": [recon.agent, surface.agent, hunt.agent, finalize.agent],
    },
    "vibe_hunt": {
        "title": "Vibe-Code Exploit Hunt · Охота в AI-коде",
        "desc": "Утёкшие секреты, debug-эндпоинты, дефолтные креды, небезопасные дефолты AI-генераторов.",
        "depth": "deep", "eta": "~15–30 мин", "sev": "high",
        "classes": ["InfoDisclosure", "AuthBypass", "Misconfig"],
        "agents": [exposure.agent, finalize.agent],
    },
    "auth_hunt": {
        "title": "Authenticated Hunt · Охота с авторизацией",
        "desc": "Регистрация тест-профиля, вход, затем охота за IDOR и Broken Access Control под сессией.",
        "depth": "deep", "eta": "~20–40 мин", "sev": "high",
        "classes": ["IDOR", "BAC", "AuthBypass"],
        "agents": [auth.agent, finalize.agent],
    },
    "redteam": {
        "title": "Red Team Sim · Симуляция атак",
        "desc": "Полная неразрушающая симуляция: разведка → поверхность → охота → авторизованный доступ → AI-код → отчёт.",
        "depth": "deep", "eta": "~60–120 мин", "sev": "critical",
        "classes": ["IDOR", "XSS", "SQLi", "SSRF", "BAC", "AuthBypass", "Misconfig"],
        "agents": [recon.agent, surface.agent, hunt.agent, auth.agent, exposure.agent, finalize.agent],
    },
    "full": {
        "title": "Full Kill Chain · Полный цикл",
        "desc": "Автономно: разведка → поверхность → охота → охота в AI-коде → валидация → отчёт.",
        "depth": "deep", "eta": "~40–90 мин", "sev": "critical",
        "classes": ["IDOR", "XSS", "SQLi", "SSRF", "BAC", "AuthBypass"],
        "agents": [recon.agent, surface.agent, hunt.agent, exposure.agent, finalize.agent],
    },
    "report": {
        "title": "Report Builder · Сборка отчёта",
        "desc": "Собрать подтверждённые находки по цели в отчёт формата HackerOne.",
        "depth": "light", "eta": "~1–2 мин", "sev": "info", "classes": [],
        "agents": [report.agent],
    },
}


def pipeline(module_id: str) -> list[Agent]:
    return MODULES[module_id]["agents"]


def stages_of(module_id: str) -> list[str]:
    return [step.name for agent in pipeline(module_id) for step in agent.steps]


def list_modules() -> list[dict]:
    out = []
    for mid, m in MODULES.items():
        out.append({
            "id": mid,
            "title": m["title"],
            "desc": m["desc"],
            "depth": m["depth"],
            "eta": m["eta"],
            "sev": m["sev"],
            "classes": m["classes"],
            "stages": stages_of(mid),
        })
    return out
