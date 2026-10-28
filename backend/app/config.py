"""Конфигурация VibeSec.

Значения берутся из переменных окружения (с префиксом VIBESEC_),
иначе используются разумные дефолты. Платформа рассчитана на Linux.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent          # backend/
PROJECT_DIR = BASE_DIR.parent                               # репозиторий
FRONTEND_DIR = PROJECT_DIR / "frontend" / "static"
REPORTS_DIR = Path(os.getenv("VIBESEC_REPORTS_DIR", PROJECT_DIR / "reports"))


class Settings:
    host: str = os.getenv("VIBESEC_HOST", "127.0.0.1")
    port: int = int(os.getenv("VIBESEC_PORT", "8787"))

    # Задержка между строками демо-вывода, когда реальный инструмент не установлен.
    demo_line_delay: float = float(os.getenv("VIBESEC_DEMO_DELAY", "0.25"))

    # Жёсткий таймаут на один шаг (сек). 0 — без таймаута.
    step_timeout: int = int(os.getenv("VIBESEC_STEP_TIMEOUT", "0"))

    reports_dir: Path = REPORTS_DIR
    frontend_dir: Path = FRONTEND_DIR


settings = Settings()
settings.reports_dir.mkdir(parents=True, exist_ok=True)
