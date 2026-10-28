"""Сценарии подготовки доступа: регистрация тест-профиля и вход.

Это задачи human-in-the-loop типа «зайти и создать профиль с логином и паролем»:
они выполняются автономно с живым выводом и скриншотом-доказательством, а их
evidence прикладывается к отчёту. Учётные данные — тестовые (сгенерированы или
переданы пользователем для его авторизованной цели); пароль в выводе маскируется.

В демо-режиме шаги имитируются; при VIBESEC_SCREENSHOTS=real и установленном
Playwright сюда подключается реальный браузерный сценарий.
"""
from __future__ import annotations

from pathlib import Path

from app.evidence import screenshot


def _mask(pw: str) -> str:
    return (pw[:2] + "•" * max(4, len(pw) - 2)) if pw else "••••••"


def register(target: str, creds: dict, run_dir: Path) -> tuple[list[tuple[str, str]], str]:
    """Регистрация тест-профиля. Вернуть (строки лога, путь к скриншоту)."""
    user, pw = creds.get("username", "vibesec_tester"), creds.get("password", "")
    url = f"https://{target}/register"
    log = [
        ("system", f"сценарий: регистрация тест-профиля на {url}"),
        ("stdout", f"→ открываю форму регистрации {url}"),
        ("stdout", f"→ ввожу логин: {user}"),
        ("stdout", f"→ ввожу пароль: {_mask(pw)} (сгенерирован, скрыт)"),
        ("stdout", "→ отправляю форму"),
        ("stdout", "← 302 Found → /dashboard — профиль создан"),
    ]
    shot = screenshot.capture(
        name="task-register", title="Профиль создан", subtitle=url, sev_label="info",
        url=url, run_dir=run_dir,
        lines=[f"user: {user}", f"password: {_mask(pw)}", "status: 302 → /dashboard"],
    )
    return log, shot


def login(target: str, creds: dict, run_dir: Path) -> tuple[list[tuple[str, str]], str]:
    """Вход под тест-профилем и захват сессии."""
    user = creds.get("username", "vibesec_tester")
    url = f"https://{target}/login"
    log = [
        ("system", f"сценарий: вход под тест-профилем на {url}"),
        ("stdout", f"→ POST /login (логин {user})"),
        ("stdout", "← 200 OK, установлена cookie-сессия"),
        ("stdout", "→ сессия сохранена для авторизованных проверок"),
    ]
    shot = screenshot.capture(
        name="task-login", title="Выполнен вход", subtitle=url, sev_label="info",
        url=url, run_dir=run_dir,
        lines=[f"user: {user}", "session: захвачена", "scope: авторизованные эндпоинты"],
    )
    return log, shot
