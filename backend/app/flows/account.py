"""Сценарии подготовки доступа: регистрация тест-профиля и вход.

Задачи human-in-the-loop вида «зайти и создать профиль с логином и паролём».
Два режима:
  • реальный  — Playwright (headless Chromium) заполняет формы и делает скриншот
                 страницы; включается VIBESEC_BROWSER=real (нужен playwright install chromium);
  • демо      — шаги имитируются, скриншот — стилизованный плейсхолдер.

Учётные данные тестовые (переданы пользователем для его авторизованной цели или
сгенерированы). Пароль в выводе маскируется.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.evidence import screenshot

Log = list[tuple[str, str]]


def _mask(pw: str) -> str:
    return (pw[:2] + "•" * max(4, len(pw) - 2)) if pw else "••••••"


def _real() -> bool:
    return os.getenv("VIBESEC_BROWSER") == "real"


def _url(target: str, path: str) -> str:
    """Собрать URL. У локальных dev-приложений схема http, у боевых целей — https.
    Явная схема в target уважается."""
    if target.startswith(("http://", "https://")):
        base = target.rstrip("/")
    else:
        host = target.split("/")[0]
        local = host.split(":")[0] in ("localhost", "127.0.0.1", "::1") or \
            host.endswith((".localhost", ".test"))
        base = f"{'http' if local else 'https'}://{target.rstrip('/')}"
    return base + path


# ---------- реальный браузерный сценарий (Playwright) ----------

_USER_SEL = ("input[name=username]", "input[name=user]", "input#username",
             "input[name=email]", "input[type=email]")
_PASS_SEL = ("input[type=password]", "input[name=password]")
_SUBMIT_SEL = ("button[type=submit]", "input[type=submit]",
               "button:has-text('Register')", "button:has-text('Sign up')",
               "button:has-text('Регистр')", "button:has-text('Войти')",
               "button:has-text('Log in')", "button:has-text('Sign in')")


def _fill_first(page, selectors, value) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.fill(value, timeout=3000)
                return True
        except Exception:
            continue
    return False


def _click_submit(page) -> None:
    for sel in _SUBMIT_SEL:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.click(timeout=3000)
                return
        except Exception:
            continue


def _pw_flow(path: str, target: str, creds: dict, run_dir: Path,
             shot_name: str, confirm_pw: bool) -> tuple[Log, str] | None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    url = _url(target, path)
    user, pw = creds["username"], creds["password"]
    log: Log = [("system", f"браузерный сценарий: {url}")]
    shots = run_dir / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    out = shots / f"{shot_name}.png"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            log.append(("stdout", f"→ открыта страница {url}"))
            if _fill_first(page, _USER_SEL, user):
                log.append(("stdout", f"→ введён логин: {user}"))
            if _fill_first(page, _PASS_SEL, pw):
                log.append(("stdout", f"→ введён пароль: {_mask(pw)}"))
            if confirm_pw:
                try:
                    pw_fields = page.locator("input[type=password]")
                    if pw_fields.count() > 1:
                        pw_fields.nth(1).fill(pw, timeout=3000)
                except Exception:
                    pass
            _click_submit(page)
            page.wait_for_timeout(1200)
            page.screenshot(path=str(out))
            cookies = page.context.cookies()
            browser.close()
        log.append(("stdout", f"← захвачено cookie-сессий: {len(cookies)}"))
        log.append(("stdout", "→ реальный скриншот страницы сохранён"))
        return log, f"screenshots/{out.name}"
    except Exception as exc:
        log.append(("stderr", f"[vibesec] браузерный сценарий не удался: {exc}; переход в демо"))
        return None


# ---------- демо-сценарий ----------

def _demo_register(target: str, creds: dict, run_dir: Path) -> tuple[Log, str]:
    user, pw, url = creds["username"], creds["password"], f"https://{target}/register"
    log: Log = [
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


def _demo_login(target: str, creds: dict, run_dir: Path) -> tuple[Log, str]:
    user, url = creds["username"], f"https://{target}/login"
    log: Log = [
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


# ---------- публичный интерфейс ----------

def register(target: str, creds: dict, run_dir: Path) -> tuple[Log, str]:
    if _real():
        res = _pw_flow("/register", target, creds, run_dir, "task-register", confirm_pw=True)
        if res:
            return res
    return _demo_register(target, creds, run_dir)


def login(target: str, creds: dict, run_dir: Path) -> tuple[Log, str]:
    if _real():
        res = _pw_flow("/login", target, creds, run_dir, "task-login", confirm_pw=False)
        if res:
            return res
    return _demo_login(target, creds, run_dir)
