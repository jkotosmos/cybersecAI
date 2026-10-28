"""Контроль scope — обязательный барьер перед любым запуском.

VibeSec предназначена только для авторизованных целей: собственные проекты
или цели в рамках официальной bug bounty программы. Перед стартом пользователь
обязан подтвердить право на тестирование (human-in-the-loop), а цель
нормализуется и проверяется здесь.

Для продакшена сюда добавляется постоянный allowlist (файл/БД) и, при желании,
проверка через out-of-band подтверждение владения доменом.
"""
from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(Exception):
    """Цель не прошла проверку scope."""


def normalize_target(raw: str) -> str:
    """Привести цель к хосту в нижнем регистре.

    Принимает 'example.com', 'https://app.example.com/path', '10.0.0.5'.
    """
    raw = (raw or "").strip()
    if "://" in raw:
        host = urlparse(raw).hostname or ""
    else:
        host = raw.split("/", 1)[0]
    return host.lower().strip()


class Scope:
    """Разрешённые цели текущей сессии."""

    def __init__(self, allowed: list[str] | None = None) -> None:
        self.allowed: set[str] = {normalize_target(a) for a in (allowed or [])}

    def permit(self, target: str) -> None:
        self.allowed.add(normalize_target(target))

    def check(self, target: str, confirmed: bool) -> str:
        """Проверить цель. Вернуть нормализованный хост или бросить ScopeError."""
        host = normalize_target(target)
        if not host:
            raise ScopeError("цель не указана")
        if not confirmed:
            raise ScopeError("не подтверждено разрешение на тестирование этой цели")
        # Если allowlist задан явно — цель обязана в нём быть.
        if self.allowed and host not in self.allowed:
            raise ScopeError(f"цель вне разрешённого scope: {host}")
        return host
