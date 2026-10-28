"""Политика безопасности — «без деструктивных действий» как код.

Перед реальным запуском инструмента argv проверяется на деструктивные опции.
Это дополнительный барьер поверх безопасных профилей, зашитых в самих агентах
(низкий risk/level у sqlmap, исключение intrusive/dos-шаблонов у nuclei и т.п.).
"""
from __future__ import annotations


class UnsafeCommand(Exception):
    """Команда содержит запрещённую (деструктивную) опцию."""


# Флаги, дающие запись/выполнение на цели — запрещены всегда.
DENY_FLAGS: set[str] = {
    "--os-shell", "--os-pwn", "--os-cmd", "--os-bof",
    "--file-write", "--file-dest", "--sql-shell", "--sql-query",
    "--eval", "--purge", "--crawl-exclude-disruptive",
    "--dns-domain",            # OOB-эксфильтрация через DNS
}

# Подстроки, недопустимые в аргументах (деструктивные HTTP-методы в payload и т.п.).
DENY_SUBSTRINGS: tuple[str, ...] = (
    "--os-", "--file-write",
)


def assert_safe(argv: list[str]) -> None:
    """Бросить UnsafeCommand, если в argv есть запрещённая опция."""
    for part in argv:
        low = part.lower()
        if low in DENY_FLAGS:
            raise UnsafeCommand(f"запрещённая опция: {part}")
        if any(sub in low for sub in DENY_SUBSTRINGS):
            raise UnsafeCommand(f"запрещённая опция: {part}")
