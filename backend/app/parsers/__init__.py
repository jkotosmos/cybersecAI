"""Нормализаторы вывода инструментов в структурные находки.

Каждый парсер получает захваченные строки stdout и цель, возвращает list[Finding].
Реестр PARSERS связывает имя парсера (указанное в шаге агента) с функцией.
Если инструмент не установлен, оркестратор берёт demo_findings шага вместо парсинга.
"""
from __future__ import annotations

from app.parsers import nuclei, dalfox, sqlmap, ffuf

PARSERS = {
    "nuclei": nuclei.parse,
    "dalfox": dalfox.parse,
    "sqlmap": sqlmap.parse,
    "ffuf": ffuf.parse,
}
