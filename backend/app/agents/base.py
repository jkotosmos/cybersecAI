"""Базовые структуры агента и шага.

Агент — это набор шагов (этапов). Шаг описывает вызов одного инструмента:
аргументы командной строки (с плейсхолдером ``{target}``) и демо-вывод,
который показывается, если инструмент ещё не установлен.

Новый модуль = новый агент с набором шагов. Транспорт и GUI не трогаются.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Step:
    name: str                       # название этапа (видно в GUI)
    argv: list[str]                 # argv[0] — инструмент; {target} заменяется на цель
    demo_lines: list[str] = field(default_factory=list)


@dataclass
class Agent:
    id: str
    title: str
    steps: list[Step]
