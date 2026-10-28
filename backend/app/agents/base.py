"""Базовые структуры агента и шага.

Агент — набор шагов (этапов). Шаг бывает двух видов:
  • tool-шаг  — вызывает CLI-инструмент (argv), вывод опционально парсится в находки;
  • action-шаг — внутренняя фаза оркестратора ('validate' | 'report' | 'collect').

Демо-поля (demo_lines, demo_findings) используются, когда реальный инструмент
не установлен, чтобы каркас работал «из коробки».
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Step:
    name: str                                   # название этапа (видно в GUI)
    argv: list[str] = field(default_factory=list)   # argv[0] — инструмент; {target} → цель
    demo_lines: list[str] = field(default_factory=list)
    parser: str | None = None                   # имя парсера вывода → находки
    demo_findings: list[dict] = field(default_factory=list)
    action: str | None = None                   # 'validate' | 'report' | 'collect'

    @property
    def is_action(self) -> bool:
        return self.action is not None


@dataclass
class Agent:
    id: str
    title: str
    steps: list[Step]
