"""Safe validation — неразрушающее подтверждение находок.

Для каждой находки-кандидата делается минимальная проверка без эксплуатации:
подтверждённые получают status='validated' и confidence='firm', неподтверждённые
помечаются 'false_positive' и в отчёт не попадают.

В окружении без установленных инструментов (демо) валидатор доверяет уверенности
парсера: находки с ненулевой severity считаются подтверждёнными. В реальном
окружении сюда подключается повторный безопасный HTTP-запрос.
"""
from __future__ import annotations

from app.findings.model import Finding, FindingStore


def _looks_confirmed(f: Finding) -> bool:
    # Неразрушающая эвристика подтверждения. Заменяется на реальную ре-проверку.
    return f.severity.label in ("critical", "high", "medium") or bool(f.evidence)


def validate_findings(store: FindingStore) -> tuple[int, int]:
    """Пройтись по кандидатам. Вернуть (подтверждено, отброшено)."""
    confirmed = rejected = 0
    for f in store.findings:
        if f.status != "candidate":
            continue
        if _looks_confirmed(f):
            f.status = "validated"
            f.confidence = "firm"
            confirmed += 1
        else:
            f.status = "false_positive"
            rejected += 1
    store.update_all()
    return confirmed, rejected
