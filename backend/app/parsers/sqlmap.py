"""Парсер текстового вывода sqlmap в находки SQLi (эвристика)."""
from __future__ import annotations

import re

from app.findings.model import Finding, Severity

_PARAM = re.compile(r"parameter '([^']+)'", re.IGNORECASE)


def parse(lines: list[str], target: str) -> list[Finding]:
    text = "\n".join(lines)
    low = text.lower()
    if "is vulnerable" not in low and "injectable" not in low:
        return []
    m = _PARAM.search(text)
    param = m.group(1) if m else "неизвестен"
    return [Finding(
        vuln_class="SQLi",
        title=f"SQL-инъекция в параметре «{param}»",
        endpoint=target,
        target=target,
        description="sqlmap определил, что параметр уязвим к SQL-инъекции (безопасный профиль, без эксплуатации ОС/ФС).",
        severity=Severity(label="critical", score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        evidence=[ln for ln in lines if "injectab" in ln.lower() or "vulnerab" in ln.lower()][:3],
        tool="sqlmap",
    )]
