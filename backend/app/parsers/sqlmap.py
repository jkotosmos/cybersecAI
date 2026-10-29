"""Парсер текстового вывода sqlmap в находки SQLi.

sqlmap печатает блоки вида:
    Parameter: id (GET)
        Type: boolean-based blind
        Title: ...
        Payload: id=1 AND 5174=5174
    ...
    back-end DBMS: MySQL >= 5.0
Парсим параметры, техники и СУБД (безопасный профиль — без эксплуатации).
"""
from __future__ import annotations

import re

from app.findings.model import Finding, Severity

_PARAM = re.compile(r"^\s*Parameter:\s*(?P<name>[^\s(]+)\s*\((?P<method>\w+)\)", re.M)
_TYPE = re.compile(r"^\s*Type:\s*(?P<t>.+)$", re.M)
_PAYLOAD = re.compile(r"^\s*Payload:\s*(?P<p>.+)$", re.M)
_DBMS = re.compile(r"back-end DBMS:\s*(?P<d>.+)", re.I)


def parse(lines: list[str], target: str) -> list[Finding]:
    text = "\n".join(lines)
    low = text.lower()
    if "injectable" not in low and "is vulnerable" not in low and "Parameter:" not in text:
        return []

    dbms_m = _DBMS.search(text)
    dbms = dbms_m.group("d").strip() if dbms_m else "неизвестна"

    # разбить на блоки по параметрам
    params = list(_PARAM.finditer(text))
    out: list[Finding] = []
    for i, m in enumerate(params):
        start = m.end()
        end = params[i + 1].start() if i + 1 < len(params) else len(text)
        block = text[start:end]
        name, method = m.group("name"), m.group("method")
        techniques = [t.group("t").strip() for t in _TYPE.finditer(block)]
        payloads = [p.group("p").strip() for p in _PAYLOAD.finditer(block)]
        out.append(Finding(
            vuln_class="SQLi",
            title=f"SQL-инъекция в параметре «{name}» ({method})",
            endpoint=target,
            target=target,
            description=f"sqlmap подтвердил SQL-инъекцию в «{name}». СУБД: {dbms}. "
                        f"Техники: {', '.join(techniques) or '—'}. "
                        f"Проверка в безопасном профиле, без эксплуатации ОС/ФС.",
            severity=Severity(label="critical", score=9.8,
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            evidence=[f"back-end DBMS: {dbms}"] + [f"Payload: {p}" for p in payloads[:3]],
            tool="sqlmap",
        ))

    if not out:  # vulnerable, но без разбора блоков
        out.append(Finding(
            vuln_class="SQLi", title="SQL-инъекция", endpoint=target, target=target,
            description=f"sqlmap определил уязвимость к SQL-инъекции. СУБД: {dbms}.",
            severity=Severity(label="critical", score=9.8),
            evidence=[ln for ln in lines if "injectab" in ln.lower()][:3], tool="sqlmap",
        ))
    return out
