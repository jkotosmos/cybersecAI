"""Парсер JSON-вывода ffuf (`ffuf ... -of json -o out.json` или `-o -`).

Формат: {"commandline","time","results":[{"input":{"FUZZ":...},"status","length",
"words","lines","content-type","redirectlocation","url","host"}],"config":{...}}.
Чувствительные пути и нетривиальные статусы отмечаются как находки.
"""
from __future__ import annotations

import json

from app.findings.model import Finding, Severity

_SENSITIVE = (".git", ".env", "backup", "config", "debug", "admin", "internal",
              "api", ".bak", ".sql", "dump", "secret", "actuator", "phpinfo", ".svn")


def _load(lines: list[str]) -> list[dict]:
    text = "\n".join(lines).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    return obj.get("results", []) if isinstance(obj, dict) else []


def parse(lines: list[str], target: str) -> list[Finding]:
    out: list[Finding] = []
    for r in _load(lines):
        if not isinstance(r, dict):
            continue
        url = r.get("url", "")
        status = int(r.get("status", 0) or 0)
        length = r.get("length", 0)
        low = url.lower()
        sensitive = any(s in low for s in _SENSITIVE)
        if status not in (200, 301, 302, 401, 403) or not sensitive:
            continue
        exposed = status in (200, 301, 302)
        out.append(Finding(
            vuln_class="InfoDisclosure" if exposed else "Misconfig",
            title=f"{'Доступен' if exposed else 'Обнаружен защищённый'} чувствительный путь ({status})",
            endpoint=url,
            target=target,
            description=f"ffuf нашёл чувствительный путь {url} — HTTP {status}, длина {length}.",
            severity=Severity(label="medium" if exposed else "low", score=5.3 if exposed else 3.1),
            evidence=[f"{status}  {url}  (len {length})"],
            tool="ffuf",
        ))
    return out
