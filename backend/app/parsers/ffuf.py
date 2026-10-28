"""Парсер JSON-вывода ffuf (`-of json -o -`) в находки раскрытия путей."""
from __future__ import annotations

import json

from app.findings.model import Finding, Severity

_SENSITIVE = ("admin", ".git", ".env", "backup", "config", "debug", "api", "internal")


def parse(lines: list[str], target: str) -> list[Finding]:
    text = "\n".join(lines).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    results = obj.get("results", []) if isinstance(obj, dict) else []
    out: list[Finding] = []
    for r in results:
        url = r.get("url", "")
        status = r.get("status", 0)
        if status not in (200, 301, 302, 401, 403):
            continue
        low = url.lower()
        sensitive = any(s in low for s in _SENSITIVE)
        if not sensitive:
            continue
        out.append(Finding(
            vuln_class="InfoDisclosure" if status < 400 else "Misconfig",
            title=f"Доступен чувствительный путь ({status})",
            endpoint=url,
            target=target,
            description=f"ffuf обнаружил отвечающий чувствительный путь: {url} (HTTP {status}).",
            severity=Severity(label="medium" if status < 400 else "low",
                              score=5.3 if status < 400 else 3.1),
            evidence=[f"{status}  {url}"],
            tool="ffuf",
        ))
    return out
