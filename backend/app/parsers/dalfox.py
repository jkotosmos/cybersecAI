"""Парсер JSON-вывода dalfox (`--format json`) в находки XSS."""
from __future__ import annotations

import json

from app.findings.model import Finding, Severity


def parse(lines: list[str], target: str) -> list[Finding]:
    text = "\n".join(lines).strip()
    items: list[dict] = []
    # dalfox может выдавать массив JSON либо JSONL.
    try:
        parsed = json.loads(text)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in lines:
            line = line.strip()
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    out: list[Finding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        poc = it.get("data") or it.get("poc") or it.get("evidence", "")
        endpoint = it.get("url") or target
        out.append(Finding(
            vuln_class="XSS",
            title="Reflected XSS",
            endpoint=endpoint,
            target=target,
            description="dalfox подтвердил отражение полезной нагрузки в ответе.",
            severity=Severity(label="high", score=7.4, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            evidence=[str(poc)[:500]],
            tool="dalfox",
        ))
    return out
