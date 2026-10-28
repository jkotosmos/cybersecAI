"""Парсер JSONL-вывода nuclei (`-jsonl`) в находки."""
from __future__ import annotations

import json

from app.findings.model import Finding, Severity

_SEV_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0, "unknown": 0.0}
_CLASS = {"xss": "XSS", "sqli": "SQLi", "ssrf": "SSRF", "redirect": "InfoDisclosure",
          "exposure": "InfoDisclosure", "misconfiguration": "Misconfig", "default-login": "AuthBypass"}


def _vuln_class(tags: list[str], name: str) -> str:
    hay = " ".join(tags).lower() + " " + name.lower()
    for key, cls in _CLASS.items():
        if key in hay:
            return cls
    return "Misconfig"


def parse(lines: list[str], target: str) -> list[Finding]:
    out: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        sev = (info.get("severity") or "info").lower()
        name = info.get("name", obj.get("template-id", "nuclei finding"))
        tags = info.get("tags", []) if isinstance(info.get("tags"), list) else []
        matched = obj.get("matched-at") or obj.get("host") or target
        out.append(Finding(
            vuln_class=_vuln_class(tags, name),
            title=name,
            endpoint=matched,
            target=target,
            description=info.get("description", "").strip() or f"nuclei: {name}",
            severity=Severity(label=sev, score=_SEV_SCORE.get(sev, 0.0)),
            evidence=[line[:500]],
            tool="nuclei",
        ))
    return out
