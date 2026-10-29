"""Парсер JSONL-вывода nuclei (`nuclei -jsonl`).

Формат: по одному JSON-объекту на строку. Значимые поля:
  template-id, info.{name,severity,description,tags,classification.{cvss-score,cvss-metrics,cve-id}},
  type, host, matched-at, matcher-name.
Док: https://docs.projectdiscovery.io/tools/nuclei/running (jsonl export).
"""
from __future__ import annotations

import json

from app.findings.model import Finding, Severity

_SEV_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0, "unknown": 0.0}

# tag/name → класс уязвимости VibeSec
_CLASS = [
    ("xss", "XSS"), ("sqli", "SQLi"), ("sql-injection", "SQLi"), ("ssrf", "SSRF"),
    ("lfi", "InfoDisclosure"), ("rce", "Misconfig"), ("redirect", "InfoDisclosure"),
    ("exposure", "InfoDisclosure"), ("disclosure", "InfoDisclosure"),
    ("default-login", "AuthBypass"), ("auth-bypass", "AuthBypass"),
    ("misconfig", "Misconfig"), ("cors", "Misconfig"), ("takeover", "Misconfig"),
]


def _vuln_class(tags, name: str) -> str:
    hay = " ".join(tags or []).lower() + " " + (name or "").lower()
    for key, cls in _CLASS:
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
        if not isinstance(obj, dict) or "info" not in obj:
            continue
        info = obj.get("info") or {}
        sev = str(info.get("severity") or "info").lower()
        name = info.get("name") or obj.get("template-id") or "nuclei finding"
        tags = info.get("tags") if isinstance(info.get("tags"), list) else []
        cls = info.get("classification") or {}
        score = cls.get("cvss-score")
        vector = cls.get("cvss-metrics") or ""
        matched = obj.get("matched-at") or obj.get("host") or target

        out.append(Finding(
            vuln_class=_vuln_class(tags, name),
            title=name,
            endpoint=matched,
            target=target,
            description=(info.get("description") or "").strip() or f"nuclei: {name}",
            severity=Severity(label=sev,
                              score=float(score) if isinstance(score, (int, float)) else _SEV_SCORE.get(sev, 0.0),
                              vector=vector),
            evidence=[f"template: {obj.get('template-id','')}", f"matched: {matched}"],
            tool="nuclei",
        ))
    return out
