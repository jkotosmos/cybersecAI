"""Парсер JSON-вывода dalfox (`dalfox url <t> --format json`).

dalfox выдаёт JSON-массив PoC-объектов. Значимые поля:
  type ("V"=verified, "R"=reflected, "G"=grep), inject_type, method,
  data (полный URL с нагрузкой), param, payload, evidence, cwe, severity, message_str.
"""
from __future__ import annotations

import json

from app.findings.model import Finding, Severity

_SEV_SCORE = {"critical": 9.1, "high": 7.4, "medium": 5.4, "low": 3.1, "info": 0.0}


def _load(lines: list[str]) -> list[dict]:
    text = "\n".join(lines).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass
    # JSONL-вариант
    items = []
    for ln in lines:
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                items.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return [x for x in items if isinstance(x, dict)]


def parse(lines: list[str], target: str) -> list[Finding]:
    out: list[Finding] = []
    for it in _load(lines):
        sev = str(it.get("severity") or "high").lower()
        verified = str(it.get("type") or "").upper() == "V"
        url = it.get("data") or it.get("url") or target
        param = it.get("param") or "?"
        payload = it.get("payload") or it.get("evidence") or ""
        out.append(Finding(
            vuln_class="XSS",
            title=f"{'Verified' if verified else 'Reflected'} XSS в параметре «{param}»",
            endpoint=url,
            target=target,
            description=it.get("message_str") or "dalfox обнаружил отражение/инъекцию полезной нагрузки в ответе.",
            severity=Severity(label=sev, score=_SEV_SCORE.get(sev, 7.4),
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            evidence=[f"param: {param}", f"payload: {str(payload)[:300]}",
                      f"cwe: {it.get('cwe','')}", f"method: {it.get('method','GET')}"],
            confidence="firm" if verified else "tentative",
            tool="dalfox",
        ))
    return out
