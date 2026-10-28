"""Компилятор отчёта в формате, близком к HackerOne.

Собирает подтверждённые находки в Markdown (секция на находку:
Title / Severity / Description / Steps / Impact / PoC / Remediation),
сортирует по severity, пишет report.md и report.json в каталог запуска.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from app.findings.model import Finding, FindingStore

_BADGE = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium",
          "low": "🔵 Low", "info": "⚪ Info"}


def _finding_md(f: Finding, n: int) -> str:
    sev = f.severity
    lines = [
        f"## {n}. [{_BADGE.get(sev.label, sev.label)}] {f.title}",
        "",
        f"- **Severity:** {sev.label.capitalize()} ({sev.score})"
        + (f" — `{sev.vector}`" if sev.vector else ""),
        f"- **Class:** {f.vuln_class}",
        f"- **Asset:** `{f.endpoint or f.target}`",
        f"- **Tool / confidence:** {f.tool or '—'} / {f.confidence}",
        "",
        "### Description",
        f.description or "—",
        "",
        "### Steps to Reproduce",
    ]
    lines += [f"{i}. {s}" for i, s in enumerate(f.steps, 1)] or ["—"]
    lines += ["", "### Impact", f.impact or "—", "", "### Proof of Concept"]
    if f.poc.curl:
        lines += ["```bash", f.poc.curl, "```"]
    if f.poc.browser_steps:
        lines += ["", "_Browser:_"] + [f"- {s}" for s in f.poc.browser_steps]
    if f.poc.script:
        lines += ["```", f.poc.script, "```"]
    if f.evidence:
        lines += ["", "<details><summary>Evidence</summary>", "", "```"] + f.evidence + ["```", "</details>"]
    lines += ["", "### Remediation", f.remediation or "—", "", "---", ""]
    return "\n".join(lines)


def compile_report(store: FindingStore, target: str, module_title: str) -> tuple[str, dict]:
    """Собрать отчёт, записать файлы. Вернуть (markdown, сводка)."""
    findings = [f for f in store.by_severity() if f.status == "validated"]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1

    header = [
        f"# VibeSec — отчёт: {module_title}",
        "",
        f"**Цель:** `{target}`  ",
        f"**Дата:** {time.strftime('%Y-%m-%d %H:%M')}  ",
        f"**Подтверждённых находок:** {len(findings)}  ",
        "**Сводка:** " + (", ".join(f"{k}: {v}" for k, v in counts.items()) or "нет находок"),
        "",
        "> Отчёт сгенерирован автоматически в рамках авторизованного тестирования.",
        "> Все проверки выполнялись в неразрушающем режиме.",
        "",
        "---",
        "",
    ]
    body = [_finding_md(f, i) for i, f in enumerate(findings, 1)] or \
           ["_Подтверждённых находок нет. Запустите охотничий модуль по цели перед сборкой отчёта._\n"]
    md = "\n".join(header) + "\n".join(body)

    (store.run_dir / "report.md").write_text(md, encoding="utf-8")
    (store.run_dir / "report.json").write_text(
        json.dumps({
            "target": target, "module": module_title,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "counts": counts,
            "findings": [f.to_dict() for f in findings],
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary = f"{len(findings)} подтверждённых находок" + (f" ({', '.join(f'{k}: {v}' for k, v in counts.items())})" if counts else "")
    return md, {"count": len(findings), "counts": counts, "summary": summary}
