"""Самодостаточный HTML-отчёт со встроенными (base64) скриншотами-доказательствами."""
from __future__ import annotations

import base64
import html
import time
from pathlib import Path

from app.findings.model import Finding

_SEV = {"critical": "#e8686c", "high": "#e8864f", "medium": "#e0b341", "low": "#4f8ff7", "info": "#6f8197"}


def _data_uri(run_dir: Path, rel: str) -> str | None:
    if not rel:
        return None
    p = run_dir / rel
    if not p.exists():
        return None
    mime = "image/png" if p.suffix == ".png" else "image/svg+xml"
    b64 = base64.b64encode(p.read_bytes()).decode()
    return f"data:{mime};base64,{b64}"


def _img(run_dir: Path, rel: str, cap: str) -> str:
    uri = _data_uri(run_dir, rel)
    if not uri:
        return ""
    return (f'<figure><img src="{uri}" alt="{html.escape(cap)}"/>'
            f'<figcaption>{html.escape(cap)}</figcaption></figure>')


def _finding_html(f: Finding, n: int, run_dir: Path) -> str:
    col = _SEV.get(f.severity.label, "#6f8197")
    steps = "".join(f"<li>{html.escape(s)}</li>" for s in f.steps)
    ev = "".join(f"<li>{html.escape(e)}</li>" for e in f.evidence)
    return f'''<section class="f" style="--sc:{col}">
  <h2><span class="sev">{html.escape(f.severity.label.upper())}</span> {n}. {html.escape(f.title)}</h2>
  <ul class="meta">
    <li><b>Severity:</b> {f.severity.label.capitalize()} ({f.severity.score}) {html.escape(f.severity.vector)}</li>
    <li><b>Class:</b> {html.escape(f.vuln_class)}</li>
    <li><b>Asset:</b> <code>{html.escape(f.endpoint or f.target)}</code></li>
    <li><b>Tool / confidence:</b> {html.escape(f.tool)} / {html.escape(f.confidence)}</li>
  </ul>
  <h3>Description</h3><p>{html.escape(f.description)}</p>
  <h3>Steps to Reproduce</h3><ol>{steps}</ol>
  <h3>Impact</h3><p>{html.escape(f.impact)}</p>
  <h3>Proof of Concept</h3><pre>{html.escape(f.poc.curl)}</pre>
  {_img(run_dir, f.screenshot, "Скриншот-доказательство: " + f.title)}
  {"<h3>Evidence</h3><ul>" + ev + "</ul>" if ev else ""}
  <h3>Remediation</h3><p>{html.escape(f.remediation)}</p>
</section>'''


def build_html(meta: dict, findings: list[Finding], tasks: list[dict], run_dir: Path) -> Path:
    counts = meta.get("counts", {})
    summary = ", ".join(f"{k}: {v}" for k, v in counts.items()) or "нет находок"
    body = "".join(_finding_html(f, i, run_dir) for i, f in enumerate(findings, 1)) \
        or "<p><i>Подтверждённых находок нет.</i></p>"

    appendix = ""
    if tasks:
        cards = "".join(
            f'<div class="task"><b>{html.escape(t["name"])}</b>'
            f'{"<br>" + html.escape(t["note"]) if t.get("note") else ""}'
            f'{_img(run_dir, t.get("screenshot", ""), t["name"])}</div>'
            for t in tasks
        )
        appendix = f'<h2 class="apx">Приложение: подготовка доступа</h2><div class="tasks">{cards}</div>'

    return _write(meta, summary, body, appendix, run_dir)


def _write(meta: dict, summary: str, body: str, appendix: str, run_dir: Path) -> Path:
    doc = f'''<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>VibeSec — {html.escape(meta.get("module", ""))}</title>
<style>
  :root{{color-scheme:dark;}}
  body{{margin:0;background:linear-gradient(145deg,#0f1b2d,#2a333f);color:#e8eef6;
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.55;}}
  .wrap{{max-width:900px;margin:0 auto;padding:40px 22px 80px;}}
  h1{{font-size:26px;margin:0 0 6px;}}
  .head{{color:#9fb0c3;font-size:14px;margin-bottom:24px;}}
  .head code{{color:#4f8ff7;}}
  section.f{{background:rgba(148,176,214,.06);border:1px solid rgba(159,186,221,.14);
    border-left:4px solid var(--sc);border-radius:12px;padding:18px 22px;margin:18px 0;}}
  section.f h2{{font-size:18px;margin:0 0 10px;}}
  .sev{{font-size:11px;font-weight:700;color:var(--sc);border:1px solid var(--sc);
    border-radius:999px;padding:2px 9px;margin-right:8px;}}
  ul.meta{{list-style:none;padding:0;margin:0 0 14px;font-size:13px;color:#9fb0c3;display:grid;gap:3px;}}
  h3{{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#9fb0c3;margin:16px 0 6px;}}
  pre{{background:#0a1420;border:1px solid rgba(159,186,221,.14);border-radius:8px;
    padding:12px;overflow:auto;font-size:12.5px;color:#8fd0c8;}}
  code{{font-family:ui-monospace,Menlo,Consolas,monospace;}}
  figure{{margin:12px 0;}}
  figure img{{max-width:100%;border:1px solid rgba(159,186,221,.2);border-radius:8px;}}
  figcaption{{font-size:12px;color:#6f8197;margin-top:5px;}}
  .apx{{margin-top:36px;font-size:20px;}}
  .tasks{{display:grid;gap:16px;}}
  .task{{background:rgba(148,176,214,.06);border:1px solid rgba(159,186,221,.14);border-radius:12px;padding:16px;}}
</style></head><body><div class="wrap">
<h1>VibeSec — отчёт: {html.escape(meta.get("module", ""))}</h1>
<div class="head">Цель: <code>{html.escape(meta.get("target", ""))}</code> ·
  {time.strftime("%Y-%m-%d %H:%M")} · Подтверждённых находок: {meta.get("count", 0)} · Сводка: {html.escape(summary)}<br>
  <i>Сгенерировано автоматически в рамках авторизованного тестирования. Все проверки — неразрушающие.</i></div>
{body}
{appendix}
</div></body></html>'''
    out = run_dir / "report.html"
    out.write_text(doc, encoding="utf-8")
    return out
