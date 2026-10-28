"""PDF-отчёт через fpdf2 со встроенными скриншотами и кириллицей.

Требует Unicode-TTF (DejaVuSans / Arial — ищется автоматически). Если шрифт или
fpdf2 недоступны, возвращает None, и отчёт остаётся в md/json/html.
"""
from __future__ import annotations

from pathlib import Path

from app.findings.model import Finding
from app.report.fonts import unicode_font, unicode_font_bold

_SEV = {"critical": (232, 104, 108), "high": (232, 134, 79), "medium": (224, 179, 65),
        "low": (79, 143, 247), "info": (111, 129, 151)}


def build_pdf(meta: dict, findings: list[Finding], tasks: list[dict], run_dir: Path) -> Path | None:
    font, font_b = unicode_font(), unicode_font_bold()
    if not font:
        return None
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError:
        return None

    try:
        pdf = FPDF(format="A4")
        pdf.set_auto_page_break(True, margin=16)
        pdf.add_font("uni", "", font)
        pdf.add_font("uni", "B", font_b or font)
        pdf.add_page()

        def h(txt, size, color=(232, 238, 246), style="B", gap=2):
            pdf.set_font("uni", style, size)
            pdf.set_text_color(*color)
            pdf.multi_cell(0, size * 0.5 + 2, txt, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(gap)

        def body(txt, size=11, color=(200, 212, 226)):
            pdf.set_font("uni", "", size)
            pdf.set_text_color(*color)
            pdf.multi_cell(0, 6, txt, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        h(f"VibeSec — отчёт: {meta.get('module','')}", 18)
        counts = meta.get("counts", {})
        summary = ", ".join(f"{k}: {v}" for k, v in counts.items()) or "нет находок"
        body(f"Цель: {meta.get('target','')}\n"
             f"Подтверждённых находок: {meta.get('count',0)}  ·  Сводка: {summary}\n"
             f"Сгенерировано автоматически в рамках авторизованного тестирования. "
             f"Все проверки — неразрушающие.", 10, (159, 176, 199))
        pdf.ln(3)

        for i, f in enumerate(findings, 1):
            col = _SEV.get(f.severity.label, (111, 129, 151))
            h(f"{i}. [{f.severity.label.upper()}] {f.title}", 13, col)
            body(f"Severity: {f.severity.label.capitalize()} ({f.severity.score})  "
                 f"{f.severity.vector}\nClass: {f.vuln_class}   Asset: {f.endpoint or f.target}   "
                 f"Tool: {f.tool} / {f.confidence}", 9, (159, 176, 199))
            h("Description", 10, (159, 176, 199), gap=1); body(f.description)
            h("Steps to Reproduce", 10, (159, 176, 199), gap=1)
            body("\n".join(f"{j}. {s}" for j, s in enumerate(f.steps, 1)))
            h("Impact", 10, (159, 176, 199), gap=1); body(f.impact)
            h("Proof of Concept", 10, (159, 176, 199), gap=1)
            body(f.poc.curl, 10, (143, 208, 200))
            shot = run_dir / f.screenshot if f.screenshot else None
            if shot and shot.exists() and shot.suffix == ".png":
                try:
                    pdf.image(str(shot), w=160)
                    pdf.ln(2)
                except Exception:
                    pass
            h("Remediation", 10, (159, 176, 199), gap=1); body(f.remediation)
            pdf.ln(4)

        if tasks:
            pdf.add_page()
            h("Приложение: подготовка доступа", 15)
            for t in tasks:
                h(t["name"], 11, (159, 176, 199), gap=1)
                if t.get("note"):
                    body(t["note"], 10)
                sp = run_dir / t.get("screenshot", "") if t.get("screenshot") else None
                if sp and sp.exists() and sp.suffix == ".png":
                    try:
                        pdf.image(str(sp), w=160); pdf.ln(2)
                    except Exception:
                        pass

        out = run_dir / "report.pdf"
        pdf.output(str(out))
        return out
    except Exception:
        return None
