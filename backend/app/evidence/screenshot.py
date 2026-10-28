"""Скриншоты-доказательства.

Для подтверждённой находки или шага-сценария делается скриншот:
  • реальная цель  — Playwright (headless Chromium), если установлен и включён режим;
  • иначе          — стилизованный плейсхолдер (Pillow → PNG, иначе SVG).

PNG нужен для встраивания в PDF; SVG — универсальный фолбэк для HTML-отчёта.
Файлы сохраняются в <run_dir>/screenshots/.
"""
from __future__ import annotations

import html
import os
import time
from pathlib import Path

from app.report.fonts import unicode_font, unicode_font_bold

_SEV_RGB = {"critical": (232, 104, 108), "high": (232, 134, 79), "medium": (224, 179, 65),
            "low": (79, 143, 247), "info": (111, 129, 151)}


def _shots_dir(run_dir: Path) -> Path:
    d = run_dir / "screenshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _playwright_png(url: str, out: Path) -> bool:
    """Реальный скриншот страницы. Включается VIBESEC_SCREENSHOTS=real."""
    if os.getenv("VIBESEC_SCREENSHOTS") != "real" or not url.startswith("http"):
        return False
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            page.screenshot(path=str(out), full_page=False)
            browser.close()
        return True
    except Exception:
        return False


def _placeholder_png(title: str, subtitle: str, lines: list[str],
                     color: tuple[int, int, int], out: Path) -> bool:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return False
    W, H = 1000, 560
    img = Image.new("RGB", (W, H), (10, 20, 32))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 78], fill=(18, 34, 52))
    d.rectangle([0, 78, 10, H], fill=color)

    fpath, fbold = unicode_font(), unicode_font_bold()
    have_ttf = bool(fpath)
    f_big = ImageFont.truetype(fbold, 30) if fbold else ImageFont.load_default()
    f_med = ImageFont.truetype(fpath, 22) if fpath else ImageFont.load_default()
    f_sm = ImageFont.truetype(fpath, 18) if fpath else ImageFont.load_default()

    d.text((28, 24), "VibeSec · Evidence", font=f_big, fill=(232, 238, 246))
    if have_ttf:
        d.text((40, 110), title[:70], font=f_med, fill=(232, 238, 246))
    d.text((40, 150), subtitle[:90], font=f_sm, fill=(159, 176, 199))
    y = 210
    for ln in lines:
        d.text((40, y), ln[:95], font=f_sm, fill=(143, 208, 200))
        y += 34
    note = "Автоматический скриншот PoC" if have_ttf else "Automated PoC screenshot (demo placeholder)"
    d.text((40, H - 50), f"{note} · {time.strftime('%Y-%m-%d %H:%M')}", font=f_sm, fill=(111, 129, 151))
    img.save(out)
    return True


def _placeholder_svg(title: str, subtitle: str, lines: list[str], color: str, out: Path) -> None:
    rows = "".join(
        f'<text x="40" y="{210 + i*34}" font-size="18" fill="#8fd0c8" '
        f'font-family="monospace">{html.escape(l[:95])}</text>'
        for i, l in enumerate(lines)
    )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="560" viewBox="0 0 1000 560">
<rect width="1000" height="560" fill="#0a1420"/>
<rect width="1000" height="78" fill="#122234"/>
<rect width="10" height="560" y="78" fill="{color}"/>
<text x="28" y="50" font-size="30" font-weight="700" fill="#e8eef6" font-family="sans-serif">VibeSec · Evidence</text>
<text x="40" y="124" font-size="22" fill="#e8eef6" font-family="sans-serif">{html.escape(title[:70])}</text>
<text x="40" y="156" font-size="18" fill="#9fb0c7" font-family="sans-serif">{html.escape(subtitle[:90])}</text>
{rows}
<text x="40" y="520" font-size="16" fill="#6f8197" font-family="monospace">Автоматический скриншот PoC · {time.strftime('%Y-%m-%d %H:%M')}</text>
</svg>'''
    out.write_text(svg, encoding="utf-8")


def capture(name: str, title: str, subtitle: str, lines: list[str],
            sev_label: str, url: str, run_dir: Path) -> str:
    """Сделать скриншот. Вернуть относительный путь (screenshots/<name>.<ext>)."""
    shots = _shots_dir(run_dir)
    rgb = _SEV_RGB.get(sev_label, _SEV_RGB["info"])
    png = shots / f"{name}.png"

    if _playwright_png(url, png) or _placeholder_png(title, subtitle, lines, rgb, png):
        return f"screenshots/{png.name}"

    hexcol = "#%02x%02x%02x" % rgb
    svg = shots / f"{name}.svg"
    _placeholder_svg(title, subtitle, lines, hexcol, svg)
    return f"screenshots/{svg.name}"
