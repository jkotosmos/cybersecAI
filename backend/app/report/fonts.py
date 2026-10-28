"""Поиск Unicode-шрифта (с кириллицей) для PDF и скриншотов-плейсхолдеров."""
from __future__ import annotations

import os
from pathlib import Path

_CANDIDATES = [
    os.getenv("VIBESEC_FONT", ""),
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/Library/Fonts/Arial.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "C:/Windows/Fonts/segoeui.ttf",
]

_BOLD_CANDIDATES = [
    os.getenv("VIBESEC_FONT_BOLD", ""),
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/Library/Fonts/Arial Bold.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
    "C:/Windows/Fonts/segoeuib.ttf",
]


def _first(paths: list[str]) -> str | None:
    for p in paths:
        if p and Path(p).exists():
            return p
    return None


def unicode_font() -> str | None:
    """Путь к обычному Unicode-TTF или None."""
    return _first(_CANDIDATES)


def unicode_font_bold() -> str | None:
    return _first(_BOLD_CANDIDATES) or unicode_font()
