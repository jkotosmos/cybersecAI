"""Структура находки и хранилище находок запуска.

Поля Finding спроектированы так, чтобы один-в-один лечь в отчёт HackerOne
(Title / Severity / Description / Steps / Impact / PoC / Remediation).
FindingStore пишет findings.json в reports/<run_id>/ по мере накопления.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Severity:
    label: str = "info"      # critical | high | medium | low | info
    score: float = 0.0       # CVSS 0..10
    vector: str = ""         # CVSS-вектор


@dataclass
class PoC:
    curl: str = ""
    browser_steps: list[str] = field(default_factory=list)
    script: str = ""


@dataclass
class Finding:
    vuln_class: str                              # IDOR | XSS | SQLi | SSRF | BAC | AuthBypass | InfoDisclosure | Misconfig
    title: str
    endpoint: str = ""
    target: str = ""
    description: str = ""
    steps: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    screenshot: str = ""                         # относительный путь к скриншоту-доказательству
    severity: Severity = field(default_factory=Severity)
    poc: PoC = field(default_factory=PoC)
    tool: str = ""
    confidence: str = "tentative"                # tentative | firm
    status: str = "candidate"                    # candidate | validated | false_positive
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=lambda: round(time.time(), 3))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        sev = d.pop("severity", None)
        poc = d.pop("poc", None)
        f = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__ and k not in ("severity", "poc")})
        if isinstance(sev, dict):
            f.severity = Severity(**{k: v for k, v in sev.items() if k in Severity.__dataclass_fields__})
        if isinstance(poc, dict):
            f.poc = PoC(**{k: v for k, v in poc.items() if k in PoC.__dataclass_fields__})
        return f


class FindingStore:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[Finding] = []
        self.tasks: list[dict] = []   # шаги-сценарии (регистрация/вход) с evidence

    def add_task(self, name: str, screenshot: str = "", note: str = "") -> None:
        self.tasks.append({"name": name, "screenshot": screenshot, "note": note})

    @property
    def run_id(self) -> str:
        return self.run_dir.name

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        self._flush()

    def update(self, f: Finding) -> None:
        self._flush()

    def update_all(self) -> None:
        self._flush()

    def validated(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "validated"]

    def by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity.label, 0), reverse=True)

    def _flush(self) -> None:
        data = [f.to_dict() for f in self.findings]
        (self.run_dir / "findings.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @staticmethod
    def load_latest_for(reports_dir: Path, target: str) -> list[Finding]:
        """Найти самый свежий findings.json с находками по данной цели."""
        best: list[Finding] = []
        best_ts = -1.0
        for fjson in reports_dir.glob("*/findings.json"):
            try:
                items = json.loads(fjson.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            matched = [Finding.from_dict(x) for x in items if x.get("target") == target]
            if matched:
                mtime = fjson.stat().st_mtime
                if mtime > best_ts:
                    best_ts, best = mtime, matched
        return best
