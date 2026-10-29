"""Тесты парсеров на фактическом выводе инструментов (фикстуры)."""
from pathlib import Path

from app.parsers import nuclei, dalfox, ffuf, sqlmap

FIX = Path(__file__).parent / "fixtures"
T = "demo.example.com"


def _lines(name: str) -> list[str]:
    return (FIX / name).read_text(encoding="utf-8").splitlines()


def test_nuclei():
    f = nuclei.parse(_lines("nuclei.jsonl"), T)
    assert len(f) == 2
    cors = next(x for x in f if "CORS" in x.title)
    assert cors.severity.label == "medium" and cors.severity.score == 6.5
    assert cors.vuln_class == "Misconfig"
    xss = next(x for x in f if x.vuln_class == "XSS")
    assert xss.severity.score == 7.4 and xss.severity.vector.startswith("CVSS:3.1")
    assert xss.endpoint.endswith("/search?q=")
    assert all(x.tool == "nuclei" for x in f)


def test_dalfox():
    f = dalfox.parse(_lines("dalfox.json"), T)
    assert len(f) == 1
    x = f[0]
    assert x.vuln_class == "XSS" and x.confidence == "firm"  # type "V" → verified
    assert "q" in x.title and x.severity.label == "high"
    assert x.endpoint.startswith("https://demo.example.com/search")


def test_ffuf():
    f = ffuf.parse(_lines("ffuf.json"), T)
    # /admin и /.git/config — чувствительные; /about пропущен
    assert len(f) == 2
    urls = {x.endpoint for x in f}
    assert any("/admin" in u for u in urls)
    assert any("/.git/config" in u for u in urls)
    assert all("about" not in x.endpoint for x in f)


def test_sqlmap():
    f = sqlmap.parse(_lines("sqlmap.txt"), T)
    assert len(f) == 1
    x = f[0]
    assert x.vuln_class == "SQLi" and x.severity.label == "critical"
    assert "id" in x.title and "GET" in x.title
    assert any("MySQL" in e for e in x.evidence)
    assert any("boolean-based" in e or "SLEEP" in e for e in x.evidence)


def test_empty_inputs():
    assert nuclei.parse([], T) == []
    assert dalfox.parse(["not json"], T) == []
    assert ffuf.parse(["garbage"], T) == []
    assert sqlmap.parse(["nothing here"], T) == []
