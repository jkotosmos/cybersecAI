"""Агент активной охоты на уязвимости (безопасные профили инструментов).

Все инструменты вызываются в неразрушающем режиме: sqlmap с низким risk/level
и без опций записи/выполнения, nuclei с исключением dos/intrusive-шаблонов,
dalfox в режиме детекта. Вывод парсится в структурные находки.
"""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="hunt",
    title="Охота на уязвимости",
    steps=[
        Step(
            name="Nuclei: CVE и misconfig",
            argv=["nuclei", "-silent", "-jsonl", "-etags", "dos,intrusive,fuzz", "-u", "{target}"],
            parser="nuclei",
            demo_lines=["[medium] cors-misconfig", "[low] exposed-version-header",
                        "[+] выполнено 340 шаблонов"],
            demo_findings=[{
                "vuln_class": "Misconfig", "title": "Небезопасная политика CORS",
                "endpoint": "https://{target}/api", "target": "{target}", "tool": "nuclei",
                "description": "Заголовок Access-Control-Allow-Origin отражает Origin и допускает credentials.",
                "severity": {"label": "medium", "score": 6.5},
                "evidence": ["Access-Control-Allow-Origin: <reflected>", "Access-Control-Allow-Credentials: true"],
            }],
        ),
        Step(
            name="Dalfox: XSS",
            argv=["dalfox", "url", "{target}", "--format", "json", "--silence"],
            parser="dalfox",
            demo_lines=["[POC] reflected on param q", "[+] XSS verification done"],
            demo_findings=[{
                "vuln_class": "XSS", "title": "Reflected XSS в параметре q",
                "endpoint": "https://{target}/search?q=", "target": "{target}", "tool": "dalfox",
                "description": "Значение параметра q отражается в HTML без экранирования.",
                "severity": {"label": "high", "score": 7.4,
                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
                "evidence": ["q=\"><svg onload=... (демо-индикатор отражения)"],
            }],
        ),
        Step(
            name="SQLi (безопасный профиль)",
            argv=["sqlmap", "-u", "{target}", "--batch", "--level", "1", "--risk", "1",
                  "--technique", "BT", "--smart", "--flush-session"],
            parser="sqlmap",
            demo_lines=["[INFO] testing parameter 'id'", "[+] parameter 'id' is injectable (boolean-based)"],
            demo_findings=[{
                "vuln_class": "SQLi", "title": "SQL-инъекция в параметре id",
                "endpoint": "https://{target}/item?id=", "target": "{target}", "tool": "sqlmap",
                "description": "Параметр id уязвим к boolean-based SQL-инъекции (детект без эксплуатации).",
                "severity": {"label": "critical", "score": 9.8,
                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                "evidence": ["parameter 'id' is injectable (boolean-based blind)"],
            }],
        ),
        Step(
            name="Контент и доступ (IDOR/BAC)",
            argv=["ffuf", "-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt",
                  "-mc", "200,301,302,401,403", "-of", "json", "-o", "-", "-s"],
            parser="ffuf",
            demo_lines=["200  /admin", "200  /api/v1/users/1001", "[+] найдено 6 путей"],
            demo_findings=[{
                "vuln_class": "IDOR", "title": "IDOR: доступ к чужому объекту пользователя",
                "endpoint": "https://{target}/api/v1/users/1001", "target": "{target}", "tool": "vibesec-bac",
                "description": "Смена числового id в /api/v1/users/{id} возвращает данные другого пользователя без проверки владения.",
                "severity": {"label": "high", "score": 8.1,
                             "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"},
                "evidence": ["GET /api/v1/users/1001 → 200 с данными чужого аккаунта"],
            }],
        ),
    ],
)
