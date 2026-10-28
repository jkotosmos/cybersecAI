"""Агент быстрой разведки: поддомены, живые хосты, порты, технологии."""
from __future__ import annotations

from app.agents.base import Agent, Step

agent = Agent(
    id="recon",
    title="Разведка",
    steps=[
        Step(
            name="Сбор поддоменов",
            argv=["subfinder", "-silent", "-d", "{target}"],
            demo_lines=["api.{target}", "dev.{target}", "staging.{target}",
                        "[+] найдено 14 поддоменов"],
        ),
        Step(
            name="Проверка живых хостов",
            argv=["httpx", "-silent", "-status-code", "-u", "{target}"],
            demo_lines=["200  https://{target}  [nginx]",
                        "200  https://api.{target}  [cloudflare]",
                        "403  https://dev.{target}",
                        "[+] живых хостов: 9"],
        ),
        Step(
            name="Скан портов",
            argv=["naabu", "-silent", "-host", "{target}"],
            demo_lines=["{target}:443", "{target}:80", "{target}:8080",
                        "[+] открытых портов: 3"],
        ),
        Step(
            name="Снятие отпечатков",
            argv=["httpx", "-silent", "-tech-detect", "-u", "{target}"],
            demo_lines=["{target} [nginx 1.24, React, Cloudflare]",
                        "[+] стек определён"],
        ),
    ],
)
