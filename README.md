# VibeSec

Linux-платформа автоматизированного **этичного** тестирования безопасности: поиск,
подтверждение и документирование уязвимостей в рамках официальных bug bounty
программ и собственных/разрешённых проектов (включая приложения, собранные
AI-генераторами кода).

> ⚠️ Только авторизованные цели. Перед каждым запуском пользователь обязан
> подтвердить право на тестирование. Все проверки выполняются в **неразрушающем**
> режиме; деструктивные опции инструментов заблокированы политикой безопасности.

## Как работает

1. Пользователь выбирает модуль на главном экране (большие карточки).
2. Указывает цель и подтверждает scope.
3. Жмёт «Запустить» — дальше всё автономно.
4. В реальном времени — живой вывод инструментов (subprocess → WebSocket → терминал),
   прогресс по этапам и **живая панель находок**.
5. После завершения платформа собирает отчёт формата HackerOne с возможностью скачать.

## Модули

| Модуль | Назначение | Классы |
|--------|-----------|--------|
| **Recon Sweep** · Быстрая разведка | Поддомены, живые хосты, порты, технологии | — |
| **Attack Surface Mapping** · Поверхность атаки | Обход контента, параметры, скрытые пути | — |
| **Vulnerability Hunt** · Охота на уязвимости | Активный поиск + валидация + отчёт | IDOR, XSS, SQLi, SSRF, BAC |
| **Vibe-Code Exploit Hunt** · Охота в AI-коде | Секреты, debug-эндпоинты, дефолтные креды | InfoDisclosure, AuthBypass, Misconfig |
| **Full Kill Chain** · Полный цикл | Разведка → поверхность → охота → AI-код → валидация → отчёт | все |
| **Report Builder** · Сборка отчёта | Подтверждённые находки → отчёт HackerOne | — |

## Архитектура

```
GUI ──WS──▶ Orchestrator ──▶ фазы: Recon → Surface → Hunt → Validate → Report
                │                        │        │        │          │
                │                     parsers/ ──▶ FindingStore (reports/<run>/findings.json)
                ├─ ScopeGuard      — проверяет цель (и найденные хосты) перед активными тулами
                ├─ SafetyPolicy    — safe-mode профили + deny-лист деструктивных опций
                └─ runner          — subprocess + live-streaming (SIGTERM всей process group)
```

- **`core/orchestrator.py`** — фазы, агенты, слой находок, трансляция событий.
- **`core/runner.py`** — запуск инструмента, построчный стриминг, остановка; демо-режим без тулов.
- **`core/scope.py`** / **`core/safety.py`** — барьер scope и запрет деструктива.
- **`core/validate.py`** / **`core/poc.py`** — неразрушающее подтверждение и генерация PoC.
- **`agents/*.py`** — агенты (recon, surface, hunt, exposure, finalize, report); агент = набор шагов.
- **`parsers/*.py`** — нормализаторы вывода nuclei/dalfox/sqlmap/ffuf в структурные находки.
- **`report/compiler.py`** — сборка отчёта HackerOne (Markdown + JSON).
- **`modules/registry.py`** — связь карточек GUI с пайплайнами агентов.

Если инструмент не установлен, шаг показывает демо-вывод и демо-находки — каркас
работает «из коробки», реальные инструменты подключаются по мере установки.

## Структура находки → отчёт HackerOne

`Finding` (см. `findings/model.py`) ложится в секции отчёта один-в-один:
`title → Title`, `severity → Severity (CVSS)`, `description → Description`,
`steps → Steps to Reproduce`, `impact → Impact`, `poc → Proof of Concept`,
`remediation → Remediation`; плюс evidence, класс и инструмент.

## Запуск (Linux)

```bash
./run.sh
# открой http://127.0.0.1:8787
```

Вручную:

```bash
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8787
```

Инструменты (опционально, для реальных данных): subfinder, dnsx, httpx, naabu,
katana, gau, arjun, ffuf, nuclei, dalfox, sqlmap, gitleaks, osv-scanner.

## API

- `GET /api/modules` — список модулей для карточек.
- `GET /api/report/{run_id}?format=md|json` — скачать готовый отчёт.
- `WS /ws/run` — живой запуск.

Протокол WebSocket:

```jsonc
// клиент → сервер
{"action": "start", "module": "vuln_hunt", "target": "example.com", "scope_confirmed": true}
{"action": "stop"}

// сервер → клиент (поток событий)
{"type": "status",   "state": "running|stopped|done", "message": "..."}
{"type": "stage",    "index": 0, "name": "...", "state": "start|done", "total": 8}
{"type": "log",      "stage": "...", "stream": "stdout|stderr|system", "line": "..."}
{"type": "progress", "value": 42}
{"type": "finding",  "finding": { /* структура Finding */ }}
{"type": "report",   "run_id": "...", "summary": "...", "formats": ["md","json"], "preview": "..."}
{"type": "done",     "summary": "..."}
{"type": "error",    "message": "..."}
```

## Безопасность

- **Scope-барьер**: без подтверждения разрешения запуск блокируется; цель нормализуется.
- **SafetyPolicy**: sqlmap с низким risk/level без опций записи/выполнения, nuclei без
  dos/intrusive, dalfox в режиме детекта; деструктивные флаги в hard-deny (`core/safety.py`).
- **Safe validation**: подтверждение находок без эксплуатации.
- **Kill switch**: остановка в любой момент (SIGTERM всей process group).

## Статус

Рабочий каркас: backend-пайплайн находок (parsers → validate → PoC → report),
охотничьи модули, функциональный фронтенд с живой панелью находок и скачиванием
отчёта. Дальше: полноценный GUI (SvelteKit/Tauri) по прототипу, реальные обёртки
инструментов и парсеры под их фактический вывод, постоянный allowlist scope, экспорт в PDF.
