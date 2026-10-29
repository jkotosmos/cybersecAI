"""Проверка реального Playwright-пути: локальное dev-приложение с формами
регистрации/входа, по нему гоняются screenshot.capture и flows.account.

Запуск:  ./.venv/Scripts/python.exe -m tests.verify_playwright
Нужен установленный chromium (playwright install chromium).
"""
from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ["VIBESEC_SCREENSHOTS"] = "real"
os.environ["VIBESEC_BROWSER"] = "real"

REGISTER = b"""<!doctype html><html><head><meta charset=utf-8><title>Register</title></head>
<body style="font-family:sans-serif;background:#0a1420;color:#e8eef6;padding:40px">
<h1>VibeSec Test App - Register</h1>
<form method=post action=/register>
  <input name=username placeholder=username><br><br>
  <input type=password name=password placeholder=password><br><br>
  <input type=password name=confirm placeholder=confirm><br><br>
  <button type=submit>Sign up</button>
</form></body></html>"""

LOGIN = b"""<!doctype html><html><head><meta charset=utf-8><title>Login</title></head>
<body style="font-family:sans-serif;background:#0a1420;color:#e8eef6;padding:40px">
<h1>VibeSec Test App - Login</h1>
<form method=post action=/login>
  <input name=username placeholder=username><br><br>
  <input type=password name=password placeholder=password><br><br>
  <button type=submit>Log in</button>
</form></body></html>"""

DASH = b"""<!doctype html><html><head><meta charset=utf-8><title>Dashboard</title></head>
<body style="font-family:sans-serif;background:#0a1420;color:#8fd0c8;padding:40px">
<h1>Welcome - session established</h1></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # тихо
        pass

    def _send(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=test-abc; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(REGISTER if self.path.startswith("/register") else
                   LOGIN if self.path.startswith("/login") else DASH)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(DASH)


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = f"127.0.0.1:{port}"
    base = f"http://{target}"
    print(f"тестовое приложение на {base}")

    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.evidence import screenshot
    from app.flows import account

    run_dir = Path(__file__).parent / "_verify_out"
    run_dir.mkdir(exist_ok=True)
    creds = {"username": "vibesec_tester", "password": "Sfx9_test_pw"}

    ok = True

    # 1) реальный скриншот страницы
    rel = screenshot.capture(
        name="verify-shot", title="t", subtitle=base, lines=["x"],
        sev_label="info", url=f"{base}/register", run_dir=run_dir)
    p = run_dir / rel
    is_png = rel.endswith(".png") and p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    print(f"[{'OK' if is_png else 'FAIL'}] screenshot.capture → {rel} ({p.stat().st_size} байт, PNG={is_png})")
    ok &= is_png

    # 2) регистрация реальным браузером
    log, shot = account.register(target, creds, run_dir)
    real_reg = any("реальный скриншот" in m for _, m in log)
    sp = run_dir / shot
    reg_png = sp.exists() and sp.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    print(f"[{'OK' if real_reg and reg_png else 'FAIL'}] register → {shot} (браузер={real_reg}, PNG={reg_png})")
    for lvl, m in log:
        print(f"      [{lvl}] {m}")
    ok &= real_reg and reg_png

    # 3) вход реальным браузером
    log2, shot2 = account.login(target, creds, run_dir)
    real_login = any("реальный скриншот" in m for _, m in log2)
    sp2 = run_dir / shot2
    login_png = sp2.exists() and sp2.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    cookies = any("cookie-сессий" in m for _, m in log2)
    print(f"[{'OK' if real_login and login_png else 'FAIL'}] login → {shot2} (браузер={real_login}, cookies={cookies}, PNG={login_png})")
    ok &= real_login and login_png

    srv.shutdown()
    print("\nИТОГ:", "ВСЁ РАБОТАЕТ (реальный Playwright)" if ok else "ЕСТЬ ОШИБКИ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
