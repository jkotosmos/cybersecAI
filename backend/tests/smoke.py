"""Сквозной тест платформы (включая авторизацию, скриншоты, PDF/HTML)."""
import os
os.environ["VIBESEC_DEMO_DELAY"] = "0"

from fastapi.testclient import TestClient
from app.main import app

c = TestClient(app)

mods = c.get("/api/modules").json()
print("modules:", [m["id"] for m in mods])

def run(module, creds=None):
    msg = {"action": "start", "module": module, "target": "demo.vibesec.local", "scope_confirmed": True}
    if creds:
        msg["credentials"] = creds
    evs = []
    with c.websocket_connect("/ws/run") as ws:
        ws.send_json(msg)
        while True:
            ev = ws.receive_json()
            evs.append(ev)
            if ev["type"] == "status" and ev["state"] in ("done", "stopped", "error"):
                break
    return evs

# Authenticated Hunt: задачи-сценарии + находки + скриншоты + отчёт
evs = run("auth_hunt", {"username": "redteam_qa"})
finds = {e["finding"]["id"]: e["finding"] for e in evs if e["type"] == "finding"}
with_shot = [f for f in finds.values() if f.get("screenshot_url")]
rep = [e for e in evs if e["type"] == "report"][0]
print("auth_hunt: findings=%d, со скриншотом=%d" % (len(finds), len(with_shot)))
print("report formats:", rep["formats"], "| summary:", rep["summary"])

rid = rep["run_id"]
for fmt in rep["formats"]:
    rr = c.get(f"/api/report/{rid}?format={fmt}")
    print(f"  GET report {fmt}: {rr.status_code}, {len(rr.content)} bytes, ct={rr.headers.get('content-type')}")
    assert rr.status_code == 200

# скриншот-доказательство через API
if with_shot:
    url = with_shot[0]["screenshot_url"]
    sr = c.get(url)
    print("  GET", url, "->", sr.status_code, len(sr.content), "bytes")
    assert sr.status_code == 200

# PDF действительно PDF?
pdf = c.get(f"/api/report/{rid}?format=pdf")
if pdf.status_code == 200:
    print("  PDF начинается с %%PDF:", pdf.content[:5] == b"%PDF-")

# задачи-сценарии в json-отчёте
import json
jr = json.loads(c.get(f"/api/report/{rid}?format=json").content)
print("  tasks в отчёте:", [t["name"] for t in jr.get("tasks", [])])

# Red Team Sim — большой пайплайн
evs2 = run("redteam")
rep2 = [e for e in evs2 if e["type"] == "report"][0]
print("redteam:", rep2["summary"], "| formats:", rep2["formats"])

print("OK: расширенный сквозной тест пройден")
