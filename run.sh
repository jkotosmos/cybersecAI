#!/usr/bin/env bash
# VibeSec — запуск dev-сервера (Linux).
# Поднимает FastAPI backend и отдаёт статический фронтенд на том же порту.
set -euo pipefail

cd "$(dirname "$0")/backend"

if [ ! -d ".venv" ]; then
  echo "[vibesec] создаю виртуальное окружение…"
  python3.12 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[vibesec] устанавливаю зависимости…"
pip install -q -r requirements.txt

HOST="${VIBESEC_HOST:-127.0.0.1}"
PORT="${VIBESEC_PORT:-8787}"
echo "[vibesec] открой http://${HOST}:${PORT}"
exec uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
