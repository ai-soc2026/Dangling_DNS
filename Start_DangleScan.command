#!/bin/zsh
set -e
cd "$(dirname "$0")"
[[ -x .venv/bin/python ]] || python3 -m venv .venv
runtime="$PWD/.venv/bin/python"
"$runtime" -m pip install -r requirements.txt
"$runtime" -m playwright install chromium
if lsof -tiTCP:8000 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port 8000 is in use. Stop the existing DangleScan backend, then run this launcher again."
  read "reply?Press Enter to close."
  exit 1
fi
frontend_pid=""
if ! lsof -tiTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; then
  "$runtime" -m http.server 3000 --bind 127.0.0.1 &
  frontend_pid=$!
fi
trap '[[ -z "$frontend_pid" ]] || kill "$frontend_pid" 2>/dev/null || true' EXIT
printf '%s\n' 'DangleScan: http://127.0.0.1:3000/index.html?api=http%3A%2F%2F127.0.0.1%3A8000' 'Keep this Terminal open. Press Ctrl+C to stop.'
"$runtime" -m uvicorn main:app --host 127.0.0.1 --port 8000
