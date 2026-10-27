#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"

printf '== venv ==\n'
[ -d .venv ] || "$PY" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel

printf '== requirements ==\n'
pip install -r requirements.txt

printf '== dev extras (optional) ==\n'
pip install -r requirements-dev.txt || printf '  (dev extras partially failed, continuing)\n'

printf '== env ==\n'
if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  printf '  created .env, chmod 600\n'
else
  chmod 600 .env
  printf '  .env exists\n'
fi

printf '== logs dir ==\n'
mkdir -p logs
[ -f logs/.gitkeep ] || touch logs/.gitkeep

printf '== exec bits ==\n'
chmod +x ops/*.sh scripts/*.sh 2>/dev/null || true

printf '\n== verify ==\n'
python verify.py

cat <<'EOF'

done.

  source .venv/bin/activate
  ./ops/runbook.sh selftest
  ./ops/runbook.sh plan

EOF
