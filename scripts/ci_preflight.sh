#!/usr/bin/env bash
# Fails fast with a readable message if the tree is incomplete.
set -uo pipefail

fail=0

need_file() {
  if [ -f "$1" ]; then printf '  ok     %s\n' "$1"
  else printf '  MISSING %s\n' "$1"; fail=1; fi
}

need_exec() {
  if [ -x "$1" ]; then printf '  ok+x   %s\n' "$1"
  elif [ -f "$1" ]; then printf '  NOT+X  %s  (run: chmod +x %s)\n' "$1" "$1"; fail=1
  else printf '  MISSING %s\n' "$1"; fail=1; fi
}

echo "== engine =="
need_file v6.py
need_file v6_offline.py
need_file verify.py

echo "== launcher =="
need_exec ops/runbook.sh
need_exec ops/gates.sh
need_exec ops/log.sh
need_file ops/RUNBOOK.md

echo "== config =="
need_file .env.example
need_file requirements.txt
need_file requirements-dev.txt
need_file AUTHORIZATION.md

echo "== tests =="
need_file tests/test_boundary.py
need_file tests/test_hashes.py
need_file tests/test_rules.py

echo "== docs =="
for f in README.md LICENSE docs/ARCHITECTURE.md docs/SAFETY.md \
         docs/CHECKS.md docs/DEPENDENCIES.md; do
  need_file "$f"
done

echo "== cases =="
need_file cases/_template/README.md
need_file cases/_template/target.json
need_file cases/_template/notes.md

echo "== python syntax =="
for f in v6.py v6_offline.py verify.py; do
  [ -f "$f" ] || continue
  if python -m py_compile "$f"; then printf '  ok     %s compiles\n' "$f"
  else printf '  BROKEN %s\n' "$f"; fail=1; fi
done

echo "== shell syntax =="
for f in ops/*.sh scripts/*.sh; do
  [ -f "$f" ] || continue
  if bash -n "$f"; then printf '  ok     %s parses\n' "$f"
  else printf '  BROKEN %s\n' "$f"; fail=1; fi
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "PREFLIGHT FAILED — commit the missing files (git add -A), or run scripts/install.sh"
  exit 1
fi

echo
echo "preflight ok"
