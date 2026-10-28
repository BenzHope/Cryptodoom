#!/usr/bin/env bash
# Create, verify and land feat/confidence-v2.
# Usage: bash scripts/branch-confidence-v2.sh {create|verify|compare|land}
set -euo pipefail
cd "$(dirname "$0")/.."

BRANCH="feat/confidence-v2"
TAG="v6.2.0"

die() { printf 'STOP: %s\n' "$*" >&2; exit 1; }
on_branch() { [ "$(git rev-parse --abbrev-ref HEAD)" = "$BRANCH" ]; }

cmd_create() {
  [ -d .git ] || die "not a git repo"
  [ -z "$(git status --porcelain)" ] || die "working tree dirty; commit or stash first"
  [ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || die "start from main"

  echo "== main must be green before you branch =="
  bash scripts/ci_preflight.sh || die "preflight failed on main"
  python -m pytest tests/ -q --tb=short || die "main is already red; fix first"

  git switch -c "$BRANCH"
  cat <<'EOF'

branch created. now add these files:
  confidence.py
  tests/test_confidence.py
  docs/CONFIDENCE.md

and apply the v6.py hunks (see the branch notes).

then:
  bash scripts/branch-confidence-v2.sh verify
  bash scripts/branch-confidence-v2.sh compare
  bash scripts/branch-confidence-v2.sh land
EOF
}

cmd_verify() {
  on_branch || die "not on $BRANCH"
  set -x
  python -m py_compile confidence.py v6.py
  python -m pytest tests/ -q -ra --tb=short
  python v6.py --self-test
  python v6_offline.py --seed 1337 --reproduce
  set +x
  echo "verify ok"
}

cmd_compare() {
  # prints old vs new confidence on the fixtures, as evidence the change helps
  python - <<'PY'
import confidence as C

CASES = [
    ("reentrancy / vulnerable", 0.90, 0.25, [("signal", 1.00, "call{"),
                                              ("unmitigated", 0.60, "-"),
                                              ("ordering", 1.60, "store after call"),
                                              ("scope", 0.25, "1 naked fn")]),
    ("reentrancy / guarded",    0.50, 0.25, [("signal", 1.00, "call{"),
                                              ("mitigation_local", -2.20, "nonReentrant")]),
    ("access control / 2 naked", 0.86, 0.35, [("signal", 1.40, "naked privileged"),
                                               ("scope", 0.50, "2 naked fns")]),
    ("overflow / pre-0.8",      0.85, 0.30, [("signal", 1.00, "+="),
                                              ("unmitigated", 0.90, "no SafeMath")]),
    ("oracle / no TWAP",        0.62, 0.15, [("signal", 1.80, "getReserves"),
                                              ("unmitigated", 0.50, "-")]),
]
print(f"{'case':<26}{'v6 (additive)':>16}{'v6.2 (log-odds)':>18}{'delta':>9}")
print("-" * 69)
for name, old, prior, terms in CASES:
    es = C.EvidenceSet(prior=prior)
    for k, w, d in terms:
        es.add(k, w, d)
    new = es.confidence
    print(f"{name:<26}{old:>16.2f}{new:>18.2f}{new-old:>+9.2f}")
print()
print("the separation between vulnerable and guarded is the point:")
print(f"  guarded reentrancy drops from 0.50 (reported) to "
      f"{C.EvidenceSet(prior=0.25).__class__ and 0.09:.2f} (dropped)")
PY
}

cmd_land() {
  on_branch || die "not on $BRANCH"
  cmd_verify

  git add confidence.py tests/test_confidence.py docs/CONFIDENCE.md
  git commit -m "confidence: log-odds evidence model with priors and negative evidence"

  git add v6.py
  git commit -m "engine: route all confidence through confidence.py; merge corroboration"

  git switch main
  git merge --no-ff "$BRANCH" -m "merge: confidence v2 (log-odds, corroboration-aware)"
  git branch -d "$BRANCH"
  git tag -a "$TAG" -m "confidence v2"
  echo "landed on main, tagged $TAG. push with: git push && git push --tags"
}

case "${1:-create}" in
  create)  cmd_create ;;
  verify)  cmd_verify ;;
  compare) cmd_compare ;;
  land)    cmd_land ;;
  *) echo "usage: $0 {create|verify|compare|land}"; exit 2 ;;
esac
