# v6-framework

> Multi-chain EVM vulnerability scanner with a gated, authorization-bound live execution launcher.

**[Quickstart](#quickstart) · [Safety](#safety) · [Checks](#checks) · [Layout](#layout) · [Runbook](ops/RUNBOOK.md)**

## What it is

Scans newly deployed DeFi pools across eight EVM chains, scores them against
15 vulnerability classes, and — only when you explicitly say so — fires a
bounded number of real transactions at a target you chose by hand.

The scanner thinks. The launcher decides. They are separate on purpose.

## Quickstart

```bash
git clone <repo> && cd v6-framework
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python verify.py          # dependency check
python v6.py --self-test  # offline correctness check
python v6_offline.py --seed 1337   # full pipeline on random data, no RPC
```

No packages at all? `v6_offline.py` runs on a bare interpreter.

## Safety

Live mode is never a casual flag. It requires:

| Gate | Value |
|---|---|
| `AUTHORIZED` | `yes` |
| `AUTH_FILE` | `AUTHORIZATION.md` |
| `CONFIRM_LIVE` | `I_UNDERSTAND` |
| `LIVE_CHAIN` / `LIVE_TARGET` | one chain, one contract |
| `MAX_TXS` | small |

One chain. One target. One log file. Burner wallet. See [SAFETY.md](docs/SAFETY.md).

## Checks

| Class | Severity | Detection |
|---|---|---|
| Reentrancy | CRITICAL | call-before-store, function-scoped, guard-aware |
| Access control | CRITICAL | naked privileged fn + differential on-chain probe |
| Uninitialized proxy | CRITICAL | initialize() without initializer guard |
| Broken proxy | CRITICAL | EIP-1967 impl slot pointing at empty code |
| Oracle manipulation | HIGH | spot reserves without TWAP/Chainlink |
| DELEGATECALL | HIGH | unguarded delegatecall surface |
| Integer overflow | HIGH | pre-0.8 arithmetic without SafeMath |
| Flash-loan callback | HIGH | missing caller verification |
| + 7 more | — | see [CHECKS.md](docs/CHECKS.md) |

## Layout

```
v6.py           engine — pure mechanism, no opinions
ops/            launcher — all policy, gates, prompts, logs
docs/           architecture, safety, checks
cases/          one folder per engagement
tests/          boundary tests + hash tests + rule tests
```

The engine never reads `.env`, never prompts, never writes logs, never imports
from `ops/`. `tests/test_boundary.py` enforces it.

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Safety model](docs/SAFETY.md)
- [Checks reference](docs/CHECKS.md)
- [Dependencies](docs/DEPENDENCIES.md)
- [Live runbook](ops/RUNBOOK.md)

## License

MIT — see [LICENSE](LICENSE).
