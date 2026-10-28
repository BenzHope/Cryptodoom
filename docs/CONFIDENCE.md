# Confidence model

## Why it changed

v6.0 scored by addition:

```
base 0.45 + 0.10/signal + 0.25/unmitigated + 0.15/scoped + 0.15/ordered, cap 0.95
```

Three problems:

1. **No negative evidence.** A `nonReentrant` guard did not subtract; it merely
   failed to add. So a guarded vault scored 0.50 and was reported.
2. **Breadth over specificity.** `.transfer(` — present in almost every contract
   — counted the same as `call{value:`.
3. **No cross-detector agreement.** Source, bytecode and on-chain findings were
   separate entries with unrelated hardcoded scores.

## What it is now

```
confidence = sigmoid( prior_logit + sum(evidence_logits) )
```

Signed log-odds. Naturally bounded, naturally diminishing. A mitigation
subtracts. A contradicted on-chain probe subtracts. Independent corroboration
adds, and absorbs the corroborating finding.

## Evidence kinds

| Kind | Sign | Example |
|---|---|---|
| `signal` | + | `call{`, `getReserves(`, `tx.origin` |
| `ordering` | + | state write observed after the external call |
| `scope` | + | number of unguarded functions, capped at 3 |
| `unmitigated` | + | nothing anywhere mitigates |
| `corroboration` | + | an independent detector agrees |
| `mitigation_local` | − | `nonReentrant` on the offending function |
| `mitigation_file` | − | `ReentrancyGuard` inherited, `SafeMath` imported |
| `contradiction` | − | on-chain probe says the function is protected |

## Calibration

| Case | v6.0 | v6.2 |
|---|---|---|
| reentrancy, vulnerable | 0.90 | 0.91 |
| reentrancy, guarded | 0.50 | 0.09 |
| access control, 2 naked fns | 0.86 | 0.78 |
| overflow, pre-0.8 | 0.85 | 0.74 |
| oracle, no TWAP | 0.62 | 0.64 |

The vulnerable cases barely move. The **guarded** case collapses from 0.50
(reported) to 0.09 (dropped). That separation is the whole point.

## Tuning

All weights are data at the top of `confidence.py`. Changing a prior is a
one-line diff, and `tests/test_confidence.py` enforces monotonicity, bounds and
diminishing returns so a bad edit fails CI rather than silently skewing output.

## Reporting

Every finding carries `evidence_summary`, the full audit trail:

```
prior 0.25 [signal \.call\s*\{ +1.00] [unmitigated - +0.60]
           [ordering store after call +1.60] [scope 1 unguarded fn +0.25]
```

So a confidence is never a bare number — it is a list of reasons you can argue
with.
