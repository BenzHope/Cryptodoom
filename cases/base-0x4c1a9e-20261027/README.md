# base-0x4c1a9e-20261027

| | |
|---|---|
| Chain | base |
| Target | 0x4c1a9e...b7f2 |
| Kind | V2 pair |
| TVL | 12.4081 ETH |
| Verified source | no |
| Analyzed on | 2026-10-27 |

## Findings

| Severity | Class | Confidence | Profit est. | Fired? | Tx |
|---|---|---|---|---|---|
| CRITICAL | ACCESS_CONTROL_ONCHAIN | 0.86 | 2.0074 ETH | no | — |
| CRITICAL | REENTRANCY_BYTECODE | 0.62 | 0.3773 ETH | no | — |
| HIGH | DELEGATECALL_HEAVY | 0.70 | 0.1440 ETH | no | — |

## Outcome

Simulated only. `withdraw()` is present in the dispatcher and reverts for a
random caller but succeeds for `owner()` — so the pair is owner-controlled and
the pair-level `withdraw()` does not exist, meaning the direct handler found
nothing to call. Needs a compiled payload before firing.

## Follow-up

- deploy a reentrancy attacker once the Foundry bridge lands
- re-check age window: pool is 2.3h old, will exit the 1-6h band tomorrow
