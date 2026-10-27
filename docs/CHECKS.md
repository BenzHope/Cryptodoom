# Checks reference

Confidence is computed from evidence, not hardcoded. Base 0.45, plus 0.10 per
distinct signal, plus 0.25 if nothing mitigates, plus 0.15 if the signal appears
in a function that also lacks the mitigation, plus 0.15 if a state write follows
the external call. Capped at 0.95. Reported at >= 0.60.

| Class | Severity | Signals | Mitigations | Payout |
|---|---|---|---|---|
| `REENTRANCY` | CRITICAL | `.call{`, `.call.value(`, `.send(`, `.transfer(` | `nonReentrant`, `ReentrancyGuard`, `_entered`, `mutex` | direct |
| `ACCESS_CONTROL` | CRITICAL | privileged fn with no modifier and no `require(msg.sender` | `onlyOwner`, `onlyRole`, `_checkOwner` | direct |
| `UNINITIALIZED_PROXY` | CRITICAL | `function initialize(` / `init(` | `initializer`, `_disableInitializers` | state |
| `BROKEN_PROXY` | CRITICAL | EIP-1967 impl slot set, impl has no code | — | state |
| `ORACLE_MANIPULATION` | HIGH | `getReserves`, `reserve0`, `balanceOf(this)`, `slot0` | `twap`, `observe`, `chainlink`, `latestRoundData` | direct |
| `DELEGATECALL` | HIGH | `.delegatecall(` | `onlyOwner`, `_authorizeUpgrade` | state |
| `INTEGER_OVERFLOW` | HIGH | `++`, `--`, `+=`, `-=` | `SafeMath`, pragma >= 0.8 | direct |
| `FLASHLOAN_CALLBACK` | HIGH | `executeOperation`, `uniswapV2Call`, `flashLoan` | caller verification | direct |
| `SELFDESTRUCT` | MEDIUM | `selfdestruct(`, `suicide(` | `onlyOwner`, timelock | direct |
| `UNCHECKED_CALL` | MEDIUM | `.send(` | `require(ok)`, `if (!ok` | direct |
| `TX_ORIGIN` | MEDIUM | `tx.origin` | `tx.origin == msg.sender` | direct |
| `DELEGATECALL_HEAVY` | HIGH | >= 3 `DELEGATECALL` opcodes | — | state |
| `REENTRANCY_BYTECODE` | HIGH | CALL:SSTORE ratio >= 3.0 | — | direct |
| `SELFDESTRUCT_PRESENT` | MEDIUM | `SELFDESTRUCT` opcode | — | direct |
| `ACCESS_CONTROL_ONCHAIN` | CRITICAL | function executes from a random address | reverts for us, succeeds for owner | direct |

## On-chain probe

`ACCESS_CONTROL_ONCHAIN` uses a differential test: call as a random address, then
call as `owner()`. If random succeeds, the function is callable by anyone. If
random reverts with an access-control message and owner succeeds, it is properly
protected. Anything else is inconclusive and reported as such.

## Claim model

Findings are sorted by severity then confidence. Each claims
`remaining * claim_fraction * confidence`, and `remaining` decreases. Findings
can never collectively exceed TVL. State-payout findings run in a second pass and
only count if `realisable` — an upgrade path exists and either there is no owner
or an unguarded `initialize()`.

## Known limits

- Selector presence in bytecode is a filter, not proof. False negatives only.
- `eth_call` as `owner()` is a simulation, not a signature. Contracts comparing
  `tx.origin` or a hardcoded relayer will confuse it.
- Regex source analysis has no AST. Function scoping is brace matching.
- Unpriced tokens make a pool `priced=False` and it is skipped.
