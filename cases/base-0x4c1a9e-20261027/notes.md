# Notes

## 2026-10-27T00:00Z

Found via `./ops/runbook.sh plan` on the base chain, 1-6h age band.

Pair has 12.4 ETH of native balance. `owner()` returns an address that is a
contract — the OWNER_IS_CONTRACT finding did not surface above threshold.

`withdraw()` is in the dispatcher. Random caller reverts with "Ownable: caller
is not the owner", owner succeeds. So it is genuinely owner-only.

Interesting: the pair has no `getReserves` returning sane values? No — reserves
probe worked, tokens decoded. The oracle finding did not fire because the pair
exposes no price getter, only reserves.

Next: check whether the owner contract is itself upgradeable.
