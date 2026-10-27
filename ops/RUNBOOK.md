# Runbook — live execution

Purpose: fire a bounded number of real transactions at one authorized target.
Everything before step 4 is read-only.

## Preconditions

- [ ] `bash scripts/install.sh` has been run
- [ ] `./ops/runbook.sh selftest` passed in the last 24 hours
- [ ] `.env` exists and is `chmod 600`
- [ ] Wallet funded with gas on `LIVE_CHAIN`
- [ ] `AUTHORIZATION.md` mentions `LIVE_CHAIN` **and** `LIVE_TARGET`
- [ ] You know which finding you expect to fire, and why

If any box is unticked: **STOP**. Do not go to step 4.

## Procedure

### 1. Selftest

```bash
./ops/runbook.sh selftest
```

Expected: `all checks passed`, then pytest green.
If FAIL: fix the dependency. Do not continue.

### 2. Plan

```bash
./ops/runbook.sh plan
```

Expected: a ranked list of findings. No transactions.
Write down the top finding and its estimated profit before moving on.

### 3. Simulate

```bash
./ops/runbook.sh simulate
```

Expected: `OK steps=N` lines with `delta=0.000000`.
`delta=0` is correct — nothing was mined.

If any step FAILs here it will also fail live. Investigate before step 4.

### 4. Arm

```bash
./ops/runbook.sh arm
```

Expected: resolved gates, gas balance, then a prompt.
Read every line. This is your last chance to notice you are pointed at mainnet.
Type `I_UNDERSTAND`.

### 5. Fire

```bash
./ops/runbook.sh live
```

Expected: one log file in `logs/`, one transaction hash, one receipt.
`live` re-runs `arm`, so you type the phrase twice. That is deliberate.

## Abort conditions

Stop and re-plan if any of these is true:

- Estimated gas cost exceeds 5% of the wallet balance
- A step reverts with a reason that is *not* an access-control message
- More than one finding is above threshold on the target
- `arm` shows a chain or target you do not recognize
- The gas balance is lower than the previous run's gas cost

## Rollback

Transactions are irreversible. Rollback means: re-run step 2 and look at new state.

Exception: a proxy that was upgraded to the selfdestruct payload cannot be
un-upgraded. Before firing, note the original implementation address from the
`arm` output or from `logs/`, so you can upgrade back later.

## Post-run

```bash
ls -lt logs/ | head -3
./ops/runbook.sh status
```

Confirm the dashcam wrote, and confirm the target's state moved the way you
expected. If it did not, the log has the revert reason.

## Mainnet extras

When `NETWORK=mainnet`, two more gates apply:

- `MAINNET_ACK=I_HAVE_WRITTEN_MAINNET_SCOPE`
- `TARGET_ALLOWLIST=0x...,0x...`

The allowlist is a hard list. Even if another contract looks juicy, live mode
refuses anything not on it. Still one target at a time.

## `live-auto`

No prompt. Only allowed when `NETWORK` is `fork` or `testnet`, because in the
practice world mistakes are free. On mainnet, a human watches.

```bash
./ops/runbook.sh live-auto
```
