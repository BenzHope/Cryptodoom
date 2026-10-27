# Safety model

## Why this exists

The engine can do two very different jobs: think (safe, reversible) and act
(spends real money, irreversible). When both are behind one flag, one day you
type `--live` by accident.

So live is not a flag. Live is a **gate**.

## Default is off

```env
AUTHORIZED="no"
```

Nothing fires until three separate values are set. Accidents are caused by
things you did not plan, so the dangerous thing must be asked for.

## The permission slip is load-bearing

`AUTHORIZATION.md` is not decoration. `ops/gates.sh` greps it:

- it must mention `LIVE_CHAIN`
- it must mention the first 12 characters of `LIVE_TARGET`

If the slip says Base and you are about to fire on Arbitrum, the launcher
refuses. This catches the single most common operator error.

## The magic words

```env
CONFIRM_LIVE="I_UNDERSTAND"
```

A phrase, not a boolean. You cannot type `I_UNDERSTAND` without your brain
briefly asking "wait, is this the real one?". That pause is the feature.

## One chain, one target

When something breaks you need to know exactly what you touched. "I touched
forty things" is not a diagnosis. One target means the blame space is one.

## Small transaction count

`MAX_TXS=1` on a first run. If it works, you learned something. If it breaks,
you lost one transaction.

## The ladder

1. `selftest` — no network, nothing can break
2. `plan` — read only
3. `simulate` — pretends to press the button
4. `analyze-target` — one contract you chose, still read only
5. `live` on fork or testnet — real transactions, fake money
6. `live` on mainnet — real transactions, real money

Do not skip rungs. Steps 1 to 4 cost nothing and catch nearly everything.

## Practice world

A **fork** is a copy of the chain on your machine. You can mint yourself a
million pretend dollars. Mistakes are free. `live-auto` is restricted to forks
and testnets for exactly this reason — in the practice world nobody needs to
watch each step.

## Mainnet lock

Two extra gates, on top of everything above:

```env
MAINNET_ACK="I_HAVE_WRITTEN_MAINNET_SCOPE"
TARGET_ALLOWLIST="0x...,0x..."
```

`TARGET_ALLOWLIST` is hard. Anything not on it is refused, however good it looks.

## The dashcam

Every live run writes `logs/<utc>_<name>.log` containing the resolved gates,
the exact command, full output, and the exit code. Live is irreversible, so the
log is the only reliable memory of what happened.

## Termux

- `termux-wake-lock` before a live run. A sleeping phone does not notice a failure.
- `termux-wake-unlock` after.
- Keep `logs/` in Termux home, never `/sdcard/`.
- `chmod 600 .env`.
