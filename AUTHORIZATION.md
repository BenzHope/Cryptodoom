# Authorized Security Test Scope

Project:      <protocol / client name>
Tester:       <you>
Date:         <YYYY-MM-DD>
Status:       Approved for limited live testing

## Allowed chains

- <e.g. Base mainnet>

## Allowed targets

| Chain  | Address                                      | Contract        | Notes            |
|--------|----------------------------------------------|-----------------|------------------|
| base   | 0x4c1a9e0000000000000000000000000000000000   | Example Vault   | read + write     |
| base   | 0x9f3b210000000000000000000000000000000000   | Example Pool    | read only        |

## Authorized actions

- [x] Read-only analysis on any listed target
- [x] Simulated execution (`eth_call`) on any listed target
- [x] Live transactions on listed targets
- [ ] Proxy upgrades
- [ ] Token approvals

## Limits

- Max transactions per run: 3
- Max value at risk: <e.g. 0.05 ETH of gas>
- Window: <start date> to <end date>

## Notes

The launcher greps this file. If a chain or target is not written here,
`./ops/runbook.sh live` refuses to run. This is intentional.

## Sign-off

Approved by: <name, role, contact>
