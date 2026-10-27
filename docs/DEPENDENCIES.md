# Dependencies

## Required

| Package | Why |
|---|---|
| Python 3.10+ | modern typing, `randbytes` |
| `web3>=6.11,<8` | transport, `Web3`, `ContractLogicError` |
| `requests>=2.31` | Etherscan source fetch, CoinGecko price |
| `pycryptodome>=3.19` | keccak fallback, `eth-hash` backend |

`web3` brings `eth-account`, `eth-utils`, `eth-abi`, `eth-typing`, `eth-hash`,
`hexbytes`, `py-ecc`, `ckzg`, `rlp`, `pydantic`, `jsonschema`, `aiohttp`,
`websockets`, `protobuf`. Pin `web3<8` until an 8.x release is tested.

## Not required

`v6_offline.py` ships its own pure-Python Keccak and shims `web3`, `eth_account`
and `eth_utils` before importing the engine. It runs on a bare interpreter with
zero packages. Note it therefore never exercises the real web3 code paths.

## Optional

| Feature | Needs |
|---|---|
| Verified source analysis | `API_KEY` (free Etherscan V2 tier) |
| Live USD figures | HTTPS to `api.coingecko.com` |
| Compiling payloads | Foundry (`forge`) or `py-solc-x` |
| Tests | `pytest` |
| Static analysis | `slither-analyzer` |

## Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup
export PATH="$HOME/.foundry/bin:$PATH"
```

Needs `git` and `curl`. On Windows use Git Bash or WSL.

## Gotchas

- `web3` v7 removed `geth_poa_middleware`. `make_w3()` wraps the import in
  `try/except` — do not tidy that away.
- `web3` v5 uses `Web3.toWei`, v6+ uses `w3.to_wei`. The engine assumes v6+.
- `pysha3` fails to build on Python 3.11+. Use `pycryptodome` and
  `pip install "eth-hash[pycryptodome]"`.
- `pycryptodome` and `pycrypto` cannot coexist.
- `ckzg` and `py-ecc` need a C toolchain where wheels are missing.
