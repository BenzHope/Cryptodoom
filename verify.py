#!/usr/bin/env python3
"""Dependency and environment check. Run before anything touches a chain."""
import importlib
import shutil
import subprocess
import sys

REQUIRED = [
    ("web3", "Web3"), ("eth_account", "Account"), ("eth_utils", "keccak"),
    ("eth_abi", None), ("eth_keys", None), ("eth_typing", None),
    ("hexbytes", "HexBytes"), ("rlp", None), ("py_ecc", None),
    ("Crypto.Hash.keccak", None), ("pydantic", None), ("jsonschema", None),
    ("aiohttp", None), ("requests", None),
]
OPTIONAL_BINARIES = ["forge", "cast", "anvil", "solc", "slither"]
OPTIONAL_MODULES = ["solcx", "eth_tester", "pytest"]

failures = []

print(f"python {sys.version.split()[0]}  ({sys.executable})")
if sys.version_info < (3, 9):
    failures.append("python must be 3.9 or newer")

print("\n== required modules ==")
for mod, attr in REQUIRED:
    try:
        m = importlib.import_module(mod)
        if attr:
            getattr(m, attr)
        print(f"  OK    {mod:<22} {getattr(m, '__version__', 'n/a')}")
    except Exception as e:
        print(f"  FAIL  {mod:<22} {e}")
        failures.append(mod)

print("\n== keccak correctness ==")
try:
    from eth_utils import keccak
    assert keccak(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert "0x" + keccak(b"transfer(address,uint256)")[:4].hex() == "0xa9059cbb"
    print("  OK    eth_utils.keccak matches known constants")
except Exception as e:
    print(f"  FAIL  {e}")
    failures.append("keccak")

print("\n== optional ==")
for mod in OPTIONAL_MODULES:
    try:
        importlib.import_module(mod)
        print(f"  OK    {mod}")
    except Exception:
        print(f"  --    {mod} (not installed)")
for b in OPTIONAL_BINARIES:
    print(f"  {'OK   ' if shutil.which(b) else '--   '} {b}")

print("\n== network ==")
for name, url in (("etherscan", "https://api.etherscan.io/v2/api"),
                  ("coingecko", "https://api.coingecko.com/api/v3/ping")):
    try:
        import requests
        r = requests.get(url, timeout=15)
        print(f"  OK    {name} reachable ({r.status_code})")
    except Exception as e:
        print(f"  --    {name} unreachable: {e}")

print()
if failures:
    print(f"FAILED: {', '.join(failures)}")
    sys.exit(1)
print("all required dependencies present")
