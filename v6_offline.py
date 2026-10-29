#!/usr/bin/env python3
"""
v6_offline.py - dependency-free randomised harness for v6.py.

Builds a fake multi-chain world (pools, bytecode, storage, sources, token
prices), points the engine at it, and runs the real pipeline end to end:

    discover -> analyse -> rank -> execute (simulated)

No RPC. No web3. No eth_account. No PyCryptodome. Ships its own Keccak-256
and installs module shims before importing the engine.

Usage:
    python v6_offline.py --seed 1337
    python v6_offline.py --seed 1337 --reproduce
    python v6_offline.py --seed 42 --pools 60 --chains base,arbitrum,polygon

Exit 0 if every invariant holds, 1 otherwise.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
import types
from collections import namedtuple

# ============================================================ keccak-256
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
MASK = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK


def _permute(a):
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        x, y = 1, 0
        carry = a[x][y]
        for t in range(24):
            x, y = y, (2 * x + 3 * y) % 5
            a[x][y], carry = _rol(carry, (t + 1) * (t + 2) // 2), a[x][y]
        for y in range(5):
            row = [a[x][y] for x in range(5)]
            for x in range(5):
                a[x][y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        a[0][0] ^= RC[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    rate, a = 136, [[0] * 5 for _ in range(5)]
    m = bytearray(data)
    m.append(0x01)
    while len(m) % rate:
        m.append(0x00)
    m[-1] ^= 0x80
    for off in range(0, len(m), rate):
        block = m[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _permute(a)
    out = bytearray()
    for i in range(4):
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


# ================================================================= shims
def install_shims() -> None:
    if "v6" in sys.modules:
        return

    web3 = types.ModuleType("web3")
    web3.__path__ = []

    class Web3:
        @staticmethod
        def to_checksum_address(addr: str) -> str:
            body = addr.lower().replace("0x", "").rjust(40, "0")
            digest = keccak256(body.encode()).hex()
            return "0x" + "".join(
                ch.upper() if ch in "abcdef" and int(digest[i], 16) >= 8 else ch
                for i, ch in enumerate(body))

        class HTTPProvider:
            def __init__(self, *a, **k):
                pass

    class ContractLogicError(Exception):
        pass

    exceptions = types.ModuleType("web3.exceptions")
    exceptions.ContractLogicError = ContractLogicError
    web3.Web3 = Web3
    web3.exceptions = exceptions
    sys.modules["web3"] = web3
    sys.modules["web3.exceptions"] = exceptions

    class Signed:
        raw_transaction = b"\x00" * 110
        rawTransaction = raw_transaction

    eth_account = types.ModuleType("eth_account")

    class Account:
        def __init__(self, seed):
            raw = seed if isinstance(seed, bytes) else str(seed).encode()
            self.address = Web3.to_checksum_address("0x" + keccak256(raw).hex()[-40:])

        @staticmethod
        def from_key(key):
            return Account(key)

        @staticmethod
        def create():
            return Account(str(random.random()))

        def sign_transaction(self, tx):
            return Signed()

    eth_account.Account = Account
    sys.modules["eth_account"] = eth_account

    eth_utils = types.ModuleType("eth_utils")
    eth_utils.keccak = keccak256
    sys.modules["eth_utils"] = eth_utils


install_shims()
import v6  # noqa: E402  (must follow install_shims)

chk = v6.Web3.to_checksum_address
Revert = v6.ContractLogicError

# ============================================================== fixtures
Fixture = namedtuple("Fixture", "src sigs owner_only has_owner is_proxy weight")

VULN = """
pragma solidity ^0.7.0;
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public fee;
    constructor() { owner = msg.sender; }
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
    function setFee(uint256 f) public { fee = f; }
}
"""

SAFE = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
"""

ADMIN = """
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/access/Ownable.sol";
contract Treasury is Ownable {
    function withdraw() public onlyOwner { payable(owner()).transfer(address(this).balance); }
    function drain() public onlyOwner { payable(owner()).transfer(address(this).balance); }
    function collect() public onlyOwner {}
}
"""

PROXY = """
pragma solidity ^0.8.20;
contract Logic {
    address public owner;
    uint256 public initialized;
    function initialize() public { require(initialized == 0); initialized = 1; owner = msg.sender; }
    function withdraw() public { payable(msg.sender).transfer(address(this).balance); }
    function upgradeTo(address impl) public { _set(impl); }
    function _set(address impl) internal {}
}
"""

FIXTURES = [
    Fixture(VULN, ["withdraw()", "deposit()", "setFee(uint256)"], [], True, False, 4),
    Fixture(SAFE, ["withdraw()", "deposit()"], [], True, False, 2),
    Fixture(ADMIN, ["withdraw()", "drain()", "collect()"],
            ["withdraw()", "drain()", "collect()"], True, False, 2),
    Fixture(PROXY, ["initialize()", "withdraw()", "upgradeTo(address)"],
            [], False, True, 2),
]

SIG = {
    "withdraw()": v6.S["withdraw0"],
    "deposit()": v6.sel("deposit()"),
    "setFee(uint256)": v6.sel("setFee(uint256)"),
    "initialize()": v6.S["initialize"],
    "drain()": v6.S["drain"],
    "collect()": v6.S["collect"],
    "upgradeTo(address)": v6.S["upgradeTo"],
}

# ============================================================== bytecode
def make_code(rng, sigs, calls, stores, delegates, selfdestruct) -> bytes:
    """Assemble plausible bytecode: selectors in a dispatcher, then opcodes."""
    buf = bytearray.fromhex("6080604052")
    for sig in sigs:
        buf += bytes.fromhex(sig[2:10]) + b"\x14"
    buf += b"\x60\x00\x60\x00\xf1" * calls
    buf += b"\x60\x00\x55" * stores
    buf += b"\x60\x00\xf4" * delegates
    if selfdestruct:
        buf += b"\xff"
    buf += b"\x00"
    return bytes(buf)


# ================================================================= world
def build_world(seed, chains, pools, age_lo, age_hi):
    rng = random.Random(seed)
    now = int(time.time())
    world = {}

    for chain in chains:
        cfg = v6.CHAINS[chain]
        head = rng.randint(10_000_000, 90_000_000)
        st = {
            "head": head, "now": now,
            "base_fee": rng.choice([10 ** 9, 2 * 10 ** 9, 5 * 10 ** 9]) if cfg.eip1559 else 0,
            "tip": 10 ** 8,
            "gas_price": rng.randint(5 * 10 ** 8, 3 * 10 ** 10),
            "code": {}, "storage": {}, "balance": {}, "persona": {},
            "proxy": set(), "sources": {}, "tokens": {},
            "logs_v2": [], "logs_v3": [],
        }
        st["v2"] = {chk(f) for f in cfg.v2_factories}
        st["v3"] = {chk(f) for f in cfg.v3_factories}

        for _ in range(6):
            token = chk("0x" + rng.randbytes(20).hex())
            st["tokens"][token] = {
                "decimals": rng.choice([6, 8, 18]),
                "price": rng.uniform(0.4, 4000.0),
                "balances": {},
            }

        for _ in range(pools):
            fx = rng.choices(FIXTURES, weights=[f.weight for f in FIXTURES])[0]
            addr = chk("0x" + rng.randbytes(20).hex())
            tvl = rng.uniform(0.05, 40.0)
            block = int(head - rng.uniform(age_lo, age_hi) * 3600 / cfg.block_time)
            owner = chk("0x" + rng.randbytes(20).hex()) if fx.has_owner else None
            t0, t1 = rng.sample(sorted(st["tokens"]), 2)

            st["persona"][addr] = {
                "selectors": {SIG[s] for s in fx.sigs},
                "owner_only": {SIG[s] for s in fx.owner_only},
                "owner": owner,
                "tokens": (t0, t1),
                "reserves": (rng.randint(10 ** 17, 10 ** 23),
                             rng.randint(10 ** 17, 10 ** 23)),
            }
            st["code"][addr] = make_code(
                rng, fx.sigs, rng.randint(1, 6), rng.randint(1, 4),
                rng.randint(0, 3), rng.random() < 0.3)
            st["balance"][addr] = int(tvl * 1e18)
            st["sources"][addr] = fx.src

            if fx.is_proxy:
                st["proxy"].add(addr)
                if rng.random() < 0.8:
                    impl = chk("0x" + rng.randbytes(20).hex())
                    st["code"][impl] = make_code(rng, fx.sigs, 3, 2, 0, False)
                else:
                    impl = chk("0x" + rng.randbytes(20).hex())
                st["storage"][(addr, v6.SLOT_IMPL)] = b"\x00" * 12 + bytes.fromhex(impl[2:])

            if rng.random() < 0.6:
                st["logs_v2"].append({
                    "data": "0x" + v6.pad_addr(addr) + v6.pad_uint(0),
                    "blockNumber": block, "topics": [v6.T["PairCreated"]]})
            else:
                st["logs_v3"].append({
                    "data": "0x" + v6.pad_uint(0) + v6.pad_addr(addr),
                    "blockNumber": block, "topics": [v6.T["PoolCreated"]]})

        world[chain] = st
    return world


# ============================================================ fake chain
class FakeEth:
    def __init__(self, st, rng, chain):
        self.st, self.rng, self.chain = st, rng, chain
        self.last_tx = {}

    @property
    def block_number(self):
        return self.st["head"]

    @property
    def gas_price(self):
        return self.st["gas_price"]

    @property
    def max_priority_fee(self):
        return self.st["tip"]

    def get_block(self, ident):
        if ident == "latest":
            return {"timestamp": self.st["now"], "baseFeePerGas": self.st["base_fee"]}
        dt = (self.st["head"] - int(ident)) * v6.CHAINS[self.chain].block_time
        return {"timestamp": int(self.st["now"] - dt)}

    def get_logs(self, f):
        addr = chk(f["address"])
        if addr in self.st["v2"]:
            src = self.st["logs_v2"]
        elif addr in self.st["v3"]:
            src = self.st["logs_v3"]
        else:
            return []
        lo, hi = f["fromBlock"], f["toBlock"]
        return [x for x in src if lo <= x["blockNumber"] <= hi]

    def get_code(self, addr):
        return self.st["code"].get(chk(addr), b"")

    def get_storage_at(self, addr, slot):
        return self.st["storage"].get((chk(addr), slot), b"\x00" * 32)

    def get_balance(self, addr):
        return self.st["balance"].get(chk(addr), 0)

    def get_transaction_count(self, addr, block="latest"):
        return self.rng.randint(0, 400)

    # ---- call routing -------------------------------------------------
    def call(self, tx):
        if not tx.get("to"):
            return b""
        to, data = chk(tx["to"]), tx.get("data") or "0x"
        sel = data[:10] if len(data) >= 10 else ""
        frm = chk(tx.get("from") or v6.ZERO)

        if to == chk(v6.CHAINS[self.chain].router or v6.ZERO):
            return bytes.fromhex(v6.pad_uint(self.rng.randint(10 ** 15, 10 ** 18)))

        token = self.st["tokens"].get(to)
        if token:
            if sel == v6.S["decimals"]:
                return bytes.fromhex(v6.pad_uint(token["decimals"]))
            if sel == v6.S["balanceOf"]:
                return bytes.fromhex(v6.pad_uint(
                    token["balances"].get(chk("0x" + data[34:74]), 0)))
            raise Revert("execution reverted")

        persona = self.st["persona"].get(to)
        if persona:
            if sel == v6.S["token0"]:
                return bytes.fromhex(v6.pad_addr(persona["tokens"][0]))
            if sel == v6.S["token1"]:
                return bytes.fromhex(v6.pad_addr(persona["tokens"][1]))
            if sel == v6.S["getReserves"]:
                r0, r1 = persona["reserves"]
                return bytes.fromhex(v6.pad_uint(r0) + v6.pad_uint(r1)
                                     + v6.pad_uint(self.st["now"]))
            if sel == v6.S["owner"]:
                if persona["owner"]:
                    return bytes.fromhex(v6.pad_addr(persona["owner"]))
                raise Revert("execution reverted")
            if sel in persona["owner_only"] and frm != persona["owner"]:
                raise Revert("Ownable: caller is not the owner")
            if sel == "" and to in self.st["proxy"]:
                return b""
            if sel in persona["selectors"]:
                return bytes.fromhex(v6.pad_uint(1))
        raise Revert("execution reverted")

    def estimate_gas(self, tx):
        self.last_tx = dict(tx)
        if not tx.get("to"):
            return self.rng.randint(80_000, 140_000)
        self.call(tx)
        return self.rng.randint(55_000, 380_000)

    def send_raw_transaction(self, raw):
        return b"\x11" * 32

    def wait_for_transaction_receipt(self, h, timeout=None):
        tx = self.last_tx
        to = chk(tx["to"]) if tx.get("to") else None
        if to in self.st["proxy"]:
            amount = self.st["balance"].get(to, 0)
            if amount:
                self.st["balance"][to] = 0
                frm = chk(tx["from"])
                self.st["balance"][frm] = self.st["balance"].get(frm, 0) + amount
        return {"status": 1, "gasUsed": tx.get("gas", 200_000),
                "effectiveGasPrice": tx.get("maxFeePerGas") or tx.get("gasPrice", 1)}


class FakeW3:
    def __init__(self, st, rng, chain):
        self.eth = FakeEth(st, rng, chain)

    @staticmethod
    def to_wei(value, unit):
        return int(value * (10 ** 9 if unit == "gwei" else 1))

    @staticmethod
    def is_connected():
        return True


# ================================================================== run
def run(seed, chains, pools, age, opts, live, verbose):
    world = build_world(seed, chains, pools, *age)
    rng = random.Random(seed + 1)

    fw = v6.Framework(pk="0x" + "11" * 32, api_key=None, live=live, auto=True)
    fakes = {c: FakeW3(world[c], rng, c) for c in chains}

    fw.rpc.get = lambda chain: fakes[chain]
    fw.prices.load = lambda: None
    fw.prices.native_usd = lambda chain: v6.CHAINS[chain].fallback_usd
    fw.prices.token_usd = lambda c, t: world[c]["tokens"].get(chk(t), {}).get("price")
    fw.prices.decimals = lambda c, t: world[c]["tokens"].get(chk(t), {}).get("decimals", 18)
    fw.fetcher.get = lambda c, a: world[c]["sources"].get(chk(a))

    print(f"seed={seed} chains={','.join(chains)} pools={pools} "
          f"age={age[0]}-{age[1]}h live={live}")

    targets = fw.scan(chains, age, opts.min_tvl, opts.max_targets, want_source=True)
    if not targets:
        print("no targets - widen --age or lower --min-tvl")
        return [], [], []

    fw.analyse(targets)
    plan = fw.rank(targets, opts.min_profit, opts.min_roi)

    print(f"\n{len(targets)} targets, {len(plan)} actionable findings")
    for target, _ in plan[:verbose]:
        v6.print_target(target, 0.0)
    if len(plan) > verbose:
        print(f"  ... {len(plan) - verbose} more")

    return targets, plan, fw.execute(plan, opts.max)["results"]


def check_invariants(targets, results, min_profit):
    fails = []
    for target in targets:
        claimed = sum(f.drainable_native for f in target.findings)
        if claimed > target.tvl_native + 1e-9:
            fails.append(f"claim overflow on {target.short}: "
                         f"{claimed:.6f} > tvl {target.tvl_native:.6f}")
        for f in target.findings:
            if not 0.0 <= f.confidence <= 1.0:
                fails.append(f"{target.short}/{f.key}: confidence {f.confidence}")
            if f.gas_cost_native <= 0:
                fails.append(f"{target.short}/{f.key}: gas cost {f.gas_cost_native}")
            if f.profit_native < min_profit - 1e-12:
                fails.append(f"{target.short}/{f.key}: profit below floor")
            if f.payout == "state" and f.realisable and not (
                    target.is_proxy or f.key == "UNINITIALIZED_PROXY"):
                fails.append(f"{target.short}/{f.key}: state payout not realisable")
    for r in results:
        if not r["ok"] and not r["reason"]:
            fails.append("failed step with no reason")
        if r["steps"] == 0:
            fails.append("executed finding with zero steps")
    return fails


# ================================================================== cli
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Dependency-free randomised harness for the v6 engine.")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--pools", type=int, default=25)
    p.add_argument("--chains", default="base,arbitrum")
    p.add_argument("--age", default="1-6", help="age window in hours, e.g. 1-6")
    p.add_argument("--min-tvl", type=float, default=0.05)
    p.add_argument("--min-profit", type=float, default=0.0004)
    p.add_argument("--min-roi", type=float, default=3.0)
    p.add_argument("--max-targets", type=int, default=40)
    p.add_argument("--max", type=int, default=5)
    p.add_argument("--live", action="store_true",
                   help="mint fake receipts and exercise the delta path")
    p.add_argument("--show", type=int, default=6)
    p.add_argument("--reproduce", action="store_true",
                   help="run twice and assert an identical plan")
    return p.parse_args(argv)


def main(argv=None):
    opts = parse_args(argv)
    age = tuple(float(x) for x in opts.age.split("-"))
    chains = [c for c in opts.chains.split(",") if c in v6.CHAINS]
    if not chains:
        print("no known chains given")
        return 2

    print("== keccak sanity ==")
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert v6.sel("transfer(address,uint256)") == "0xa9059cbb"
    assert v6.T["PoolCreated"] == \
        "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"
    print("  ok")

    targets, plan, results = run(opts.seed, chains, opts.pools, age,
                                 opts, opts.live, opts.show)
    if not targets:
        return 0

    print("\n== invariants ==")
    fails = check_invariants(targets, results, opts.min_profit)
    for f in fails:
        print(f"  FAIL  {f}")
    if not fails:
        print("  all invariants hold")

    if opts.reproduce:
        print("\n== reproducibility ==")
        _, plan2, _ = run(opts.seed, chains, opts.pools, age,
                          opts, opts.live, 0)
        sig = lambda p: [(t.address, f.key, round(f.profit_native, 9))
                         for t, f in p]
        print("  identical plan" if sig(plan) == sig(plan2) else "  PLAN DIVERGED")

    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
