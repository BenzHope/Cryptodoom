"""Keccak, selectors and topics against known-good constants."""
import pytest

import v6


def test_keccak_empty():
    from eth_utils import keccak
    assert keccak(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


@pytest.mark.parametrize("sig,want", [
    ("transfer(address,uint256)", "0xa9059cbb"),
    ("approve(address,uint256)", "0x095ea7b3"),
    ("balanceOf(address)", "0x70a08231"),
    ("owner()", "0x8da5cb5b"),
    ("totalSupply()", "0x18160ddd"),
    ("getReserves()", "0x0902f1ac"),
])
def test_selectors(sig, want):
    assert v6.sel(sig) == want


@pytest.mark.parametrize("sig,want", [
    ("Transfer(address,address,uint256)",
     "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
    ("Approval(address,address,uint256)",
     "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"),
    ("PairCreated(address,address,address,uint256)",
     "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"),
    ("PoolCreated(address,address,uint24,int24,address)",
     "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"),
    ("OwnershipTransferred(address,address)",
     "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"),
])
def test_topics(sig, want):
    assert v6.topic(sig) == want


def test_eip1967_slots():
    assert v6.SLOT_IMPL == ("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a92"
                            "0a3ca505d382bbc")
    assert v6.SLOT_ADMIN == ("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee117"
                             "8d6a717850b5d6103")


def test_selector_shape():
    assert v6.sel("foo()").startswith("0x")
    assert len(v6.sel("foo()")) == 10
    assert len(v6.topic("foo()")) == 66
