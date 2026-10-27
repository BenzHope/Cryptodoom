"""Rule engine: fires on vulnerable fixtures, quiet on guarded ones."""
import pytest

import v6

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


def analyse(src):
    a = v6.Analyzer(rpc=None, prices=None)
    t = v6.Target(address="0x" + "aa" * 20, chain="ethereum", source_code=src)
    return {f.key: f for f in a.analyse_source(t)}


def test_reentrancy_fires_on_vuln():
    assert "REENTRANCY" in analyse(VULN)


def test_reentrancy_quiet_on_guarded():
    assert "REENTRANCY" not in analyse(SAFE)


def test_guard_detection_is_case_insensitive():
    r = analyse(VULN).get("REENTRANCY")
    assert r is not None and r.confidence >= 0.75


def test_naked_privileged_fn_detected():
    assert "ACCESS_CONTROL" in analyse(VULN)


def test_overflow_gated_by_pragma():
    assert "INTEGER_OVERFLOW" in analyse(VULN)
    assert "INTEGER_OVERFLOW" not in analyse(SAFE)


@pytest.mark.parametrize("src,want", [(VULN, (0, 7, 0)), (SAFE, (0, 8, 20))])
def test_pragma_parsing(src, want):
    assert v6.parse_pragma(src) == want


def test_store_after_call_heuristic():
    fns = {f.name: f for f in v6.extract_functions(VULN)}
    assert v6.state_write_after_call(fns["withdraw"].body) is True
    fns2 = {f.name: f for f in v6.extract_functions(SAFE)}
    assert v6.state_write_after_call(fns2["withdraw"].body) is False


def test_disassembler_honours_push_width():
    ops = v6.disassemble(bytes.fromhex("60ff61fffff1f4ff"))
    assert [o.name for o in ops] == \
        ["PUSH1", "PUSH2", "CALL", "DELEGATECALL", "SELFDESTRUCT"]


def test_payload_is_34_bytes():
    dep = v6.Payloads.selfdestruct_impl("0x" + "11" * 20)
    assert len(dep) == 2 + (12 + 22) * 2
    assert dep.endswith("73" + "11" * 20 + "ff")


def test_claim_model_never_exceeds_tvl():
    class E(v6.Economics):
        def __init__(self):
            pass

        def gas_price_native(self, chain):
            return 1e-8

    t = v6.Target(address="0x" + "cc" * 20, chain="arbitrum", tvl_native=10.0)
    t.findings = [
        v6.Finding(key="REENTRANCY", severity="CRITICAL", confidence=0.9,
                   desc="", claim=0.85),
        v6.Finding(key="ACCESS_CONTROL", severity="CRITICAL", confidence=0.9,
                   desc="", claim=0.95),
        v6.Finding(key="ORACLE_MANIPULATION", severity="HIGH", confidence=0.7,
                   desc="", claim=0.2),
    ]
    E().score(t, min_profit=0.0, min_roi=0.0)
    assert sum(f.drainable_native for f in t.findings) <= 10.0 + 1e-9


def test_confidences_are_probabilities():
    for f in analyse(VULN).values():
        assert 0.0 <= f.confidence <= 1.0
