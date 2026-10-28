"""
confidence.py - log-odds evidence model.

v6.0 scored findings by addition: base + signals + bonuses, capped at 0.95.
That model cannot express negative evidence, rewards breadth over
specificity, and gives one detector the same score as three agreeing.

This module replaces it. Every confidence is

    sigmoid( prior_logit + sum(evidence_logits) )

Evidence is signed. A mitigation subtracts. A contradicted on-chain probe
subtracts. Corroboration from an independent detector adds, and absorbs the
corroborating finding so it is not double-counted.

All weights are data, in this file, so tuning is a one-file diff.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPORT_THRESHOLD = 0.60
HIGH_THRESHOLD = 0.85


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


@dataclass(frozen=True)
class Evidence:
    kind: str
    weight: float
    detail: str

    def __str__(self) -> str:
        return f"[{self.kind} {self.detail} {self.weight:+.2f}]"


@dataclass
class EvidenceSet:
    prior: float
    terms: List[Evidence] = field(default_factory=list)

    def add(self, kind: str, weight: float, detail: str) -> None:
        self.terms.append(Evidence(kind, weight, detail))

    @property
    def z(self) -> float:
        return logit(self.prior) + sum(t.weight for t in self.terms)

    @property
    def confidence(self) -> float:
        return round(sigmoid(self.z), 4)

    def explain(self) -> str:
        return (f"prior {self.prior:.2f} "
                + " ".join(str(t) for t in self.terms)).strip()


@dataclass
class Score:
    confidence: float
    terms: List[Evidence]
    unprotected: List[str]
    ordered: bool
    summary: str


# ---------------------------------------------------------------- priors
# Base rate that the class is genuinely exploitable *given* it was detected.
PRIOR: Dict[str, float] = {
    "REENTRANCY": 0.25,
    "ACCESS_CONTROL": 0.35,
    "UNINITIALIZED_PROXY": 0.30,
    "ORACLE_MANIPULATION": 0.15,
    "DELEGATECALL": 0.20,
    "SELFDESTRUCT": 0.10,
    "INTEGER_OVERFLOW": 0.30,
    "FLASHLOAN_CALLBACK": 0.25,
    "UNCHECKED_CALL": 0.15,
    "TX_ORIGIN": 0.20,
    # on-chain / bytecode only
    "BROKEN_PROXY": 0.60,
    "PROXY": 0.45,
    "ACCESS_CONTROL_ONCHAIN": 0.45,
    "ACCESS_CONTROL_PROTECTED": 0.40,
    "OWNER_IS_CONTRACT": 0.25,
    "DELEGATECALL_HEAVY": 0.30,
    "REENTRANCY_BYTECODE": 0.30,
    "SELFDESTRUCT_PRESENT": 0.50,
}

# ------------------------------------------------------------- signals
# Weight is specificity: call{value: is near-proof of an external call,
# .transfer( is present in almost everything.
SIGNAL: Dict[str, Dict[str, float]] = {
    "REENTRANCY": {
        r"\.call\s*\{": 1.00,
        r"\.call\.value\(": 0.90,
        r"\.send\s*\(": 0.40,
        r"\.transfer\s*\(": 0.30,
    },
    "UNINITIALIZED_PROXY": {
        r"function\s+initialize\s*\(": 1.30,
        r"function\s+init\s*\(": 0.90,
        r"function\s+__\w*_init\s*\(": 0.80,
    },
    "ORACLE_MANIPULATION": {
        r"getReserves\s*\(": 1.80,
        r"slot0\s*\(": 1.50,
        r"reserve0\s*\(": 1.20,
        r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)": 1.10,
        r"getAmountsOut\s*\(": 0.80,
        r"\.balance\b": 0.50,
    },
    "DELEGATECALL": {
        r"\.delegatecall\s*\(": 1.20,
    },
    "SELFDESTRUCT": {
        r"selfdestruct\s*\(": 1.60,
        r"suicide\s*\(": 1.40,
    },
    "INTEGER_OVERFLOW": {
        r"\+=": 1.00,
        r"-=": 0.80,
        r"\+\+": 0.60,
        r"--": 0.50,
    },
    "FLASHLOAN_CALLBACK": {
        r"executeOperation\s*\(": 1.30,
        r"uniswapV2Call\s*\(": 1.20,
        r"flashLoan\s*\(": 0.90,
    },
    "UNCHECKED_CALL": {
        r"\.send\s*\(": 1.00,
    },
    "TX_ORIGIN": {
        r"tx\.origin": 1.20,
    },
}

# --------------------------------------------------------- mitigations
MITIGATION_LOCAL: Dict[str, Dict[str, float]] = {
    "REENTRANCY": {
        r"nonReentrant": -2.20,
        r"_\w*[Ee]ntered": -2.00,
        r"reentrancyGuard": -1.90,
        r"mutex": -1.80,
        r"locked\s*=": -1.50,
    },
    "UNINITIALIZED_PROXY": {
        r"initializer\b": -2.00,
        r"reinitializer": -1.80,
        r"require\s*\(\s*!\s*initialized": -1.40,
        r"_disableInitializers": -1.20,
    },
    "DELEGATECALL": {
        r"onlyOwner": -1.20,
        r"_authorizeUpgrade": -1.00,
    },
    "SELFDESTRUCT": {
        r"onlyOwner": -1.00,
    },
    "FLASHLOAN_CALLBACK": {
        r"require\s*\(\s*_?msg\.sender\s*==": -1.60,
        r"require\s*\(\s*initiator\s*==": -1.20,
    },
}

MITIGATION_FILE: Dict[str, Dict[str, float]] = {
    "REENTRANCY": {
        r"ReentrancyGuard": -1.20,
        r"is\s+\w+Guard": -0.90,
    },
    "INTEGER_OVERFLOW": {
        r"SafeMath": -2.00,
        r"safeAdd|safeSub|safeMul": -0.80,
    },
    "ORACLE_MANIPULATION": {
        r"twap": -1.60,
        r"latestRoundData": -1.50,
        r"chainlink|aggregator": -1.45,
        r"cumulative": -1.20,
        r"observe\s*\(": -1.20,
        r"consult\s*\(": -1.10,
    },
    "UNCHECKED_CALL": {
        r"require\s*\(\s*(ok|success)": -1.30,
        r"if\s*\(\s*!\s*(ok|success)": -1.10,
    },
    "TX_ORIGIN": {
        r"tx\.origin\s*==\s*(_?msg\.sender|_msgSender\(\))": -1.50,
    },
    "UNINITIALIZED_PROXY": {
        r"Initializable": -0.80,
    },
}

# state write observed *after* the external call
ORDERING: Dict[str, float] = {"REENTRANCY": 1.60}

# nothing at all mitigates it
UNMITIGATED_BONUS: Dict[str, float] = {
    "REENTRANCY": 0.60,
    "INTEGER_OVERFLOW": 0.90,
    "UNINITIALIZED_PROXY": 0.70,
    "FLASHLOAN_CALLBACK": 0.60,
    "UNCHECKED_CALL": 0.60,
    "DELEGATECALL": 0.50,
    "ORACLE_MANIPULATION": 0.50,
    "TX_ORIGIN": 0.40,
    "SELFDESTRUCT": 0.40,
}

SCOPE_BONUS_PER_FN = 0.25
SCOPE_BONUS_CAP = 3

# ------------------------------------------------------- corroboration
# (primary, secondary) -> log-odds. Positive absorbs the secondary.
CORROBORATION: Dict[Tuple[str, str], float] = {
    ("ACCESS_CONTROL", "ACCESS_CONTROL_ONCHAIN"): 1.50,
    ("UNINITIALIZED_PROXY", "PROXY"): 1.30,
    ("REENTRANCY", "REENTRANCY_BYTECODE"): 1.10,
    ("DELEGATECALL", "DELEGATECALL_HEAVY"): 1.00,
    ("REENTRANCY", "ACCESS_CONTROL_ONCHAIN"): 0.60,
    ("ACCESS_CONTROL", "ACCESS_CONTROL_PROTECTED"): -0.60,
}


def score_rule(rule: Any, src: str, funcs: Sequence[Any]) -> Optional[Score]:
    """Score one source rule. Returns None if below threshold."""
    sig = SIGNAL.get(rule.key)
    if not sig:
        return None

    es = EvidenceSet(prior=PRIOR.get(rule.key, 0.20))
    hit = []
    for pat, w in sig.items():
        if re.search(pat, src, re.I):
            es.add("signal", w, pat)
            hit.append(pat)
    if not hit:
        return None

    local = MITIGATION_LOCAL.get(rule.key, {})
    filemit = MITIGATION_FILE.get(rule.key, {})
    unprotected: List[str] = []
    ordered = False

    if rule.scope == "function":
        for f in funcs:
            if not any(re.search(p, f.text, re.I) for p in sig):
                continue
            mit = [(p, w) for p, w in local.items() if re.search(p, f.text, re.I)]
            for p, w in mit:
                es.add("mitigation_local", w, f"{f.name}:{p}")
            if mit:
                continue
            unprotected.append(f.name)
            if rule.order_signals and any(
                    re.search(o, f.body, re.I) for o in rule.order_signals):
                ordered = True
        if ordered:
            es.add("ordering", ORDERING.get(rule.key, 0.0), "store after call")
        if unprotected:
            es.add("scope", SCOPE_BONUS_PER_FN * min(len(unprotected), SCOPE_BONUS_CAP),
                   f"{len(unprotected)} unguarded fn(s)")
    else:
        for p, w in filemit.items():
            if re.search(p, src, re.I):
                es.add("mitigation_file", w, p)

    if not any(t.kind.startswith("mitigation") for t in es.terms):
        es.add("unmitigated", UNMITIGATED_BONUS.get(rule.key, 0.40),
               "no mitigation found")

    if es.confidence < REPORT_THRESHOLD:
        return None
    return Score(es.confidence, es.terms, unprotected, ordered, es.explain())


# privileged names live in v6.py; duplicated here as data for the scorer
PRIVILEGED = {
    "withdraw", "withdrawall", "emergencywithdraw", "collect", "collectfees",
    "drain", "mint", "burn", "setprice", "updateoracle", "setfee", "changefee",
    "setfees", "pause", "unpause", "setadmin", "changeadmin", "setimplementation",
    "upgradeto", "transferownership", "renounceownership", "skim", "sync",
    "rescue", "sweep", "harvest", "setrouter", "settreasury", "setmaxtx",
    "setlimits", "setblacklist", "setminamount", "setmaxamount", "setswapthreshold",
    "setdistribution", "setminter", "setpool", "setwhitelist", "settax",
    "setparams", "setconfig", "migrate", "claim", "claimrewards", "getreward",
    "redeem", "distribute", "setoracle", "setkeeper", "setoperator", "grantrole",
    "setrewardrate", "setrewardsduration", "notifyrewardamount", "setcooldown",
    "setlock", "setauthorized", "setexcluded", "excludeaccount", "setmarketing",
    "setliquidityfee", "settaxfee", "setmaxtxamount", "setmaxwallet",
}

MODIFIER_RE = re.compile(
    r"onlyOwner|onlyAdmin|onlyRole|hasRole|auth\b|requiresAuth|_checkOwner|"
    r"onlyMinter|onlyKeeper|onlyOperator|onlyGov|onlyDAO|onlyGovernance|"
    r"onlyTimelock|onlyManager|onlyController|onlyRouter|onlyFactory|"
    r"onlyVault|onlyPool|onlyStrategy", re.I)
BODY_GUARD_RE = re.compile(
    r"require\s*\(\s*(_?msg\.sender|_msgSender\(\))|_checkOwner\s*\(|"
    r"_checkRole\s*\(|hasRole\s*\(|require\s*\(\s*owner\s*==", re.I)

AC_SIGNAL_WEIGHT = 1.40


def score_access_control(funcs: Sequence[Any]) -> Optional[Score]:
    naked = []
    for f in funcs:
        if f.name.lower() not in PRIVILEGED:
            continue
        if MODIFIER_RE.search(f.header):
            continue
        if BODY_GUARD_RE.search(f.body):
            continue
        naked.append(f.name)
    if not naked:
        return None

    es = EvidenceSet(prior=PRIOR["ACCESS_CONTROL"])
    es.add("signal", AC_SIGNAL_WEIGHT, "privileged fn with no guard")
    es.add("scope", SCOPE_BONUS_PER_FN * min(len(naked), SCOPE_BONUS_CAP),
           f"{len(naked)} naked fn(s)")
    if es.confidence < REPORT_THRESHOLD:
        return None
    return Score(es.confidence, es.terms, naked, False, es.explain())


def merge_corroboration(findings: List[Any]) -> List[Any]:
    """Fold bytecode/on-chain findings into what they corroborate.

    Corroboration is evidence about an existing finding, not a finding.
    Absorbed findings are removed so claims are not double-counted.
    """
    by_key: Dict[str, List[Any]] = {}
    for f in findings:
        by_key.setdefault(f.key, []).append(f)

    absorbed = set()
    for (primary, secondary), weight in CORROBORATION.items():
        for p in by_key.get(primary, []):
            for s in by_key.get(secondary, []):
                p.evidence_terms.append(Evidence(
                    "corroboration" if weight > 0 else "contradiction",
                    weight, secondary))
                if weight > 0:
                    absorbed.add(id(s))

    out = [f for f in findings if id(f) not in absorbed]
    for f in out:
        recompute(f)
    return out


def recompute(finding: Any) -> None:
    es = EvidenceSet(prior=PRIOR.get(finding.key, 0.20))
    es.terms = list(getattr(finding, "evidence_terms", []))
    finding.confidence = es.confidence
    finding.evidence_summary = es.explain()
