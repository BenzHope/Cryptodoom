"""The confidence model must be monotone, bounded, and separable."""
import math

import pytest

import confidence as C


def z_of(*pairs, prior=0.25):
    es = C.EvidenceSet(prior=prior)
    for k, w, d in pairs:
        es.add(k, w, d)
    return es.z


def test_sigmoid_bounds():
    assert C.sigmoid(0) == pytest.approx(0.5)
    assert 0 < C.sigmoid(-50) < 1e-6
    assert 1 - C.sigmoid(50) < 1e-6


def test_sigmoid_is_monotone():
    xs = [C.sigmoid(i / 10) for i in range(-50, 51)]
    assert xs == sorted(xs)


def test_logit_roundtrip():
    for p in (0.01, 0.2, 0.5, 0.8, 0.99):
        assert C.sigmoid(C.logit(p)) == pytest.approx(p, abs=1e-6)


def test_evidence_accumulates_in_log_odds():
    a = C.sigmoid(z_of(("signal", 1.0, "x")))
    b = C.sigmoid(z_of(("signal", 1.0, "x"), ("signal", 1.0, "y")))
    assert b > a


def test_mitigation_subtracts():
    plain = C.sigmoid(z_of(("signal", 1.0, "x")))
    guarded = C.sigmoid(z_of(("signal", 1.0, "x"), ("mitigation_local", -2.2, "g")))
    assert guarded < plain


def test_diminishing_returns():
    one = C.sigmoid(z_of(("signal", 1.0, "a")))
    two = C.sigmoid(z_of(("signal", 1.0, "a"), ("signal", 1.0, "b")))
    three = C.sigmoid(z_of(("signal", 1.0, "a"), ("signal", 1.0, "b"),
                           ("signal", 1.0, "c")))
    assert (two - one) > (three - two)


def test_never_reaches_one():
    es = C.EvidenceSet(prior=0.5)
    for i in range(40):
        es.add("signal", 1.0, str(i))
    assert es.confidence < 1.0
    assert es.confidence > 0.99


def test_vulnerable_beats_guarded():
    vuln = C.sigmoid(z_of(("signal", 1.0, "call{"), ("unmitigated", 0.6, "-"),
                          ("ordering", 1.6, "-"), ("scope", 0.25, "-")))
    guarded = C.sigmoid(z_of(("signal", 1.0, "call{"),
                             ("mitigation_local", -2.2, "nonReentrant")))
    assert vuln > 0.85
    assert guarded < C.REPORT_THRESHOLD
    assert vuln - guarded > 0.7


def test_guarded_drops_below_threshold():
    assert C.sigmoid(z_of(("signal", 1.0, "call{"),
                          ("mitigation_local", -2.2, "nonReentrant"))) < 0.60


def test_corroboration_absorbs_secondary():
    class F:
        def __init__(self, key):
            self.key = key
            self.confidence = 0.5
            self.evidence_terms = []
            self.evidence_summary = ""

    a = F("ACCESS_CONTROL")
    b = F("ACCESS_CONTROL_ONCHAIN")
    out = C.merge_corroboration([a, b])
    assert len(out) == 1
    assert out[0] is a
    assert a.confidence > 0.5


def test_contradiction_does_not_absorb():
    class F:
        def __init__(self, key):
            self.key = key
            self.confidence = 0.5
            self.evidence_terms = []
            self.evidence_summary = ""

    a = F("ACCESS_CONTROL")
    b = F("ACCESS_CONTROL_PROTECTED")
    out = C.merge_corroboration([a, b])
    assert len(out) == 2
    assert any(t.kind == "contradiction" for t in a.evidence_terms)


def test_all_priors_are_probabilities():
    for k, p in C.PRIOR.items():
        assert 0.0 < p < 1.0, k


def test_all_weights_are_finite():
    for table in (C.SIGNAL, C.MITIGATION_LOCAL, C.MITIGATION_FILE):
        for key, d in table.items():
            for pat, w in d.items():
                assert math.isfinite(w), f"{key}/{pat}"


def test_all_signal_regexes_compile():
    import re
    for key, d in C.SIGNAL.items():
        for pat in d:
            re.compile(pat)
