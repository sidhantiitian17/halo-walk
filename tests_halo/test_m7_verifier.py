"""M7 QoE verifier (halo/verifier.py): E-model, verdicts, missing samples = loss."""
import math, random

import pytest
from hypothesis import given, settings, strategies as st

from halo import verifier as V


# --------------------------------------------------------------------------- E-model
def test_reference_point_zero_impairment():
    """Cole & Rosenbluth simplified G.711 E-model: R0 = 94.2 at d=0, e=0.
    With a typical 40 ms one-way delay R = 94.2 - 0.96 = 93.24 (~93.2) -> MOS ~= 4.41."""
    assert V.r_factor(0.0, 0.0) == pytest.approx(94.2)
    r = V.r_factor(40.0, 0.0)
    assert r == pytest.approx(93.2, abs=0.05)
    assert V.mos(r) == pytest.approx(4.41, abs=0.01)
    assert V.mos(93.2) == pytest.approx(4.41, abs=0.01)


def test_mos_saturation_and_floor():
    assert V.mos(100.0) == 4.5 and V.mos(150.0) == 4.5
    assert V.mos(0.0) == 1.0 and V.mos(-20.0) == 1.0
    assert math.isnan(V.mos(float("nan")))


def test_delay_knee_at_177ms():
    below = V.r_factor(177.0, 0.0) - V.r_factor(176.0, 0.0)
    above = V.r_factor(201.0, 0.0) - V.r_factor(200.0, 0.0)
    assert below == pytest.approx(-0.024)
    assert above == pytest.approx(-0.134)


def test_known_loss_point():
    # 1 % loss: Ie = 30 ln(1.15) = 4.19
    assert V.r_factor(0.0, 0.01) == pytest.approx(94.2 - 30 * math.log(1.15))


@settings(max_examples=300, deadline=None)
@given(d1=st.floats(0, 1000), d2=st.floats(0, 1000), e=st.floats(0, 1))
def test_r_and_mos_monotonic_in_delay(d1, d2, e):
    lo, hi = sorted((d1, d2))
    assert V.r_factor(hi, e) <= V.r_factor(lo, e) + 1e-12
    assert V.mos(V.r_factor(hi, e)) <= V.mos(V.r_factor(lo, e)) + 1e-12


@settings(max_examples=300, deadline=None)
@given(e1=st.floats(0, 1), e2=st.floats(0, 1), d=st.floats(0, 1000))
def test_r_and_mos_monotonic_in_loss(e1, e2, d):
    lo, hi = sorted((e1, e2))
    assert V.r_factor(d, hi) <= V.r_factor(d, lo) + 1e-12
    assert V.mos(V.r_factor(d, hi)) <= V.mos(V.r_factor(d, lo)) + 1e-12


@settings(max_examples=200, deadline=None)
@given(r=st.floats(-50, 150))
def test_mos_range(r):
    assert 1.0 <= V.mos(r) <= 4.5


def test_nan_propagates_not_zero():
    assert math.isnan(V.r_factor(float("nan"), 0.0))
    assert math.isnan(V.r_factor(10.0, float("nan")))


# --------------------------------------------------------------------------- statistics helpers
def test_pct_ignores_nan_and_empty_is_nan():
    assert V.pct([1, 2, 3, float("nan")], 50) == 2
    assert math.isnan(V.pct([], 50))
    assert math.isnan(V.pct([float("nan")], 95))


def test_jitter_rfc3550():
    assert V.rfc3550_jitter([10.0] * 50) == 0.0
    assert V.rfc3550_jitter([10.0, 20.0]) == pytest.approx(10.0 / 16)


def test_jain():
    assert V.jain([5, 5, 5]) == pytest.approx(1.0)
    assert V.jain([1, 0, 0, 0]) == pytest.approx(0.25)
    assert math.isnan(V.jain([]))


def test_mannwhitney():
    p, delta = V.mannwhitney(list(range(30)), list(range(100, 130)))
    assert p < 0.001 and delta == -1.0
    assert all(math.isnan(x) for x in V.mannwhitney([], [1]))


# --------------------------------------------------------------------------- verdict
def sample(mu, sd=2.0, n=60, seed=0, loss=0.0, tput=50.0):
    r = random.Random(seed)
    return {"owd": [max(0.0, r.gauss(mu, sd)) for _ in range(n)], "loss": loss, "tput": tput}


def test_verdict_improved():
    v, info = V.verdict(sample(120, seed=1), sample(30, seed=2))
    assert v == "IMPROVED" and info["ci"][1] < 0


def test_verdict_neutral():
    v, _ = V.verdict(sample(30, seed=1), sample(30, seed=2))
    assert v == "NEUTRAL"


def test_verdict_regressed_delay():
    v, info = V.verdict(sample(30, seed=1), sample(120, seed=2))
    assert v == "REGRESSED" and info["ci"][0] > 15.0


def test_verdict_regressed_loss():
    v, info = V.verdict(sample(30, seed=1), sample(30, seed=2, loss=0.10))
    assert v == "REGRESSED" and info["d_loss"] == pytest.approx(0.10)


def test_verdict_regressed_throughput_collapse():
    v, info = V.verdict(sample(30, seed=1, tput=80.0), sample(30, seed=2, tput=10.0))
    assert v == "REGRESSED" and info["tput"] == [80.0, 10.0]


def test_verdict_too_few_samples_neutral():
    v, info = V.verdict(sample(30, n=5), sample(300, n=5))
    assert v == "NEUTRAL" and info["reason"] == "too_few_samples"


def test_missing_samples_counted_as_loss_not_zero():
    """a probe blackout leaves no OWD samples: it must surface as loss -> REGRESSED,
    never as a perfect 'zero delay' window."""
    pre = sample(30, n=60)
    post = {"owd": [], "loss": 1.0, "tput": 50.0}          # every probe of the window missing
    v, info = V.verdict(pre, post)
    assert v == "REGRESSED" and info["reason"] == "probe_blackout"


def test_missing_samples_not_treated_as_zero_delay():
    """if missing samples were coded as 0 ms, a blackout window would look IMPROVED"""
    pre = sample(80, n=60)
    post = sample(80, n=60, loss=0.5)
    post["owd"] = post["owd"][:30]                            # half the probes never came back
    v, _ = V.verdict(pre, post)
    assert v == "REGRESSED"


def test_controller_window_codes_missing_as_loss(tmp_path):
    """Ctl.window(): lost probes are excluded from OWD and counted in the loss fraction; an empty
    window yields NaN loss (unknown), not 0."""
    from collections import deque
    from halo.controller import Ctl
    c = object.__new__(Ctl)
    nan = float("nan")
    c.probes = deque([(1.0, 1.0, 10.0, 0), (1.1, nan, nan, 1), (1.2, 2.0, 12.0, 0), (1.3, nan, nan, 1)])
    c.ach_hist = deque([(1.0, 40.0), (1.2, 60.0)])
    w = c.window(0.0, 2.0)
    assert w["owd"] == [10.0, 12.0] and w["loss"] == 0.5 and w["tput"] == 50.0
    empty = c.window(5.0, 6.0)
    assert empty["owd"] == [] and math.isnan(empty["loss"]) and empty["tput"] is None
