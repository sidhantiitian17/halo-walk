"""Deployed classifier bundle (halo/model.pkl, written by analysis/train_classifier.py).

Skipped when the bundle has not been trained yet.
"""
import os, random

import pytest

from halo import classifier as C
from halo import policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL = os.path.join(ROOT, "halo", "model.pkl")

pytestmark = pytest.mark.skipif(not os.path.exists(MODEL), reason="halo/model.pkl not trained yet")


class Poison:
    """TTL value that explodes if the feature path reads it"""
    def __float__(self):
        raise AssertionError("classifier read the TTL field")
    __int__ = __index__ = __float__


def flows(n=60, seed=7, ttl=64):
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        proto = rnd.choice(["udp", "tcp"])
        t, pk = 0.0, []
        for _ in range(16):
            t += rnd.uniform(0.0005, 0.08)
            pk.append((t, rnd.choice([1, -1]) * rnd.randint(40, 1500), ttl))
        bins = [(rnd.uniform(0.5, 4), rnd.randint(0, 3_000_000), rnd.randint(0, 3_000_000),
                 rnd.randint(0, 3000), rnd.randint(0, 3000)) for _ in range(rnd.randint(2, 8))]
        out.append({"key": (proto, "10.0.0.2", 40000 + i, "198.51.100.7", rnd.randint(1, 65535)),
                    "proto": proto, "pkts": pk, "bins": bins, "tot": (0, 0)})
    return out


@pytest.fixture(scope="module")
def model():
    return C.Model(MODEL)


def test_bundle_format(model):
    b = model.b
    for k in ("m1", "m2", "cal1", "cal2", "version"):
        assert k in b
    for k in ("cal1", "cal2"):
        assert b[k]["kind"] in ("temperature", "isotonic")
        if b[k]["kind"] == "isotonic":
            assert len(b[k]["iso"]) == len(C.CLASSES)
        else:
            assert b[k]["T"] > 0


def test_feature_vector_has_no_ttl(model):
    assert model.b["m1"].n_features_in_ == len(C.F1_NAMES)
    assert model.b["m2"].n_features_in_ == len(C.F2_NAMES)
    assert not any("ttl" in n.lower() for n in C.F1_NAMES + C.F2_NAMES)
    for f in flows(10, ttl=Poison()):           # TTL is never read on the deployed path
        model.predict1(f)
        for h in C.HORIZONS:
            model.predict2(f, h)


def test_probabilities_sum_to_one(model):
    for f in flows():
        for c, p, pv in [model.predict1(f)] + [model.predict2(f, h) for h in C.HORIZONS]:
            assert len(pv) == len(C.CLASSES)
            assert abs(sum(pv) - 1.0) < 1e-6
            assert all(0.0 <= q <= 1.0 for q in pv)
            assert c in C.CLASSES and p == max(pv)


def test_low_confidence_never_promoted(model):
    seen_low = 0
    for f in flows(200, seed=11):
        for c, p, _ in [model.predict1(f)] + [model.predict2(f, h) for h in C.HORIZONS]:
            tin = policy.tin_for(c, p, p < 0.9, 0.9)          # how controller.classify() calls it
            if p < 0.9:
                seen_low += 1
                assert tin == policy.TIN["other"]
                assert policy.tin_for(c, p, False, 0.9) == policy.TIN["other"]
    # independent of the model: the rule itself
    for c in C.CLASSES:
        assert policy.tin_for(c, 0.899, False, 0.9) == policy.TIN["other"]
