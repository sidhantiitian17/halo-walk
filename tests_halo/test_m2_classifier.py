"""M2 classifier (halo/classifier.py): heuristic baseline, ML-model wrapper, feature policy.

Feature policy under test: only sizes, directions, inter-arrival times, protocol and rate shape.
NEVER payload, SNI/DNS, IP addresses, ports, TTL (TTL is kept only for the with-TTL ablation).
"""
import math, os, pickle, warnings

import pytest

from halo import classifier as C
from halo import policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOYED_HALO_MODEL = os.path.join(ROOT, "halo", "model.pkl")          # controller.py --model default
LEGACY_MODEL = os.path.join(ROOT, "classifier", "xgb_model.pkl")      # controller_daemon.py / dashboard stack


class Poison:
    """a TTL / payload value that explodes if the feature extractor touches it"""
    def __float__(self):
        raise AssertionError("feature extractor read a forbidden field")
    __int__ = __index__ = __float__

    def __eq__(self, o):
        raise AssertionError("feature extractor read a forbidden field")
    __hash__ = object.__hash__


def flow(proto="udp", port=3478, sizes=(200, -200) * 4, iat=0.02, ttl=64, tot=(0, 0), bins=None, **extra):
    pkts = [(i * iat, s, ttl) for i, s in enumerate(sizes)]
    f = {"key": (proto, "10.0.0.2", 50000, "198.51.100.7", port), "proto": proto, "pkts": pkts, "tot": tot,
         "bins": bins or [(1.0, 20_000, 30_000, 50, 50)] * 6}
    f.update(extra)
    return f


# --------------------------------------------------------------------------- heuristic
@pytest.mark.parametrize("proto,port,tot,cls,abstain", [
    ("udp", 3478, (0, 0), "call", False),        # STUN/TURN (WebRTC)
    ("udp", 16400, (0, 0), "call", False),       # RTP range
    ("udp", 19305, (0, 0), "call", False),       # Google Meet
    ("udp", 3074, (0, 0), "gaming", False),      # Xbox Live
    ("udp", 27015, (0, 0), "gaming", False),     # Steam / Source
    ("udp", 443, (0, 0), "other", True),         # QUIC: unknown -> abstain
    ("tcp", 6881, (0, 0), "bulk", False),        # BitTorrent
    ("tcp", 443, (0, 9_000_000), "bulk", False), # elephant flow
    ("tcp", 443, (9_000_000, 0), "bulk", False), # elephant upload
    ("tcp", 443, (0, 100_000), "other", True),   # small web object
    ("tcp", 3478, (0, 0), "other", True),        # call port but TCP -> no rule
])
def test_heuristic_mapping(proto, port, tot, cls, abstain):
    c, p, ab = C.heuristic(flow(proto=proto, port=port, tot=tot))
    assert (c, ab) == (cls, abstain)
    assert p == (0.5 if abstain else 1.0)


def test_heuristic_abstain_maps_to_best_effort():
    c, p, ab = C.heuristic(flow(proto="udp", port=443))
    assert policy.tin_for(c, p, ab) == policy.TIN["other"]


def test_heuristic_rule_hit_promotes():
    c, p, ab = C.heuristic(flow(proto="udp", port=3478))
    assert policy.tin_for(c, p, ab) == 4


# --------------------------------------------------------------------------- features
def test_feature_vector_lengths_match_names():
    f = flow()
    assert len(C.feat1(f)) == len(C.F1_NAMES)
    for h in C.HORIZONS:
        assert len(C.feat2(f, h)) == len(C.F2_NAMES)


def test_feature_names_exclude_forbidden_fields():
    bad = ("ttl", "port", "ip", "addr", "payload", "sni", "dns", "host")
    for n in C.F2_NAMES:
        assert not any(b in n.lower() for b in bad), n
    assert set(C.TTL_NAMES).isdisjoint(C.F2_NAMES)


def test_features_never_read_ttl():
    """TTL slot of every packet is a poison value: feat1/feat2 must not touch it"""
    f = flow(ttl=Poison())
    C.feat1(f)
    C.feat2(f, 6)
    with pytest.raises(AssertionError):
        C.feat_ttl(f)                                   # the ablation helper does read it (sanity)


def test_features_invariant_to_ttl_ports_addresses_payload():
    a = flow(ttl=64)
    b = flow(ttl=128, payload=b"\x16\x03\x01 SNI=example.org" * 10, sni="example.org")
    b["key"] = ("udp", "10.0.0.99", 1234, "203.0.113.9", 9999)
    for h in C.HORIZONS:
        assert C.feat2(a, h) == C.feat2(b, h)
    assert C.feat1(a) == C.feat1(b)


def test_feat1_padding_and_iat_cap():
    f = flow(sizes=(100, -1400, 100), iat=5.0)          # 3 packets, 5 s apart
    x = C.feat1(f)
    assert x[0] == 1.0 and x[1] == 3.0
    assert x[2:10] == [100.0, -1400.0, 100.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    assert x[10:18] == [0.0, 2000.0, 2000.0, 0.0, 0.0, 0.0, 0.0, 0.0]     # IAT capped at 2000 ms


def test_rate_shape_empty_and_values():
    assert C.rate_shape([], 4) == [4.0] + [0.0] * 11
    r = C.rate_shape([(1.0, 125_000, 1_250_000, 100, 1000)] * 2, 2)
    assert r[1] == pytest.approx(10.0)                  # dn_mean Mbit/s
    assert r[6] == pytest.approx(1.0)                   # up_mean
    assert r[7] == pytest.approx(math.log10(2_500_001 / 250_001))


# --------------------------------------------------------------------------- ML wrapper (synthetic bundle)
def _bundle(tmp_path, kind="temperature"):
    np = pytest.importorskip("numpy")
    xgb = pytest.importorskip("xgboost")
    from sklearn.isotonic import IsotonicRegression
    rng = np.random.default_rng(0)
    b = {"version": "unit-test"}
    for stage, n in ((1, len(C.F1_NAMES)), (2, len(C.F2_NAMES))):
        X = rng.normal(size=(200, n))
        y = np.arange(200) % len(C.CLASSES)
        X[:, 0] += y * 3                                 # learnable signal
        m = xgb.XGBClassifier(n_estimators=8, max_depth=2, verbosity=0)
        m.fit(X, y)
        b["m%d" % stage] = m
        if kind == "temperature":
            b["cal%d" % stage] = {"kind": "temperature", "T": 2.0}
        else:
            isos = []
            for k in range(len(C.CLASSES)):
                iso = IsotonicRegression(out_of_bounds="clip").fit([0.0, 0.5, 1.0], [0.0, 0.4, 1.0])
                isos.append(iso)
            b["cal%d" % stage] = {"kind": "isotonic", "iso": isos}
    p = tmp_path / ("model_%s.pkl" % kind)
    with open(p, "wb") as f:
        pickle.dump(b, f)
    return str(p)


@pytest.mark.parametrize("kind", ["temperature", "isotonic"])
def test_model_wrapper_loads_and_predicts(tmp_path, kind):
    m = C.Model(_bundle(tmp_path, kind))
    assert m.version == "unit-test"
    for pred in (m.predict1(flow()), m.predict2(flow(), 4)):
        cls, p, probs = pred
        assert cls in C.CLASSES
        assert len(probs) == len(C.CLASSES)
        assert sum(probs) == pytest.approx(1.0)
        assert p == max(probs)


def test_temperature_calibration_flattens():
    p = [0.9, 0.05, 0.03, 0.01, 0.01]
    q = C.Model._cal(p, {"kind": "temperature", "T": 3.0})
    assert sum(q) == pytest.approx(1.0)
    assert max(q) < max(p)
    assert q.index(max(q)) == 0


def test_low_confidence_model_output_never_promotes(tmp_path):
    """a heavily tempered model is never confident -> abstain -> Best Effort (controller rule p < promote_p)"""
    path = _bundle(tmp_path)
    m = C.Model(path)
    m.b["cal1"] = m.b["cal2"] = {"kind": "temperature", "T": 50.0}
    for f in (flow(), flow(proto="tcp", port=443)):
        cls, p, _ = m.predict1(f)
        assert p < 0.9
        abstain = p < 0.9                                # exactly how controller.classify derives it
        assert policy.tin_for(cls, p, abstain) == policy.TIN["other"]


def test_ece_perfect_and_bad():
    assert C.ece([[1.0, 0.0], [0.0, 1.0]], [0, 1]) == pytest.approx(0.0)
    assert C.ece([[0.9, 0.1]] * 10, [1] * 10) == pytest.approx(0.9)


# --------------------------------------------------------------------------- the deployed models
@pytest.mark.skipif(not os.path.exists(DEPLOYED_HALO_MODEL),
                    reason="halo/model.pkl (controller --classifier ml default) is not present in the repo checkout; cannot test the deployed ML bundle here")
def test_deployed_halo_model_loads_without_ttl():
    m = C.Model(DEPLOYED_HALO_MODEL)
    assert m.b["m1"].n_features_in_ == len(C.F1_NAMES)
    assert m.b["m2"].n_features_in_ == len(C.F2_NAMES)              # no TTL columns appended
    cls, p, probs = m.predict2({"proto": "udp", "pkts": [(0.0, 200, Poison())] * 8, "bins": []}, 2)
    assert cls in C.CLASSES


@pytest.mark.xfail(strict=True, reason="TTL leak: legacy classifier/xgb_model.pkl (used by controller_daemon.py -> "
                   "dashboard/unified_dashboard.py -> systemd adaptive-qos.service) is trained on "
                   "['total_length', 'ttl', 'inter_arrival_ms']")
def test_legacy_deployed_model_does_not_use_ttl():
    if not os.path.exists(LEGACY_MODEL):
        pytest.skip("legacy model not present")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with open(LEGACY_MODEL, "rb") as f:
            b = pickle.load(f)
    names = list(b["model"].get_booster().feature_names or [])
    assert "ttl" not in [n.lower() for n in names], names
