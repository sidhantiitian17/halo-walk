"""M2 - payload-free traffic classifier: features, deterministic baseline, calibrated ML model.

Feature policy (anti-shortcut): only packet sizes, directions, inter-arrival times, transport
protocol and rate-shape statistics. NEVER: payload, SNI/DNS, IP addresses, ports, TTL.
(TTL is recorded only so that the "with-TTL" ablation can show whether it leaks.)

  stage 1 : first 8 packets of the flow (signed size, IAT) + protocol        -> early decision
  stage 2 : stage 1 + rate-shape over the first h seconds (h = 2, 4, 6)      -> final decision
"""
import math, os, pickle

CLASSES = ["call", "gaming", "streaming", "bulk", "other"]
N1 = 8
HORIZONS = (2, 4, 6)

F1_NAMES = ["proto_udp", "n_pkts"] + ["size%d" % i for i in range(N1)] + ["iat%d" % i for i in range(N1)]
F2_NAMES = F1_NAMES + ["h", "dn_mean", "dn_max", "dn_min", "dn_idle_frac", "dn_cv", "up_mean",
                       "log_ratio", "dn_pktsize", "up_pktsize", "dn_pps", "up_pps"]
TTL_NAMES = ["ttl%d" % i for i in range(N1)]


def feat1(flow):
    """flow: {"proto": "tcp"|"udp", "pkts": [(t, signed_size, ttl), ...]} (first packets, both directions)"""
    pk = flow["pkts"][:N1]
    sizes = [p[1] for p in pk] + [0] * (N1 - len(pk))
    iats = [0.0] + [min(2000.0, (b[0] - a[0]) * 1e3) for a, b in zip(pk, pk[1:])]
    iats += [0.0] * (N1 - len(iats))
    return [1.0 if flow["proto"] == "udp" else 0.0, float(len(pk))] + [float(s) for s in sizes] + iats


def feat_ttl(flow):
    pk = flow["pkts"][:N1]
    return [float(p[2]) for p in pk] + [0.0] * (N1 - len(pk))


def rate_shape(bins, h):
    """bins: [(dt, up_bytes, dn_bytes, up_pkts, dn_pkts)] consecutive conntrack deltas since flow start."""
    b = bins[:h]
    if not b:
        return [float(h)] + [0.0] * 11
    dn = [x[2] * 8 / max(x[0], 1e-3) / 1e6 for x in b]
    up = [x[1] * 8 / max(x[0], 1e-3) / 1e6 for x in b]
    mx, mean = max(dn), sum(dn) / len(dn)
    idle = sum(1 for v in dn if v < max(0.05, 0.1 * mx)) / len(dn)
    cv = (math.sqrt(sum((v - mean) ** 2 for v in dn) / len(dn)) / mean) if mean > 0 else 0.0
    upm = sum(up) / len(up)
    T = sum(x[0] for x in b)
    dnb, upb = sum(x[2] for x in b), sum(x[1] for x in b)
    dnp, upp = sum(x[4] for x in b), sum(x[3] for x in b)
    return [float(h), mean, mx, min(dn), idle, cv, upm, math.log10((dnb + 1.0) / (upb + 1.0)),
            dnb / dnp if dnp else 0.0, upb / upp if upp else 0.0, dnp / T, upp / T]


def feat2(flow, h):
    return feat1(flow) + rate_shape(flow.get("bins", []), h)


# ----------------------------------------------------------------------------- deterministic baseline
CALL_PORTS = set(range(3478, 3482)) | set(range(16384, 16501)) | set(range(19302, 19310))
GAME_PORTS = {3074} | set(range(27000, 27101)) | set(range(30000, 30101))
BULK_PORTS = set(range(6881, 6890))


ELEPHANT_BYTES = 8_000_000


def heuristic(flow, h=0):
    """port / protocol / flow-size rules (the deterministic baseline B-CLS).
    Returns (class, confidence, abstain): 1.0 for a rule hit, otherwise abstain -> Best Effort."""
    port, proto = flow["key"][4], flow["proto"]
    if proto == "udp":
        if port in CALL_PORTS:
            return "call", 1.0, False
        if port in GAME_PORTS:
            return "gaming", 1.0, False
        return "other", 0.5, True
    if port in BULK_PORTS:
        return "bulk", 1.0, False
    tot = flow.get("tot", (0, 0))
    if max(tot) > ELEPHANT_BYTES:           # elephant-flow rule (cumulative bytes, either direction)
        return "bulk", 1.0, False
    return "other", 0.5, True


# ----------------------------------------------------------------------------- ML model
class Model:
    """two calibrated XGBoost models (stage 1 / stage 2). Calibration = temperature or isotonic,
    whichever gave the lower ECE on the held-out calibration fold (stored in the bundle)."""

    def __init__(self, path):
        with open(path, "rb") as f:
            b = pickle.load(f)
        self.b = b
        self.version = b.get("version", "?")
        self._predictors = {stage: self._predictor(b[f"m{stage}"]) for stage in (1, 2)}

    @staticmethod
    def _predictor(model):
        # The multiclass probability wrapper returns the booster output directly.
        # Keep the estimator path for other objectives, devices and early stopping.
        if (getattr(model, "objective", None) == "multi:softprob"
                and model.get_xgb_params().get("device") in (None, "cpu")):
            booster = model.get_booster()
            if booster.attr("best_iteration") is None:
                return booster.inplace_predict
        return model.predict_proba

    @staticmethod
    def _cal(p, cal):
        if cal["kind"] == "temperature":
            q = [max(x, 1e-12) ** (1.0 / cal["T"]) for x in p]
        else:
            q = [max(1e-9, float(iso.predict([x])[0])) for x, iso in zip(p, cal["iso"])]
        s = sum(q)
        return [x / s for x in q]

    def _predict_rows(self, stage, rows):
        import numpy as np
        if not rows:
            return []
        cal = self.b["cal%d" % stage]
        results = []
        for raw in self._predictors[stage](np.asarray(rows, dtype=np.float32)).tolist():
            p = self._cal(raw, cal)
            i = max(range(len(p)), key=p.__getitem__)
            results.append((CLASSES[i], p[i], p))
        return results

    def predict_batch(self, stage1, stage2):
        """Infer all ready samples in one call per model, preserving order and per-row calibration."""
        return (self._predict_rows(1, [feat1(flow) for flow in stage1]),
                self._predict_rows(2, [feat2(flow, h) for flow, h in stage2]))

    def predict1(self, flow):
        return self._predict_rows(1, [feat1(flow)])[0]

    def predict2(self, flow, h):
        return self._predict_rows(2, [feat2(flow, h)])[0]


def ece(probs, labels, bins=15):
    """expected calibration error of the top-1 confidence"""
    n = len(labels)
    tot = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i in range(n) if lo < max(probs[i]) <= hi or (b == 0 and max(probs[i]) == 0)]
        if not idx:
            continue
        conf = sum(max(probs[i]) for i in idx) / len(idx)
        acc = sum(1 for i in idx if max(range(len(probs[i])), key=lambda k: probs[i][k]) == labels[i]) / len(idx)
        tot += len(idx) / n * abs(acc - conf)
    return tot
