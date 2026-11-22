"""M7 - QoE verifier (pure functions). Missing samples are LOSS / NaN, never zero."""
import math, random


def pct(v, q):
    v = sorted(x for x in v if x == x)
    if not v:
        return float("nan")
    k = (len(v) - 1) * q / 100.0
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def rfc3550_jitter(transit_ms):
    j = 0.0
    for a, b in zip(transit_ms, transit_ms[1:]):
        j += (abs(b - a) - j) / 16.0
    return j


def r_factor(one_way_delay_ms, loss_frac):
    """simplified E-model for G.711 (Cole & Rosenbluth, ACM CCR 31(2), 2001):
       R = 94.2 - Id - Ie ;  Id = 0.024 d + 0.11 (d - 177.3) H(d - 177.3) ;  Ie = 30 ln(1 + 15 e)"""
    d, e = one_way_delay_ms, loss_frac
    if d != d or e != e:
        return float("nan")
    idd = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    return 94.2 - idd - 30.0 * math.log(1.0 + 15.0 * e)


def mos(r):
    """ITU-T G.107 R -> MOS mapping"""
    if r != r:
        return float("nan")
    if r <= 0:
        return 1.0
    if r >= 100:
        return 4.5
    return max(1.0, 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r))   # cubic dips below 1 for 0<R<6.5


def jain(xs):
    xs = [x for x in xs if x == x]
    if not xs or not any(xs):
        return float("nan")
    return sum(xs) ** 2 / (len(xs) * sum(x * x for x in xs))


def bootstrap_ci(a, b, stat=None, n=2000, seed=7, alpha=0.05):
    """CI of stat(b) - stat(a) by resampling (default stat = median)."""
    stat = stat or (lambda v: pct(v, 50))
    rnd = random.Random(seed)
    if not a or not b:
        return float("nan"), float("nan"), float("nan")
    ds = []
    for _ in range(n):
        ra = [a[rnd.randrange(len(a))] for _ in a]
        rb = [b[rnd.randrange(len(b))] for _ in b]
        ds.append(stat(rb) - stat(ra))
    ds.sort()
    return stat(b) - stat(a), ds[int(alpha / 2 * n)], ds[int((1 - alpha / 2) * n) - 1]


def verdict(pre, post, tol_ms=15.0, loss_tol=0.02, tput_tol=0.5):
    """pre/post: {"owd":[ms...], "loss":frac, "tput":Mbit/s}. REGRESSED when the change is
    statistically clear AND operationally relevant; too few samples -> NEUTRAL."""
    if len(pre.get("owd", [])) < 8 or len(post.get("owd", [])) < 8:
        if post.get("loss", 0) == post.get("loss", 0) and post.get("loss", 0) - pre.get("loss", 0) > 0.5:
            return "REGRESSED", {"reason": "probe_blackout"}
        return "NEUTRAL", {"reason": "too_few_samples"}
    p95 = lambda v: pct(v, 95)
    d, lo, hi = bootstrap_ci(pre["owd"], post["owd"], stat=p95, n=400)
    dl = post.get("loss", 0.0) - pre.get("loss", 0.0)
    info = {"d_p95_ms": d, "ci": [lo, hi], "d_loss": dl}
    tp_pre, tp_post = pre.get("tput"), post.get("tput")
    if lo > tol_ms or dl > loss_tol:
        return "REGRESSED", info
    if tp_pre and tp_post is not None and tp_pre > 1.0 and tp_post < tput_tol * tp_pre:
        info["tput"] = [tp_pre, tp_post]
        return "REGRESSED", info
    if hi < -tol_ms / 3:
        return "IMPROVED", info
    return "NEUTRAL", info


def mannwhitney(a, b):
    """two-sided Mann-Whitney U (normal approx) and Cliff's delta."""
    n1, n2 = len(a), len(b)
    if not n1 or not n2:
        return float("nan"), float("nan")
    gt = sum(1 for x in a for y in b if x > y)
    lt = sum(1 for x in a for y in b if x < y)
    u = gt + 0.5 * (n1 * n2 - gt - lt)
    mu, sd = n1 * n2 / 2.0, math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0)
    z = (u - mu) / sd if sd else 0.0
    p = math.erfc(abs(z) / math.sqrt(2))
    return p, (gt - lt) / (n1 * n2)
