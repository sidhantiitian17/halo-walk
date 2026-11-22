#!/usr/bin/env python3
"""HALO-Walk evidence analysis pipeline.

Reads   results/raw/<SCENARIO>/<CONFIG>/rNN/   (written by scenarios/run.py inside the VM)
        results/fidelity/*.json                (scenarios/fidelity.py)
        results/classifier/eval.json           (classifier evaluation, optional)
Writes  results/summary.json, results/tables.md, results/figs/m01..m12.png, results/figs/dashboard.png

Rules: every number is computed from files on disk; nothing is hard-coded. Missing data -> pass=null and
value "pending: no data". Pass criteria are the pre-registered ones (see analysis/README.md); they are
constants below and are NOT tuned to the data. Idempotent: outputs are fully regenerated on each run.

usage: python3 analysis/analyze.py [--root /home/claude/halo-walk] [--boot 10000]
"""
import argparse, csv, glob, json, math, os, re, sys, warnings
import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

try:
    from scipy import stats as _sps          # optional; own implementation below otherwise
except Exception:                            # pragma: no cover
    _sps = None

warnings.filterwarnings("ignore", category=RuntimeWarning)

# ------------------------------------------------------------------ pre-registered criteria (do not tune)
CRIT = {
    1: "adopted: |rate error| <= 4% AND p99 inter-dequeue deviation <= 5 ms at 20, 50 and 100 Mbit/s "
       "(strict Mininet-HiFi: p99 deviation <= 1 MTU serialisation time, reported separately)",
    2: "C3 call p99 added delay <= 15 ms AND C3 < C0 (Mann-Whitney U, Holm-corrected p < 0.05)",
    3: "C3 median-over-reps call p99 added delay <= 10 ms (S1x32, 32 bulk flows)",
    4: "C3: T_adapt <= 2 s AND recovery <= 30 s AND steady-state dl rate changes <= 6 /min (medians over reps)",
    5: "estimator |c_est - true| / true <= 10% at 10, 20, 50 and 100 Mbit/s",
    6: "C3: gaming p99 added delay <= 15 ms AND demand-normalised Jain index over 3 TVs >= 0.9",
    7: "min 1-s bulk goodput in lease window >= 0.8 * R/16 AND kernel lease expiry <= TTL + 1 s (controller killed)",
    8: "ECE(chosen calibration) <= 0.05 AND macro-F1 without TTL > macro-F1 of heuristic",
    9: "gate evaluated validly: C3 and C4 each >= 3 reps in S1, S3, S5 (outcome reported in value)",
    10: "override correction latency (POST -> flow re-marked into Voice tin) <= 1 s",
    11: "rollback: restore <= 1 s after the REGRESSED verdict (rollback_s; detection = health window, reported "
        "separately) AND SAFE <= 3 s after kill -9",
    12: "controller CPU (C3/C4) minus C1 <= 2% of one core",
}
NAMES = {1: "Rig fidelity (20/50/100 Mbit/s)", 2: "S1 call latency under ISO download (C0..C4)",
         3: "S1x32 call latency with 32 bulk flows", 4: "S2 capacity step: adaptation, recovery, stability",
         5: "Estimator accuracy", 6: "S3 gaming latency + TV fairness", 7: "S4 lease abuse / starvation / expiry",
         8: "Classifier accuracy + calibration", 9: "AI gate C4 (ML) vs C3 (heuristic)",
         10: "S5 misclassification override latency", 11: "S6 rollback + watchdog SAFE", 12: "Controller CPU cost"}

WARMUP_S = 3.0          # excluded after load_on
PRE_SKIP_S = 1.0        # excluded at the start of a real-time flow (socket/ARP warm-up)
ADDED_THR, X32_THR = 15.0, 10.0
FID_RATE_ERR, FID_DEV_P99_US = 4.0, 5000.0
T_ADAPT_MAX, RECOVERY_MAX, CHANGES_MAX = 2.0, 30.0, 6.0
SUSTAIN_S = 1.0         # T_adapt: both conditions must hold for this long (excludes a transient crossing)
EST_ERR_MAX, EST_RATES = 0.10, (10, 20, 50, 100)
JAIN_MIN = 0.9
ECE_MAX = 0.05
OVR_MAX, RB_MAX, SAFE_MAX, CPU_MAX = 1.0, 1.0, 3.0, 2.0
MIN_REPS_TEST = 3       # statistical criteria (M2, M9) need >= 3 reps per group, else pending
CONFIGS = ["C0", "C1", "C2", "C3", "C4"]
CFG_LABEL = {"C0": "C0 FIFO", "C1": "C1 static CAKE", "C2": "C2 autorate", "C3": "C3 HALO heur", "C4": "C4 HALO ML"}
BLUE, ORANGE, GREY, LGREY, GREEN, RED = "#1f5fa8", "#e8771e", "#555555", "#bbbbbb", "#2a9d4b", "#c0392b"
CFG_COLOR = {"C0": GREY, "C1": LGREY, "C2": "#7fa7d6", "C3": BLUE, "C4": ORANGE}

NOTES = []


def note(s):
    if s not in NOTES:
        NOTES.append(s)


# ------------------------------------------------------------------ small utilities
def fnum(x):
    try:
        x = float(x)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def r(x, nd=3):
    x = fnum(x)
    return None if x is None else round(x, nd)


def load_json(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


def pctl(v, q):
    v = np.asarray([x for x in v if x is not None and np.isfinite(x)], float)
    return float(np.percentile(v, q)) if v.size else float("nan")


def fmt(x, nd=1, unit=""):
    x = fnum(x)
    return "n/a" if x is None else ("%.*f%s" % (nd, x, unit))


# ------------------------------------------------------------------ statistics
class Stats:
    def __init__(self, n_boot=10000, seed=20261117):
        self.B, self.seed = n_boot, seed

    def _rng(self):
        return np.random.default_rng(self.seed)

    def boot_ci(self, x, stat=np.median):
        """percentile bootstrap 95% CI of stat over reps (B resamples, fixed seed). n<2 -> (nan, nan)"""
        x = np.asarray([v for v in x if fnum(v) is not None], float)
        if x.size < 2:
            return float("nan"), float("nan")
        idx = self._rng().integers(0, x.size, (self.B, x.size))
        s = stat(x[idx], axis=1)
        return float(np.percentile(s, 2.5)), float(np.percentile(s, 97.5))

    def boot_diff(self, a, b, stat=np.median):
        """CI of stat(b) - stat(a); groups resampled independently"""
        a = np.asarray([v for v in a if fnum(v) is not None], float)
        b = np.asarray([v for v in b if fnum(v) is not None], float)
        if a.size < 2 or b.size < 2:
            d = float(stat(b) - stat(a)) if a.size and b.size else float("nan")
            return d, float("nan"), float("nan")
        g = self._rng()
        sa = stat(a[g.integers(0, a.size, (self.B, a.size))], axis=1)
        sb = stat(b[g.integers(0, b.size, (self.B, b.size))], axis=1)
        d = sb - sa
        return float(stat(b) - stat(a)), float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))

    @staticmethod
    def mannwhitney(a, b):
        """two-sided Mann-Whitney U. scipy (exact for small n w/o ties) if present, else normal approx w/ tie corr."""
        a = [v for v in a if fnum(v) is not None]
        b = [v for v in b if fnum(v) is not None]
        if not a or not b:
            return float("nan"), float("nan")
        if _sps is not None:
            try:
                res = _sps.mannwhitneyu(a, b, alternative="two-sided", method="auto")
                p = float(res.pvalue)
                if not math.isfinite(p) and len(set(a) | set(b)) == 1:
                    p = 1.0                                   # all observations tied: no evidence of a difference
                return float(res.statistic), p
            except Exception:
                pass
        n1, n2 = len(a), len(b)
        allv = np.concatenate([a, b])
        order = allv.argsort(kind="mergesort")
        ranks = np.empty(len(allv))
        sv = allv[order]
        i = 0
        tie = 0.0
        while i < len(sv):
            j = i
            while j + 1 < len(sv) and sv[j + 1] == sv[i]:
                j += 1
            ranks[order[i:j + 1]] = (i + j) / 2.0 + 1
            t = j - i + 1
            tie += t ** 3 - t
            i = j + 1
        u = ranks[:n1].sum() - n1 * (n1 + 1) / 2.0
        mu = n1 * n2 / 2.0
        n = n1 + n2
        sd = math.sqrt(n1 * n2 / 12.0 * ((n + 1) - tie / (n * (n - 1)))) if n > 1 else 0
        if sd == 0:
            return u, 1.0
        z = (abs(u - mu) - 0.5) / sd
        return u, float(min(1.0, math.erfc(z / math.sqrt(2))))

    @staticmethod
    def cliffs_delta(a, b):
        """delta = P(a > b) - P(a < b), in [-1, 1]"""
        a = [v for v in a if fnum(v) is not None]
        b = [v for v in b if fnum(v) is not None]
        if not a or not b:
            return float("nan")
        gt = sum(1 for x in a for y in b if x > y)
        lt = sum(1 for x in a for y in b if x < y)
        return (gt - lt) / (len(a) * len(b))

    @staticmethod
    def holm(pvals):
        """Holm-Bonferroni adjusted p-values (dict key -> p); NaN p are left out of the family"""
        items = sorted([(p, k) for k, p in pvals.items() if fnum(p) is not None])
        m, out, run = len(items), {}, 0.0
        for i, (p, k) in enumerate(items):
            run = max(run, min(1.0, (m - i) * p))
            out[k] = run
        for k, p in pvals.items():
            out.setdefault(k, float("nan"))
        return out


def cliff_mag(d):
    d = abs(d) if fnum(d) is not None else None
    if d is None:
        return ""
    return "negligible" if d < 0.147 else "small" if d < 0.33 else "medium" if d < 0.474 else "large"


def jain(xs):
    xs = [x for x in xs if fnum(x) is not None]
    if not xs or not any(xs):
        return float("nan")
    return sum(xs) ** 2 / (len(xs) * sum(x * x for x in xs))


def rfc3550_running(transit_ms):
    """running RFC 3550 interarrival jitter J_i = J_{i-1} + (|D_i| - J_{i-1}) / 16 (transits in send order)"""
    out = np.zeros(len(transit_ms))
    j = 0.0
    for i in range(1, len(transit_ms)):
        j += (abs(transit_ms[i] - transit_ms[i - 1]) - j) / 16.0
        out[i] = j
    return out


def maxmin_share(demands, cap):
    """max-min fair (water-filling) allocation of `cap` among demands"""
    n = len(demands)
    alloc, left, active = [0.0] * n, cap, set(range(n))
    while active and left > 1e-12:
        eq = left / len(active)
        sat = [i for i in active if demands[i] - alloc[i] <= eq]
        if not sat:
            for i in active:
                alloc[i] += eq
            break
        for i in sat:
            left -= demands[i] - alloc[i]
            alloc[i] = demands[i]
            active.discard(i)
    return alloc


# ------------------------------------------------------------------ scenario parameters parsed from the harness
def parse_harness(root):
    """traffic parameters that run.py does not copy into meta.json are parsed from scenarios/run.py itself"""
    out = {}
    try:
        src = open(os.path.join(root, "scenarios", "run.py")).read()
    except OSError:
        note("scenarios/run.py not readable: gaming downstream rate / TV ladder unknown")
        return out
    m = re.search(r"def game\(.*?\n(.*?)\ndef ", src, re.S)
    if m:
        pd = re.search(r"--pps_down (\d+(?:\.\d+)?)", m.group(1))
        sd = re.search(r"--size_down (\d+)", m.group(1))
        if pd and sd:
            out["game_down_mbps"] = float(pd.group(1)) * float(sd.group(1)) * 8 / 1e6
    m = re.search(r"def tv\([^)]*ladder=\"([\d. ]+)\"", src)
    if m:
        out["tv_ladder"] = [float(x) for x in m.group(1).split()]
    m = re.search(r"def call\(.*?\n(.*?)\ndef ", src, re.S)
    if m:
        pd = re.search(r"--pps_down (\d+(?:\.\d+)?)", m.group(1))
        if pd:
            out["call_pps_down"] = float(pd.group(1))
    return out


# ------------------------------------------------------------------ run loading
class Run:
    def __init__(self, path, scn, cfg, rep):
        self.path, self.scn, self.cfg, self.rep = path, scn, cfg, rep
        self.id = "%s/%s/r%02d" % (scn, cfg, rep)
        self.meta = load_json(os.path.join(path, "meta.json")) or {}
        self.ev = {}
        for e in self.meta.get("events", []):
            self.ev.setdefault(e.get("name"), e)
        self.complete = "end" in self.ev
        self._cache = {}
        log = os.path.join(path, "ctl.log")
        if os.path.exists(log):
            try:
                if "Traceback" in open(log, errors="replace").read():
                    note("%s: controller crashed during the run (Traceback in ctl.log); telemetry/events are truncated" % self.id)
            except OSError:
                pass

    def t(self, name):
        e = self.ev.get(name)
        return e.get("t") if e else None

    def f(self, *p):
        return os.path.join(self.path, *p)

    def rt(self, name):
        """real-time flow (call/game): arrays t, seq, owd_ms sorted by arrival time + sidecar"""
        if name in self._cache:
            return self._cache[name]
        res = None
        fn = self.f(name + ".csv")
        if os.path.exists(fn):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    a = np.loadtxt(fn, delimiter=",", skiprows=1, ndmin=2)
                if a.size:
                    a = a[np.argsort(a[:, 0])]
                    res = {"t": a[:, 0], "seq": a[:, 1].astype(int), "owd": a[:, 2],
                           "side": load_json(fn + ".json") or {}}
            except Exception as e:
                note("%s: cannot parse %s.csv (%s)" % (self.id, name, e))
        self._cache[name] = res
        return res

    def telemetry(self):
        if "tel" in self._cache:
            return self._cache["tel"]
        res = None
        fn = self.f("ctl", "telemetry.csv")
        if os.path.exists(fn):
            rows = []
            try:
                for x in csv.DictReader(open(fn)):
                    try:
                        rows.append({k: (float(v) if k not in ("st_dl", "st_ul", "fsm") else v) for k, v in x.items()})
                    except (TypeError, ValueError):
                        continue           # truncated last line
            except Exception:
                rows = []
            if rows:
                res = {k: np.array([row[k] for row in rows]) for k in rows[0]}
        self._cache["tel"] = res
        return res

    def ctl_events(self):
        if "cev" in self._cache:
            return self._cache["cev"]
        out = []
        fn = self.f("ctl", "events.jsonl")
        if os.path.exists(fn):
            for line in open(fn, errors="replace"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        self._cache["cev"] = out
        return out

    def iperf(self, name="bulk"):
        """per-second iperf3 intervals: abs start/end times, Mbit/s, per-stream Mbit/s. Launch time from the
        harness event that immediately precedes the iperf3 launch (more precise than iperf's integer timesecs)."""
        key = "ip_" + name
        if key in self._cache:
            return self._cache[key]
        j = load_json(self.f(name + ".json"))
        res = None
        if j and isinstance(j, dict) and j.get("intervals"):
            t0 = self.iperf_launch(name, j)
            iv = j["intervals"]
            res = {"t0": t0,
                   "ts": np.array([t0 + i["sum"]["start"] for i in iv]),
                   "te": np.array([t0 + i["sum"]["end"] for i in iv]),
                   "mbps": np.array([i["sum"]["bits_per_second"] / 1e6 for i in iv]),
                   "streams": [[s["bits_per_second"] / 1e6 for s in i.get("streams", [])] for i in iv],
                   "mean_mbps": fnum((j.get("end", {}).get("sum_received") or {}).get("bits_per_second")),
                   "duration": fnum(j.get("start", {}).get("test_start", {}).get("duration"))}
            if res["mean_mbps"] is not None:
                res["mean_mbps"] /= 1e6
        elif j and isinstance(j, dict) and j.get("error"):
            note("%s: %s.json reports iperf3 error: %s" % (self.id, name, str(j["error"])[:80]))
        self._cache[key] = res
        return res

    def iperf_launch(self, name, j):
        scn = self.scn
        if name == "abuse":
            t = self.t("lease_granted")
        elif scn in ("S1", "S1x32", "S7", "S5"):
            t = self.t("load_on")
        elif scn == "S2":
            t = self.t("start") + 3.0 if self.t("start") else None       # run.py: sleep(3) after the call launch
        else:
            t = self.t("start")
        if t is None:
            t = fnum(j.get("start", {}).get("timestamp", {}).get("timesecs"))
        return t or 0.0


REP_MIN, REP_MAX = 1, 30      # matrix reps; r00 and r31+ (e.g. r90/r91) are debug runs of older controller code


def discover(raw):
    runs, debug = [], []
    for d in sorted(glob.glob(os.path.join(raw, "*", "*", "r[0-9]*"))):
        scn, cfg, rep = d.split(os.sep)[-3:]
        try:
            rp = int(rep[1:])
        except ValueError:
            continue
        if not os.path.exists(os.path.join(d, "meta.json")):
            note("%s/%s/%s: no meta.json (run incomplete) -> ignored" % (scn, cfg, rep))
            continue
        if not REP_MIN <= rp <= REP_MAX:
            debug.append("%s/%s/%s" % (scn, cfg, rep))
            continue
        run = Run(d, scn, cfg, rp)
        if not run.complete:
            note("%s: meta.json has no 'end' event (aborted run) -> ignored" % run.id)
            continue
        runs.append(run)
    if debug:
        note("debug runs ignored (rep outside r%02d..r%02d; older controller code): %s" % (REP_MIN, REP_MAX, ", ".join(debug)))
    return runs


# ------------------------------------------------------------------ per-run metrics
def send_model(rt, pps_hint=None):
    """sender schedule seq -> send time: send = a + seq / pps; fitted on received packets (t - owd)."""
    st = rt["t"] - rt["owd"] / 1e3
    seq = rt["seq"]
    if len(seq) < 10 or seq.max() == seq.min():
        return None
    pps = (seq.max() - seq.min()) / (st[seq.argmax()] - st[seq.argmin()])
    if pps_hint and abs(pps - pps_hint) / pps_hint < 0.05:
        pps = pps_hint
    a = float(np.median(st - seq / pps))
    return a, pps


def window_loss(rt, model, t0, t1):
    """fraction of packets SENT in [t0, t1] that never arrived (missing seq numbers = lost)"""
    if model is None or t1 <= t0:
        return float("nan")
    a, pps = model
    s0, s1 = max(0, int(math.ceil((t0 - a) * pps))), int(math.floor((t1 - a) * pps))
    s1 = min(s1, int(rt["seq"].max()))
    if s1 < s0:
        return float("nan")
    exp = s1 - s0 + 1
    got = np.unique(rt["seq"][(rt["seq"] >= s0) & (rt["seq"] <= s1)]).size
    return max(0.0, 1.0 - got / exp)


def rt_metrics(rt, pre, load, pps_hint=None):
    """pre/load: (t0, t1) absolute windows (pre may be None). Returns dict of metrics."""
    if rt is None:
        return None
    t, owd = rt["t"], rt["owd"]
    m = {"n": int(len(t))}
    pre_med = float("nan")
    if pre and pre[1] > pre[0]:
        sel = (t >= pre[0]) & (t < pre[1])
        m["n_pre"] = int(sel.sum())
        if sel.sum() >= 20:
            pre_med = float(np.median(owd[sel]))
    m["pre_median_ms"] = pre_med
    sel = (t >= load[0]) & (t <= load[1])
    m["n_load"] = int(sel.sum())
    if sel.sum() < 20:
        return m
    w = owd[sel]
    for q in (50, 95, 99):
        m["p%d_ms" % q] = float(np.percentile(w, q))
    m["added_p99_ms"] = m["p99_ms"] - pre_med
    m["added_p50_ms"] = m["p50_ms"] - pre_med
    m["added_p95_ms"] = m["p95_ms"] - pre_med
    # RFC 3550 jitter: transit series in SEND order (by seq), mean of running J over the load window
    order = np.argsort(rt["seq"], kind="stable")
    jr = rfc3550_running(owd[order])
    ts_o = t[order]
    js = (ts_o >= load[0]) & (ts_o <= load[1])
    m["jitter_ms"] = float(np.mean(jr[js])) if js.any() else float("nan")
    model = send_model(rt, pps_hint)
    # windows in send time (loss is defined over packets the sender emitted inside the window)
    m["loss_load"] = window_loss(rt, model, load[0], load[1] - 0.2)
    sd = rt["side"]
    if sd.get("sent_down"):
        m["loss_total"] = 1.0 - sd.get("recv_down", len(t)) / sd["sent_down"]
    # p99 counting lost packets as infinite delay (conservative variant, detail only)
    if fnum(m["loss_load"]) is not None:
        nl = m["loss_load"]
        m["p99_lost_inf_ms"] = float(np.percentile(w, min(100.0, 99.0 / (1 - nl)))) if nl < 0.01 else float("inf")
    return m


def windows_for(run, flow="call"):
    """(pre, load) windows per scenario. pre=None when the scenario has no unloaded period."""
    rt = run.rt(flow)
    if rt is None:
        return None, None
    c0 = fnum(rt["side"].get("t0")) or float(rt["t"][0])
    tend = float(rt["t"][-1])
    scn = run.scn
    lo = run.t("load_on")
    if scn in ("S1", "S1x32", "S7", "S5", "S3") and lo:
        ip = run.iperf("bulk")
        le = tend
        if ip and ip.get("duration"):
            le = min(tend, lo + ip["duration"])
        return (c0 + PRE_SKIP_S, lo), (lo + WARMUP_S, le)
    if scn == "S2":
        st = run.t("start")
        if st is None:
            return None, None
        b0 = st + 3.0
        ip = run.iperf("bulk")
        le = min(tend, b0 + ip["duration"]) if ip and ip.get("duration") else tend
        return (c0 + 0.5, b0), (b0 + WARMUP_S, le)
    if scn in ("S4", "S6"):                     # call starts with the load already present: no pre window
        end = run.t("bad_policy") if scn == "S6" and run.t("bad_policy") else tend
        return None, (c0 + PRE_SKIP_S + WARMUP_S, end)
    return None, (c0 + PRE_SKIP_S, tend)


def call_metrics(run, flow="call", H=None):
    k = "cm_" + flow
    if k not in run._cache:
        pre, load = windows_for(run, flow)
        hint = (H or {}).get("call_pps_down") if flow == "call" else None
        run._cache[k] = rt_metrics(run.rt(flow), pre, load, hint) if load else None
    return run._cache[k]


def step_series(tel, cev, d="dl"):
    """dl shaper-rate step function: telemetry r_dl preferred; else events.jsonl kind=rate dir=dl"""
    if tel is not None and len(tel["t"]):
        return tel["t"], tel["r_" + d], "telemetry r_%s" % d
    ev = [e for e in cev if e.get("kind") == "rate" and e.get("dir") == d]
    if ev:
        t = np.array([ev[0]["t"] - 1e-3] + [e["t"] for e in ev])
        v = np.array([ev[0]["old"]] + [e["new"] for e in ev])
        return t, v, "events.jsonl rate/%s" % d
    return None, None, None


def value_at(ts, vs, t):
    i = np.searchsorted(ts, t, side="right") - 1
    return vs[i] if i >= 0 else float("nan")


def s2_metrics(run, H):
    rt = run.rt("call")
    tdn, tup, tend = run.t("rate_down"), run.t("rate_up"), run.t("end")
    if rt is None or tdn is None or tup is None:
        return None
    cm = call_metrics(run, "call", H) or {}
    base = cm.get("pre_median_ms", float("nan"))
    cap_dn = fnum(run.ev["rate_down"].get("down"))
    cap_up = fnum(run.ev["rate_up"].get("down"))
    out = {"cap_down": cap_dn, "cap_up": cap_up, "pre_median_ms": base}
    t, owd = rt["t"], rt["owd"]
    # latency penalty during the low-capacity phase (all configs, incl. static C1)
    sel = (t >= tdn) & (t <= tup)
    if sel.sum() > 20 and fnum(base) is not None:
        out["low_phase_added_p99_ms"] = float(np.percentile(owd[sel], 99) - base)
        out["low_phase_added_p95_ms"] = float(np.percentile(owd[sel], 95) - base)
    tel, cev = run.telemetry(), run.ctl_events()
    ts, rs, src = step_series(tel, cev)
    out["rate_source"] = src
    if run.cfg in ("C0", "C1") or ts is None:
        out["t_adapt_s"] = None
        out["t_adapt_note"] = "never (no adaptive shaper)" if run.cfg in ("C0", "C1") else "no controller data"
        return out
    target = 0.95 * cap_dn
    grid = np.arange(tdn, tup, 0.1)
    ok = []
    for g in grid:
        rr = value_at(ts, rs, g)
        c1 = abs(rr - target) <= 0.10 * target
        w = owd[(t > g - 1.0) & (t <= g)]
        c2 = len(w) >= 10 and fnum(base) is not None and np.percentile(w, 95) <= base + ADDED_THR
        ok.append(bool(c1 and c2))
    ok = np.array(ok)
    need = int(round(SUSTAIN_S / 0.1))
    ta = None
    for i in range(len(ok) - need + 1):
        if ok[i:i + need].all():
            ta = float(grid[i] - tdn)
            break
    out["t_adapt_s"] = ta
    if ta is None:
        out["t_adapt_note"] = "not reached before rate_up"
    # strict variant: conditions hold continuously from T until rate_up
    bad = np.where(~ok)[0]
    out["t_settle_strict_s"] = float(grid[bad[-1] + 1] - tdn) if len(bad) and bad[-1] + 1 < len(grid) else (
        0.0 if not len(bad) else None)
    # recovery
    thr = 0.9 * 0.95 * cap_up
    sel = (ts >= tup) & (rs >= thr)
    if value_at(ts, rs, tup) >= thr:
        out["recovery_s"] = 0.0
    else:
        out["recovery_s"] = float(ts[sel][0] - tup) if sel.any() else None
    out["telemetry_end_rel_s"] = float(ts[-1] - tup) if ts is not None else None
    if out["recovery_s"] is None:
        out["recovery_note"] = "r_dl never reached %.2f Mbit/s after rate_up (data ends %.1f s after rate_up)" % (
            thr, out["telemetry_end_rel_s"])
    # stability: dl rate changes per minute, last 20 s before rate_down + last 15 s of the run
    rev = [e["t"] for e in cev if e.get("kind") == "rate" and e.get("dir") == "dl"]
    if not rev and tel is not None:
        ch = np.where(np.abs(np.diff(tel["r_dl"])) > 1e-6)[0]
        rev = list(tel["t"][ch + 1])
    rev = np.array(rev)
    n1 = int(((rev >= tdn - 20) & (rev < tdn)).sum()) if rev.size else 0
    n2 = int(((rev >= tend - 15) & (rev <= tend)).sum()) if rev.size and tend else 0
    out["changes_pre_down"], out["changes_last15"] = n1, n2
    out["changes_per_min"] = (n1 + n2) / (35.0 / 60.0)
    # data coverage of the stability windows (controller crash would make the count meaningless)
    if ts is not None and tend and ts[-1] < tend - 15:
        out["stability_note"] = "controller data ends %.1f s before run end" % (tend - ts[-1])
    return out


def tv_goodput(fn, t_from):
    """achieved goodput of one TV: delivered media bits / elapsed session time (see README)"""
    try:
        rows = list(csv.DictReader(open(fn)))
    except OSError:
        return None
    rows = [x for x in rows if float(x["t"]) >= t_from]
    if len(rows) < 2:
        return None
    t = np.array([float(x["t"]) for x in rows])
    b = np.array([float(x["bytes"]) for x in rows])
    dl = np.array([float(x["dl_s"]) for x in rows])
    seg = float(np.median(np.diff(t)))
    span = max(len(rows) * seg, t[-1] + dl[-1] - t[0])
    return {"goodput_mbps": float(b.sum() * 8 / span / 1e6), "seg_s": seg, "n_chunks": len(rows),
            "stalls": int(sum(int(x["stall"]) for x in rows)),
            "mean_rung": float(np.mean([float(x["rung_mbps"]) for x in rows]))}


def shaper_rate(run, t0, t1):
    """R: shaper rate in force. C0 -> physical rate (no shaper); C1 -> 0.95*down; C2-4 -> telemetry median."""
    down = fnum(run.meta.get("down"))
    if run.cfg == "C0":
        return down, "C0 no shaper: physical link rate meta.down"
    tel = run.telemetry()
    if run.cfg != "C1" and tel is not None:
        sel = (tel["t"] >= t0) & (tel["t"] <= t1)
        if sel.any():
            return float(np.median(tel["r_dl"][sel])), "median telemetry r_dl in window"
    return (0.95 * down if down else None), "0.95 * meta.down (default shaper rate)"


def s3_metrics(run, H):
    gm = call_metrics(run, "game", H)
    out = {"game": gm}
    lo = run.t("load_on")
    ladder = run.meta.get("tv_ladder") or H.get("tv_ladder")
    if lo is None or not ladder:
        return out
    tvs = {}
    for h in ("tv1", "tv2", "tv3"):
        g = tv_goodput(run.f(h + ".csv"), lo + WARMUP_S)
        if g:
            tvs[h] = g
    out["tv"] = tvs
    if len(tvs) == 3:
        end = run.t("end") or lo + 40
        R, src = shaper_rate(run, lo + WARMUP_S, end)
        gd = H.get("game_down_mbps", 0.0)
        resid = R - gd
        dem = [max(ladder)] * 3
        share = maxmin_share(dem, resid)
        x = [tvs[h]["goodput_mbps"] / s for h, s in zip(("tv1", "tv2", "tv3"), share)]
        out.update(jain=jain(x), x=x, share=share, R=R, R_src=src, demand=dem, game_down_mbps=gd)
    return out


def s4_metrics(run):
    out = {}
    tg, ttl = run.t("lease_granted"), fnum(run.ev.get("lease_granted", {}).get("ttl"))
    ex = run.ev.get("lease_expired_in_kernel")
    if ex:
        a = fnum(ex.get("after_grant_s"))
        out["ttl"] = fnum(ex.get("ttl")) or ttl
        out["after_grant_s"] = a
        out["expiry_ok"] = bool(a is not None and 0 < a <= out["ttl"] + 1.0)
        if a is not None and a <= 0:
            out["expiry_note"] = "lease still present in the kernel at TTL+6 s (run.py records 0 - t_grant)"
    out["controller_killed_rel_grant_s"] = (run.t("controller_killed") - tg) if tg and run.t("controller_killed") else None
    ip = run.iperf("bulk")
    if tg and ttl and ip:
        w0, w1 = tg, tg + ttl
        R, src = shaper_rate(run, w0, w1)
        sel = (ip["ts"] >= w0 - 1e-6) & (ip["te"] <= w1 + 1e-6)
        if sel.any() and R:
            down = fnum(run.meta.get("down"))
            out.update(R=R, R_src=src, thr=0.8 * R / 16, thr_nominal=(0.8 * 0.95 * down / 16) if down else None, min_1s_mbps=float(ip["mbps"][sel].min()),
                       mean_window_mbps=float(ip["mbps"][sel].mean()), n_seconds=int(sel.sum()),
                       series_t=list((ip["ts"] - tg)), series=list(ip["mbps"]))
            out["goodput_ok"] = out["min_1s_mbps"] >= out["thr"]
    ab = run.iperf("abuse")
    if ab:
        out["abuse_mean_mbps"] = ab["mean_mbps"]
    return out


def s5_metrics(run):
    out = {"evidence": []}
    tp = run.t("override_post")
    if tp is None:
        return None
    ret = run.ev.get("override_returned")
    va = run.meta.get("voice_tin_pkts_before_after")
    if ret:
        lat = fnum(ret.get("curl_roundtrip_s")) or (ret["t"] - tp)
        out["api_roundtrip_s"] = lat
        if isinstance(va, list) and len(va) == 2 and None not in va:
            out["voice_tin_pkts"] = va
            if va[1] > va[0]:
                out["evidence"].append(("kernel: Voice-tin packets increased by POST return", lat))
    # controller event: the flow's classify event with the override applied (stage 9, Voice tin = 4)
    for e in run.ctl_events():
        if e.get("t", 0) < tp:
            continue
        k = e.get("kind", "")
        if ("override" in k or "remark" in k) or (k == "classify" and (e.get("stage") == 9 or e.get("ovr")) and e.get("tin") == 4):
            out["ctl_event"] = k
            out["evidence"].append(("ctl/events.jsonl: %s (tin 4)" % k, e["t"] - tp))
            break
    eff = run.ev.get("override_effective")              # legacy harness format
    if eff and fnum(eff.get("latency_s")) is not None:
        out["evidence"].append(("meta override_effective.latency_s (legacy harness)", float(eff["latency_s"])))
        note("%s: legacy S5 meta format (override_effective.latency_s; no override_returned / "
             "voice_tin_pkts_before_after)" % run.id)
    # independent data-plane check: call p95 (1 s sliding) back under pre-load median + 15 ms
    cm = call_metrics(run, "call") or {}
    rt = run.rt("call")
    if rt is not None and fnum(cm.get("pre_median_ms")) is not None:
        for g in np.arange(tp, rt["t"][-1], 0.1):
            w = rt["owd"][(rt["t"] > g - 1) & (rt["t"] <= g)]
            if len(w) >= 10 and np.percentile(w, 95) <= cm["pre_median_ms"] + ADDED_THR and g - tp >= 1.0 - 1e-9:
                out["qoe_recovered_s"] = float(g - tp)
                break
    if out["evidence"]:
        out["latency_s"], out["source"] = out["evidence"][0][1], out["evidence"][0][0]
    return out


def s6_metrics(run):
    out = {}
    cev = run.ctl_events()
    tb = run.t("bad_policy")
    app = [e for e in cev if e.get("kind") == "txn_applied" and (tb is None or e["t"] >= tb - 1)]
    rb = [e for e in cev if e.get("kind") == "rollback"]
    rej = [e for e in cev if e.get("kind") == "txn_rejected"]
    out["shield_rejected_in_api"] = '"accepted":false' in str(run.meta.get("shield_reject", "")).replace(" ", "")
    out["bad_policy_resp"] = str(run.meta.get("bad_policy_resp", ""))[:120]
    out["txn_rejected_events"] = len(rej)
    rb = [e for e in rb if tb is None or e["t"] >= tb - 1]
    if rb:
        b = rb[0]
        out["restore_s"] = fnum(b.get("rollback_s"))        # verdict -> LKG re-applied and read back (criterion)
        out["detect_s"] = fnum(b.get("detect_s"))           # apply -> REGRESSED verdict (health window, >= 1.5 s)
        out["rollback_ok"] = bool(b.get("ok", True))
        a = [e for e in app if e["t"] <= b["t"]]
        if a:
            out["rollback_total_s"] = b["t"] - a[-1]["t"]   # apply -> rollback event (info only)
        if out["restore_s"] is None:
            out["rollback_note"] = "rollback event has no rollback_s field"
    else:
        out["rollback_note"] = ("no txn_applied/rollback events in ctl/events.jsonl" +
                                ("; bad_policy_resp is empty (API request did not complete)" if not out["bad_policy_resp"] else ""))
    wt = load_json(run.f("watchdog_trip.json"))
    k9 = run.t("kill9")
    if wt and k9 and fnum(wt.get("t_safe")):
        out["safe_s"] = wt["t_safe"] - k9
        out["detect_after_kill_s"] = (wt.get("t_detect") or wt["t_safe"]) - k9
        out["hb_age_s"] = fnum(wt.get("hb_age"))
    elif k9:
        out["safe_note"] = "no watchdog_trip.json"
    return out


def est_valid(run):
    """EST runs must use plan_dl = 1.3 x true capacity (recorded in meta) so the estimator has to discover capacity;
    older EST runs (plan 80, no plan_dl in meta) are excluded."""
    true, plan = fnum(run.meta.get("down")), fnum(run.meta.get("plan_dl"))
    return bool(true and plan and abs(plan / true - 1.3) <= 0.05)


def est_metrics(run):
    tel = run.telemetry()
    true = fnum(run.meta.get("down"))
    if tel is None or not true:
        return None
    t1 = tel["t"][-1]
    sel = (tel["t"] >= t1 - 10) & (tel["c_dl"] > 0)
    if not sel.any():
        return {"true": true, "c_est": None}
    c = float(np.median(tel["c_dl"][sel]))
    return {"true": true, "c_est": c, "err": abs(c - true) / true, "n": int(sel.sum())}


# ------------------------------------------------------------------ plotting helpers
def style():
    plt.rcParams.update({
        "figure.facecolor": "white", "axes.facecolor": "white", "savefig.facecolor": "white",
        "font.size": 10, "axes.titlesize": 11, "axes.labelsize": 10, "legend.fontsize": 8.5,
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.alpha": 0.25,
        "axes.prop_cycle": matplotlib.cycler(color=[BLUE, ORANGE, GREY, GREEN, RED])})


def verdict_str(p):
    return "PASS" if p is True else "FAIL" if p is False else "PENDING"


def new_fig(mid, ncols=1, nrows=1, **kw):
    fig, axes = plt.subplots(nrows, ncols, figsize=(1600 / 150, 900 / 150), dpi=150, squeeze=False, **kw)
    return fig, axes


def finish(fig, path, mid, passed, subtitle=""):
    col = GREEN if passed is True else RED if passed is False else GREY
    fig.suptitle("M%d  %s  —  %s" % (mid, NAMES[mid], verdict_str(passed)), fontsize=13, fontweight="bold",
                 color=col, x=0.01, ha="left", y=0.99, va="top")
    fig.text(0.01, 0.935, "Criterion: " + CRIT[mid] + (("\n" + subtitle) if subtitle else ""), fontsize=8.5,
             color="#333333", ha="left", va="top", wrap=True)
    fig.tight_layout(rect=(0, 0, 1, 0.87))
    fig.savefig(path, dpi=150)
    plt.close(fig)


def pending_fig(path, mid, msg="pending: no data"):
    fig, ax = new_fig(mid)
    ax = ax[0][0]
    ax.axis("off")
    ax.text(0.5, 0.5, msg, ha="center", va="center", fontsize=16, color=GREY, transform=ax.transAxes, wrap=True)
    finish(fig, path, mid, None)


def cfg_points(ax, data, ylabel, stats, thr=None, thr_label=None, configs=CONFIGS, nd=1):
    """per-config strip of per-rep values + median with bootstrap 95% CI error bar"""
    xs = []
    for i, c in enumerate(configs):
        v = [x for x in data.get(c, []) if fnum(x) is not None]
        xs.append(c)
        if not v:
            ax.text(i, 0.5, "no data", ha="center", va="center", fontsize=8, color=GREY, rotation=90,
                    transform=matplotlib.transforms.blended_transform_factory(ax.transData, ax.transAxes))
            continue
        jit = (np.arange(len(v)) - (len(v) - 1) / 2) * 0.06
        ax.scatter(i + jit, v, s=16, color=CFG_COLOR[c], alpha=0.55, zorder=3, edgecolor="none")
        med = float(np.median(v))
        lo, hi = stats.boot_ci(v)
        if fnum(lo) is not None:
            ax.errorbar(i + 0.22, med, yerr=[[med - lo], [hi - med]], fmt="o", color="black", ms=5, capsize=4, zorder=4)
        else:
            ax.plot(i + 0.22, med, "o", color="black", ms=5, zorder=4)
        ax.annotate("%.*f\nN=%d" % (nd, med, len(v)), (i + 0.3, med), fontsize=7.5, va="center")
    ax.set_xticks(range(len(configs)))
    ax.set_xticklabels([CFG_LABEL.get(c, c) for c in configs], fontsize=8.5)
    ax.set_xlim(-0.5, len(configs) - 0.3)
    ax.set_ylabel(ylabel)
    if thr is not None:
        ax.axhline(thr, color=RED, ls="--", lw=1.2, label=thr_label or "threshold")
        ax.legend(loc="upper right")


# ------------------------------------------------------------------ the analysis
class Analysis:
    def __init__(self, root, n_boot):
        self.root = root
        self.res = os.path.join(root, "results")
        self.figs = os.path.join(self.res, "figs")
        os.makedirs(self.figs, exist_ok=True)
        self.S = Stats(n_boot)
        self.H = parse_harness(root)
        self.runs = discover(os.path.join(self.res, "raw"))
        self.by = {}
        for run in self.runs:
            self.by.setdefault(run.scn, {}).setdefault(run.cfg, []).append(run)
        self.M = {}
        self.cmp = {}          # comparison results for tables + M2

    def runs_of(self, scn, cfg=None):
        d = self.by.get(scn, {})
        if cfg:
            return sorted(d.get(cfg, []), key=lambda x: x.rep)
        return d

    def per_cfg(self, scn, fn):
        out = {}
        for c, rs in self.runs_of(scn).items():
            out[c] = [fn(rr) for rr in sorted(rs, key=lambda x: x.rep)]
        return out

    def ci_str(self, v, nd=1, unit=" ms"):
        v = [x for x in v if fnum(x) is not None]
        if not v:
            return "n/a"
        med = float(np.median(v))
        lo, hi = self.S.boot_ci(v)
        ci = ("[95%% CI %.*f, %.*f]" % (nd, lo, nd, hi)) if fnum(lo) is not None else "[CI n/a, N<2]"
        return "%.*f%s %s, N=%d" % (nd, med, unit, ci, len(v))

    def summ(self, v):
        v = [x for x in v if fnum(x) is not None]
        if not v:
            return {"n": 0}
        lo, hi = self.S.boot_ci(v)
        return {"n": len(v), "median": r(np.median(v)), "ci95": [r(lo), r(hi)], "values": [r(x) for x in v]}

    def put(self, mid, value, passed, detail):
        self.M[mid] = {"id": mid, "name": NAMES[mid], "value": value, "pass": passed, "criterion": CRIT[mid],
                       "detail": detail}

    # ------------------------------------------------ comparisons (tables + M2), Holm across scenarios
    def comparisons(self):
        metric = {"S1": "call", "S1x32": "call", "S7": "call", "S5": "call", "S2": "call", "S3": "game"}
        pairs = [("C3", "C0"), ("C3", "C1"), ("C3", "C2"), ("C4", "C3")]
        for a, b in pairs:
            raw = {}
            for scn, flow in metric.items():
                va = [(call_metrics(x, flow, self.H) or {}).get("added_p99_ms") for x in self.runs_of(scn, a)]
                vb = [(call_metrics(x, flow, self.H) or {}).get("added_p99_ms") for x in self.runs_of(scn, b)]
                va = [v for v in va if fnum(v) is not None]
                vb = [v for v in vb if fnum(v) is not None]
                if len(va) >= 2 and len(vb) >= 2:
                    u, p = self.S.mannwhitney(va, vb)
                    d, lo, hi = self.S.boot_diff(vb, va)           # median(a) - median(b)
                    raw[scn] = {"n_a": len(va), "n_b": len(vb), "U": u, "p": p, "cliff": self.S.cliffs_delta(va, vb),
                                "diff": d, "ci": [lo, hi], "med_a": float(np.median(va)), "med_b": float(np.median(vb))}
                elif va and vb:
                    d, lo, hi = self.S.boot_diff(vb, va)
                    raw[scn] = {"n_a": len(va), "n_b": len(vb), "U": float("nan"), "p": float("nan"),
                                "cliff": self.S.cliffs_delta(va, vb), "diff": d, "ci": [lo, hi],
                                "med_a": float(np.median(va)), "med_b": float(np.median(vb))}
            adj = Stats.holm({k: v["p"] for k, v in raw.items()})
            for k in raw:
                raw[k]["p_holm"] = adj[k]
                raw[k]["family_size"] = sum(1 for v in raw.values() if fnum(v["p"]) is not None)
            self.cmp[(a, b)] = raw

    # ------------------------------------------------ M1
    def m1(self):
        files = sorted(glob.glob(os.path.join(self.res, "fidelity", "fid_*.json")))
        per = {}
        for fn in files:
            j = load_json(fn)
            if not isinstance(j, dict) or fnum(j.get("rate")) is None:
                continue
            need = ("rate_err_pct", "dev_p99_us", "mtu_time_us")
            if any(fnum(j.get(k)) is None for k in need):
                note("fidelity file %s lacks %s" % (os.path.basename(fn), need))
                continue
            per.setdefault(float(j["rate"]), []).append(j)
        path = os.path.join(self.figs, "m01.png")
        if not per:
            self.put(1, "pending: no data", None, {"files": [os.path.basename(f) for f in files]})
            pending_fig(path, 1)
            return
        det, rows = {}, []
        for rate in sorted(per):
            js = per[rate]
            med = lambda k: float(np.median([fnum(j.get(k)) for j in js if fnum(j.get(k)) is not None])) if any(
                fnum(j.get(k)) is not None for j in js) else None
            d = {"n_files": len(js), "rate_err_pct": r(med("rate_err_pct")), "dev_p95_us": r(med("dev_p95_us"), 1),
                 "dev_p99_us": r(med("dev_p99_us"), 1), "mtu_time_us": r(med("mtu_time_us"), 1),
                 "cpu_idle_pct": r(med("cpu_idle_pct"), 1)}
            d["strict_pass"] = bool(d["dev_p99_us"] <= d["mtu_time_us"])
            d["adopted_pass"] = bool(abs(d["rate_err_pct"]) <= FID_RATE_ERR and d["dev_p99_us"] <= FID_DEV_P99_US)
            det["%g" % rate] = d
            rows.append((rate, d))
        needed = [20.0, 50.0, 100.0]
        have = all(x in per for x in needed)
        passed = all(det["%g" % x]["adopted_pass"] for x in needed) if have else None
        if not have and any(not d["adopted_pass"] for _, d in rows):
            passed = False
        val = "; ".join("%g Mbit/s: err %+.1f%%, p99 dev %.0f us (MTU %.0f us) adopted %s / strict %s" % (
            rt, d["rate_err_pct"], d["dev_p99_us"], d["mtu_time_us"], verdict_str(d["adopted_pass"]),
            verdict_str(d["strict_pass"])) for rt, d in rows)
        if not have:
            val += "; pending rates: %s" % ", ".join("%g" % x for x in needed if x not in per)
        self.put(1, val, passed, {"per_rate": det, "strict_pass_all": all(d["strict_pass"] for _, d in rows),
                                  "thresholds": {"rate_err_pct": FID_RATE_ERR, "dev_p99_us": FID_DEV_P99_US}})
        fig, ax = new_fig(1, ncols=2)
        a1, a2 = ax[0]
        x = np.arange(len(rows))
        a1.bar(x - 0.2, [d["dev_p99_us"] for _, d in rows], 0.4, color=BLUE, label="p99 inter-dequeue deviation")
        a1.bar(x + 0.2, [d["dev_p95_us"] for _, d in rows], 0.4, color="#7fa7d6", label="p95 deviation")
        for i, (_, d) in enumerate(rows):
            a1.hlines(d["mtu_time_us"], i - 0.42, i + 0.42, color=ORANGE, lw=2.2, zorder=5,
                      label="1 MTU serialisation time (strict)" if i == 0 else None)
        a1.axhline(FID_DEV_P99_US, color=RED, ls="--", label="adopted budget 5 ms")
        a1.set_yscale("log")
        a1.set_xticks(x)
        a1.set_xticklabels(["%g Mbit/s" % rt for rt, _ in rows])
        a1.set_ylabel("deviation from ideal dequeue gap (µs, log)")
        a1.legend(fontsize=7.5)
        a2.bar(x, [d["rate_err_pct"] for _, d in rows], 0.5, color=BLUE)
        for s in (-FID_RATE_ERR, FID_RATE_ERR):
            a2.axhline(s, color=RED, ls="--")
        a2.set_xticks(x)
        a2.set_xticklabels(["%g Mbit/s" % rt for rt, _ in rows])
        a2.set_ylabel("rate error (%)")
        a2.set_title("emulated-modem rate error (±4% budget)")
        a1.set_title("dequeue timing (N files: %s)" % ", ".join(str(d["n_files"]) for _, d in rows))
        finish(fig, path, 1, passed, "Software emulation (QEMU TCG): the strict criterion is expected to fail and is reported as such.")

    # ------------------------------------------------ M2
    def m2(self):
        path = os.path.join(self.figs, "m02.png")
        vals = {c: [(call_metrics(x, "call", self.H) or {}).get("added_p99_ms") for x in self.runs_of("S1", c)] for c in CONFIGS}
        jit = {c: [(call_metrics(x, "call", self.H) or {}).get("jitter_ms") for x in self.runs_of("S1", c)] for c in CONFIGS}
        los = {c: [100 * (call_metrics(x, "call", self.H) or {}).get("loss_load", float("nan")) for x in self.runs_of("S1", c)] for c in CONFIGS}
        if not any(fnum(v) is not None for vv in vals.values() for v in vv):
            self.put(2, "pending: no data", None, {})
            pending_fig(path, 2)
            return
        det = {c: {"p99_added_ms": self.summ(vals[c]), "jitter_ms": self.summ(jit[c]), "loss_pct": self.summ(los[c])}
               for c in CONFIGS if any(fnum(v) is not None for v in vals[c])}
        c3 = [v for v in vals["C3"] if fnum(v) is not None]
        c0 = [v for v in vals["C0"] if fnum(v) is not None]
        cmp30 = self.cmp.get(("C3", "C0"), {}).get("S1")
        passed, why = None, ""
        if len(c3) >= MIN_REPS_TEST and len(c0) >= MIN_REPS_TEST and cmp30:
            passed = bool(np.median(c3) <= ADDED_THR and cmp30["med_a"] < cmp30["med_b"] and cmp30["p_holm"] < 0.05)
        else:
            why = "pending: C3 N=%d, C0 N=%d (need >= %d each)" % (len(c3), len(c0), MIN_REPS_TEST)
        diffs = {}
        for b in ("C0", "C1", "C2"):
            cm = self.cmp.get(("C3", b), {}).get("S1")
            if cm:
                diffs["C3-" + b] = {"diff_median_ms": r(cm["diff"]), "ci95": [r(cm["ci"][0]), r(cm["ci"][1])],
                                    "p": r(cm["p"], 4), "p_holm": r(cm["p_holm"], 4), "cliffs_delta": r(cm["cliff"]),
                                    "holm_family_size": cm["family_size"]}
        det["comparisons"] = diffs
        parts = []
        for c in CONFIGS:
            v = [x for x in vals[c] if fnum(x) is not None]
            if v:
                parts.append("%s %s" % (c, self.ci_str(v)))
        val = "call p99 added delay: " + "; ".join(parts)
        for k, d in diffs.items():
            val += "; %s = %s ms [CI %s, %s], Holm p=%s" % (k, fmt(d["diff_median_ms"], 1), fmt(d["ci95"][0], 1),
                                                          fmt(d["ci95"][1], 1), fmt(d["p_holm"], 4))
        if why:
            val += " | " + why
        self.put(2, val, passed, det)
        fig, ax = new_fig(2, ncols=3)
        cfg_points(ax[0][0], vals, "call p99 added one-way delay (ms)", self.S, ADDED_THR, "15 ms")
        ax[0][0].set_title("p99 OWD (load) − median OWD (pre-load)")
        cfg_points(ax[0][1], jit, "RFC 3550 jitter (ms)", self.S)
        ax[0][1].set_title("mean running RFC 3550 jitter, load window")
        cfg_points(ax[0][2], los, "downstream loss in load window (%)", self.S)
        ax[0][2].set_title("call packet loss (missing seq = lost)")
        for a in ax[0]:
            for lb in a.get_xticklabels():
                lb.set_rotation(20)
        sub = "Points = reps; black = median with bootstrap 95% CI (10k resamples)."
        if cmp30:
            sub += "  C3 vs C0: Δmedian %.1f ms, Holm p=%.3g, Cliff's δ=%.2f" % (cmp30["diff"], cmp30["p_holm"], cmp30["cliff"])
        finish(fig, path, 2, passed, sub)

    # ------------------------------------------------ M3
    def m3(self):
        path = os.path.join(self.figs, "m03.png")
        vals = {c: [(call_metrics(x, "call", self.H) or {}).get("added_p99_ms") for x in self.runs_of("S1x32", c)] for c in CONFIGS}
        c3 = [v for v in vals["C3"] if fnum(v) is not None]
        if not any(fnum(v) is not None for vv in vals.values() for v in vv):
            self.put(3, "pending: no data", None, {})
            pending_fig(path, 3)
            return
        passed = bool(np.median(c3) <= X32_THR) if c3 else None
        val = "; ".join("%s %s" % (c, self.ci_str(vals[c])) for c in CONFIGS if any(fnum(v) is not None for v in vals[c]))
        if not c3:
            val += " | pending: no C3 runs"
        self.put(3, "call p99 added delay: " + val, passed, {c: self.summ(vals[c]) for c in CONFIGS})
        fig, ax = new_fig(3)
        cfg_points(ax[0][0], vals, "call p99 added one-way delay (ms)", self.S, X32_THR, "10 ms")
        finish(fig, path, 3, passed, "S1 with 32 parallel bulk TCP flows; points = reps, black = median ± bootstrap 95% CI")

    # ------------------------------------------------ M4
    def m4(self):
        path = os.path.join(self.figs, "m04.png")
        per = {c: [s2_metrics(x, self.H) for x in self.runs_of("S2", c)] for c in CONFIGS}
        per = {c: [m for m in v if m] for c, v in per.items()}
        if not any(per.values()):
            self.put(4, "pending: no data", None, {})
            pending_fig(path, 4)
            return
        det, parts = {}, []
        inf = lambda x: float("inf") if x is None else x
        for c in CONFIGS:
            ms = per[c]
            if not ms:
                continue
            d = {"n": len(ms), "runs": [{k: (r(v) if isinstance(v, float) else v) for k, v in m.items()} for m in ms]}
            if c in ("C0", "C1"):
                d["t_adapt"] = "never (no adaptive shaper)"
                d["low_phase_added_p99_ms"] = self.summ([m.get("low_phase_added_p99_ms") for m in ms])
                parts.append("%s T_adapt never, low-phase p99 added %s" % (c, self.ci_str([m.get("low_phase_added_p99_ms") for m in ms])))
            else:
                ta = [inf(m.get("t_adapt_s")) for m in ms]
                rc = [inf(m.get("recovery_s")) for m in ms]
                cpm = [m.get("changes_per_min") for m in ms]
                d.update(t_adapt_median_s=r(np.median(ta)), recovery_median_s=r(np.median(rc)),
                         changes_per_min_median=r(np.median(cpm)), t_adapt_s=self.summ([x for x in ta if math.isfinite(x)]),
                         recovery_s=self.summ([x for x in rc if math.isfinite(x)]), changes_per_min=self.summ(cpm),
                         low_phase_added_p99_ms=self.summ([m.get("low_phase_added_p99_ms") for m in ms]))
                d["pass"] = bool(np.median(ta) <= T_ADAPT_MAX and np.median(rc) <= RECOVERY_MAX and np.median(cpm) <= CHANGES_MAX)
                parts.append("%s T_adapt %s, recovery %s, %s changes/min (medians, N=%d)%s" % (
                    c, fmt(np.median(ta), 2, " s") if math.isfinite(np.median(ta)) else "never",
                    fmt(np.median(rc), 1, " s") if math.isfinite(np.median(rc)) else "never", fmt(np.median(cpm), 1), len(ms),
                    "" if c == "C3" else " [%s]" % verdict_str(d["pass"])))
            det[c] = d
        caps = sorted({(m.get("cap_down"), m.get("cap_up")) for ms in per.values() for m in ms})
        det["capacity_steps_mbps"] = caps
        if any(cu and cu != 50 for _, cu in caps):
            note("S2: capacity step taken from meta events (rate_down.down, rate_up.down) = %s; the run.py header "
                 "describes 50->10->50 but some runs used other values (older harness)" % caps)
        passed = det.get("C3", {}).get("pass")
        val = "; ".join(parts) + ("" if "C3" in det else " | pending: no C3 runs (pass judged on C3)")
        self.put(4, val, passed, det)
        # figure: representative time series + metric bars
        fig, ax = new_fig(4, ncols=2)
        a1, a2 = ax[0]
        rep = None
        for c in ("C3", "C4", "C2"):
            if self.runs_of("S2", c):
                rep = self.runs_of("S2", c)[0]
                break
        if rep is not None:
            t0 = rep.t("start")
            ts, rs, src = step_series(rep.telemetry(), rep.ctl_events())
            rt = rep.rt("call")
            if rt is not None:
                a1b = a1.twinx()
                a1b.plot(rt["t"] - t0, rt["owd"], ".", ms=1, color=ORANGE, alpha=0.35)
                a1b.set_ylabel("call one-way delay (ms)", color=ORANGE)
                a1b.spines["right"].set_visible(True)
                a1b.grid(False)
            if ts is not None:
                a1.step(ts - t0, rs, where="post", color=BLUE, lw=1.8, label="shaper rate r_dl (%s)" % src)
            tl = rep.telemetry()
            if tl is not None:
                a1.plot(tl["t"] - t0, tl["c_dl"], color=GREEN, lw=0.9, alpha=0.8, label="capacity estimate c_dl")
            for nm, ls in (("rate_down", "--"), ("rate_up", ":")):
                if rep.t(nm):
                    a1.axvline(rep.t(nm) - t0, color=RED, ls=ls, lw=1)
                    cap = rep.ev[nm].get("down")
                    a1.hlines(0.95 * cap, rep.t(nm) - t0, rep.t(nm) - t0 + 20, color=RED, lw=0.8, alpha=0.6)
                    a1.text(rep.t(nm) - t0, a1.get_ylim()[1] if a1.get_ylim()[1] > 1 else 1, " %s -> %s Mbit/s" % (nm, cap),
                            fontsize=7.5, color=RED, va="top")
            a1.set_xlabel("time since start (s)")
            a1.set_ylabel("Mbit/s")
            a1.legend(loc="upper right", fontsize=7.5)
            a1.set_title("representative run %s" % rep.id)
        names = [c for c in ("C2", "C3", "C4") if c in det]
        x = np.arange(3)
        w = 0.8 / max(1, len(names))
        for i, c in enumerate(names):
            ms = per[c]
            series = [[inf(m.get("t_adapt_s")) for m in ms], [inf(m.get("recovery_s")) for m in ms],
                      [m.get("changes_per_min") for m in ms]]
            for j, s in enumerate(series):
                fin = [v for v in s if fnum(v) is not None]
                med = float(np.median(s))
                if not math.isfinite(med):
                    a2.text(j + (i - (len(names) - 1) / 2) * w, 0.5, "never", rotation=90, ha="center", fontsize=8, color=CFG_COLOR[c])
                    continue
                lo, hi = self.S.boot_ci(fin) if len(fin) == len(s) else (float("nan"), float("nan"))
                yerr = [[med - lo], [hi - med]] if fnum(lo) is not None else None
                a2.bar(j + (i - (len(names) - 1) / 2) * w, med, w, color=CFG_COLOR[c], yerr=yerr, capsize=3,
                       label=("%s (N=%d)" % (CFG_LABEL[c], len(ms))) if j == 0 else None)
        for j, thr in enumerate((T_ADAPT_MAX, RECOVERY_MAX, CHANGES_MAX)):
            a2.hlines(thr, j - 0.45, j + 0.45, color=RED, ls="--")
        a2.set_xticks(x)
        a2.set_xticklabels(["T_adapt (s)\n≤ 2", "recovery (s)\n≤ 30", "dl rate changes/min\n≤ 6"])
        a2.set_yscale("symlog", linthresh=1)
        a2.set_title("medians over reps (bootstrap 95% CI)")
        a2.legend(fontsize=7.5)
        finish(fig, path, 4, passed, "T_adapt: r_dl within ±10%% of 0.95·C_new AND 1-s sliding call p95 OWD ≤ pre-load median + 15 ms, sustained %.0f s" % SUSTAIN_S)

    # ------------------------------------------------ M5
    def m5(self):
        path = os.path.join(self.figs, "m05.png")
        per = {}
        for scn, d in self.by.items():
            m = re.match(r"EST(\d+(?:\.\d+)?)$", scn)
            if not m:
                continue
            for c, rs in d.items():
                for x in rs:
                    if not est_valid(x):
                        note("%s: EST run without meta plan_dl = 1.3 x down (plan_dl=%s, down=%s; old plan-80 harness) "
                             "-> ignored for M5" % (x.id, x.meta.get("plan_dl"), x.meta.get("down")))
                        continue
                    em = est_metrics(x)
                    if em and em.get("err") is not None:
                        per.setdefault(float(m.group(1)), {}).setdefault(c, []).append(em)
        if not per:
            self.put(5, "pending: no data", None, {})
            pending_fig(path, 5)
            return
        det, parts = {}, []
        for rate in sorted(per):
            allm = [e for es in per[rate].values() for e in es]
            errs = [e["err"] for e in allm]
            d = {"true_mbps": rate, "err": self.summ(errs), "c_est": self.summ([e["c_est"] for e in allm]),
                 "configs": {c: len(v) for c, v in per[rate].items()}}
            d["pass"] = bool(np.median(errs) <= EST_ERR_MAX)
            det["%g" % rate] = d
            parts.append("%g Mbit/s: err %s" % (rate, self.ci_str([100 * e for e in errs], 1, "%")))
        have = all(float(x) in per for x in EST_RATES)
        passed = all(det["%g" % x]["pass"] for x in EST_RATES) if have else (False if any(not d["pass"] for d in det.values()) else None)
        val = "; ".join(parts)
        if not have:
            val += " | pending rates: %s" % ", ".join(str(x) for x in EST_RATES if float(x) not in per)
        self.put(5, val, passed, det)
        fig, ax = new_fig(5)
        a = ax[0][0]
        rates = sorted(per)
        for i, rate in enumerate(rates):
            errs = [100 * e["err"] for es in per[rate].values() for e in es]
            med = np.median(errs)
            lo, hi = self.S.boot_ci(errs)
            a.bar(i, med, 0.55, color=BLUE, yerr=[[med - lo], [hi - med]] if fnum(lo) is not None else None, capsize=4)
            a.scatter(i + (np.arange(len(errs)) - (len(errs) - 1) / 2) * 0.04, errs, color=ORANGE, s=14, zorder=4)
            a.annotate("%.1f%%\nN=%d" % (med, len(errs)), (i, med), ha="center", va="bottom", fontsize=8)
        a.axhline(100 * EST_ERR_MAX, color=RED, ls="--", label="10% threshold")
        a.set_xticks(range(len(rates)))
        a.set_xticklabels(["%g Mbit/s" % x for x in rates])
        a.set_ylabel("|c_est − true| / true (%)")
        a.legend()
        finish(fig, path, 5, passed, "c_est = median of non-zero telemetry c_dl over the last 10 s; true = meta.down. Bars = median ± bootstrap 95% CI, dots = reps")

    # ------------------------------------------------ M6
    def m6(self):
        path = os.path.join(self.figs, "m06.png")
        per = {c: [s3_metrics(x, self.H) for x in self.runs_of("S3", c)] for c in CONFIGS}
        gam = {c: [(m.get("game") or {}).get("added_p99_ms") for m in v] for c, v in per.items()}
        jn = {c: [m.get("jain") for m in v] for c, v in per.items()}
        if not any(fnum(x) is not None for v in list(gam.values()) + list(jn.values()) for x in v):
            self.put(6, "pending: no data", None, {"tv_ladder": self.H.get("tv_ladder"), "game_down_mbps": self.H.get("game_down_mbps")})
            pending_fig(path, 6)
            return
        det = {c: {"game_p99_added_ms": self.summ(gam[c]), "jain": self.summ(jn[c]),
                   "runs": [{"R": r(m.get("R")), "R_src": m.get("R_src"), "threshold_at_0.95_down_mbps": r(m.get("thr_nominal")), "share": [r(s) for s in m.get("share", [])],
                             "x": [r(s) for s in m.get("x", [])],
                             "tv": {h: {k: r(v) for k, v in g.items()} for h, g in (m.get("tv") or {}).items()}} for m in per[c]]}
               for c in CONFIGS if per[c]}
        g3 = [x for x in gam["C3"] if fnum(x) is not None]
        j3 = [x for x in jn["C3"] if fnum(x) is not None]
        passed = bool(np.median(g3) <= ADDED_THR and np.median(j3) >= JAIN_MIN) if g3 and j3 else None
        val = "; ".join("%s game p99 added %s, Jain %s" % (c, self.ci_str(gam[c]), self.ci_str(jn[c], 3, ""))
                        for c in CONFIGS if per[c])
        if passed is None:
            val += " | pending: C3 data incomplete"
        self.put(6, val, passed, det)
        fig, ax = new_fig(6, ncols=2)
        cfg_points(ax[0][0], gam, "gaming p99 added one-way delay (ms)", self.S, ADDED_THR, "15 ms")
        cfg_points(ax[0][1], jn, "Jain index of x_i = goodput_i / max-min share_i", self.S, JAIN_MIN, "0.9", nd=3)
        ax[0][1].set_ylim(0, 1.05)
        for a in ax[0]:
            for lb in a.get_xticklabels():
                lb.set_rotation(20)
        finish(fig, path, 6, passed, "3 DASH-like TVs (demand = top ladder rung) + gaming flow; fair share = max-min of (shaper rate − gaming rate)")

    # ------------------------------------------------ M7
    def m7(self):
        path = os.path.join(self.figs, "m07.png")
        per = {c: [(x.id, s4_metrics(x)) for x in self.runs_of("S4", c)] for c in CONFIGS}
        per = {c: v for c, v in per.items() if v}
        if not per:
            self.put(7, "pending: no data", None, {})
            pending_fig(path, 7)
            return
        det, parts, allok = {}, [], []
        for c, ms in per.items():
            rows = []
            for rid, m in ms:
                gok, eok = m.get("goodput_ok"), m.get("expiry_ok")
                ok = (bool(gok and eok) if gok is not None and eok is not None else None)
                if c in ("C3", "C4"):
                    allok.append(ok)
                rows.append({"run": rid, "min_1s_mbps": r(m.get("min_1s_mbps")), "threshold_mbps": r(m.get("thr")),
                             "R": r(m.get("R")), "R_src": m.get("R_src"), "threshold_at_0.95_down_mbps": r(m.get("thr_nominal")), "after_grant_s": r(m.get("after_grant_s")),
                             "ttl": m.get("ttl"), "goodput_ok": gok, "expiry_ok": eok, "pass": ok,
                             "abuse_mean_mbps": r(m.get("abuse_mean_mbps")), "note": m.get("expiry_note")})
                parts.append("%s: min 1-s bulk %s Mbit/s vs %s needed; lease expired %s s after grant (TTL %s)" % (
                    rid, fmt(m.get("min_1s_mbps"), 2), fmt(m.get("thr"), 2), fmt(m.get("after_grant_s"), 2), m.get("ttl")))
            det[c] = rows
        if not allok:
            passed = None
            parts.append("pending: no C3/C4 runs")
        elif any(o is None for o in allok):
            passed = None if not any(o is False for o in allok) else False
        else:
            passed = all(allok)
        self.put(7, "; ".join(parts) + " (pass requires every C3/C4 rep to meet both)", passed, det)
        fig, ax = new_fig(7, ncols=2)
        a1, a2 = ax[0]
        k = 0
        for c, ms in per.items():
            for rid, m in ms:
                if m.get("series"):
                    a1.step(m["series_t"], m["series"], where="post", lw=1.4, label="%s bulk goodput" % rid,
                            color=[BLUE, ORANGE, GREEN, GREY][k % 4])
                    k += 1
        th = [m.get("thr") for ms in per.values() for _, m in ms if m.get("thr")]
        ttl = [m.get("ttl") for ms in per.values() for _, m in ms if m.get("ttl")]
        if th:
            a1.axhline(th[0], color=RED, ls="--", label="0.8·R/16 = %.2f Mbit/s" % th[0])
        if ttl:
            a1.axvspan(0, ttl[0], color=ORANGE, alpha=0.08, label="lease window (TTL %g s)" % ttl[0])
        a1.set_xlabel("time since lease grant (s)")
        a1.set_ylabel("victim bulk goodput, 1-s iperf3 intervals (Mbit/s)")
        a1.legend(fontsize=7.5)
        names, ag, tt = [], [], []
        for c, ms in per.items():
            for rid, m in ms:
                names.append(rid)
                ag.append(m.get("after_grant_s") or 0)
                tt.append(m.get("ttl") or 0)
        a2.bar(range(len(names)), ag, 0.45, color=BLUE, label="kernel lease removal after grant")
        a2.set_xlim(-0.8, len(names) - 0.2)
        for i, t_ in enumerate(tt):
            a2.hlines(t_ + 1, i - 0.4, i + 0.4, color=RED, ls="--", label="TTL + 1 s" if i == 0 else None)
        a2.set_xticks(range(len(names)))
        a2.set_xticklabels(names, rotation=20, fontsize=8)
        a2.set_ylabel("seconds")
        a2.legend(fontsize=7.5)
        a2.set_title("lease expiry with controller killed")
        finish(fig, path, 7, passed, "R = shaper rate in force (median telemetry r_dl in the lease window, else 0.95·meta.down)")

    # ------------------------------------------------ M8
    def m8(self):
        path = os.path.join(self.figs, "m08.png")
        fn = os.path.join(self.res, "classifier", "eval.json")
        j = load_json(fn)
        if not isinstance(j, dict):
            self.put(8, "pending: no data", None, {"expected_file": "results/classifier/eval.json"})
            pending_fig(path, 8, "pending: no data (results/classifier/eval.json absent)")
            return
        g = lambda k: fnum(j.get(k))
        ece, f1n, f1h, f1t = g("ece_chosen"), g("macro_f1_no_ttl"), g("macro_f1_heuristic"), g("macro_f1_with_ttl")
        missing = [k for k, v in (("ece_chosen", ece), ("macro_f1_no_ttl", f1n), ("macro_f1_heuristic", f1h)) if v is None]
        passed = None if missing else bool(ece <= ECE_MAX and f1n > f1h)
        det = {k: j.get(k) for k in ("macro_f1_with_ttl", "macro_f1_no_ttl", "macro_f1_heuristic", "ece_raw", "ece_isotonic",
                                     "ece_temperature", "ece_chosen", "split", "n_flows", "per_class", "confusion")}
        val = "macro-F1 no-TTL %s vs heuristic %s (with TTL %s); ECE chosen %s (raw %s); split=%s, n_flows=%s" % (
            fmt(f1n, 3), fmt(f1h, 3), fmt(f1t, 3), fmt(ece, 3), fmt(g("ece_raw"), 3), j.get("split"), j.get("n_flows"))
        if missing:
            val += " | pending: missing keys %s" % missing
        self.put(8, val, passed, det)
        fig, ax = new_fig(8, ncols=2)
        a1, a2 = ax[0]
        bins = j.get("reliability_bins") or j.get("reliability") or j.get("reliability_diagram")
        conf, acc, cnt = self._rel_bins(bins)
        a1.plot([0, 1], [0, 1], color=GREY, ls="--", label="perfect calibration")
        if conf:
            a1.plot(conf, acc, "o-", color=BLUE, label="chosen calibration")
            if cnt:
                a1b = a1.twinx()
                a1b.bar(conf, cnt, width=0.05, color=ORANGE, alpha=0.25)
                a1b.set_ylabel("flows per bin", color=ORANGE)
                a1b.grid(False)
        else:
            a1.text(0.5, 0.5, "no reliability bins in eval.json", ha="center", color=GREY)
        a1.set_xlabel("predicted confidence")
        a1.set_ylabel("observed accuracy")
        a1.set_title("reliability diagram (ECE chosen = %s)" % fmt(ece, 3))
        a1.legend(loc="upper left")
        labels = ["with TTL", "no TTL", "heuristic"]
        vv = [f1t, f1n, f1h]
        a2.bar(range(3), [v or 0 for v in vv], color=[BLUE, BLUE, ORANGE])
        for i, v in enumerate(vv):
            a2.text(i, (v or 0) + 0.01, fmt(v, 3), ha="center")
        a2.set_xticks(range(3))
        a2.set_xticklabels(labels)
        a2.set_ylim(0, 1.05)
        a2.set_ylabel("macro-F1")
        a2.set_title("held-out macro-F1 (split: %s, n=%s)" % (j.get("split"), j.get("n_flows")))
        finish(fig, path, 8, passed)

    @staticmethod
    def _rel_bins(bins):
        conf, acc, cnt = [], [], []
        if isinstance(bins, dict):
            conf = bins.get("conf") or bins.get("confidence") or bins.get("mean_pred") or []
            acc = bins.get("acc") or bins.get("accuracy") or bins.get("frac_pos") or []
            cnt = bins.get("count") or bins.get("n") or []
        elif isinstance(bins, list):
            for b in bins:
                if isinstance(b, dict):
                    c = b.get("conf", b.get("confidence", b.get("mean_pred")))
                    a = b.get("acc", b.get("accuracy", b.get("frac_pos")))
                    if c is not None and a is not None:
                        conf.append(c), acc.append(a), cnt.append(b.get("count", b.get("n", 0)))
                elif isinstance(b, (list, tuple)) and len(b) >= 2:
                    conf.append(b[0]), acc.append(b[1]), cnt.append(b[2] if len(b) > 2 else 0)
        return list(conf), list(acc), list(cnt) if any(cnt) else []

    # ------------------------------------------------ M9
    def m9(self):
        path = os.path.join(self.figs, "m09.png")
        spec = (("S1", "call"), ("S3", "game"), ("S5", "call"))
        res, ns = {}, {}
        for scn, flow in spec:
            a = [(call_metrics(x, flow, self.H) or {}).get("added_p99_ms") for x in self.runs_of(scn, "C3")]
            b = [(call_metrics(x, flow, self.H) or {}).get("added_p99_ms") for x in self.runs_of(scn, "C4")]
            a = [v for v in a if fnum(v) is not None]
            b = [v for v in b if fnum(v) is not None]
            ns[scn] = (len(a), len(b))
            if a and b:
                d, lo, hi = self.S.boot_diff(a, b)             # C4 - C3 (negative = ML better)
                res[scn] = {"n_c3": len(a), "n_c4": len(b), "median_c3": r(np.median(a)), "median_c4": r(np.median(b)),
                            "diff_c4_minus_c3_ms": r(d), "ci95": [r(lo), r(hi)], "metric": "%s p99 added delay" % flow}
        valid = all(ns[s][0] >= MIN_REPS_TEST and ns[s][1] >= MIN_REPS_TEST for s, _ in spec)
        if not res:
            self.put(9, "pending: no data", None, {"n_reps(C3,C4)": ns})
            pending_fig(path, 9)
            return
        outcome = None
        if valid:
            better = [s for s, d in res.items() if fnum(d["ci95"][1]) is not None and d["ci95"][1] < 0]
            worse = [s for s, d in res.items() if fnum(d["ci95"][0]) is not None and d["ci95"][0] > 0]
            outcome = "ML ships" if better and not worse else "deterministic heuristic ships"
        passed = True if valid else None
        val = ("gate outcome: %s; " % outcome if outcome else "gate not evaluable yet (need >= %d reps of C3 and C4 in S1,S3,S5; have %s); " % (
            MIN_REPS_TEST, {s: "%d/%d" % n for s, n in ns.items()})) + "; ".join(
            "%s C4−C3 = %s ms [CI %s, %s] (N=%d/%d)" % (s, fmt(d["diff_c4_minus_c3_ms"], 1), fmt(d["ci95"][0], 1), fmt(d["ci95"][1], 1),
                                                       d["n_c3"], d["n_c4"]) for s, d in res.items())
        self.put(9, val, passed, {"per_scenario": res, "n_reps(C3,C4)": ns, "outcome": outcome})
        fig, ax = new_fig(9)
        a = ax[0][0]
        ss = [s for s, _ in spec]
        for i, s in enumerate(ss):
            d = res.get(s)
            if not d:
                a.text(0, i, "  %s: no paired data" % s, va="center", color=GREY)
                continue
            lo, hi = d["ci95"]
            if fnum(lo) is not None:
                a.errorbar(d["diff_c4_minus_c3_ms"], i, xerr=[[d["diff_c4_minus_c3_ms"] - lo], [hi - d["diff_c4_minus_c3_ms"]]],
                           fmt="o", color=BLUE, capsize=5)
            else:
                a.plot(d["diff_c4_minus_c3_ms"], i, "o", color=BLUE)
            a.annotate("  N=%d/%d" % (d["n_c3"], d["n_c4"]), (d["diff_c4_minus_c3_ms"], i), fontsize=8, va="bottom")
        a.axvline(0, color=GREY)
        a.set_yticks(range(len(ss)))
        a.set_yticklabels(["%s (%s p99 added)" % (s, f) for s, f in spec])
        a.set_xlabel("C4 (ML) − C3 (heuristic), difference of medians (ms); < 0 = ML better")
        a.set_title("outcome: %s" % (outcome or "not evaluable (insufficient reps)"))
        finish(fig, path, 9, passed, "bootstrap 95% CI of the difference of medians over reps")

    # ------------------------------------------------ M10
    def m10(self):
        path = os.path.join(self.figs, "m10.png")
        rows = []
        for c in CONFIGS:
            for x in self.runs_of("S5", c):
                m = s5_metrics(x)
                if m:
                    rows.append((x, m))
        rows = [(x, m) for x, m in rows if x.cfg in ("C3", "C4")] or rows
        if not rows:
            self.put(10, "pending: no data", None, {})
            pending_fig(path, 10)
            return
        lat = [m.get("latency_s") for _, m in rows if m.get("latency_s") is not None]
        det = {"runs": [{"run": x.id, "latency_s": r(m.get("latency_s")), "source": m.get("source"),
                         "evidence": [[e, r(v)] for e, v in m.get("evidence", [])], "api_roundtrip_s": r(m.get("api_roundtrip_s")),
                         "voice_tin_pkts_before_after": m.get("voice_tin_pkts"), "qoe_recovered_s": r(m.get("qoe_recovered_s"))}
                        for x, m in rows], "latency_s": self.summ(lat)}
        passed = bool(np.median(lat) <= OVR_MAX) if lat else None
        val = ("override latency %s (source: %s)" % (self.ci_str(lat, 2, " s"), "; ".join(sorted({m.get("source") or "-" for _, m in rows})))
               if lat else "pending: no latency evidence")
        self.put(10, val, passed, det)
        fig, ax = new_fig(10)
        a = ax[0][0]
        for i, (x, m) in enumerate(rows):
            for k, (e, v) in enumerate(m.get("evidence", [])):
                a.bar(i + (k - 0.5) * 0.25, v, 0.25, color=[BLUE, ORANGE, GREEN][k % 3], label=e if i == 0 else None)
            if m.get("qoe_recovered_s") is not None:
                a.plot(i, m["qoe_recovered_s"], "kx", ms=8, label="call p95 back ≤ pre+15 ms (data plane)" if i == 0 else None)
        a.axhline(OVR_MAX, color=RED, ls="--", label="1 s threshold")
        a.set_xlim(-0.8, len(rows) - 0.2)
        a.set_xticks(range(len(rows)))
        a.set_xticklabels([x.id for x, _ in rows], rotation=15)
        a.set_ylabel("seconds after POST /v1/overrides")
        a.legend(fontsize=7.5)
        finish(fig, path, 10, passed, "primary latency = first available evidence (kernel tin counters > ctl event > legacy meta field)")

    # ------------------------------------------------ M11
    def m11(self):
        path = os.path.join(self.figs, "m11.png")
        rows = [(x, s6_metrics(x)) for c in ("C3", "C4", "C2") for x in self.runs_of("S6", c)]
        if not rows:
            self.put(11, "pending: no data", None, {})
            pending_fig(path, 11)
            return
        rb = [m.get("restore_s") for _, m in rows if m.get("restore_s") is not None]
        dt = [m.get("detect_s") for _, m in rows if m.get("detect_s") is not None]
        sf = [m.get("safe_s") for _, m in rows if m.get("safe_s") is not None]
        det = {"runs": [dict(run=x.id, **{k: (r(v) if isinstance(v, float) else v) for k, v in m.items()}) for x, m in rows],
               "restore_s": self.summ(rb), "detect_s_health_window": self.summ(dt), "safe_s": self.summ(sf),
               "definitions": {"restore_s": "rollback event rollback_s: REGRESSED verdict -> LKG re-applied and read back (criterion)",
                               "detect_s": "rollback event detect_s: bad policy applied -> REGRESSED verdict (health window; "
                                           "bounded below by the controller's 1.5 s early check; not part of the criterion)"}}
        rb_ok = bool(max(rb) <= RB_MAX) if rb else None
        sf_ok = bool(max(sf) <= SAFE_MAX) if sf else None
        if rb_ok is False or sf_ok is False:
            passed = False
        elif rb_ok is None or sf_ok is None:
            passed = None
        else:
            passed = True
        det["rollback_pass"], det["safe_pass"] = rb_ok, sf_ok
        val = "restore after REGRESSED verdict %s%s; SAFE after kill -9 %s (worst-case rep must meet threshold)" % (
            self.ci_str(rb, 2, " s") if rb else "pending: no rollback events (%s)" % "; ".join(
                sorted({m.get("rollback_note", "") for _, m in rows if m.get("rollback_note")})),
            (" (detection/health window %s, not judged)" % self.ci_str(dt, 2, " s")) if dt else "",
            self.ci_str(sf, 2, " s") if sf else "pending: no watchdog_trip.json")
        self.put(11, val, passed, det)
        fig, ax = new_fig(11, ncols=2)
        a1, a2 = ax[0]
        for i, (x, m) in enumerate(rows):
            if m.get("restore_s") is not None or m.get("detect_s") is not None:
                if m.get("detect_s") is not None:
                    a1.bar(i - 0.13, m["detect_s"], 0.25, color=LGREY,
                           label="detection = health window (apply → verdict; not judged)" if i == 0 else None)
                if m.get("restore_s") is not None:
                    a1.bar(i + 0.13, m["restore_s"], 0.25, color=BLUE,
                           label="restore LKG after REGRESSED verdict (judged)" if i == 0 else None)
                    a1.text(i + 0.13, m["restore_s"], "%.2f s" % m["restore_s"], ha="center", va="bottom", fontsize=8)
            else:
                a1.text(i, 0.05, "no rollback\nevents", ha="center", fontsize=8, color=GREY)
            if m.get("safe_s") is not None:
                a2.bar(i, m["safe_s"], 0.5, color=BLUE)
                a2.text(i, m["safe_s"], "%.2f s" % m["safe_s"], ha="center", va="bottom", fontsize=8)
        a1.axhline(RB_MAX, color=RED, ls="--", label="restore limit 1 s")
        a2.axhline(SAFE_MAX, color=RED, ls="--", label="3 s")
        for a, t in ((a1, "seconds"), (a2, "kill -9 → SAFE state (s)")):
            a.set_xlim(-0.8, len(rows) - 0.2)
            a.set_xticks(range(len(rows)))
            a.set_xticklabels([x.id for x, _ in rows], rotation=15, fontsize=8)
            a.set_ylabel(t)
            a.legend(fontsize=7.5)
        finish(fig, path, 11, passed, "restore = rollback event rollback_s (verdict → LKG re-applied + read back); detection = detect_s "
               "(health window, ≥ 1.5 s by design); SAFE = watchdog_trip.t_safe − meta kill9.t")

    # ------------------------------------------------ M12
    def m12(self):
        path = os.path.join(self.figs, "m12.png")
        vals = {}
        for c in CONFIGS:
            for x in self.runs_of("CPU", c):
                cp = x.meta.get("cpu") or {}
                v = fnum(cp.get("ctl_pct_of_core"))
                if c in ("C0", "C1") and v is None:
                    v = 0.0                                         # no controller process
                if v is not None:
                    vals.setdefault(c, []).append(v)
        if not vals:
            self.put(12, "pending: no data", None, {})
            pending_fig(path, 12)
            return
        base = float(np.median(vals["C1"])) if vals.get("C1") else 0.0
        det = {c: self.summ(v) for c, v in vals.items()}
        det["baseline_C1"] = base
        det["ncpu"] = sorted({(x.meta.get("cpu") or {}).get("ncpu") for c in vals for x in self.runs_of("CPU", c)} - {None})
        det["softirq_pct"] = {c: self.summ([fnum((x.meta.get("cpu") or {}).get("softirq_pct")) for x in self.runs_of("CPU", c)]) for c in vals}
        ctl = [c for c in ("C3", "C4") if vals.get(c)]
        passed = all(np.median(vals[c]) - base <= CPU_MAX for c in ctl) if ctl else None
        val = "; ".join("%s %s of a core" % (c, self.ci_str(v, 2, "%")) for c, v in sorted(vals.items()))
        val += " (C1 baseline %.2f%%; platform software-emulated (TCG) -> pessimistic)" % base
        if not ctl:
            val += " | pending: no C3/C4 runs"
        self.put(12, val, passed, det)
        fig, ax = new_fig(12)
        cfg_points(ax[0][0], {c: [v - base for v in vals.get(c, [])] for c in CONFIGS}, "controller CPU − C1 (% of one core)",
                   self.S, CPU_MAX, "2% of a core")
        finish(fig, path, 12, passed, "measured over 20 s of loaded operation (CPU scenario, 50/10 Mbit/s); QEMU TCG emulation inflates CPU cost")

    # ------------------------------------------------ dashboard
    def dashboard(self):
        path = os.path.join(self.figs, "dashboard.png")
        cand, cfg_used = [], None
        for c in ("C3", "C4", "C2", "C1", "C0"):
            cand = [x for x in self.runs_of("S1", c) if (call_metrics(x, "call", self.H) or {}).get("added_p99_ms") is not None]
            if cand:
                cfg_used = c
                break
        fig, ax = plt.subplots(2, 3, figsize=(1600 / 150, 900 / 150), dpi=150)
        if not cand:
            for a in ax.flat:
                a.axis("off")
            ax[0][1].text(0.5, 0.5, "pending: no S1 data", ha="center", fontsize=16, color=GREY, transform=ax[0][1].transAxes)
            fig.suptitle("HALO-Walk dashboard — S1 — pending", fontweight="bold")
            fig.savefig(path, dpi=150)
            plt.close(fig)
            return
        v = [(call_metrics(x, "call", self.H) or {})["added_p99_ms"] for x in cand]
        med = np.median(v)
        run = cand[int(np.argmin([abs(a - med) for a in v]))]
        if cfg_used != "C3":
            note("dashboard: no S1/C3 run available; dashboard shows %s (labelled)" % run.id)
        cm = call_metrics(run, "call", self.H)
        pre, load = windows_for(run, "call")
        t0 = run.t("start") or run.rt("call")["t"][0]
        rt = run.rt("call")
        tt = rt["t"] - t0
        lo = (run.t("load_on") or t0) - t0

        def mark(a):
            a.axvspan(lo, lo + WARMUP_S, color=GREY, alpha=0.08)
            a.axvline(lo, color=RED, lw=0.8, ls="--")
            a.set_xlabel("time since start (s)")
        bins = np.arange(np.floor(tt.min()), np.ceil(tt.max()) + 1, 1.0)
        idx = np.digitize(tt, bins) - 1
        bc = bins[:-1] + 0.5
        p50 = np.array([np.percentile(rt["owd"][idx == i], 50) if (idx == i).sum() > 3 else np.nan for i in range(len(bc))])
        p99 = np.array([np.percentile(rt["owd"][idx == i], 99) if (idx == i).sum() > 3 else np.nan for i in range(len(bc))])
        a = ax[0][0]
        a.plot(tt, rt["owd"], ".", ms=1, color=BLUE, alpha=0.25)
        a.plot(bc, p50, color=BLUE, lw=1.5, label="p50 (1 s)")
        a.plot(bc, p99, color=ORANGE, lw=1.5, label="p99 (1 s)")
        if fnum(cm.get("pre_median_ms")) is not None:
            a.axhline(cm["pre_median_ms"] + ADDED_THR, color=RED, ls=":", lw=1, label="pre-load median + 15 ms")
        a.set_ylabel("call one-way delay (ms)")
        a.set_title("Latency (p99 added %.1f ms)" % cm["added_p99_ms"])
        a.legend(fontsize=7)
        mark(a)
        a = ax[0][1]
        order = np.argsort(rt["seq"], kind="stable")
        jr = rfc3550_running(rt["owd"][order])
        a.plot(tt[order], jr, color=BLUE, lw=1)
        a.set_ylabel("RFC 3550 jitter J (ms)")
        a.set_title("Jitter (mean in load window %.2f ms)" % cm.get("jitter_ms", float("nan")))
        mark(a)
        a = ax[0][2]
        model = send_model(rt, self.H.get("call_pps_down"))
        if model:
            ls = [100 * window_loss(rt, model, t0 + b, t0 + b + 1.0) for b in bins[:-1]]
            a.bar(bc, ls, 0.9, color=ORANGE)
        a.set_ylabel("call packet loss per 1 s (%)")
        a.set_title("Loss (load window %.2f%%)" % (100 * cm.get("loss_load", float("nan"))))
        mark(a)
        a = ax[1][0]
        ip = run.iperf("bulk")
        if ip:
            a.step(ip["ts"] - t0, ip["mbps"], where="post", color=BLUE, lw=1.5, label="bulk goodput (iperf3, 8 flows)")
        tel = run.telemetry()
        if tel is not None:
            a.plot(tel["t"] - t0, tel["r_dl"], color=ORANGE, lw=1.2, label="shaper rate r_dl")
            a.plot(tel["t"] - t0, tel["ach_dl"], color=GREEN, lw=0.8, alpha=0.7, label="achieved dl (ctl EWMA)")
        a.set_ylabel("Mbit/s")
        a.set_title("Throughput")
        a.legend(fontsize=7)
        mark(a)
        a = ax[1][1]
        if tel is not None:
            a.plot(tel["t"] - t0, tel["d_dl"], color=BLUE, lw=1)
            a.axhline(15, color=RED, ls=":", lw=1, label="controller bloat threshold 15 ms")
            a.set_ylabel("d_dl: probe OWD − baseline (ms)")
            a.set_title("Queue depth PROXY (controller d_dl)")
            a.legend(fontsize=7)
        else:
            base = cm.get("pre_median_ms") if fnum(cm.get("pre_median_ms")) is not None else np.nanmin(rt["owd"])
            a.plot(bc, p50 - base, color=BLUE)
            a.set_ylabel("call p50 OWD − pre-load median (ms)")
            a.set_title("Queue depth PROXY (call OWD; no telemetry)")
        tcj = load_json(run.f("tc_lan0_end.json"))
        if isinstance(tcj, list) and tcj and tcj[0].get("tins"):
            txt = "end-of-run CAKE avg_delay per tin (µs): " + ", ".join(str(tn.get("avg_delay_us")) for tn in tcj[0]["tins"])
            a.text(0.01, 0.97, txt, transform=a.transAxes, fontsize=6.5, va="top", color=GREY)
        mark(a)
        a = ax[1][2]
        if ip and ip["streams"] and len(ip["streams"][0]) > 1:
            jt = [jain(s) for s in ip["streams"]]
            a.plot(ip["ts"] - t0, jt, "o-", ms=3, color=BLUE)
            a.set_ylim(0, 1.05)
            a.set_title("Fairness: Jain over %d bulk flows" % len(ip["streams"][0]))
        a.set_ylabel("Jain index (1 s)")
        mark(a)
        fig.suptitle("HALO-Walk dashboard — S1 run %s (%s; median-p99 rep of N=%d)%s" % (
            run.id, CFG_LABEL.get(run.cfg), len(cand), "" if cfg_used == "C3" else "  [no C3 data yet]"),
            fontsize=12, fontweight="bold", x=0.01, ha="left")
        fig.text(0.01, 0.935, "dashed red = load_on (8 bulk flows start); grey band = 3 s warm-up excluded from metrics; "
                 "1-s bins", ha="left", fontsize=7.5, color=GREY)
        fig.tight_layout(rect=(0, 0, 1, 0.93))
        fig.savefig(path, dpi=150)
        plt.close(fig)

    # ------------------------------------------------ tables.md
    def tables(self):
        L = ["# HALO-Walk results tables", "",
             "Generated by `analysis/analyze.py` from `results/raw`. Cells: median over reps [bootstrap 95% CI, "
             "10k resamples, fixed seed]; `N` = reps. CI is `n/a` for N<2. Definitions: `analysis/README.md`.", ""]

        def cell(v, nd=1):
            v = [x for x in v if fnum(x) is not None]
            if not v:
                return "–"
            lo, hi = self.S.boot_ci(v)
            return "%.*f [%.*f, %.*f]" % (nd, np.median(v), nd, lo, nd, hi) if fnum(lo) is not None else "%.*f" % (nd, np.median(v))
        for scn in sorted(self.by):
            d = self.by[scn]
            L += ["## %s" % scn, ""]
            flow = "game" if scn == "S3" else "call"
            if scn.startswith("EST"):
                L += ["| config | N | c_est (Mbit/s) | true (Mbit/s) | error (%) |", "|---|---|---|---|---|"]
                for c in CONFIGS:
                    ms = [est_metrics(x) for x in self.runs_of(scn, c)]
                    ms = [m for m in ms if m and m.get("err") is not None]
                    if ms:
                        L.append("| %s | %d | %s | %g | %s |" % (CFG_LABEL[c], len(ms), cell([m["c_est"] for m in ms], 2),
                                                                  ms[0]["true"], cell([100 * m["err"] for m in ms], 1)))
                L.append("")
                continue
            if scn == "DATAGEN":
                L += ["%d classifier data-generation run(s); analysed by the classifier pipeline, not here." % sum(
                    len(v) for v in d.values()), ""]
                continue
            if scn == "CPU":
                L += ["| config | N | ctl CPU (% core) | softirq (%) | idle (%) |", "|---|---|---|---|---|"]
                for c in CONFIGS:
                    rs = self.runs_of(scn, c)
                    if rs:
                        g = lambda k: [fnum((x.meta.get("cpu") or {}).get(k)) for x in rs]
                        L.append("| %s | %d | %s | %s | %s |" % (CFG_LABEL[c], len(rs), cell(g("ctl_pct_of_core"), 2),
                                                                  cell(g("softirq_pct"), 1), cell(g("idle_pct"), 1)))
                L.append("")
                continue
            hdr = "| config | N | %s p50 added (ms) | %s p99 added (ms) | p99 abs OWD (ms) | jitter (ms) | loss load (%%) | bulk goodput (Mbit/s) |" % (flow, flow)
            L += [hdr, "|---|---|---|---|---|---|---|---|"]
            for c in CONFIGS:
                rs = self.runs_of(scn, c)
                if not rs:
                    continue
                ms = [call_metrics(x, flow, self.H) or {} for x in rs]
                bulk = [(x.iperf("bulk") or {}).get("mean_mbps") for x in rs]
                L.append("| %s | %d | %s | %s | %s | %s | %s | %s |" % (
                    CFG_LABEL[c], len(rs), cell([m.get("added_p50_ms") for m in ms]), cell([m.get("added_p99_ms") for m in ms]),
                    cell([m.get("p99_ms") for m in ms]), cell([m.get("jitter_ms") for m in ms], 2),
                    cell([100 * m["loss_load"] if fnum(m.get("loss_load")) is not None else None for m in ms], 2), cell(bulk, 2)))
            if scn in ("S4", "S6"):
                L += ["", "_No unloaded pre-window in %s (call starts under load): 'added' columns are empty; absolute OWD shown._" % scn]
            if scn == "S2":
                L += ["", "| config | N | T_adapt (s) | recovery (s) | dl changes/min | low-phase p99 added (ms) |", "|---|---|---|---|---|---|"]
                for c in CONFIGS:
                    ms = [s2_metrics(x, self.H) for x in self.runs_of(scn, c)]
                    ms = [m for m in ms if m]
                    if ms:
                        ta = [m.get("t_adapt_s") for m in ms]
                        L.append("| %s | %d | %s | %s | %s | %s |" % (
                            CFG_LABEL[c], len(ms), "never" if all(t is None for t in ta) else cell(ta, 2) + (
                                " (%d never)" % sum(t is None for t in ta) if any(t is None for t in ta) else ""),
                            cell([m.get("recovery_s") for m in ms]), cell([m.get("changes_per_min") for m in ms]),
                            cell([m.get("low_phase_added_p99_ms") for m in ms])))
            if scn == "S3":
                L += ["", "| config | N | Jain (demand-normalised, 3 TVs) | TV goodputs (Mbit/s, median per TV) |", "|---|---|---|---|"]
                for c in CONFIGS:
                    ms = [s3_metrics(x, self.H) for x in self.runs_of(scn, c)]
                    if ms:
                        gp = ["%.2f" % np.median([m["tv"][h]["goodput_mbps"] for m in ms if h in m.get("tv", {})])
                              if any(h in m.get("tv", {}) for m in ms) else "–" for h in ("tv1", "tv2", "tv3")]
                        L.append("| %s | %d | %s | %s |" % (CFG_LABEL[c], len(ms), cell([m.get("jain") for m in ms], 3), " / ".join(gp)))
            L.append("")
        L += ["## Key comparisons (p99 added delay of the real-time flow; S3 = gaming, others = call)", "",
              "Δ = median(A) − median(B) with bootstrap 95%% CI; Mann-Whitney U two-sided (%s); Cliff's δ = P(A>B) − P(A<B); "
              "Holm correction across scenarios within each comparison family. Tests need N ≥ 2 per group." % (
                  "scipy exact/asymptotic" if _sps is not None else "normal approximation"), "",
              "| comparison | scenario | N (A/B) | median A | median B | Δ (ms) [95% CI] | U | p | p (Holm) | Cliff's δ |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        any_cmp = False
        for (a, b), d in self.cmp.items():
            for scn, x in sorted(d.items()):
                any_cmp = True
                L.append("| %s vs %s | %s | %d/%d | %.1f | %.1f | %s [%s, %s] | %s | %s | %s | %s %s |" % (
                    a, b, scn, x["n_a"], x["n_b"], x["med_a"], x["med_b"], fmt(x["diff"], 1), fmt(x["ci"][0], 1),
                    fmt(x["ci"][1], 1), fmt(x["U"], 1), fmt(x["p"], 4), fmt(x["p_holm"], 4), fmt(x["cliff"], 2), cliff_mag(x["cliff"])))
        if not any_cmp:
            L.append("| – | pending: no scenario has both configs of any pair | | | | | | | | |")
        L.append("")
        open(os.path.join(self.res, "tables.md"), "w").write("\n".join(L) + "\n")

    # ------------------------------------------------ summary
    def platform(self):
        ks = sorted({x.meta.get("kernel") for x in self.runs if x.meta.get("kernel")})
        emu = any(x.meta.get("emulated") for x in self.runs)
        ncpu = sorted({(x.meta.get("cpu") or {}).get("ncpu") for x in self.runs} - {None})
        if not ks:
            return "pending: no meta.json"
        cpu = ("%s vCPU" % "/".join(map(str, ncpu))) if ncpu else "2 vCPU (per rig documentation; vCPU count not yet in any meta.json)"
        return "Linux %s, QEMU TCG %s, %s" % ("/".join(ks), cpu, "EMULATED" if emu else "emulated flag not set in meta")

    def run(self):
        style()
        self.comparisons()
        for k in range(1, 13):
            try:
                getattr(self, "m%d" % k)()
            except Exception as e:                 # one broken measurement must not kill the report
                import traceback
                traceback.print_exc()
                self.put(k, "pending: analysis error (%s)" % str(e)[:120], None, {})
                pending_fig(os.path.join(self.figs, "m%02d.png" % k), k, "analysis error: %s" % str(e)[:80])
        try:
            self.dashboard()
        except Exception as e:
            import traceback
            traceback.print_exc()
            note("dashboard failed: %s" % e)
        self.tables()
        meas = [self.M[k] for k in range(1, 13)]
        cnt = {"pass": sum(m["pass"] is True for m in meas), "fail": sum(m["pass"] is False for m in meas),
               "pending": sum(m["pass"] is None for m in meas)}
        inv = {}
        for x in self.runs:
            inv.setdefault(x.scn, {}).setdefault(x.cfg, 0)
            inv[x.scn][x.cfg] += 1
        head = {"verdicts": "%d PASS / %d FAIL / %d PENDING of 12" % (cnt["pass"], cnt["fail"], cnt["pending"]),
                "runs_analysed": "%d complete runs: %s" % (len(self.runs), ", ".join(
                    "%s[%s]" % (s, ",".join("%s×%d" % (c, n) for c, n in sorted(v.items()))) for s, v in sorted(inv.items())))}
        for k in (2, 4, 9, 11):
            head["M%d" % k] = "%s — %s" % (verdict_str(self.M[k]["pass"]), self.M[k]["value"][:160])
        notes = list(NOTES) + [
            "All values computed by analysis/analyze.py from files under results/; nothing hard-coded. pass=null means pending.",
            "Platform is software-emulated (QEMU TCG): absolute latencies and CPU costs are pessimistic vs. real hardware.",
            "Bootstrap: %d percentile resamples, seed %d; statistical criteria require >= %d reps per group." % (self.S.B, self.S.seed, MIN_REPS_TEST)]
        matrix = {s: {c: n for c, n in sorted(v.items())} for s, v in sorted(inv.items())}
        out = {"platform": self.platform(), "matrix": matrix, "measurements": meas, "headline": head, "notes": notes}
        with open(os.path.join(self.res, "summary.json.tmp"), "w") as f:
            f.write(json.dumps(sanitize(out), indent=1, allow_nan=False))
        os.replace(os.path.join(self.res, "summary.json.tmp"), os.path.join(self.res, "summary.json"))
        return out


def sanitize(o):
    """JSON-safe: NaN/inf -> null, numpy -> python"""
    if isinstance(o, dict):
        return {str(k): sanitize(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [sanitize(v) for v in o]
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (float, np.floating)):
        return float(o) if math.isfinite(o) else None
    return o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--boot", type=int, default=10000)
    a = ap.parse_args()
    out = Analysis(a.root, a.boot).run()
    for m in out["measurements"]:
        print("M%-2d %-8s %s" % (m["id"], verdict_str(m["pass"]), m["value"][:200]))
    print(out["headline"]["verdicts"])


if __name__ == "__main__":
    main()
