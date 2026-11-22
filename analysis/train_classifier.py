#!/usr/bin/env python3
"""Train + evaluate the HALO-Walk M2 flow classifier from labelled DATAGEN batches.

    python3 analysis/train_classifier.py                 # matrix reps r01..r30 only (analysis convention)
    python3 analysis/train_classifier.py --include-debug # also r00 / r31+ (development only)
    options: --root <project> --folds 5 --no-write-model --boot 1000

Data   : results/raw/DATAGEN/C2/rNN/ctl/raw_flows.jsonl  (controller --collect: key, proto, t0, pkts, bins)
         results/raw/DATAGEN/C2/rNN/labels.jsonl          (halo/gen.py ground truth, one line per socket)
         joined on the LAN-first 5-tuple (proto, lan_ip, lan_port, wan_ip, wan_port) == controller flow key,
         restricted to label lines whose "batch" field equals b%03d % rep. A batch counts only when its
         meta.json contains the "end" event.
Features are computed with the SAME functions the controller calls at runtime (halo.classifier.feat1/feat2;
feat_ttl only for the TTL-leak ablation). Calibration is applied with halo.classifier.Model._cal.

Protocol (anti-leakage): leave-batches-out GroupKFold over batches (= sessions); inside every training fold a
group-disjoint subset of batches is held out for calibration. Nothing is ever split per flow or per packet.

Outputs: halo/model.pkl (Model bundle), results/classifier/eval.json, results/classifier/README.md
"""
import argparse, glob, hashlib, io, ipaddress, json, math, os, pickle, sys, time, warnings
from collections import Counter, defaultdict

import numpy as np

ROOT_DEFAULT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DEFAULT)
from halo import classifier as C          # noqa: E402
from halo import policy                    # noqa: E402

SEED = 20261116
PROMOTE_P = 0.9
INTERACTIVE = set(policy.INTERACTIVE)
K = len(C.CLASSES)
CI = {c: i for i, c in enumerate(C.CLASSES)}
XGB_PARAMS = dict(n_estimators=150, max_depth=4, learning_rate=0.1, subsample=1.0, colsample_bytree=1.0,
                  min_child_weight=1.0, reg_lambda=1.0, tree_method="hist", n_jobs=1, random_state=SEED,
                  objective="multi:softprob", eval_metric="mlogloss")
CAL_FRAC = 0.25                            # share of training batches held out for calibration


# ============================================================================ data
def norm_ip(s):
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def fkey(proto, lan_ip, lan_port, wan_ip, wan_port):
    return (proto, norm_ip(lan_ip), int(lan_port), norm_ip(wan_ip), int(wan_port))


def complete(run_dir):
    try:
        m = json.load(open(os.path.join(run_dir, "meta.json")))
    except Exception:
        return False, None
    return any(e.get("name") == "end" for e in m.get("events", [])), m


def load(root, include_debug):
    base = os.path.join(root, "results", "raw", "DATAGEN", "C2")
    flows, report, skipped = [], [], []
    for d in sorted(glob.glob(os.path.join(base, "r[0-9][0-9]*"))):
        name = os.path.basename(d)
        rep = int(name[1:])
        ok, meta = complete(d)
        if not ok:
            skipped.append({"batch": name, "why": "no meta.json 'end' event (incomplete/in progress)"})
            continue
        if not include_debug and not 1 <= rep <= 30:
            skipped.append({"batch": name, "why": "not a matrix rep (r01..r30); use --include-debug"})
            continue
        rf, lf = os.path.join(d, "ctl", "raw_flows.jsonl"), os.path.join(d, "labels.jsonl")
        if not (os.path.exists(rf) and os.path.exists(lf)):
            skipped.append({"batch": name, "why": "raw_flows.jsonl or labels.jsonl missing"})
            continue
        bid = "b%03d" % rep
        labels, n_lab_other_batch, dup = {}, 0, set()
        lab_lines = [json.loads(l) for l in open(lf) if l.strip()]
        for r in lab_lines:
            if r.get("batch", bid) != bid:
                n_lab_other_batch += 1
                continue
            k = fkey(r["proto"], r["lan_ip"], r["lan_port"], r["wan_ip"], r["wan_port"])
            if k in labels and labels[k]["cls"] != r["cls"]:
                dup.add(k)
            labels[k] = r
        raw = [json.loads(l) for l in open(rf) if l.strip()]
        seen, n_join, unj, amb = set(), 0, [], 0
        for r in raw:
            k = fkey(*r["key"])
            if k in seen:
                continue                                 # a flow is dumped once; guard anyway
            seen.add(k)
            if k in dup:
                amb += 1
                continue
            lab = labels.get(k)
            if lab is None:
                unj.append(list(k))
                continue
            n_join += 1
            pk = [tuple(p) for p in r["pkts"]]
            bins = [tuple(b) for b in r["bins"]]
            flows.append({"batch": name, "key": tuple(k), "proto": r["proto"], "pkts": pk, "bins": bins,
                          "cls": lab["cls"], "sid": lab.get("sid", ""), "v6": ":" in k[1],
                          # runtime `tot` = cumulative conntrack bytes; raw_flows has no counter, so use the sum
                          # of the recorded deltas (a lower bound: misses bytes before the first poll / after bin 8)
                          "tot": (sum(b[1] for b in bins), sum(b[2] for b in bins))})
        lab_not_seen = [k for k in labels if k not in seen]
        report.append({"batch": name, "link": [meta.get("down"), meta.get("up")], "n_raw": len(raw),
                       "n_labels": len(labels), "joined": n_join, "unjoinable_flows": len(unj),
                       "ambiguous": amb, "labels_without_flow": len(lab_not_seen),
                       "labels_without_flow_by": dict(Counter("%s/%s/%s" % (labels[k]["cls"], k[0], "v6" if ":" in k[1] else "v4")
                                                               for k in lab_not_seen)),
                       "label_lines_other_batch": n_lab_other_batch,
                       "per_class": dict(Counter(f["cls"] for f in flows if f["batch"] == name))})
    return flows, report, skipped


def data_hash(root, batches):
    h = hashlib.sha256()
    base = os.path.join(root, "results", "raw", "DATAGEN", "C2")
    for b in sorted(batches):
        for fn in ("ctl/raw_flows.jsonl", "labels.jsonl"):
            h.update(b.encode()); h.update(fn.encode())
            h.update(open(os.path.join(base, b, fn), "rb").read())
    return h.hexdigest()


def mask_request(f):
    """generator-artefact ablation: halo/gen.py's chunk_server protocol sends one short request line
    ("GET <n>" / "PUT <n>") whose length differs by client type (bulk asks for 2**40 bytes -> a constant length).
    Replace that first upstream TCP payload packet's size by a class-neutral constant (63 B v4 / 83 B v6)."""
    if f["proto"] != "tcp":
        return f
    pk = list(f["pkts"])
    for j in range(1, len(pk)):
        t, sz, ttl = pk[j]
        if sz > 0 and sz not in (52, 72) and sz < 200:
            pk[j] = (t, 83 if f["v6"] else 63, ttl)
            break
    return dict(f, pkts=pk)


# ============================================================================ features (runtime functions)
def rows_stage1(flows):
    X, y, g, fi = [], [], [], []
    for i, f in enumerate(flows):
        if len(f["pkts"]) >= 2:                      # controller: predict1 needs >= 2 packets
            X.append(C.feat1(f)); y.append(CI[f["cls"]]); g.append(f["batch"]); fi.append(i)
    return np.asarray(X, float), np.asarray(y), np.asarray(g), np.asarray(fi)


def rows_stage2(flows, horizons=C.HORIZONS, ttl=False):
    """one row per (flow, h) where the controller would call predict2 (len(bins) >= h)"""
    X, y, g, fi, hh = [], [], [], [], []
    for i, f in enumerate(flows):
        for h in horizons:
            if len(f["bins"]) >= h:
                x = C.feat2(f, h) + (C.feat_ttl(f) if ttl else [])
                X.append(x); y.append(CI[f["cls"]]); g.append(f["batch"]); fi.append(i); hh.append(h)
    return np.asarray(X, float), np.asarray(y), np.asarray(g), np.asarray(fi), np.asarray(hh)


# ============================================================================ model + calibration
def fit_xgb(X, y):
    from xgboost import XGBClassifier
    present = set(y.tolist())
    if present != set(range(K)):
        raise RuntimeError("fit set lacks classes %s" % sorted(set(range(K)) - present))
    cnt = np.bincount(y, minlength=K).astype(float)
    w = (len(y) / (K * cnt))[y]                      # class-balanced sample weights
    m = XGBClassifier(num_class=K, **XGB_PARAMS)
    m.fit(X, y, sample_weight=w)
    return m


def fit_temperature(P, y):
    from scipy.optimize import minimize_scalar
    L = np.log(np.clip(P, 1e-12, None))

    def nll(lt):
        z = L / math.exp(lt)
        z = z - z.max(1, keepdims=True)
        lp = z - np.log(np.exp(z).sum(1, keepdims=True))
        return -lp[np.arange(len(y)), y].mean()
    r = minimize_scalar(nll, bounds=(-3, 3), method="bounded", options={"xatol": 1e-6})
    return {"kind": "temperature", "T": float(math.exp(r.x))}


def fit_isotonic(P, y):
    from sklearn.isotonic import IsotonicRegression
    iso = []
    for k in range(K):
        r = IsotonicRegression(y_min=0.0, y_max=1.0, increasing=True, out_of_bounds="clip")
        r.fit(P[:, k], (y == k).astype(float))
        iso.append(r)
    return {"kind": "isotonic", "iso": iso}


def apply_cal(P, cal):
    """vectorised twin of halo.classifier.Model._cal (verified against it on the final bundle)"""
    if cal is None:
        return P
    if cal["kind"] == "temperature":
        Q = np.clip(P, 1e-12, None) ** (1.0 / cal["T"])
    else:
        Q = np.stack([np.maximum(1e-9, cal["iso"][k].predict(P[:, k])) for k in range(K)], 1)
    return Q / Q.sum(1, keepdims=True)


# ============================================================================ metrics
def cls_metrics(y, yhat):
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support
    p, r, f, s = precision_recall_fscore_support(y, yhat, labels=list(range(K)), zero_division=0)
    return {"macro_f1": float(f1_score(y, yhat, labels=list(range(K)), average="macro", zero_division=0)),
            "accuracy": float(accuracy_score(y, yhat)), "n": int(len(y)),
            "per_class": {c: {"precision": float(p[k]), "recall": float(r[k]), "f1": float(f[k]), "support": int(s[k])}
                          for k, c in enumerate(C.CLASSES)},
            "confusion": {"labels": list(C.CLASSES), "rows_true_cols_pred":
                          confusion_matrix(y, yhat, labels=list(range(K))).tolist()}}


def ece(P, y):
    return float(C.ece(P.tolist(), y.tolist(), bins=15))


def reliability(P, y, bins=15):
    conf, pred = P.max(1), P.argmax(1)
    out = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = (conf > lo) & (conf <= hi) | ((b == 0) & (conf == 0))
        n = int(idx.sum())
        out.append({"lo": round(lo, 4), "hi": round(hi, 4), "count": n,
                    "conf": float(conf[idx].mean()) if n else None, "acc": float((pred[idx] == y[idx]).mean()) if n else None})
    return out


def cp95(k, n):
    """Clopper-Pearson 95 % interval (flows treated as independent; ignores batch clustering)"""
    from scipy.stats import beta
    if n == 0:
        return [None, None]
    return [float(beta.ppf(0.025, k, n - k + 1)) if k else 0.0, float(beta.ppf(0.975, k + 1, n - k)) if k < n else 1.0]


def promote_stats(y, cls_idx, p, abstain):
    """tin_for(...) == Voice tin.  wrongful = non-interactive flows promoted; recall = interactive flows promoted"""
    prom = np.array([policy.tin_for(C.CLASSES[c], float(q), bool(a), PROMOTE_P) == policy.TIN["call"]
                     for c, q, a in zip(cls_idx, p, abstain)])
    inter = np.array([C.CLASSES[t] in INTERACTIVE for t in y])
    return {"wrongful_promotion": float(prom[~inter].mean()) if (~inter).any() else None,
            "n_non_interactive": int((~inter).sum()), "n_wrongly_promoted": int((prom & ~inter).sum()),
            "interactive_recall_promote": float(prom[inter].mean()) if inter.any() else None,
            "n_interactive": int(inter.sum()), "n_interactive_promoted": int((prom & inter).sum()),
            "wrongful_promotion_ci95": cp95(int((prom & ~inter).sum()), int((~inter).sum())),
            "interactive_recall_promote_ci95": cp95(int((prom & inter).sum()), int(inter.sum()))}, prom


def heuristic_preds(flows, idx, tot_bins=None):
    out = []
    for i in idx:
        f = flows[i]
        if tot_bins is not None:
            b = f["bins"][:tot_bins]
            f = dict(f, tot=(sum(x[1] for x in b), sum(x[2] for x in b)))
        out.append(C.heuristic(f))
    return out


def boot_macro_f1(groups, y, preds, n_boot, seed=SEED):
    """batch-level (cluster) bootstrap of macro-F1 for one or more prediction vectors (paired resamples)"""
    from sklearn.metrics import f1_score
    if n_boot <= 0:
        return None
    ug = sorted(set(groups.tolist()))
    by = {g: np.where(groups == g)[0] for g in ug}
    rng = np.random.RandomState(seed)
    res = {k: [] for k in preds}
    for _ in range(n_boot):
        idx = np.concatenate([by[ug[j]] for j in rng.randint(0, len(ug), len(ug))])
        for k, ph in preds.items():
            res[k].append(f1_score(y[idx], ph[idx], labels=list(range(K)), average="macro", zero_division=0))
    return {k: np.asarray(v) for k, v in res.items()}


# ============================================================================ CV
def split_cal(train_groups, y_by_group, fold):
    """group-disjoint calibration subset of the training batches; the fit part must contain every class"""
    tg = sorted(train_groups)
    n_cal = max(1, int(round(CAL_FRAC * len(tg))))
    rng = np.random.RandomState(SEED + fold)
    for _ in range(200):
        perm = [tg[i] for i in rng.permutation(len(tg))]
        cal, fit = set(perm[:n_cal]), set(perm[n_cal:])
        if set().union(*[y_by_group[g] for g in fit]) == set(range(K)):
            return fit, cal
    raise RuntimeError("cannot draw a calibration subset leaving all classes in the fit part")


def run_cv(flows, folds, log):
    from sklearn.model_selection import GroupKFold
    batches = np.array(sorted(set(f["batch"] for f in flows)))
    y_by_group = defaultdict(set)
    for f in flows:
        y_by_group[f["batch"]].add(CI[f["cls"]])
    k = min(folds, len(batches))
    gkf = GroupKFold(n_splits=k)
    X1, y1, g1, fi1 = rows_stage1(flows)
    X2, y2, g2, fi2, h2 = rows_stage2(flows)
    XT, yT, gT, fiT, hT = rows_stage2(flows, ttl=True)
    oof = {"s1": {m: np.zeros((len(y1), K)) for m in ("raw", "temperature", "isotonic")},
           "s2": {m: np.zeros((len(y2), K)) for m in ("raw", "temperature", "isotonic")},
           "ttl": {m: np.zeros((len(yT), K)) for m in ("raw", "temperature", "isotonic")}}
    fold_of_batch, fold_info = {}, []
    for fold, (tr_b, te_b) in enumerate(gkf.split(batches, groups=batches)):
        trb, teb = set(batches[tr_b]), set(batches[te_b])
        for b in teb:
            fold_of_batch[b] = fold
        fitb, calb = split_cal(trb, y_by_group, fold)
        assert not (fitb & calb) and not (trb & teb)
        cal_used = {}
        for name, X, y, g in (("s1", X1, y1, g1), ("s2", X2, y2, g2), ("ttl", XT, yT, gT)):
            fit, cal, te = np.isin(g, list(fitb)), np.isin(g, list(calb)), np.isin(g, list(teb))
            m = fit_xgb(X[fit], y[fit])
            Pc, Pt = m.predict_proba(X[cal]), m.predict_proba(X[te])
            ct, ci = fit_temperature(Pc, y[cal]), fit_isotonic(Pc, y[cal])
            oof[name]["raw"][te] = Pt
            oof[name]["temperature"][te] = apply_cal(Pt, ct)
            oof[name]["isotonic"][te] = apply_cal(Pt, ci)
            cal_used[name] = {"T": round(ct["T"], 4), "n_cal_rows": int(cal.sum()), "n_fit_rows": int(fit.sum()),
                              "n_test_rows": int(te.sum())}
        fold_info.append({"fold": fold, "test_batches": sorted(teb), "cal_batches": sorted(calb),
                          "fit_batches": sorted(fitb), "stats": cal_used})
        log("  fold %d: test %s | cal %s | fit %d batches | T(s2)=%.3f" % (
            fold, ",".join(sorted(teb)), ",".join(sorted(calb)), len(fitb), cal_used["s2"]["T"]))
    return dict(k=k, batches=batches, fold_info=fold_info, fold_of_batch=fold_of_batch, oof=oof,
                s1=(y1, g1, fi1), s2=(y2, g2, fi2, h2), ttl=(yT, gT, fiT, hT))


def runtime_emulation(flows, cv, cal_kind):
    """replays controller.classify() for the ML path on out-of-fold predictions:
    stage 1 (>= 2 pkts) sets cls/p; each horizon h with len(bins) >= h overrides when p >= promote_p or h == last."""
    y1, _, fi1 = cv["s1"]
    y2, _, fi2, h2 = cv["s2"]
    P1, P2 = cv["oof"]["s1"][cal_kind], cv["oof"]["s2"][cal_kind]
    s1 = {int(i): P1[j] for j, i in enumerate(fi1)}
    s2 = {(int(i), int(h)): P2[j] for j, (i, h) in enumerate(zip(fi2, h2))}
    traj = []
    for i, f in enumerate(flows):
        st, tins = None, []
        if i in s1:
            p = s1[i]; st = (int(p.argmax()), float(p.max()))
            tins.append(policy.tin_for(C.CLASSES[st[0]], st[1], st[1] < PROMOTE_P, PROMOTE_P))
        for h in C.HORIZONS:
            if (i, h) in s2:
                p = s2[(i, h)]; c, q = int(p.argmax()), float(p.max())
                if q >= PROMOTE_P or h == C.HORIZONS[-1]:
                    st = (c, q)
                if st is not None:
                    tins.append(policy.tin_for(C.CLASSES[st[0]], st[1], st[1] < PROMOTE_P, PROMOTE_P))
        traj.append((st, tins))
    y = np.array([CI[f["cls"]] for f in flows])
    inter = np.array([f["cls"] in INTERACTIVE for f in flows])
    ever = np.array([any(t == 4 for t in tins) for _, tins in traj])
    final = np.array([bool(tins) and tins[-1] == 4 for _, tins in traj])
    fin_cls = np.array([st[0] if st else CI["other"] for st, _ in traj])
    return {"wrongful_promotion_ever": float(ever[~inter].mean()), "wrongful_promotion_final": float(final[~inter].mean()),
            "interactive_recall_ever": float(ever[inter].mean()), "interactive_recall_final": float(final[inter].mean()),
            "final_decision_macro_f1": cls_metrics(y, fin_cls)["macro_f1"],
            "n_wrong_ever": int((ever & ~inter).sum()), "n_non_interactive": int((~inter).sum()),
            "n_interactive": int(inter.sum())}


# ============================================================================ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT_DEFAULT)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--include-debug", action="store_true", help="also use r00 / r31+ (debug reps)")
    ap.add_argument("--no-write-model", action="store_true")
    ap.add_argument("--out", default=None, help="default <root>/results/classifier")
    ap.add_argument("--model-out", default=None, help="default <root>/halo/model.pkl (controller default)")
    a = ap.parse_args()
    warnings.filterwarnings("ignore", category=UserWarning)
    out_dir = a.out or os.path.join(a.root, "results", "classifier")
    os.makedirs(out_dir, exist_ok=True)
    log = lambda s: print(s, flush=True)

    flows, report, skipped = load(a.root, a.include_debug)
    batches = sorted(set(f["batch"] for f in flows))
    log("batches used: %d (%s)  skipped: %s" % (len(batches), ",".join(batches), [s["batch"] for s in skipped]))
    for r in report:
        log("  %s link=%s raw=%d labels=%d joined=%d unjoinable=%d labels_without_flow=%d %s %s" % (
            r["batch"], r["link"], r["n_raw"], r["n_labels"], r["joined"], r["unjoinable_flows"],
            r["labels_without_flow"], r["per_class"], r["labels_without_flow_by"] or ""))
    cnt = Counter(f["cls"] for f in flows)
    log("flows per class: %s  total=%d" % (dict(cnt), len(flows)))
    if len(batches) < 3:
        raise SystemExit("need >= 3 complete batches for leave-batches-out CV (have %d)" % len(batches))

    # ------------------------------------------------------------------ CV
    log("leave-batches-out CV ...")
    t0 = time.time()
    cv = run_cv(flows, a.folds, log)
    log("  CV done in %.1fs" % (time.time() - t0))
    oof = cv["oof"]
    y1, g1, fi1 = cv["s1"]
    y2, g2, fi2, h2 = cv["s2"]
    yT, gT, fiT, hT = cv["ttl"]

    # calibration bake-off (deployed decision = stage 2 at h=2; stage-1 chosen separately)
    def bake(P, y):
        e = {m: ece(P[m], y) for m in ("raw", "temperature", "isotonic")}
        return e, ("temperature" if e["temperature"] <= e["isotonic"] else "isotonic")
    m2h2 = h2 == 2
    ece2, chosen2 = bake({m: oof["s2"][m][m2h2] for m in oof["s2"]}, y2[m2h2])
    ece2_all, _ = bake(oof["s2"], y2)
    ece1, chosen1 = bake(oof["s1"], y1)
    mT2 = hT == 2
    eceT, chosenT = bake({m: oof["ttl"][m][mT2] for m in oof["ttl"]}, yT[mT2])
    log("ECE s2@h2 %s -> %s | s1 %s -> %s" % ({k: round(v, 4) for k, v in ece2.items()}, chosen2,
                                              {k: round(v, 4) for k, v in ece1.items()}, chosen1))

    # classification metrics (argmax of the chosen-calibrated probabilities = what is deployed)
    P2c, P1c, PTc = oof["s2"][chosen2], oof["s1"][chosen1], oof["ttl"][chosenT]
    per_h = {}
    for h in C.HORIZONS:
        mk = h2 == h
        per_h["h%d" % h] = cls_metrics(y2[mk], P2c[mk].argmax(1))
    per_h["stage1"] = cls_metrics(y1, P1c.argmax(1))
    ml = per_h["h2"]
    ttl = cls_metrics(yT[mT2], PTc[mT2].argmax(1))
    # heuristic on the same flow set as the deployed decision (flows with >= 2 bins)
    idx_h2 = fi2[m2h2]
    yh = y2[m2h2]
    hp = heuristic_preds(flows, idx_h2)
    hp2 = heuristic_preds(flows, idx_h2, tot_bins=2)
    heur = cls_metrics(yh, np.array([CI[c] for c, _, _ in hp]))
    heur_h2 = cls_metrics(yh, np.array([CI[c] for c, _, _ in hp2]))
    log("macro-F1: ML h2 %.3f | +TTL %.3f | heuristic %.3f (tot@2 bins %.3f) | stage1 %.3f h4 %.3f h6 %.3f" % (
        ml["macro_f1"], ttl["macro_f1"], heur["macro_f1"], heur_h2["macro_f1"], per_h["stage1"]["macro_f1"],
        per_h["h4"]["macro_f1"], per_h["h6"]["macro_f1"]))

    # promote rule
    p2 = P2c[m2h2]
    pm_ml, _ = promote_stats(yh, p2.argmax(1), p2.max(1), p2.max(1) < PROMOTE_P)
    pm_h, _ = promote_stats(yh, [CI[c] for c, _, _ in hp], [p for _, p, _ in hp], [ab for _, _, ab in hp])
    pm_ttl, _ = promote_stats(yT[mT2], PTc[mT2].argmax(1), PTc[mT2].max(1), PTc[mT2].max(1) < PROMOTE_P)
    pm_raw, _ = promote_stats(yh, oof["s2"]["raw"][m2h2].argmax(1), oof["s2"]["raw"][m2h2].max(1),
                              oof["s2"]["raw"][m2h2].max(1) < PROMOTE_P)
    rt = runtime_emulation(flows, cv, chosen2) if chosen1 == chosen2 else None
    if rt is None:      # mixed calibration kinds: emulate with each stage's own choice
        cv2 = dict(cv, oof={"s1": {chosen2: oof["s1"][chosen1]}, "s2": oof["s2"]})
        rt = runtime_emulation(flows, cv2, chosen2)
    log("promote: ML wrongful %.4f recall %.3f | heuristic wrongful %.4f recall %.3f | runtime-emul ever %.4f" % (
        pm_ml["wrongful_promotion"], pm_ml["interactive_recall_promote"], pm_h["wrongful_promotion"],
        pm_h["interactive_recall_promote"], rt["wrongful_promotion_ever"]))

    # generator-artefact ablation (request-line length masked), same CV protocol
    log("artefact ablation (request size masked) ...")
    cvm = run_cv([mask_request(f) for f in flows], a.folds, lambda *_: None)
    ym2, _, _, hm2 = cvm["s2"]
    mk = hm2 == 2
    masked = cls_metrics(ym2[mk], cvm["oof"]["s2"][chosen2][mk].argmax(1))
    log("  masked macro-F1 %.3f (bulk F1 %.3f)" % (masked["macro_f1"], masked["per_class"]["bulk"]["f1"]))

    # bootstrap CIs over batches (paired)
    bs = boot_macro_f1(g2[m2h2], yh, {"ml": p2.argmax(1), "heur": np.array([CI[c] for c, _, _ in hp])}, a.boot)
    bsT = boot_macro_f1(gT[mT2], yT[mT2], {"ttl": PTc[mT2].argmax(1), "nottl": oof["s2"][chosenT][m2h2].argmax(1)}, a.boot) \
        if np.array_equal(fiT[mT2], fi2[m2h2]) else None
    ci = lambda v: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
    boot = None
    if bs is not None:
        boot = {"n_boot": a.boot, "unit": "batch (cluster bootstrap, paired)",
                "macro_f1_no_ttl_ci95": ci(bs["ml"]), "macro_f1_heuristic_ci95": ci(bs["heur"]),
                "diff_ml_minus_heuristic_ci95": ci(bs["ml"] - bs["heur"]),
                "p_ml_le_heuristic": float((bs["ml"] - bs["heur"] <= 0).mean())}
        if bsT is not None:
            boot["diff_ttl_minus_no_ttl_ci95"] = ci(bsT["ttl"] - bsT["nottl"])

    # ------------------------------------------------------------------ final bundle (all batches)
    log("final fit on all %d batches ..." % len(batches))
    y_by_group = defaultdict(set)
    for f in flows:
        y_by_group[f["batch"]].add(CI[f["cls"]])
    fitb, calb = split_cal(set(batches), y_by_group, fold=999)
    bundle = {"version": None, "classes": list(C.CLASSES), "f1_names": list(C.F1_NAMES), "f2_names": list(C.F2_NAMES),
              "horizons": list(C.HORIZONS), "params": XGB_PARAMS, "fit_batches": sorted(fitb), "cal_batches": sorted(calb)}
    for st, (X, y, g), kind in ((1, rows_stage1(flows)[:3], chosen1), (2, rows_stage2(flows)[:3], chosen2)):
        fit, cal = np.isin(g, list(fitb)), np.isin(g, list(calb))
        m = fit_xgb(X[fit], y[fit])
        Pc = m.predict_proba(X[cal])
        calib = fit_temperature(Pc, y[cal]) if kind == "temperature" else fit_isotonic(Pc, y[cal])
        bundle["m%d" % st], bundle["cal%d" % st] = m, calib
        bundle["n_fit_rows%d" % st], bundle["n_cal_rows%d" % st] = int(fit.sum()), int(cal.sum())
    dh = data_hash(a.root, batches)
    ph = hashlib.sha256(json.dumps({"xgb": XGB_PARAMS, "cal_frac": CAL_FRAC, "seed": SEED, "cal": [chosen1, chosen2],
                                    "batches": batches, "f2": C.F2_NAMES}, sort_keys=True).encode()).hexdigest()
    bundle["version"] = "m2-" + hashlib.sha256((dh + ph).encode()).hexdigest()[:12]
    bundle["data_sha256"], bundle["params_sha256"] = dh, ph

    model_path = a.model_out or os.path.join(a.root, "halo", "model.pkl")
    verify = {}
    if not a.no_write_model:
        tmp = model_path + ".tmp"
        with open(tmp, "wb") as fh:
            pickle.dump(bundle, fh)
        os.replace(tmp, model_path)
        # ---- verify through the runtime loader
        M = C.Model(model_path)
        assert M.version == bundle["version"]
        maxdiff, t1s, t2s = 0.0, [], []
        for f in flows[:200]:
            if len(f["pkts"]) >= 2:
                s = time.perf_counter(); c, p, pv = M.predict1(f); t1s.append(time.perf_counter() - s)
                assert abs(sum(pv) - 1) < 1e-9
            if len(f["bins"]) >= 2:
                s = time.perf_counter(); c, p, pv = M.predict2(f, 2); t2s.append(time.perf_counter() - s)
                assert abs(sum(pv) - 1) < 1e-9 and c in C.CLASSES
                q = apply_cal(bundle["m2"].predict_proba(np.asarray([C.feat2(f, 2)])), bundle["cal2"])[0]
                maxdiff = max(maxdiff, float(np.abs(q - np.asarray(pv)).max()))
        assert maxdiff < 1e-6, maxdiff
        ex = [{"key": list(f["key"]), "true": f["cls"], "pred": M.predict2(f, 2)[0], "p": round(M.predict2(f, 2)[1], 3)}
              for f in flows[:: max(1, len(flows) // 6)][:6]]
        verify = {"loaded_version": M.version, "max_abs_diff_vectorised_vs_Model_cal": maxdiff, "examples": ex,
                  "inference_us_per_flow_stage1_median": float(np.median(t1s) * 1e6),
                  "inference_us_per_flow_stage2_median": float(np.median(t2s) * 1e6), "n_timed": len(t2s)}
        log("wrote %s version=%s; Model() verified (max diff %.2e); predict2 median %.0f us" % (
            model_path, M.version, maxdiff, verify["inference_us_per_flow_stage2_median"]))

    # ------------------------------------------------------------------ leakage probes / notes
    v6udp = sum(r["labels_without_flow_by"].get(k, 0) for r in report for k in ("call/udp/v6", "gaming/udp/v6"))
    lab_wo = sum(r["labels_without_flow"] for r in report)
    unj = sum(r["unjoinable_flows"] for r in report)
    nbins = Counter(len(f["bins"]) for f in flows)
    notes = [
        "Split unit = batch (one DATAGEN session: own link rate, ports, sizes, v4/v6). No flow of a test batch is used "
        "for fitting or calibration; calibration batches are disjoint from fit batches inside every training fold.",
        "Classification metrics use argmax of the CHOSEN-calibrated probabilities (what the controller deploys); "
        "ML 'decision' carries no abstain, the promote metrics apply policy.tin_for with p >= %.2f." % PROMOTE_P,
        "Deployed decision = stage 2 at h=2 conntrack bins (bins are poll deltas, not exactly 1 s). Stage-2 model is ONE "
        "model over h in %s (h is a feature); per-horizon rows exist only for flows with len(bins) >= h." % (C.HORIZONS,),
        "Heuristic: abstain -> 'other'. `tot` (elephant rule) is not in raw_flows.jsonl; it is reconstructed as the sum "
        "of recorded conntrack deltas (all recorded bins, <= 8): a lower bound of the runtime counter. A stricter variant "
        "using only the first 2 bins gives macro-F1 %.3f." % heur_h2["macro_f1"],
        "Calibration choice is made on pooled out-of-fold TEST ECE (as specified); with only two candidates this is a "
        "mild selection effect on the reported chosen ECE.",
        "Joined flows: %d; label lines without a collected flow: %d (of which call/gaming UDP over IPv6: %d); "
        "collected flows without a label (dropped): %d." % (len(flows), lab_wo, v6udp, unj),
        "Not modelled in the promote metrics: the controller's demote-on-behaviour guard and the Voice-share shield "
        "(policy.admit_voice), both of which can only remove promotions.",
        "Stage-1 is evaluated on the first 8 recorded packets; at runtime predict1 may fire at age > 1 s with fewer "
        "packets (only for slow flows).",
        "Distribution of recorded bins per flow: %s." % dict(sorted(nbins.items())),
        "Synthetic generators (halo/gen.py) only: results describe separability of these generators under this "
        "rig, not real applications.",
    ]
    if v6udp:
        notes.append("FINDING: %d labelled call/gaming UDP-over-IPv6 flows never appear in raw_flows.jsonl -> the "
                     "classifier is neither trained nor evaluated on IPv6 interactive flows, and the controller probably "
                     "never classifies them at runtime (sniffer/conntrack path issue; outside this pipeline)." % v6udp)
    if any(not s["batch"].startswith("r") or s["why"].startswith("not a matrix") for s in skipped):
        notes.append("Skipped: %s" % skipped)
    for nm, e, ch in (("stage-2 (h=2)", ece2, chosen2), ("stage-1", ece1, chosen1)):
        if e["raw"] < e[ch]:
            notes.append("%s: uncalibrated ECE (%.4f) is LOWER than the chosen %s (%.4f); per the spec only temperature vs "
                         "isotonic is chosen. Calibration fitted on a few held-out sessions does not transfer perfectly to "
                         "new sessions." % (nm, e["raw"], ch, e[ch]))
    if pm_ml["n_wrongly_promoted"] == 0:
        notes.append("Zero wrongful ML promotions out of %d non-interactive flows: 95%% upper bound %.3f (Clopper-Pearson, "
                     "ignoring batch clustering) - absence of errors in this sample, not proof of zero risk."
                     % (pm_ml["n_non_interactive"], pm_ml["wrongful_promotion_ci95"][1]))
    ttl_vals = sorted(set(p[2] for f in flows for p in f["pkts"]))
    notes.append("TTL/hop-limit values observed in the data: %s. If TTL is constant per direction in this rig, the "
                 "ablation cannot show a leak here (direction is already in the signed size); real homes with mixed OSes "
                 "(TTL 64/128/255) could still leak device identity." % ttl_vals[:12])
    lossy = [r["batch"] for r in report if r["unjoinable_flows"] > r["joined"]]
    if lossy:
        notes.append("Batches with more unlabelled than labelled collected flows (label file incomplete?): %s - their "
                     "unlabelled flows are dropped, not guessed." % lossy)
    if bundle["cal2"]["kind"] == "temperature":
        Ts = [fi["stats"]["s2"]["T"] for fi in cv["fold_info"]]
        notes.append("Deployed stage-2 temperature T=%.3f (fit on %s); CV-fold temperatures ranged %.3f-%.3f, so the "
                     "deployed calibration is not identical to the evaluated ones." % (
                         bundle["cal2"]["T"], ",".join(bundle["cal_batches"]), min(Ts), max(Ts)))
    if len(batches) < 20:
        notes.append("Only %d complete batches were available (target >= 20)." % len(batches))
    gap = ttl["macro_f1"] - ml["macro_f1"]
    notes.append("TTL ablation: macro-F1 with TTL %.3f vs without %.3f (gap %+.3f)." % (ttl["macro_f1"], ml["macro_f1"], gap))
    notes.append("Generator-artefact probe: the first upstream TCP payload packet is gen.py's request line, whose length "
                 "differs by client (bulk always requests 2**40 bytes -> constant length). With that one size masked, "
                 "macro-F1 is %.3f (bulk F1 %.3f) vs %.3f unmasked (bulk F1 %.3f). Call vs gaming are separated mainly by "
                 "the generators' non-overlapping packet-size ranges in scenarios/run.py." % (
                     masked["macro_f1"], masked["per_class"]["bulk"]["f1"], ml["macro_f1"], ml["per_class"]["bulk"]["f1"]))
    if ml["macro_f1"] <= heur["macro_f1"]:
        notes.append("HONEST RESULT: the ML model does NOT beat the deterministic heuristic on macro-F1 here.")

    ev = {
        "macro_f1_no_ttl": ml["macro_f1"], "macro_f1_with_ttl": ttl["macro_f1"], "macro_f1_heuristic": heur["macro_f1"],
        "accuracy_no_ttl": ml["accuracy"], "accuracy_with_ttl": ttl["accuracy"], "accuracy_heuristic": heur["accuracy"],
        "ece_raw": ece2["raw"], "ece_temperature": ece2["temperature"], "ece_isotonic": ece2["isotonic"],
        "ece_chosen": ece2[chosen2], "chosen_calibration": chosen2,
        "ece_scope": "stage-2 model at h=2, pooled out-of-fold test predictions, 15 bins, top-1 (halo.classifier.ece)",
        "ece_stage2_all_h": ece2_all, "ece_stage1": ece1, "chosen_calibration_stage1": chosen1,
        "ece_with_ttl": eceT, "chosen_calibration_with_ttl": chosenT,
        "split": "leave-batches-out GroupKFold, k=%d (group = DATAGEN batch/session); calibration = %d%% of training "
                 "batches, group-disjoint, inside each training fold" % (cv["k"], round(CAL_FRAC * 100)),
        "folds": cv["fold_info"],
        "n_flows": len(flows), "n_batches": len(batches), "batches": batches,
        "n_eval_flows_h2": int(m2h2.sum()), "flows_per_class": dict(cnt), "per_batch": report, "skipped_batches": skipped,
        "per_class": {"no_ttl": ml["per_class"], "with_ttl": ttl["per_class"], "heuristic": heur["per_class"]},
        "confusion": {"labels": list(C.CLASSES), "layout": "rows = true class, cols = predicted",
                      "no_ttl": ml["confusion"]["rows_true_cols_pred"], "with_ttl": ttl["confusion"]["rows_true_cols_pred"],
                      "heuristic": heur["confusion"]["rows_true_cols_pred"]},
        "reliability": {"method": chosen2, "bins": reliability(P2c[m2h2], yh)},
        "reliability_raw": reliability(oof["s2"]["raw"][m2h2], yh),
        "wrongful_promotion": {"ml": pm_ml["wrongful_promotion"], "heuristic": pm_h["wrongful_promotion"],
                               "ml_with_ttl": pm_ttl["wrongful_promotion"], "ml_uncalibrated": pm_raw["wrongful_promotion"]},
        "interactive_recall_promote": {"ml": pm_ml["interactive_recall_promote"], "heuristic": pm_h["interactive_recall_promote"],
                                       "ml_with_ttl": pm_ttl["interactive_recall_promote"],
                                       "ml_uncalibrated": pm_raw["interactive_recall_promote"]},
        "promote_counts": {"ml": pm_ml, "heuristic": pm_h},
        "runtime_emulation_ml": rt,
        "per_horizon_macro_f1": {k: v["macro_f1"] for k, v in per_h.items()},
        "ablation_request_size_masked": {"macro_f1": masked["macro_f1"], "accuracy": masked["accuracy"],
                                         "per_class": masked["per_class"],
                                         "confusion": masked["confusion"]["rows_true_cols_pred"],
                                         "what": "first upstream TCP payload packet (gen.py request line) set to a constant "
                                                 "size in train+cal+test; stage-2 h=2, same folds"},
        "per_horizon_n": {k: v["n"] for k, v in per_h.items()},
        "per_horizon_per_class": {k: v["per_class"] for k, v in per_h.items()},
        "heuristic_tot_first2bins": {"macro_f1": heur_h2["macro_f1"], "per_class": heur_h2["per_class"]},
        "bootstrap": boot,
        "inference_us_per_flow": verify.get("inference_us_per_flow_stage2_median"),
        "inference_us_per_flow_stage1": verify.get("inference_us_per_flow_stage1_median"),
        "inference_note": "median wall time of one Model.predict2(flow, 2) call (features + XGBoost + calibration), "
                          "single flow, this machine (%d CPUs)" % (os.cpu_count() or 0),
        "feature_names": {"stage1": list(C.F1_NAMES), "stage2": list(C.F2_NAMES),
                          "with_ttl_ablation": list(C.F2_NAMES) + list(C.TTL_NAMES)},
        "model": {"path": None if a.no_write_model else os.path.relpath(model_path, a.root), "version": bundle["version"],
                  "xgb_params": XGB_PARAMS, "fit_batches": bundle["fit_batches"], "cal_batches": bundle["cal_batches"],
                  "cal1": {"kind": bundle["cal1"]["kind"], "T": bundle["cal1"].get("T")},
                  "cal2": {"kind": bundle["cal2"]["kind"], "T": bundle["cal2"].get("T")},
                  "n_rows": {k: bundle[k] for k in ("n_fit_rows1", "n_cal_rows1", "n_fit_rows2", "n_cal_rows2")},
                  "data_sha256": dh, "verify": verify},
        "notes": notes,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    json.dump(ev, open(os.path.join(out_dir, "eval.json"), "w"), indent=1)
    write_readme(os.path.join(out_dir, "README.md"), ev)
    log("wrote %s/eval.json and README.md" % out_dir)


# ============================================================================ README (numbers filled from eval)
def write_readme(path, ev):
    f3 = lambda v: "n/a" if v is None else "%.3f" % v
    pc = lambda v: "n/a" if v is None else "%.1f %%" % (100 * v)
    L = []
    L.append("# M2 classifier - training and evaluation\n")
    L.append("Generated by `analysis/train_classifier.py` on %s. Every number below is read from `eval.json`.\n" % ev["generated"])
    L.append("## Data\n")
    L.append("* %d labelled flows from %d complete DATAGEN batches (%s). Flows per class: %s." % (
        ev["n_flows"], ev["n_batches"], ", ".join(ev["batches"]),
        ", ".join("%s %d" % (c, ev["flows_per_class"].get(c, 0)) for c in ev["confusion"]["labels"])))
    L.append("* Each batch is one recorded session with its own random link rate, ports, packet sizes/rates and IPv4/IPv6 mix. "
             "Flow records (`ctl/raw_flows.jsonl`, written by the controller with `--collect`) are joined to the generator "
             "labels (`labels.jsonl`) on the 5-tuple (protocol, LAN address/port, WAN address/port), only within the same batch.")
    L.append("* Features are computed by the very functions the controller uses at runtime (`halo.classifier.feat1/feat2`): "
             "protocol, first 8 packet sizes with direction, inter-arrival times, and rate-shape statistics over the first h "
             "conntrack intervals. No addresses, ports, payload or TTL.\n")
    L.append("## How we evaluated (and why)\n")
    L.append("Flows from the same session share conditions (link rate, host, generator parameters). Splitting flows or packets "
             "at random would let the model recognise the session instead of the traffic class, which inflates scores "
             "(Arp et al., USENIX Security 2022; Zhao et al., SIGCOMM 2025). So whole batches are held out:\n")
    L.append("* **Split:** %s." % ev["split"])
    L.append("* Inside each training fold, a separate group of batches is used only to fit the calibration; the test batches are "
             "never seen by fitting or calibration.")
    L.append("* XGBoost, %d trees, depth %d, learning rate %s, class-balanced weights, fixed seed, single thread (deterministic)." % (
        ev["model"]["xgb_params"]["n_estimators"], ev["model"]["xgb_params"]["max_depth"], ev["model"]["xgb_params"]["learning_rate"]))
    L.append("* The deployed decision is the stage-2 model after h=2 conntrack intervals; all classification numbers use the "
             "calibrated probabilities that are actually deployed.\n")
    L.append("## Results (out-of-fold, %d flows at h=2)\n" % ev["n_eval_flows_h2"])
    b = ev.get("bootstrap") or {}
    L.append("| classifier | macro-F1 | accuracy |\n|---|---|---|")
    L.append("| ML, no TTL (deployed, h=2) | %s %s | %s |" % (f3(ev["macro_f1_no_ttl"]),
             "(95%% CI %s-%s)" % tuple(f3(x) for x in b["macro_f1_no_ttl_ci95"]) if b else "", f3(ev["accuracy_no_ttl"])))
    L.append("| ML + TTL (leak ablation) | %s | %s |" % (f3(ev["macro_f1_with_ttl"]), f3(ev["accuracy_with_ttl"])))
    L.append("| port/protocol/elephant heuristic | %s %s | %s |" % (f3(ev["macro_f1_heuristic"]),
             "(95%% CI %s-%s)" % tuple(f3(x) for x in b["macro_f1_heuristic_ci95"]) if b else "", f3(ev["accuracy_heuristic"])))
    if b:
        L.append("\nPaired batch bootstrap, ML minus heuristic macro-F1: 95%% CI %s to %s." % tuple(f3(x) for x in b["diff_ml_minus_heuristic_ci95"]))
        if "diff_ttl_minus_no_ttl_ci95" in b:
            L.append("With-TTL minus no-TTL: 95%% CI %s to %s." % tuple(f3(x) for x in b["diff_ttl_minus_no_ttl_ci95"]))
    ab = ev["ablation_request_size_masked"]
    L.append("\nShortcut check: with the size of the generator's request packet masked (an artefact of the synthetic "
             "traffic tool, not of real applications), ML macro-F1 is %s (bulk F1 %s)." % (f3(ab["macro_f1"]), f3(ab["per_class"]["bulk"]["f1"])))
    L.append("\nMacro-F1 by decision point: " + ", ".join("%s %s (n=%d)" % (k, f3(v), ev["per_horizon_n"][k])
                                                      for k, v in ev["per_horizon_macro_f1"].items()) + ".\n")
    L.append("### Per class (precision / recall / F1)\n")
    L.append("| class | ML no-TTL | heuristic | support |\n|---|---|---|---|")
    for c in ev["confusion"]["labels"]:
        m, h = ev["per_class"]["no_ttl"][c], ev["per_class"]["heuristic"][c]
        L.append("| %s | %s / %s / %s | %s / %s / %s | %d |" % (c, f3(m["precision"]), f3(m["recall"]), f3(m["f1"]),
                 f3(h["precision"]), f3(h["recall"]), f3(h["f1"]), m["support"]))
    L.append("\nConfusion matrices (rows = true, columns = predicted, order %s):\n" % ", ".join(ev["confusion"]["labels"]))
    for k in ("no_ttl", "with_ttl", "heuristic"):
        L.append("* %s: `%s`" % (k, ev["confusion"][k]))
    L.append("\n### Promotion to the interactive (Voice) tin\n")
    L.append("A flow is promoted only if its class is call/gaming with calibrated confidence >= 0.9 (`policy.tin_for`).\n")
    L.append("| | wrongful promotion (non-interactive flows promoted) | interactive recall under the rule |\n|---|---|---|")
    for k, lab in (("ml", "ML (h=2, calibrated)"), ("ml_uncalibrated", "ML (h=2, uncalibrated)"), ("heuristic", "heuristic")):
        L.append("| %s | %s | %s |" % (lab, pc(ev["wrongful_promotion"][k]), pc(ev["interactive_recall_promote"][k])))
    rt = ev["runtime_emulation_ml"]
    L.append("\n95%% intervals (Clopper-Pearson, flows treated as independent): ML wrongful %s, heuristic wrongful %s; "
             "ML recall %s, heuristic recall %s." % tuple("[%s, %s]" % (pc(x[0]), pc(x[1])) for x in (
                 ev["promote_counts"]["ml"]["wrongful_promotion_ci95"], ev["promote_counts"]["heuristic"]["wrongful_promotion_ci95"],
                 ev["promote_counts"]["ml"]["interactive_recall_promote_ci95"],
                 ev["promote_counts"]["heuristic"]["interactive_recall_promote_ci95"])))
    L.append("\nReplaying the controller's full ML sequence (stage 1, then h=2/4/6): a non-interactive flow is promoted at "
             "*some* point in %s of cases (%d of %d) and at the end in %s; interactive recall %s at some point, %s at the end.\n" % (
                 pc(rt["wrongful_promotion_ever"]), rt["n_wrong_ever"], rt["n_non_interactive"],
                 pc(rt["wrongful_promotion_final"]), pc(rt["interactive_recall_ever"]), pc(rt["interactive_recall_final"])))
    L.append("## Calibration\n")
    L.append("Expected calibration error (15 bins, top-1) on the held-out test batches: raw %s, temperature scaling %s, "
             "per-class isotonic %s. Chosen: **%s** (lower ECE). Stage-1 choice: %s." % (
                 f3(ev["ece_raw"]), f3(ev["ece_temperature"]), f3(ev["ece_isotonic"]), ev["chosen_calibration"],
                 ev["chosen_calibration_stage1"]))
    L.append("\n| confidence bin | flows | mean confidence | accuracy |\n|---|---|---|---|")
    for r in ev["reliability"]["bins"]:
        if r["count"]:
            L.append("| %.2f-%.2f | %d | %s | %s |" % (r["lo"], r["hi"], r["count"], f3(r["conf"]), f3(r["acc"])))
    L.append("\n## Deployed model\n")
    L.append("`halo/model.pkl`, version `%s` (hash of the training files + parameters). Fit on batches %s; calibrated on the "
             "disjoint batches %s. Verified by loading with `halo.classifier.Model`. Median inference time per flow "
             "(features + model + calibration): %s us." % (
                 ev["model"]["version"], ", ".join(ev["model"]["fit_batches"]), ", ".join(ev["model"]["cal_batches"]),
                 "n/a" if ev["inference_us_per_flow"] is None else "%.0f" % ev["inference_us_per_flow"]))
    L.append("\n## Caveats\n")
    for n in ev["notes"]:
        L.append("* " + n)
    open(path, "w").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
