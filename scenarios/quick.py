#!/usr/bin/env python3
"""quick per-run summary (debug aid)"""
import csv, json, os, sys, statistics as st
d = sys.argv[1]
q = lambda v, p: sorted(v)[min(len(v) - 1, int(len(v) * p / 100))] if v else float("nan")
for name in ("call", "game"):
    f = os.path.join(d, name + ".csv")
    if os.path.exists(f):
        rows = [(float(x["t"]), float(x["owd_ms"])) for x in csv.DictReader(open(f))]
        if rows:
            t0 = rows[0][0]
            pre = [o for t, o in rows if 2 < t - t0 < 5.5]; post = [o for t, o in rows if t - t0 > 8]
            j = json.load(open(f + ".json"))
            print("%s n=%d loss=%.2f%% pre med %.1f p99 %.1f | load med %.1f p95 %.1f p99 %.1f" % (
                name, len(rows), 100 * (1 - j["recv_down"] / j["sent_down"]) if j.get("sent_down") else -1,
                st.median(pre), q(pre, 99), st.median(post), q(post, 95), q(post, 99)))
f = os.path.join(d, "bulk.json")
if os.path.exists(f):
    try:
        print("bulk mbps %.2f" % (json.load(open(f))["end"]["sum_received"]["bits_per_second"] / 1e6))
    except Exception as e:
        print("bulk parse", e)
f = os.path.join(d, "ctl", "events.jsonl")
if os.path.exists(f):
    ev = [json.loads(l) for l in open(f)]
    kinds = {}
    for e in ev:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print("events", kinds)
    t0 = ev[0]["t"]
    for e in ev:
        if e["kind"] in ("rate",) and e["dir"] == "dl":
            print("  %.1fs %s %.1f->%.1f c=%.1f ach=%.1f" % (e["t"] - t0, e["why"], e["old"], e["new"], e["c_est"], e["ach"]))
        elif e["kind"] not in ("rate", "start", "classify"):
            print("  %.1fs %s %s" % (e["t"] - t0, e["kind"], json.dumps({k: v for k, v in e.items() if k not in ("t", "kind")})[:150]))
for tv in ("tv1", "tv2", "tv3"):
    f = os.path.join(d, tv + ".csv")
    if os.path.exists(f):
        r = list(csv.DictReader(open(f)))
        if r:
            print(tv, "chunks", len(r), "mean rung %.2f stalls %d" % (st.mean(float(x["rung_mbps"]) for x in r), sum(int(x["stall"]) for x in r)))
s0 = os.path.join(d, "procstat_end.txt")
