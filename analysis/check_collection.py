#!/usr/bin/env python3
"""Quantify the DATAGEN collection gaps per batch from the raw files only (no VM, no root).

    python3 analysis/check_collection.py [--root <project>] [--all]     # default: matrix reps r01..r30

Join = analysis/train_classifier.py: (proto, LAN ip, LAN port, WAN ip, WAN port), IPs canonicalised, same batch.
For every gap it prints the evidence that attributes it to a cause:

  v6udp_lab_nf   labelled UDP-over-IPv6 call/gaming flows missing from raw_flows.jsonl
    .twin6       ... of which flows.json (controller's live table at the end) holds a second, WAN-side twin key
                 with wan_ip fd00:9::6: the rt_server answered from the reflector alias instead of fd00:9::2
    .no_ct       ... of which neither key ever got a conntrack counter (rate_dn is the int default 0, never a
                 float): the entries were one-way "[UNREPLIED]" lines, which CT_RE did not match -> no bins -> the
                 dump rule (>= 2 bins) can never fire
  oth_lab_nf     other labels without a collected flow
    .live_end    ... of which the flow is still in flows.json at the end and its label is < 14 s old (12 s generator
                 + dump grace): the controller was killed before the flow was dumped
  unlab          collected flows without a label
    .after_copy  ... of which the flow started after labels.jsonl was copied (copy time ~= end - 2.5 s)
  gen_start      seconds from T0 to the first label line (generator start-up latency in the emulated VM)
  zero_bins      collected flows whose bins are all zero (the whole transfer happened before the first conntrack
                 poll, which only sets the baseline); poll interval statistics are printed at the end.
"""
import argparse, glob, ipaddress, json, os, statistics
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REFLECTOR6 = "fd00:9::6"
COPY_BEFORE_END_S = 2.5          # run.py: labels copied, then sleep(2.5), then mark("end")


def n(ip):
    return str(ipaddress.ip_address(ip))


def key(proto, lip, lport, wip, wport):
    return (proto, n(lip), int(lport), n(wip), int(wport))


def batch(d):
    meta = json.load(open(os.path.join(d, "meta.json")))
    end = next((e for e in meta.get("events", []) if e.get("name") == "end"), None)
    if end is None:
        return None
    t_end, t0 = end["t"], end["t"] - end["rel"]
    t_copy = t_end - COPY_BEFORE_END_S
    bid = "b%03d" % meta["rep"]
    labs = {}
    for l in open(os.path.join(d, "labels.jsonl")):
        if l.strip():
            r = json.loads(l)
            if r.get("batch", bid) == bid:
                labs[key(r["proto"], r["lan_ip"], r["lan_port"], r["wan_ip"], r["wan_port"])] = r
    raw = {}
    for l in open(os.path.join(d, "ctl", "raw_flows.jsonl")):
        if l.strip():
            r = json.loads(l)
            raw[key(*r["key"])] = r
    try:
        live = {key(*f["key"]): f for f in json.load(open(os.path.join(d, "flows.json")))["flows"]}
    except (OSError, ValueError):
        live = {}
    s = Counter(labels=len(labs), raw=len(raw), joined=sum(1 for k in raw if k in labs))
    for k, lab in labs.items():
        if k in raw:
            continue
        if k[0] == "udp" and ":" in k[1]:
            s["v6udp_lab_nf"] += 1
            twin = (k[0], k[1], k[2], REFLECTOR6, k[4])
            s["v6udp_lab_nf.twin6"] += twin in live
            if not any(isinstance(live.get(x, {}).get("rate_dn"), float) for x in (k, twin)):
                s["v6udp_lab_nf.no_ct"] += 1
        else:
            s["oth_lab_nf"] += 1
            s["oth_lab_nf.live_end"] += k in live and t_end - lab["t"] < 14
    for k, r in raw.items():
        if k not in labs:
            s["unlab"] += 1
            s["unlab.after_copy"] += r["t0"] > t_copy
        if r["bins"] and not any(b[1] or b[2] for b in r["bins"]):
            s["zero_bins"] += 1
    s["v6udp_raw"] = sum(1 for k in raw if k[0] == "udp" and ":" in k[1])
    dts = [b[0] for r in raw.values() for b in r["bins"]]
    first = min((l["t"] for l in labs.values()), default=float("nan"))
    return {"batch": os.path.basename(d), "gen_start": first - t0, "t_copy_rel": t_copy - t0, "s": s, "dts": dts}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=ROOT)
    p.add_argument("--all", action="store_true", help="include r00 / r31+ debug batches")
    a = p.parse_args()
    cols = ["labels", "raw", "joined", "v6udp_lab_nf", "v6udp_lab_nf.twin6", "v6udp_lab_nf.no_ct", "v6udp_raw",
            "oth_lab_nf", "oth_lab_nf.live_end", "unlab", "unlab.after_copy", "zero_bins"]
    short = ["lab", "raw", "join", "v6nf", "twin6", "no_ct", "v6raw", "othnf", "live", "unlab", "aftcp", "zbins"]
    print("%-5s %6s %6s " % ("batch", "gen_t0", "copy") + " ".join("%5s" % c for c in short))
    tot, dts = Counter(), []
    for d in sorted(glob.glob(os.path.join(a.root, "results", "raw", "DATAGEN", "C2", "r[0-9][0-9]*"))):
        rep = int(os.path.basename(d)[1:])
        if not a.all and not 1 <= rep <= 30:
            continue
        try:
            b = batch(d)
        except OSError as e:
            print("%-5s missing file: %s" % (os.path.basename(d), e))
            continue
        if b is None:
            print("%-5s incomplete (no 'end' event)" % os.path.basename(d))
            continue
        tot.update(b["s"]); dts += b["dts"]
        flag = "  <- labels truncated" if b["s"]["unlab"] > b["s"]["joined"] else ""
        print("%-5s %6.1f %6.1f " % (b["batch"], b["gen_start"], b["t_copy_rel"]) +
              " ".join("%5d" % b["s"][c] for c in cols) + flag)
    print("TOTAL %13s " % "" + " ".join("%5d" % tot[c] for c in cols))
    if dts:
        q = sorted(dts)
        print("conntrack poll interval (bin dt) n=%d median=%.2f s p10=%.2f p90=%.2f max=%.2f" % (
            len(q), statistics.median(q), q[len(q) // 10], q[9 * len(q) // 10], q[-1]))
    print("gen_t0 = first label - T0 [s]; copy = labels.jsonl copy time - T0 [s] (generators run 12 s)")


if __name__ == "__main__":
    main()
