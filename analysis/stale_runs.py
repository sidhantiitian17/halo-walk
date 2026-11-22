#!/usr/bin/env python3
"""List matrix runs of adaptive configs (C2/C3/C4) that STARTED before the code freeze (results/CODE_FREEZE_EPOCH):
they were produced by superseded controller code and must be re-run. Prints 'SCN CFG REP' lines; --move archives them."""
import glob, json, os, re, shutil, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FZ = json.load(open(os.path.join(ROOT, "results/CODE_FREEZE.json")))      # per-config freeze epoch
out = []
for d in sorted(glob.glob(os.path.join(ROOT, "results/raw/*/*/r*"))):
    scn, cfg, rep = d.split(os.sep)[-3:]
    m = re.match(r"r(\d+)$", rep)
    if not m or not (1 <= int(m.group(1)) <= 30) or cfg not in ("C2", "C3", "C4") or scn == "DATAGEN":
        continue
    try:
        meta = json.load(open(os.path.join(d, "meta.json")))
        t0 = min(e["t"] for e in meta["events"])
    except Exception:
        t0 = os.path.getmtime(d)
    if t0 < FZ[cfg]:
        out.append((scn, cfg, int(m.group(1)), d))
for scn, cfg, rep, d in out:
    print(scn, cfg, rep)
    if "--move" in sys.argv:
        dst = os.path.join(ROOT, "results/raw_superseded/pre_freeze", scn, cfg, "r%02d" % rep)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(d, dst)
