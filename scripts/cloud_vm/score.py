#!/usr/bin/env python3
"""Score the cloud run directories with the existing M4 and M12 analysis."""
import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from analysis.analyze import Analysis, fnum, parse_harness  # noqa: E402


def controller_ready(run):
    """Exclude runs where the traffic started before the controller was serving."""
    start = run.t("start")
    telemetry = run.telemetry()
    return start is not None and telemetry is not None and bool(telemetry["t"][0] <= start)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Directory containing results/raw")
    args = parser.parse_args()

    analysis = Analysis(str(args.root), 10000)
    analysis.H = parse_harness(str(REPO))
    rejected = []
    for scenario, config in (("CPU", "C3"), ("CPU", "C4"), ("S2", "C3")):
        ready = []
        for run in analysis.runs_of(scenario, config):
            if controller_ready(run):
                ready.append(run)
            else:
                rejected.append(run.id)
        if ready or config in analysis.by.get(scenario, {}):
            analysis.by[scenario][config] = ready
    analysis.m4()
    analysis.m12()
    required = {("S2", "C3"): 3, ("CPU", "C1"): 2, ("CPU", "C3"): 2, ("CPU", "C4"): 2}
    counts = {}
    for (scenario, config), expected in required.items():
        runs = analysis.runs_of(scenario, config)
        if scenario == "CPU":
            runs = [
                run for run in runs
                if (fnum((run.meta.get("cpu") or {}).get("wall_s")) or 0) >= 20
                and (config == "C1" or fnum((run.meta["cpu"]).get("ctl_pct_of_core")) is not None)
            ]
        counts[f"{scenario}/{config}"] = {"observed": len(runs), "expected": expected}
    enough = all(cell["observed"] >= cell["expected"] for cell in counts.values())
    passed = enough and all(analysis.M[m]["pass"] is True for m in (4, 12))
    print(json.dumps({
        "campaign_pass": passed if enough else None,
        "run_counts": counts,
        "controller_not_ready": rejected,
        "measurements": analysis.M,
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
