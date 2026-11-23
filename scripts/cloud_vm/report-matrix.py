#!/usr/bin/env python3
"""Run the original M8 pipeline and M1–M12 scorer on one frozen campaign."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from analysis.analyze import Analysis, parse_harness  # noqa: E402


def expected_runs(root):
    return {
        (scenario, config, int(rep))
        for name in ("all.txt", "dg2.txt")
        for line in (root / name).read_text().splitlines()
        if (fields := line.split())
        for scenario, config, rep in [fields]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    expected = expected_runs(root)
    analyses = root / "results"
    with (analyses / "classifier-eval.log").open("w") as log:
        training = subprocess.run([
            sys.executable, str(REPO / "analysis/train_classifier.py"),
            "--root", str(root), "--no-write-model",
        ], stdout=log, stderr=subprocess.STDOUT, check=False)
    analysis = Analysis(str(root), 10000)
    analysis.H = parse_harness(str(REPO))
    observed = {(run.scn, run.cfg, run.rep) for run in analysis.runs}
    late_controller = []
    for run in analysis.runs:
        if run.cfg not in ("C2", "C3", "C4"):
            continue
        telemetry, start = run.telemetry(), run.t("start")
        if start is None or telemetry is None or telemetry["t"][0] > start:
            late_controller.append(run.id)
    summary = analysis.run()
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    passed = (not missing and not unexpected and not late_controller and training.returncode == 0
              and all(m["pass"] is True for m in summary["measurements"]))
    check = {
        "source_revision": (root / "source-revision.txt").read_text().strip(),
        "expected_runs": len(expected), "observed_runs": len(observed),
        "missing": missing, "unexpected": unexpected, "controller_not_ready": late_controller,
        "classifier_evaluation_exit": training.returncode, "all_pass": passed,
    }
    (analyses / "campaign-check.json").write_text(json.dumps(check, indent=2) + "\n")
    print(summary["headline"]["verdicts"])
    print(json.dumps(check, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
