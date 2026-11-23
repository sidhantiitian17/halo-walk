#!/usr/bin/env python3
"""Compare model inference on captured flows outside the acceptance run."""
import argparse
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from halo.classifier import HORIZONS, Model, feat1, feat2  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    args = parser.parse_args()
    flows = [json.loads(line) for path in args.captures for line in path.read_text().splitlines()]
    model = Model(ROOT / "halo/model.pkl")
    for stage in (1, 2):
        if stage == 1:
            samples = [(flow,) for flow in flows if len(flow["pkts"]) >= 2]
            extract = feat1
        else:
            samples = [(flow, h) for flow in flows for h in HORIZONS if len(flow["bins"]) >= h]
            extract = feat2
        if not samples:
            parser.error(f"no captures with usable stage {stage} data")
        reference = model.b[f"m{stage}"].predict_proba
        optimized = model._predictors[stage]
        results = []
        for predictor in (reference, optimized):
            model._predictors[stage] = predictor
            features, inference = [], []
            predictions = None
            for _ in range(5):
                start = time.thread_time()
                rows = [extract(*sample) for sample in samples]
                features.append(time.thread_time() - start)
                start = time.thread_time()
                predictions = [p for i in range(0, len(rows), 8) for p in model._predict_rows(stage, rows[i:i + 8])]
                inference.append(time.thread_time() - start)
            results.append((predictions, statistics.median(features), statistics.median(inference)))
        assert results[0][0] == results[1][0], f"stage {stage} calibrated outputs differ"
        print(f"stage={stage} rows={len(samples)} exact_match=true "
              f"feature_cpu_ms={1000 * results[1][1]:.3f} "
              f"reference_inference_cpu_ms={1000 * results[0][2]:.3f} "
              f"optimized_inference_cpu_ms={1000 * results[1][2]:.3f}")


if __name__ == "__main__":
    main()
