# Independent audit of the v2 evidence matrix (2026-11-22)

An agent that took no part in building or fixing the system audited the code and results read-only. It found the result **11 PASS / 1 FAIL**, reproducible from the raw data.

## Integrity checks
- `analysis/analyze.py` is byte-identical to the pre-fix baseline (sha256 65bde3c3…). The criteria and thresholds are unchanged.
- `scenarios/` changes are harness-only: the S5 override client (`ovr_client.py`), CPU per-thread diagnostics, and the sentinel build step. Load, rates, flows and timelines are unchanged. `rig/` and `scenarios/fidelity.py` are identical to the baseline.
- **Completeness:**
  - all 95 listed runs started, completed and are present, with no FAILED runs;
  - every run started after the `CODE_FREEZE.json` epoch;
  - `md5sum -c CODE_FREEZE.md5` passes.
- **Independent re-derivation:**
  - M2 C3 median 7.71 ms (C3 vs C0 Holm p = 0.0043);
  - M4 C3 T_adapt 2.3 / 1.8 / 1.9 s (median 1.9);
  - M10 C3 0.159 / 0.223 / 0.183 s, consistent with controller events;
  - M12 C3 9.07 %, C4 9.10 %.
  - Re-running `analyze.py` reproduces `summary.json` exactly.
- **Gaming check:** no scenario-specific code in `halo/`. The HALO_* environment variables are tuning and diagnostic knobs with defaults, and the harness sets none of them per scenario.

## Verdicts
| M | Verdict | Note |
|---|---|---|
| M1 | PASS (adopted criterion) | The strict criterion (≤ 1 MTU time) fails at 20/50/100 Mbit/s. Data is from the earlier campaign; the rig is unchanged. |
| M2 | PASS | |
| M3 | PASS, fragile | Reps 10.7 / 6.9 / 7.0 ms (N=3). Uses a many-flows ceiling tuned on this scenario. |
| M4 | PASS, thin | Median 1.9 s against ≤ 2 s; one rep at 2.3 s. |
| M5 | PASS | N=2 per rate; 5.2 % error at 100 Mbit/s. |
| M6 | PASS | Depends on the decision not to auto-demote flows to the Bulk tin. |
| M7 | PASS | Lease expiry 15.2–16.0 s against a 16 s TTL. |
| M8 | PASS | Offline classifier. The deployed C3 controller does not act on size-based bulk verdicts. |
| M9 | PASS | Gate valid; the heuristic ships. |
| M10 | PASS (C3) | Post-hoc harness fix, disclosed. Legacy spawn-inclusive figure 0.76–1.22 s. The C4 half does not exercise the override. |
| M11 | PASS | Restore about 0.01 s; SAFE about 2.0 s. |
| M12 | **FAIL** | About 9.1 % of a core against ≤ 2 %, worse than v1 (7.4–8.2 %). Saturation-triggered full-rate probing, which M4 needs, keeps calm mode off. |

## Required disclosures
All are in the deck (Annexure 5 and 6):
- the M12 FAIL and its trade-off with M4;
- the M10 harness change with the legacy figure;
- the M1 strict criterion;
- the design changes tuned on the evaluation scenarios with no held-out set;
- the thin margins and low N;
- M8 measured offline;
- the in-process sentinel counted in M12;
- the DATAGEN data predating the freeze.
