# HALO-Walk evidence analysis

`analysis/analyze.py` turns the raw experiment bundles into the evidence package:

```
python3 analysis/analyze.py            # ~5-10 s; options: --root <project>, --boot <resamples>
```

| output | content |
|---|---|
| `results/summary.json` | `platform`, 12 `measurements` (`id,name,value,pass,criterion,detail`), `headline`, `notes` |
| `results/tables.md` | per-scenario × per-config tables, key pairwise comparisons |
| `results/figs/m01.png … m12.png` | one figure per measurement (title states criterion and PASS/FAIL/PENDING) |
| `results/figs/dashboard.png` | 2×3 time-series panel of a representative S1 run |

Dependencies: python3, numpy, matplotlib; scipy is used for Mann-Whitney if installed (own implementation otherwise).

## Ground rules

* Every value is computed from files on disk. Nothing is hard-coded. Traffic parameters that `run.py` does not
  copy into `meta.json` (gaming downstream rate, TV bitrate ladder, call packet rate) are **parsed from
  `scenarios/run.py`** itself.
* Missing data → `pass: null`, value `"pending: …"`, and a placeholder figure.
* A run counts only if `meta.json` exists **and** contains the `end` event (same rule as `scenarios/batch.sh`).
  Aborted/in-progress runs are listed in `notes`.
* **Matrix reps only**: only rep numbers `r01..r30` are analysed, in every scenario. `r00` and `r31+` (e.g. r90/r91)
  are debug runs of older controller code; they are listed in `notes` and ignored everywhere (incl. the dashboard).
* `summary.json` has a top-level `"matrix"`: `{scenario: {config: number of complete matrix reps}}`.
* A `Traceback` in a run's `ctl.log` is reported in `notes` (controller crash: truncated telemetry/events).
* Pass criteria are the pre-registered ones (constants at the top of `analyze.py`); they are not tuned to data.
* Statistical criteria (M2, M9) need ≥ 3 reps per group; otherwise `pass: null` ("pending: insufficient reps").
* Idempotent: all outputs are regenerated from scratch on every run (summary.json written atomically).

## Data sources and formats used

| file | columns / keys used |
|---|---|
| `call.csv`, `game.csv` | `t` (kernel RX time, s), `seq`, `owd_ms` (one-way delay, shared clock) — received downstream packets only |
| `call.csv.json` | `t0` (client start), `sent_down`, `recv_down` |
| `tv1..3.csv` | `t` (chunk request time), `rung_mbps`, `bytes`, `dl_s`, `stall` |
| `bulk.json`, `abuse.json` | iperf3 `-J -i 1`: `intervals[].sum.{start,end,bits_per_second}`, `intervals[].streams[]`, `end.sum_received`, `start.test_start.duration` |
| `meta.json` | `events[]` (`name`, `t` absolute, `rel`), `down`, `kernel`, `emulated`, `cpu{}`, `voice_tin_pkts_before_after`, … |
| `ctl/telemetry.csv` | `t,r_dl,r_ul,c_dl,c_ul,st_dl,st_ul,ach_dl,ach_ul,d_dl,d_ul,bloat_dl,bloat_ul,fsm` (10 Hz) |
| `ctl/events.jsonl` | `kind` ∈ {`rate`,`classify`,`txn_applied`,`rollback`,`commit`,…}, `t` |
| `watchdog_trip.json` | `t_detect`, `t_safe`, `hb_age` |
| `tc_lan0_end.json` | CAKE per-tin stats at run end (dashboard annotation only; no time series exists) |
| `results/fidelity/fid_<rate>.json` | `rate, rate_err_pct, dev_p95_us, dev_p99_us, mtu_time_us, cpu_idle_pct` |
| `results/classifier/eval.json` | `macro_f1_with_ttl, macro_f1_no_ttl, macro_f1_heuristic, ece_raw, ece_isotonic, ece_temperature, ece_chosen, split, n_flows, per_class, confusion`, reliability bins under `reliability_bins` / `reliability` / `reliability_diagram` (list of `{conf,acc,count}` or `[conf,acc,count]`, or dict of lists) |

iperf3 interval times are relative to the iperf3 launch; the launch time is taken from the harness event that
immediately precedes it (`load_on` for S1/S1x32/S5/S7; `start`+3 s for S2; `start` for S4/S6/EST/CPU;
`lease_granted` for `abuse.json`), because iperf3's own `timesecs` has 1-s resolution.

## Metric definitions

### Windows
* **Pre-load window**: `[call t0 + 1 s, load_on)` (S1, S1x32, S5, S7, S3-game); S2: `[call t0 + 0.5 s, start + 3 s)`
  (bulk launch). S4 and S6 start the call under load: no pre-load window; tables show absolute OWD only.
* **Load window**: `[load_on + 3 s, min(load_on + bulk duration, last packet)]` (3 s warm-up excluded).

### Real-time flow (call / game), per run
* **Added delay** = p99(OWD in load window) − median(OWD in pre-load window). p50/p95 analogous.
  Percentiles: linear interpolation (`numpy.percentile`).
* **RFC 3550 jitter**: transit times in send (`seq`) order, `J_i = J_{i-1} + (|D_i| − J_{i-1}) / 16`,
  `D_i = transit_i − transit_{i-1}`; reported value = mean of the running `J` over packets in the load window.
* **Loss** (missing packets count as lost): the sender schedule `send(seq) = a + seq / pps` is fitted on received
  packets (`send = t − owd`; `pps` from the fit, snapped to the configured rate parsed from run.py if within 5 %);
  loss in a window = 1 − (distinct received seq sent in the window) / (seq numbers sent in the window).
  Whole-run loss `1 − recv_down / sent_down` from the sidecar is also reported.
* Detail only: `p99_lost_inf_ms` = p99 with lost packets counted as infinite delay (`inf` if loss ≥ 1 %).

### Statistics (over reps)
* **Bootstrap 95 % CI**: percentile bootstrap of the median, 10 000 resamples, `numpy.random.default_rng(20261117)`.
  N < 2 → CI n/a. Difference CIs resample both groups independently: CI of median(A) − median(B).
* **Mann-Whitney U**: two-sided; scipy (`method="auto"`: exact for small samples without ties) or own
  normal approximation with tie and continuity correction; all-tied groups → p = 1.
* **Cliff's δ** = P(A > B) − P(A < B) = (#{a>b} − #{a<b}) / (n_A n_B); magnitude: |δ|<0.147 negligible,
  <0.33 small, <0.474 medium, else large.
* **Holm-Bonferroni**: within each comparison family (C3vsC0, C3vsC1, C3vsC2, C4vsC3), across scenarios
  {S1, S1x32, S7, S5, S2 (call), S3 (game)} with ≥ 2 reps per group: sorted p_(i) → max_{j≤i} min(1, (m−j+1) p_(j)).
* **Jain index** J(x) = (Σx)² / (n Σx²).

## The 12 measurements

| # | definition | pass (pre-registered) |
|---|---|---|
| M1 | per rate (median over files): `rate_err_pct`, `dev_p99_us`; strict = `dev_p99_us ≤ mtu_time_us`; adopted = `|rate_err_pct| ≤ 4 ∧ dev_p99_us ≤ 5000` | adopted at 20, 50 and 100 Mbit/s (strict reported per rate in `detail`) |
| M2 | S1 call added p99, jitter, loss for C0..C4; C3 vs C0/C1/C2 Δ median with CI, MW p, Holm p, Cliff's δ | median C3 ≤ 15 ms ∧ median C3 < median C0 ∧ Holm p < 0.05 |
| M3 | S1x32 call added p99 | median over C3 reps ≤ 10 ms |
| M4 | S2 (see below) | C3 medians: T_adapt ≤ 2 s ∧ recovery ≤ 30 s ∧ changes/min ≤ 6 |
| M5 | EST\<rate\>: c_est = median of non-zero `c_dl` in the last 10 s of telemetry; err = |c_est − meta.down| / meta.down. Only runs whose meta has `plan_dl` = 1.3 × `down` (±5 %) are used, so the estimator must discover capacity; older plan-80 EST runs are ignored and flagged in `notes` | median err ≤ 10 % at each of 10/20/50/100 |
| M6 | S3 gaming added p99 (game.csv); demand-normalised Jain over 3 TVs (below) | C3 medians: ≤ 15 ms ∧ Jain ≥ 0.9 |
| M7 | S4 (below) | every C3/C4 rep meets both parts |
| M8 | from eval.json | `ece_chosen ≤ 0.05 ∧ macro_f1_no_ttl > macro_f1_heuristic` |
| M9 | C4 − C3 difference of medians of added p99 (S1 call, S3 game, S5 call) with bootstrap CI | `pass` = evaluated validly (≥ 3 reps of C3 and C4 in each); value states outcome: "ML ships" iff some CI is entirely < 0 and no CI is entirely > 0, else "deterministic heuristic ships" |
| M10 | S5 override latency (below) | median ≤ 1 s |
| M11 | S6: **restore** = `rollback_s` of the first `rollback` event in `ctl/events.jsonl` (REGRESSED verdict → LKG re-applied and read back). **Detection** = the event's `detect_s` (bad policy applied → verdict = health window, bounded below by the controller's 1.5 s early check) is reported separately and not judged; `rollback.t − txn_applied.t` is kept as info. SAFE = `watchdog_trip.t_safe − meta kill9.t` | worst rep: restore ≤ 1 s after the REGRESSED verdict ∧ SAFE ≤ 3 s after kill -9 |
| M12 | CPU: `meta.cpu.ctl_pct_of_core` (C1: no controller → 0, i.e. NaN in meta mapped to 0) | median(C3) − C1 ≤ 2 ∧ median(C4) − C1 ≤ 2 (for configs present) |

### M4 (S2) details
* Capacities come from the meta events: new capacity = `rate_down.down`, restored = `rate_up.down`.
* dl shaper rate = step function of telemetry `r_dl` (fallback: `events.jsonl` `kind=rate, dir=dl`).
* **T_adapt**: on a 100 ms grid from `rate_down` to `rate_up`, condition A = |r_dl − 0.95·C_new| ≤ 0.10·0.95·C_new,
  condition B = p95 of call OWD in the trailing 1 s window ≤ pre-load median + 15 ms (needs ≥ 10 packets).
  T_adapt = first grid time at which A ∧ B hold **continuously for 1 s** (excludes a transient crossing) − `rate_down`.
  Never reached → `inf` ("never"). Detail also gives `t_settle_strict_s` (A ∧ B hold until `rate_up`).
  C0/C1: "never" (no adaptive shaper); their low-phase p99 added delay is reported as the latency penalty.
* **Recovery**: first time after `rate_up` with r_dl ≥ 0.9·0.95·C_up.
* **Stability**: dl rate-change events in `[rate_down − 20 s, rate_down)` plus `[end − 15 s, end]`, divided by 35 s, ×60.

### M6 (S3) TV fairness derivation
* Chunks requested ≥ `load_on + 3 s`. Segment period `seg` = median inter-request interval (data-driven).
* **Achieved goodput_i** = 8·Σbytes / max(n_chunks·seg, t_last + dl_last − t_first) — delivered media rate; stalls
  stretch the denominator.
* **Demand_i** = top rung of the TV ladder (`meta.tv_ladder` if present, else the default of `tv()` in run.py).
* **Capacity for TVs** = R − gaming downstream rate (pps_down·size_down parsed from `game()` in run.py), where
  R = median telemetry `r_dl` in the window (C2–C4), 0.95·meta.down (C1), meta.down (C0, no shaper).
* **Fair share_i** = max-min (water-filling) allocation of that capacity to the demands (= min(demand, equal share of
  residual)); x_i = goodput_i / share_i; Jain over x_1..x_3.

### M7 (S4)
* Lease window = `[lease_granted.t, lease_granted.t + ttl]`; only iperf3 1-s intervals fully inside it.
* R = median telemetry `r_dl` in the window (else 0.95·meta.down; C0: meta.down). Threshold 0.8·R/16. The threshold
  at the nominal 0.95·down is also reported in `detail`.
* Expiry: `lease_expired_in_kernel.after_grant_s ≤ ttl + 1` (a value ≤ 0 means run.py never saw the set empty
  within TTL+6 s → fail).

### M10 (S5) correction latency — evidence in priority order
1. `override_returned` (curl round-trip) when `voice_tin_pkts_before_after` shows Voice-tin packets increasing by the
   time the POST returned (kernel re-mark is effective at return);
2. first `ctl/events.jsonl` event after the POST that is an override/remark event, or `classify` with `stage=9`
   (override) and `tin=4` (Voice);
3. legacy harness: `meta.events[override_effective].latency_s`.

Data-plane cross-check in `detail.qoe_recovered_s`: first time ≥ 1 s after the POST at which the trailing-1 s call p95
OWD is back ≤ pre-load median + 15 ms.

## Dashboard
Representative run = S1 C3 rep whose call p99 added delay is closest to the C3 median (falls back to another config,
clearly labelled, if no C3 run exists). Panels: call OWD (points, 1-s p50/p99), running RFC 3550 jitter, 1-s call loss,
throughput (iperf3 1-s goodput, shaper `r_dl`, controller `ach_dl`), queue depth **proxy** = controller `d_dl` (probe
OWD above baseline; no CAKE backlog time series exists — tc stats are end-of-run snapshots, shown as an annotation;
without telemetry the proxy is call p50 OWD − pre-load median), Jain index over the 8 iperf3 streams per second.
