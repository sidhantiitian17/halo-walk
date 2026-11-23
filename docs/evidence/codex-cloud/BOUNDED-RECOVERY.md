# HALO-Walk Codex Cloud recovery and CPU retest

The controller at `6524cee69bd45af628712e1fe3d6cc0badedd81d` ran the original
S2 and CPU workload in the same three vCPU Debian 6.12.118 QEMU guest used for
`ee51eea`. The scorer included all three S2 repetitions and both repetitions
of C1, C3 and C4. [Raw runs and original scores](../../../results/codex-cloud/bounded-recovery)

| Check | Limit | Median | Result |
|---|---:|---:|---|
| M4 adaptation | ≤2.00 s | 1.80 s | PASS |
| M4 recovery | ≤30 s | 15.47 s | PASS |
| M4 steady rate changes | ≤6/min | 8.57/min | FAIL |
| M12 heuristic CPU above static CAKE | ≤2% of a core | 1.89% | PASS |
| M12 ML CPU above static CAKE | ≤2% of a core | 2.03% | FAIL |

Adaptation by repetition was 1.70, 1.80 and 2.70 s. Recovery was 10.59, 15.47
and 16.86 s. The final steady window contained six, five and zero rate
changes. In the second repetition the sentinel counter interval stretched to
476 ms immediately before it reported a collapse. The download had delivered
46.48 Mbit/s before that interval and 10.87 Mbit/s at the next sample. The
new rate was 3.26 Mbit/s. Probe delay had fallen to 2.34 ms at the next
active tick, 82 ms after the initial decision. In the first repetition,
delivery and delay varied before the cut, and the initial congestion alert
used ordinary delay confirmation. [Packet and controller timing](../../../results/codex-cloud/bounded-recovery/profile.json)

The original stall at 29.716 Mbit/s required 22.287 Mbit/s of arrival before
the estimator would probe higher. Arrival held near 20 Mbit/s and the
sentinel repeatedly woke Python at its lower threshold. This revision
shares an admission threshold between the estimator and sentinel. It allows
a smaller load fraction only when the arrival rate shows a substantial
increase over the last congestion ceiling and the target is bounded by
previously demonstrated clear delivery. The three new S2 repetitions
recovered through the ordinary load threshold. The below-threshold recovery
case has direct regression coverage. [Estimator and native changes](https://github.com/sidhantiitian17/halo-walk/commit/6524cee69bd45af628712e1fe3d6cc0badedd81d)

The two heuristic CPU repetitions used 1.66% and 2.12%. ML used 1.84% and
2.21%. Both ML repetitions stayed on the native calm path throughout the CPU
window. In the 2.21% repetition the sentinel used 1.30%, the slow loop 0.63%,
and the main loop 0.34% by thread counters. Comparing the existing and new
inference paths on 628 recorded stage 1 and 1,411 recorded stage 2 inputs
gave identical calibrated probabilities and decisions. In that isolated CPU
profile, inference cost fell by about 21% for stage 1 and 20% for stage 2.
[Thread counters](../../../results/codex-cloud/bounded-recovery/results/raw/CPU) ·
[Inference profile](../../../results/codex-cloud/bounded-recovery/model-profile.txt)

The HALO-Walk regression suite passed 331 checks with one expected failure.
A follow-up candidate for missed sentinel deadlines also passed the suite.
An experiment to widen the Python burst allowance was dropped after three
existing regressions failed. [Regression output](../../../results/codex-cloud/bounded-recovery/regression.txt) ·
[Follow-up and rejected experiment](../../../results/codex-cloud/timely-evidence)
