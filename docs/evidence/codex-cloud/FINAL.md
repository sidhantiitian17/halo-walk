# HALO-Walk Codex Cloud acceptance report

**Overall status: FAIL.** M4 and both M12 CPU variants passed together on
controller revision `d2165baf23279766ff8bfb1a2527313f760f3357` in the pinned
three vCPU Debian 6.12.118 QEMU guest. M1 fidelity remained below threshold
in the same guest. [Original scores and raw runs](../../../results/codex-cloud/timely-recovery)

| Check | Original limit | Measured | Verdict |
|---|---:|---:|---|
| M4 adaptation median | ≤2.00 s | 1.90 s | PASS |
| M4 recovery median | ≤30 s | 15.35 s | PASS |
| M4 steady rate changes median | ≤6/min | 0/min | PASS |
| M12 heuristic CPU above static CAKE | ≤2% of one core | 1.53% | PASS |
| M12 ML CPU above static CAKE | ≤2% of one core | 1.62% | PASS |
| M1 throughput at 100 Mbit/s, pinned guest | ≥96 Mbit/s | 90.36 Mbit/s | FAIL |

M4 used three repetitions. Adaptation was 1.90, 1.80 and 2.90 s, so the
passing median had 0.10 s of margin. Recovery was 15.35, 15.83 and 15.05 s.
Every repetition had zero steady rate changes. In the 2.90 s outlier the
first cut was applied 129 ms after the recorded step and the shaper entered
the target band at 0.90 s. Delayed call packets still affected the scorer's
one second latency window. The second repetition logged a 397 ms sentinel
sampling interval and used ordinary confirmation. [Packet timing and controller events](../../../results/codex-cloud/timely-recovery/s2-live-profile.json)

M12 used two static controls and two repetitions of each adaptive variant.
Heuristic used 1.69% and 1.37%, and ML used 1.52% and 1.73%. Both static
controls contributed 0% controller CPU. All nine targeted runs were included.
[CPU raw evidence](../../../results/codex-cloud/timely-recovery/results/raw/CPU)

The controller now shares a load gate with the native sentinel and can
probe toward previously demonstrated clear delivery after evidence of
recovery. A missed native sample deadline uses ordinary confirmation before
a severe loss decision. The classifier uses the existing XGBoost booster
for supported probability models and preserves calibration. On 2,039
captured classifier inputs, the faster inference path reduced measured
inference CPU by about 20% with identical calibrated outputs.
[Controller comparison and inference profile](BOUNDED-RECOVERY.md)

The 100 Mbit/s fidelity workload uses HTB and NetEm without HALO or CAKE.
Five tested profiles delivered 56.59 to 93.22 Mbit/s. The previous best
94.33 Mbit/s also falls short. The separate diagnostic with the original
160 Mbit/s request recorded only 92.9 Mbit/s of sender payload in the pinned
guest and zero HTB drops at all snapshots. The raw capture also reported
zero kernel drops. The four vCPU diagnostic also fell short of its offered
load and spent about 84% of one core in kernel CPU time on the sender over
the sampled interval. The managed host returned `Operation not permitted`
for network namespace creation and exposed no `/dev/kvm`. The guest
therefore used QEMU TCG to run the real Linux stack. The pinned guest
retained TSC throughout the M4 and M12 campaign. [M1 raw evidence and diagnosis](FIDELITY-FOLLOWUP.md) ·
[Clocksource log](../../../results/codex-cloud/timely-recovery/clock-post-run.txt)

The HALO-Walk regression suite ran 331 passing checks and one expected
failure. The older integration suite ran inside a separate guest
namespace with 95 passing checks, two skips and 17 passing subtests.
The older host suite encountered the same twelve environment failures
on the starting and final controller revisions. Git verified the
original scenario, rig, scorer and workload lists against the import. The
full M1–M12 matrix remains pending because M1 did not clear its original
fidelity gate. [Regression evidence](../../../results/codex-cloud/timely-evidence) ·
[Reproduction](README.md) · [Previous report](EE51-ACCEPTANCE.md)
