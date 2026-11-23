# HALO-Walk Codex Cloud acceptance report

**Overall result: FAIL.** The three-vCPU Debian guest ran the untouched S2 and CPU benchmarks against controller revision `ee51eeafc96bcbe920c27e97045f2a4ea9e811b0`. All three S2 repetitions, both static controls and both repetitions of each adaptive CPU variant are in the evidence. [Raw runs, packet timing profiles and original scores](../../../results/codex-cloud/severe-drop-followup)

| Check | Limit | Measured median | Result |
|---|---:|---:|---|
| M4 adaptation | ≤2.00 s | 2.00 s | PASS |
| M4 recovery | ≤30 s | Never reached | FAIL |
| M4 steady-state rate changes | ≤6/min | 1.71/min | PASS |
| M12 heuristic CPU above static CAKE | ≤2% of one core | 1.98% | PASS |
| M12 ML CPU above static CAKE | ≤2% of one core | 3.88% | FAIL |

M4 adaptation was never reached, 1.80 s and 2.00 s across the three repetitions. Recovery was never reached, 15.67 s and never reached. In the first repetition the nominal 18-second capacity step occurred at 26.14 s. In the third, the controller reached 29.72 Mbit/s after the capacity step back up, while the last ten one-second bulk intervals delivered 15.7–18.9 Mbit/s. The achieved load was below the controller's threshold for probing higher. The two ML CPU repetitions used 2.15% and 5.62%. In the higher-CPU run the controller cut the shaper from 39.08 to 8.17 Mbit/s during a delivery dip and spent the remaining part of that episode probing back up. [S2 and CPU traces](../../../results/codex-cloud/severe-drop-followup/results/raw)

The earlier `a84df7f` revision passed M4 at a 1.80 s median, with 15.15 s recovery and 0.0 changes/min, and failed both CPU gates. The earlier `6f6005e` revision passed both CPU gates at 1.67% and 1.80%, and missed M4 adaptation at 2.10 s. These are separate campaigns. [M4-passing campaign](../../../results/codex-cloud/m4-calm-replay) · [CPU-passing campaign](../../../results/codex-cloud/three-vcpu-candidate9-local-deps)

The managed host reported `CapEff: 0000000000000000`, `CapBnd: 0000000000000000` and no `/dev/kvm`. Rootless QEMU TCG booted Linux and passed the actual namespace, veth, CAKE and NetEm checks. At the 100 Mbit/s fidelity setting, two Debian trials delivered 94.33 and 89.39 Mbit/s against the original allowable rate error of ±4%. The Ubuntu kernel and iperf3 3.16 delivered 59.15 Mbit/s under QEMU 10. Under QEMU 8.2 they delivered 43.15 Mbit/s at the 50 Mbit/s setting and hit the execution timeout at 100 Mbit/s. [Host output](host-preflight.txt) · [Debian preflight](restarted-guest-preflight.txt) · [Fidelity evidence](README.md#original-kernel-comparison)

The final fidelity diagnostic changed only the traffic-generator version to iperf3 3.16 on the three-vCPU Debian guest. The original scorer passed the 20 Mbit/s run at 20.00 Mbit/s and failed the 50 and 100 Mbit/s runs at 42.97 and 83.19 Mbit/s. The original generator version therefore failed to resolve the throughput deficit in this environment. [Version output, raw captures and original score](../../../results/codex-cloud/debian-iperf316-fidelity)

The same controller revision passed the complete HALO-Walk regression suite with 329 passed and one expected failure. Git comparison against the imported version verified the original scenario, rig, analysis and workload-list files. The full M1–M12 matrix remains pending because no tested revision cleared M4 and both M12 gates together. [Regression output](severe-drop-regression.txt) · [Matrix reproduction](README.md#repeat-the-full-matrix)
