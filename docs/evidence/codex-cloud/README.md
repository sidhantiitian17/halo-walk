# HALO-Walk inside Codex Cloud

The cloud host ran as UID 1000, with zero effective and bounding capabilities. Creating a network namespace directly returned `Operation not permitted`. A nested user namespace could be created without a UID map. Mapping root failed on the read-only `/proc/self/uid_map`, and an unmapped child had no effective capabilities and could not create a veth pair. The host had `tc` but exposed neither the running kernel's module directory nor `/dev/kvm`. See [host command outputs](host-preflight.txt).

The benchmark used an x86-64 QEMU 10.0.13 TCG guest with two vCPUs, 4 GiB of RAM and Debian Linux 6.12.118. QEMU ran as the normal cloud user with no guest NIC. Only the benchmark exchange directory and read-only Python dependencies were shared. Package downloads used the signed Debian repositories. The guest created its own namespaces and veth devices and attached real kernel CAKE and NetEm queue disciplines. The original topology and workload are emulated. The qdiscs, packet paths, process accounting, and measurements are from the guest Linux kernel. See [guest command outputs](guest-preflight.txt).

## Repeat the benchmark

Run from the repository root on the Debian 13 Codex Cloud machine. The setup script uses writable storage under `/workspace` and does not need host sudo.

```bash
scripts/cloud_vm/prepare.sh /workspace/halo-benchmark-vm
scripts/cloud_vm/boot.sh /workspace/halo-benchmark-vm
```

Keep the guest running. Submit each source revision from its checkout after the console prints `HALO_GUEST_READY`. The guest first runs the veth and qdisc preflight, then runs the existing scenario harness serially.

```bash
scripts/cloud_vm/submit.sh /workspace/halo-benchmark-vm run-01 \
  CPU,C1,1 CPU,C1,2 CPU,C3,1 CPU,C3,2 CPU,C4,1 CPU,C4,2 \
  S2,C3,1 S2,C3,2 S2,C3,3
```

The guest writes raw runs to `/workspace/halo-benchmark-vm/exchange/run-01` and the batch exit code to `exchange/status`. To score the runs, copy that directory's contents under a separate `results/raw` and pass its parent project directory to the scorer.

```bash
mkdir -p /workspace/halo-score/results/raw
cp -r /workspace/halo-benchmark-vm/exchange/run-01/. /workspace/halo-score/results/raw/
MPLCONFIGDIR=/tmp/halo-mpl /workspace/halo-benchmark-vm/venv/bin/python \
  scripts/cloud_vm/score.py /workspace/halo-score
```

The scorer invokes the original M4 and M12 functions and checks that the campaign includes the original number of repetitions. M4 requires median adaptation at most 2 s, recovery at most 30 s, and at most 6 rate changes per minute. M12 requires both controller variants to use at most 2% of one core above static CAKE. The original results and analyzer remain intact.

## Repeat the full matrix

Prepare the guest from the revision you want to measure. Start it with three vCPUs to match the latest targeted campaigns.

```bash
vm=/workspace/halo-benchmark-vm
scripts/cloud_vm/prepare.sh "$vm"
HALO_VM_VCPUS=3 scripts/cloud_vm/boot.sh "$vm"
```

From a second terminal in the same checkout, submit a new label after the guest prints `HALO_GUEST_READY`. The job executes the original 20, 50 and 100 Mbit/s fidelity tests, the 95 runs in `lists/all.txt` and the 24 classifier data batches in `lists/dg2.txt`, in order. The guest records the exact source revision and archives every completed run, including unsuccessful runs. The original workload runner and scoring rules apply.

```bash
vm=/workspace/halo-benchmark-vm
label=matrix-01
scripts/cloud_vm/submit-matrix.sh "$vm" "$label"
```

Wait for the batch exit code in `exchange/status`. Copy the guest output to a separate directory so the imported evidence stays intact. Run the scorer from the measured checkout. It runs leave-batch-out evaluation on the new classifier data and records missing runs and late controller startup alongside the original M1–M12 analysis.

```bash
input="$vm/exchange/$label"
report="/workspace/$label-report"
mkdir -p "$report/results/raw"
cp "$input/"{all.txt,dg2.txt,source-revision.txt,input-sha256.txt} "$report/"
while read -r scenario; do
    if [ -d "$input/$scenario" ]; then
        cp -a "$input/$scenario" "$report/results/raw/"
    fi
done < <(awk '{print $1}' "$input/all.txt" "$input/dg2.txt" | sort -u)
cp -a "$input/fidelity" "$report/results/"
MPLCONFIGDIR=/tmp/halo-mpl "$vm/venv/bin/python" scripts/cloud_vm/report-matrix.py "$report"
```

## Evidence

Each experimental revision has a separate directory under [results/codex-cloud](../../../results/codex-cloud). A candidate uses the static-CAKE runs from the same guest through its shared C1 path. This avoids duplication of control runs. Each `score.json` distinguishes an incomplete campaign from a pass.

| Directory | Source revision |
|---|---|
| `baseline` | `d7c24faa4bdb863b71914c518edc3008c54edd1d` |
| `candidate` | `01d751666f2ef64386b50c1871a9791d045e883b` |
| `candidate2` | `bd82666f65c45c86a302479a779afb733bdf6a11` |
| `candidate3` | `9318173` |
| `candidate4` | `8b6d3b42fe3d230bdd403e5083b9ea7eb1a3bba5` |
| `candidate5-smoke` | `42799d4f993b51bfa2ec9ac7f61c7253741a7e3b` (separate guest, diagnostic only) |
| `candidate6` | `21ca28e044252507f7559f98a8359bc5ba5a8463` |
| `candidate7` | `6247ae4e8ec1c81b22e1f46e14f5f40479ad5420` |
| `candidate8` | `5c8bf0016999091f9949d08cbf652f848579d130` |
| `three-vcpu-baseline` | `d7c24faa4bdb863b71914c518edc3008c54edd1d` (three-vCPU guest, dependencies staged on the guest filesystem) |
| `three-vcpu-candidate8` | `5c8bf0016999091f9949d08cbf652f848579d130` (three-vCPU guest) |
| `three-vcpu-candidate9` | `6f6005e04020053e47d8d10e79c45beacae1c2c7` (three-vCPU guest) |
| `three-vcpu-candidate9-local-deps` | `6f6005e04020053e47d8d10e79c45beacae1c2c7` (three-vCPU guest, dependencies staged on the guest filesystem) |

The original evidence campaign used Ubuntu 6.8. This Debian guest is a separate measurement environment. Compare baseline and candidate within the cloud guest. The original results remain in `results/raw`.

The second guest reproduced the kernel preflight. Its diagnostic C4 run began traffic before the model finished loading, so the scorer excludes its CPU number. The batch helper stages the pinned Python environment on the guest filesystem before its first C4 run. The scorer checks that adaptive-controller telemetry started before the workload.

The 22 tracked source and model files in each guest input bundle were byte-compared with its source revision. See [native build fingerprints](native-builds.txt) and [unchanged harness and scorer fingerprints](unchanged-files.sha256). The separate setup diagnostic overlapped part of the candidate4 campaign. The candidate6 and candidate7 campaigns ran without the diagnostic guest.

The three-vCPU diagnostic used `HALO_VM_VCPUS=3` with the same C8 source, kernel and workload. The first guest had exited before the diagnostic began. The three-vCPU evidence is scored separately. See [three-vCPU preflight](three-vcpu-preflight.txt).

Both initial three-vCPU ML trials loaded the model after traffic began. The guest-local dependency stage was verified with the original harness and produced a ready controller before the measured traffic. The local-dependency campaign uses its own C1 reference runs and original repetitions.

## Complete three-vCPU candidate campaign

The guest-local campaign finished all nine runs. Controller telemetry began before traffic in every adaptive run. The scorer used both static-CAKE runs from the same guest.

| Acceptance check | Measured median | Limit | Result |
|---|---:|---:|---|
| M12 heuristic CPU above static CAKE | 1.67% of one core | 2% | Pass |
| M12 ML CPU above static CAKE | 1.80% of one core | 2% | Pass |
| M4 adaptation | 2.10 s | 2.00 s | Fail |
| M4 recovery | 10.1 s | 30 s | Pass |
| M4 steady-state rate changes | 0.0/min | 6/min | Pass |

The M4 adaptation repetitions were 2.10, 2.20 and 2.10 s. The CPU repetitions were 1.58% and 1.76% for the heuristic controller, and 1.53% and 2.07% for ML. The existing M12 rule uses the median for each configuration. See the [machine-readable score](../../../results/codex-cloud/three-vcpu-candidate9-local-deps/score.json), [raw runs](../../../results/codex-cloud/three-vcpu-candidate9-local-deps/results/raw), and [controller test output](controller-tests.txt).

The original controller's matched three-vCPU M4 repetitions were all 2.20 s, with median recovery of 15.4 s and 0.0 rate changes per minute. The candidate improved median adaptation by 0.10 s and median recovery by about 5.3 s on that guest. Both versions missed the 2.00 s adaptation gate there. The archived 1.90 s result was measured on the earlier Ubuntu guest. See the [matched baseline score](../../../results/codex-cloud/three-vcpu-baseline/score.json) and [raw runs](../../../results/codex-cloud/three-vcpu-baseline/results/raw).

## Adaptation profile

The time origin is the original S2 `rate_down` marker after both rig rate commands. The profile records the native drop observation, reflector confirmation, controller decision, CAKE update and packet arrival relative to that marker. The downlink can begin slowing before the marker. Acceptance uses the original rolling one-second p95 and rate-band checks.

In the packet-tap repetition, 13,246 call packets matched at modem ingress, gateway ingress and client receipt. During the first half-second the modem-to-gateway p95 rose from 3.7 ms to 167.2 ms. In the next 0.6 s the gateway-to-client p95 rose from 2.6 ms to 128.8 ms. In the 0.7–0.8 s interval the modem-to-gateway p95 had fallen below 1 ms while the gateway-to-client p95 was still 121.4 ms. CAKE applied the first cut 234.9 ms after the marker and entered the scoring rate band at 1.10 s. The unchanged scorer returned 2.00 s for this diagnostic repetition. See the [packet taps and matched profile](../../../results/codex-cloud/m4-quorum-diagnostic).

| Targeted campaign | M4 repetitions (s) | Heuristic CPU median | ML CPU median | Combined |
|---|---|---:|---:|---|
| `m4-quorum` | 2.00, 2.10, 2.10 | 2.04% | 5.56% | Fail |
| `m4-native` | 2.10, never, 2.20 | 2.10% | 2.55% | Fail |
| `m4-shared-threshold` | 2.60, 2.30, 1.50 | 2.32% | 2.24% | Fail |
| `m4-fresh-delivery` | never, never, 1.70 | 4.21% | 16.05% | Fail |

In the native midpoint campaign, the failed S2 run had cut rates before the capacity step following late-probe alerts. In the CPU runs, the native thread reached 1.56% of a core in one heuristic repetition and 1.75% in one ML repetition. Both were measured inside the original process-wide CPU window. See the [quorum evidence](../../../results/codex-cloud/m4-quorum) and [native evidence](../../../results/codex-cloud/m4-native).

The widened native detector made the first cut within 26 ms of the harness marker in all three repetitions. Two runs still estimated initial capacity above 22 Mbit/s and cut initially to 6.6–6.8 Mbit/s. The 1.50 s run initially estimated 14.6 Mbit/s and cut to 4.38 Mbit/s. See the [widened-detector runs](../../../results/codex-cloud/m4-shared-threshold).

The fresh-sample detector applied its first cut 83 ms after the marker and entered the rate band at 0.80 s in the 1.70 s repetition. Its first repetition instead confirmed a drop using a sample 2.90 s old, beyond the 0.40 s confirmation window. One heuristic CPU repetition made a rate cut during routine replay while the native watcher had withheld an alert. All three M4 repetitions and all six CPU and control runs are included in the failed campaign. See the [fresh-sample evidence](../../../results/codex-cloud/m4-fresh-delivery).

The first fidelity capture was empty because package extraction had skipped creating the Debian `tcpdump` account. An independent run confirmed that the original `iperf3` flow reached the receiver and that HTB dequeued packets while `tcpdump` reported `Couldn't find user 'tcpdump'`. After installing the account, the original scorer passed 20 and 50 Mbit/s under the adopted criterion. The 100 Mbit/s test measured 94.33 Mbit/s and failed the ±4% limit. See the [capture diagnostic](../../../results/codex-cloud/m1-platform-diagnostic) and [fidelity repetitions](../../../results/codex-cloud/m1-platform-fixed).
