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

## Evidence

Each experimental revision has a separate directory under [results/codex-cloud](../../../results/codex-cloud). A candidate uses the static-CAKE runs from the same guest through its shared C1 path. This avoids duplication of control runs. Each `score.json` distinguishes an incomplete campaign from a pass.

| Directory | Source revision |
|---|---|
| `baseline` | `d7c24faa4bdb863b71914c518edc3008c54edd1d` |
| `candidate` | `01d751666f2ef64386b50c1871a9791d045e883b` |
| `candidate2` | `bd82666f65c45c86a302479a779afb733bdf6a11` |
| `candidate3` | `9318173` |
| `candidate4` | `8b6d3b42fe3d230bdd403e5083b9ea7eb1a3bba5` |

The original evidence campaign used Ubuntu 6.8. This Debian guest is a separate measurement environment. Compare baseline and candidate within the cloud guest. The original results remain in `results/raw`.
