# M1 fidelity on the existing Codex Cloud guest

The original M1 workload asks iperf3 to send 1,400 byte UDP payloads at
160 Mbit/s for five seconds for the 100 Mbit/s modem setting. The scorer uses
the recorded frame sizes and dequeue timestamps. The modem uses HTB at
100 Mbit/s, with a 62,500 byte burst, zero configured overhead and a byte FIFO.
The captured data frames are 1,442 bytes. M1 creates the modem and NetEm rig
without starting the controller or installing CAKE. [Rig and original test](../../../scenarios/fidelity.py)

| Guest boot | 20 Mbit/s | 50 Mbit/s | 100 Mbit/s | Adopted M1 verdict |
|---|---:|---:|---:|---|
| Existing three vCPU, HPET | 19.99 | 49.38 | 80.93 | FAIL |
| Fresh three vCPU | 19.22 | 49.73 | 93.22 | FAIL |
| Fresh single vCPU | 19.89 | 47.68 | 80.99 | FAIL |
| Fresh three vCPU, pinned | 20.00 | 49.94 | 90.36 | FAIL |
| Fresh four vCPU | 19.99 | 42.28 | 56.59 | FAIL |

The minimum at the 100 Mbit/s setting is 96 Mbit/s. The existing long running
guest had switched from TSC to HPET after a 2.67 ms TSC watchdog read-back
delay exceeded the 0.125 ms limit. The fresh three vCPU run retained TSC at
every tested rate and still missed throughput. The original 94.33 Mbit/s
best remains below acceptance. [Existing guest](../../../results/codex-cloud/fidelity-current) ·
[Fresh three vCPU](../../../results/codex-cloud/fidelity-fresh-3vcpu) ·
[Fresh one vCPU](../../../results/codex-cloud/fidelity-fresh-1vcpu) ·
[Pinned three vCPU](../../../results/codex-cloud/fidelity-fresh-3vcpu-pinned) ·
[Fresh four vCPU](../../../results/codex-cloud/fidelity-fresh-4vcpu)

An additional diagnostic repeated the same 100 Mbit/s traffic command and
recorded sender throughput, modem backlog, and capture loss. Sender payload
throughput was 83.1 Mbit/s on three fresh vCPUs, 77.0 Mbit/s on one, and
92.9 Mbit/s on three pinned vCPUs. The four vCPU diagnostic reached 85.1
Mbit/s and spent about 84% of a core in kernel CPU time across the sampled
2.71 seconds, plus about 4% in userspace. The sampler logged zero HTB drops
at each snapshot, and tcpdump reported zero kernel capture
drops. The sender could not sustain the requested load in these runs, and
the qdisc did not have a constant backlog of offered packets. The original
M1 JSON and these diagnostics are stored separately because the counter
sampling added work to the guest. [Reproduction](README.md#repeat-the-fidelity-and-inference-diagnostics)

The host reported zero effective and bounding capabilities, `unshare --net`
returned `Operation not permitted`, and `/dev/kvm` was absent. All guest
trials used QEMU TCG with Linux namespaces, veth, CAKE and NetEm verified by
the guest preflight. [Host output](../../../results/codex-cloud/fidelity-current/host-capabilities.txt)
