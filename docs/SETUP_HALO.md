# HALO-Walk setup guide (prototype, EMULATED rig)

Everything below runs on one Linux machine. The WAN link, the home devices and the modem buffer are
**emulated** with network namespaces (see `rig/rig_up.sh` and Annexure 3 of the deck); nothing is real hardware.

## 1. Prerequisites (exact versions used for the evidence runs: `VERSIONS.lock`)

| Item | Version used | Why |
|---|---|---|
| Linux kernel | 6.8.0-149-generic (Ubuntu 24.04 `linux-image` + `linux-modules-extra`) | needs `sch_cake`, `sch_netem`, `sch_htb`, `act_mirred`, `act_ctinfo`, `ifb`, `nf_tables`, `nf_conntrack`, `veth`, `bridge`, `dummy` |
| Userland | Ubuntu 24.04.5 LTS | |
| iproute2 | 6.1.0 | `tc` with CAKE options |
| nftables | 1.0.9 | `destroy element`, timeout sets/maps |
| iperf3 | 3.16 | bulk traffic |
| conntrack-tools | Ubuntu 24.04 package | flow accounting |
| Python | 3.13 | controller, API, analysis |
| Python packages | `requirements-halo.txt` | xgboost 3.4.1, scikit-learn 1.9.1, fastapi, uvicorn, numpy, scipy, matplotlib, pytest, hypothesis |
| CPU / RAM | 2+ cores, 4+ GB | |

Stock WSL2 kernels may lack `sch_cake`/`sch_netem`/`act_ctinfo`; use native Ubuntu or a full VM. The evidence in the deck was
produced inside a QEMU **TCG (software-emulated, no KVM)** VM with 2 vCPUs, which is slower and noisier than real hardware
(measured in M1 "rig fidelity").

Pre-flight check:
```bash
for m in sch_cake sch_netem sch_htb act_mirred act_ctinfo ifb nf_tables nf_conntrack veth bridge dummy; do modinfo -F filename $m >/dev/null && echo "ok $m" || echo "MISSING $m"; done
sudo apt-get install -y iproute2 nftables iperf3 conntrack ethtool curl
python3 -m pip install -r requirements-halo.txt
```

### 1a. Native calm-mode sentinel (optional, M12)
The controller's calm mode (probes at 2 Hz, byte counters, telemetry, heartbeat, delay / late / arrival-collapse / probe-up
detection) runs in an in-process C thread, `halo/libhalo_sentinel.so`. Build it once, on the machine that runs the controller
(gcc, make and glibc headers are all it needs; in the QEMU rig the VM mounts the host root, so the host build is the one used):
```bash
make            # -> halo/libhalo_sentinel.so   (make clean removes it)
```
If the library is missing, fails to load or does not match `halo/sentinel.py`, the controller logs
`{"kind": "sentinel", "msg": "... pure-Python calm path"}` in `events.jsonl` and keeps the pure-Python path (same behaviour,
more CPU). `--sentinel 0` or `HALO_NO_SENTINEL=1` force the Python path. The C thread writes the heartbeat only while the Python
main loop keeps bumping a liveness counter (`halo/sentinel.py: GATE_S`), so a hung controller still stops the heartbeat and the
watchdog still trips; SIGTERM stops the C thread with the process.

## 2. Configuration
* API token: copy `.env.example` to `.env` (git-ignored) and set your own `HALO_API_TOKEN`. The example value
  `EXAMPLE-NOT-A-SECRET-0000` is fictitious. No credential is ever committed.
* Controller parameters (command line of `python3 -m halo.controller`): `--plan-dl/--plan-ul` (ISP plan, Mbit/s; the shaper never
  exceeds 0.95 x plan), `--safe-dl/--safe-ul` (known-safe-state rates), `--classifier none|heur|ml`, `--promote-p 0.9`,
  `--reflectors` (4 OWD reflectors), `--probe-hz 20`, `--health-s 5`.
* Rig parameters: `rig/rig_up.sh DOWN UP DELAY` (Mbit/s, Mbit/s, ms each way); modem buffer `RIG_BUF_BYTES` (default 1.5 MB).
  Every run writes all impairment/traffic parameters and its seed to `results/raw/<scenario>/<config>/rNN/meta.json`.

## 3. Commands
```bash
make                                                  # build the optional C calm-mode sentinel (see 1a)
python3 -m pytest tests_halo -q                       # host-only unit tests (no root needed)
sudo rig/rig_up.sh 20 4 10                            # build the emulated household (reset = rig/rig_down.sh)
sudo python3 scenarios/fidelity.py 20 results/fidelity/fid_20.json   # emulation fidelity check
sudo python3 scenarios/run.py S1 C3 1                 # one scenario: reset -> configure -> induce -> collect
sudo bash scenarios/batch.sh lists/m1.txt             # the evidence matrix (resumable)
python3 analysis/train_classifier.py                  # retrain + evaluate the classifier (writes halo/model.pkl)
python3 analysis/analyze.py                           # 12 measurements -> results/summary.json, figs/, tables.md
```
Scenarios: S1 ISO download during a call, S1x32, S2 capacity step (50->10->50, scaled 2:1 from 100->20), S3 3 TVs + gaming,
S4 intent lease + abuse + kernel expiry, S5 misclassification + correction, S6 bad policy -> rollback and kill -9 -> safe state,
S7 S1 over IPv6, EST<rate> estimator accuracy, CPU. Configs: C0 FIFO, C1 static CAKE, C2 autorate-only, C3 HALO heuristic, C4 HALO ML.

## 4. Verification steps
1. `pytest` prints `... passed`.
2. `ip netns exec gw tc -s qdisc show dev lan0` shows `cake ... diffserv4 dual-dsthost ingress fwmark 0xf` while a C1-C4 run is active.
3. `ip netns exec laptop curl -s http://10.0.0.1:8080/v1/health` returns `controller_heartbeat_age_s` < 1.
4. `ip netns exec gw nft list table inet halo` lists the flow/device maps and the `intent_*` timeout sets.
5. `results/summary.json` lists the 12 measurements with PASS/FAIL and `results/figs/m01..m12.png` exist.
6. Reset: `sudo rig/rig_down.sh` removes every namespace, qdisc and nft table created by the rig.
