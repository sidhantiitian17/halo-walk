# CPU priority scheme (merged tree)

Linux nice/SCHED_IDLE are per thread. Higher number = lower priority. Data-plane forwarding (ksoftirqd, iperf, CAKE) runs at nice 0.

| actor | priority | why |
|---|---|---|
| watchdog process (halo/watchdog.py) | nice -15 | sleeps 100 ms between heartbeat checks, a few us of CPU; the SAFE trip (2.0 s) must not wait behind load |
| rollback restore (controller, calling thread, transient) | nice -10, restored afterwards | only for the rtnetlink LKG restore + read-back (ms); then back to the thread's previous value |
| rate loop (main thread, 10 Hz) and OWD prober thread (20 Hz) | nice -5 (`rate_loop_thread()`, RATE_LOOP_NICE) | the shaper's control path; under CPU saturation a nice-10 loop stalled 1-3 s between ticks. Outranks the classification and poll work below |
| API process (halo/api.py) | nice 0 (NOT niced, deliberately) | idle almost always; must not be pushed below the load, but must not outrank forwarding either. Latency comes from the synchronous in-process nft write, not from priority |
| controller process baseline (`--nice`, default 10) | nice 10 | anything not explicitly raised, e.g. the shadow-check thread, runs below the data plane |
| classification: sniffer, slow loop (classify, conntrack/ctnetlink poll), shadow thread | SCHED_IDLE (`background_thread()`) | best-effort work; never delays forwarding or the rate loop; children (conntrack) inherit |

Ordering: watchdog (-15) > rollback (-10) > rate loop + prober (-5) > data plane and API (0) > controller default (10) > SCHED_IDLE classification/poll.

Nothing starves forwarding: the only threads above nice 0 are the watchdog (idle), the rate loop/prober (a few ms of CPU per second) and the transient rollback; all bulk work (classification, polling) is SCHED_IDLE or nice 10.

Changes vs. the pre-merge history: the rate loop/prober moved from nice 10 to -5 (est); watchdog -15 and rollback -10 are new (ctl). ctl also set the API to nice -10; that was DROPPED in the merge to keep the API un-niced.
Fast paths are skipped when `sh` is mocked (unit tests never renice the runner).

M12 note (round 2): the prober/rate-loop cadence is adaptive (halo/probe_gov.py). While the link is calm the OWD probes run at 2 Hz (sent from the rate loop's 4 Hz tick, received by the prober thread) and the slow loop at 0.5 Hz when the flow table is settled; any delay evidence, late/lost probe, arrival-rate collapse, estimator episode, rate change or transaction restores 20 Hz x 4 reflectors and the 10 Hz loop within one tick. The nice -5 threads are therefore a constant 20 Hz consumer only while the link is not calm.

M12 note (round 3): when `halo/libhalo_sentinel.so` is built, calm mode and the full-rate probing both run in an in-process C thread (`halo-sentinel`, nice -5 like the rate loop). Calm: 4 Hz tick (byte counters, telemetry text, heartbeat), probes at 2 Hz whose replies are collected at the next tick (kernel RX timestamps carry the timing); Python's main loop only wakes every `SYNC_S` (liveness bump) and runs a full pass every `HEAVY_S`, or at once on an alert (delay confirmed by a burst, late probe, arrival collapse, probe-up imminent), a SIGUSR1 or a transaction request. On an alert the thread switches itself to the full probe rate without a gap; Python replays its samples to the estimators in batches. The slow loop is event-driven when the flow table is settled (new flow / override / guard poll every 5 s; 1 s only while ML flows still collect bins).
