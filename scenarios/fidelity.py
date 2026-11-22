#!/usr/bin/env python3
"""Measurement 1 - rig fidelity (Mininet-HiFi style invariant): saturate the EMULATED modem with a UDP
flood and compare the inter-dequeue gaps on its egress with the ideal size/rate serialization time.
usage: fidelity.py <rate_mbit> <out.json>"""
import json, os, struct, subprocess, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rate, out = float(sys.argv[1]), sys.argv[2]
sh = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
sh("%s/rig/rig_up.sh %s %s 10" % (ROOT, rate, rate / 5))
srv = subprocess.Popen("exec ip netns exec pc iperf3 -s -p 5300", shell=True, stdout=subprocess.DEVNULL)
time.sleep(1.0)
s0 = open("/proc/stat").readline().split()
cap = subprocess.Popen("exec ip netns exec modem tcpdump -ni m-gw -Q out -s 64 -B 16384 -w /tmp/fid.pcap udp 2>/dev/null", shell=True)
time.sleep(1.5)
sh("ip netns exec wan iperf3 -c 10.0.0.15 -p 5300 -u -b %dM -l 1400 -t 5 >/dev/null" % int(rate * 1.6))
time.sleep(0.5); cap.terminate(); cap.wait(); srv.kill()
s1 = open("/proc/stat").readline().split()
tot = sum(int(b) - int(a) for a, b in zip(s0[1:9], s1[1:9]))
idle = 100.0 * (int(s1[4]) - int(s0[4])) / tot
d = open("/tmp/fid.pcap", "rb").read()
ts, sz, off = [], [], 24
while off + 16 <= len(d):
    sec, usec, incl, orig = struct.unpack("<IIII", d[off:off + 16])
    ts.append(sec + usec * 1e-6); sz.append(orig); off += 16 + incl
n = len(ts)
ts, sz = ts[n // 5:], sz[n // 5:]           # skip ramp-up
gaps = [b - a for a, b in zip(ts, ts[1:])]
ideal = [s * 8 / (rate * 1e6) for s in sz[1:]]
dev = sorted(abs(g - i) for g, i in zip(gaps, ideal))
mtu_t = 1514 * 8 / (rate * 1e6)
meas = sum(sz[1:]) * 8 / (ts[-1] - ts[0]) / 1e6
q = lambda p: dev[min(len(dev) - 1, int(len(dev) * p / 100))]
res = {"rate": rate, "pkts": len(ts), "measured_mbit": meas, "rate_err_pct": 100 * (meas - rate) / rate, "mtu_time_us": mtu_t * 1e6,
       "dev_p50_us": q(50) * 1e6, "dev_p95_us": q(95) * 1e6, "dev_p99_us": q(99) * 1e6, "cpu_idle_pct": idle,
       "dev_us_sample": [x * 1e6 for x in dev[::max(1, len(dev) // 400)]],
       "pass": bool(q(99) <= mtu_t and abs(meas - rate) / rate <= 0.02)}
json.dump(res, open(out, "w"))
print({k: (round(v, 2) if isinstance(v, float) else v) for k, v in res.items() if k != "dev_us_sample"})
sh("%s/rig/rig_down.sh" % ROOT)
