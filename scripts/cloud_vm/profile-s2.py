#!/usr/bin/env python3
"""Decompose observed S2 timing without changing the acceptance scorer."""
import argparse
import json
from pathlib import Path
import struct
import sys

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from analysis.analyze import (  # noqa: E402
    ADDED_THR, Run, parse_harness, s2_metrics, step_series, value_at,
)
from halo.gen import HDR, MAGIC  # noqa: E402


def profile(path):
    run = Run(str(path), "S2", path.parent.name, int(path.name[1:]))
    start = run.t("rate_down")
    score = s2_metrics(run, parse_harness(str(REPO)))
    if not run.complete or score is None:
        raise ValueError(f"incomplete S2 evidence: {path}")
    relative = lambda t: None if t is None else round(t - start, 4)
    events = run.ctl_events()
    rates = [e for e in events if e.get("kind") == "rate" and e.get("dir") == "dl" and e["t"] >= start - 0.5]
    cut = next((e for e in rates if e["why"] == "bloat_fast_down"), {})
    ts, rate, _ = step_series(run.telemetry(), events)
    target = 0.95 * score["cap_down"]
    first_in_band = None if ts is None else next(
        (g for g in np.arange(start, run.t("rate_up"), 0.1)
         if abs(value_at(ts, rate, g) - target) <= 0.1 * target), None)
    call = run.rt("call")
    times, owd = call["t"], call["owd"]
    limit = score["pre_median_ms"] + ADDED_THR
    last_delayed = None
    if score.get("t_adapt_s") is not None:
        adapted = start + score["t_adapt_s"]
        late = times[(times > adapted - 1.0) & (times <= adapted) & (owd > limit)]
        if late.size:
            last_delayed = float(late.max())
    bins = []
    for offset in range(-2, 26):
        upper = start + (offset + 1) / 10
        values = owd[(times > upper - 0.1) & (times <= upper)]
        if values.size:
            bins.append({"end_s": relative(upper), "packets": int(values.size),
                         "p95_ms": round(float(np.percentile(values, 95)), 3)})
    return {
        "run": str(path), "time_origin": "rate_down event after the rig's rate command",
        "native_drop_s": [relative(e["collapse_t"]) for e in events if e.get("kind") == "drop_confirmed"
                          and -0.5 <= e["collapse_t"] - start <= 2],
        "alert_s": [relative(e["t"]) for e in events if e.get("kind") == "sent_alert"
                    and e.get("why") == "collapse" and -0.5 <= e["t"] - start <= 2],
        "confirm_s": [relative(e["observed_t"]) for e in events if e.get("kind") == "drop_confirmed"
                      and -0.5 <= e["t"] - start <= 2],
        "first_cut_decision_s": relative(cut.get("decision_t")), "first_cut_applied_s": relative(cut.get("t")),
        "first_rate_in_band_s": relative(first_in_band),
        "latency_limit_ms": round(limit, 3), "last_delayed_packet_in_passing_window_s": relative(last_delayed),
        "disjoint_100ms_call_latency": bins, "original_score": score,
    }


def tap_packets(path):
    """Read S2 IPv4 call sequence numbers and timestamps from an Ethernet pcap."""
    with path.open("rb") as capture:
        header = capture.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        endian, scale = formats[header[:4]]
        linktype, = struct.unpack_from(endian + "I", header, 20)
        if linktype != 1:
            raise ValueError(f"expected Ethernet pcap: {path}")
        packets = {}
        while record := capture.read(16):
            seconds, ticks, size, _ = struct.unpack(endian + "IIII", record)
            frame = capture.read(size)
            if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17:
                continue
            payload = 14 + (frame[14] & 15) * 4 + 8
            if len(frame) < payload + HDR.size:
                continue
            magic, seq, sent = HDR.unpack_from(frame, payload)
            if magic == MAGIC:
                packets.setdefault(seq, (seconds + ticks / scale, sent))
    return packets


def tap_profile(run_path, taps):
    run = Run(str(run_path), "S2", run_path.parent.name, int(run_path.name[1:]))
    start = run.t("rate_down")
    modem = tap_packets(taps / "modem-ingress.pcap")
    gateway = tap_packets(taps / "gateway-ingress.pcap")
    egress_file = taps / "gateway-egress.pcap"
    egress = tap_packets(egress_file) if egress_file.exists() else None
    call = run.rt("call")
    samples = []
    for seq, received in zip(call["seq"], call["t"]):
        if seq not in modem or seq not in gateway or (egress is not None and seq not in egress):
            continue
        admitted, sent = modem[seq]
        delivered, _ = gateway[seq]
        delays = [(admitted - sent) * 1e3, (delivered - admitted) * 1e3, (received - delivered) * 1e3]
        if egress is not None:
            dequeued, _ = egress[seq]
            delays.extend([(dequeued - delivered) * 1e3, (received - dequeued) * 1e3])
        samples.append((received - start, *delays))
    if not samples:
        raise ValueError("no call packets matched across both taps and the receiver")
    samples = np.asarray(samples)
    phases = {}
    for label, lower, upper in (("before", -4, -1), ("queue_growth", 0, 0.5),
                                ("draining", 0.5, 1.1), ("settled", 1.5, 2.5)):
        phase = samples[(samples[:, 0] >= lower) & (samples[:, 0] < upper)]
        if phase.size:
            p95 = np.percentile(phase[:, 1:], 95, axis=0).round(3)
            names = ("sender_to_modem", "modem_to_gateway", "gateway_to_client", "inside_gateway", "egress_to_client")
            phases[label] = {"matched_packets": len(phase), **{
                f"p95_{name}_ms": float(value) for name, value in zip(names, p95)
            }}
    return {"matched_packets": len(samples), "phases": phases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument("--taps", type=Path, help="pcap directory for one diagnostic repetition")
    args = parser.parse_args()
    profiles = [profile(path) for path in args.runs]
    if args.taps:
        if len(args.runs) != 1:
            parser.error("--taps requires exactly one run")
        profiles[0]["packet_taps"] = tap_profile(args.runs[0], args.taps)
    print(json.dumps(profiles, indent=2))


if __name__ == "__main__":
    main()
