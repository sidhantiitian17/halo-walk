"""Tiny fluid model of a bottleneck link used to drive the REAL halo.estimator.DirEstimator.

It is test scaffolding (the 'world'), not a re-implementation of the estimator:
  * a greedy sender offers exactly the shaper rate (TCP fills the narrowest point it can see);
  * the upstream bottleneck queue grows at (offered - capacity) and drains at (capacity - offered);
  * the arrival rate measured behind the bottleneck is the capacity while a queue stands,
    otherwise the offered rate;
  * one-way delay = base + queue/capacity (+ optional externally injected delay).
"""
import random


class Link:
    def __init__(self, cap, base_ms=20.0, qmax_ms=300.0):
        self.cap, self.base, self.q, self.qmax_ms = float(cap), base_ms, 0.0, qmax_ms
        self.extra_ms = 0.0          # delay injected by "someone else" (noise spike / other queue)
        self.jitter_ms = 0.0
        self.rnd = random.Random(1)

    def step(self, rate, dt, demand=True):
        send = rate if demand else 0.0
        self.q = max(0.0, min(self.q + (send - self.cap) * dt, self.qmax_ms / 1000.0 * self.cap))
        return self.cap if self.q > 0 else min(send, self.cap)

    def owd(self):
        j = self.rnd.uniform(-self.jitter_ms, self.jitter_ms) if self.jitter_ms else 0.0
        return self.base + self.q / self.cap * 1000.0 + self.extra_ms + j


def run(est, link, seconds, t0=0.0, dt=0.05, reflectors=(0, 1, 2, 3), demand=True, hook=None):
    """20 Hz aggregate probes round-robin over the reflectors, 100 ms control ticks
    (the controller defaults). Returns [(t, state, rate, reason, owd, achieved)] per tick."""
    out, t, k = [], t0, 0
    n = int(round(seconds / dt))
    for _ in range(n):
        if hook:
            hook(t, link)
        ach = link.step(est.rate, dt, demand)
        refl = reflectors[k % len(reflectors)] if reflectors else None
        if refl is not None:
            est.on_probe(refl, link.owd(), t)
        k += 1
        if k % 2 == 0:
            _, why = est.tick(t, ach)
            out.append((round(t, 3), est.state, est.rate, why, link.owd(), ach))
        t += dt
    return out
