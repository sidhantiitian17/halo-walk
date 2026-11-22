"""Adaptive probe/tick governor (M12): pure logic, no I/O.

The OWD prober (20 Hz x 4 reflectors) and the 10 Hz estimator loop are the controller's steady CPU cost.  While the link
is quiet - both estimators STEADY and not about to probe upwards, no delay signal, no rate change for a few seconds,
no collapse of the arrival rate - the prober runs at a low rate (default 2 Hz, round-robin over the reflectors) and the
rate loop at 4 Hz.  The full rate returns at once on any of:
  * a delayed probe sample (OWD above baseline by > thresh) -> confirmation burst: one probe to EVERY reflector
    immediately; three more delayed replies -> full rate for FAST_HOLD s;
  * a late (> 0.4 s unanswered) or lost probe;
  * a collapse of the arrival rate (the same signature the estimator uses for capacity loss), seen by the 4 Hz loop;
  * any estimator episode / rate change / transaction / probing step (the loop calls force() while it is not calm).
"""
import math

FAST_HOLD = 0.75         # s the full rate is kept after the last trigger (the loop re-forces it every tick while anything is not calm)
WARM_S = 5.0             # s of full-rate probing at start (per-reflector baselines)
CONFIRM_WIN = 0.4        # s after the first delayed sample in which the burst replies are counted
CONFIRM_N = 3            # delayed burst replies (of 4 reflectors) needed to go to the full rate: a sustained queue, not a blip


class ProbeGovernor:
    def __init__(self, fast_hz=20.0, quiet_hz=2.0, fast_tick=0.1, quiet_tick=0.25, t0=0.0):
        self.fast_hz, self.quiet_hz = fast_hz, quiet_hz
        self.fast_tick, self.quiet_tick = fast_tick, quiet_tick
        self.enabled = quiet_hz < fast_hz or quiet_tick > fast_tick
        self.fast_until = t0 + WARM_S
        self.confirm_until = 0.0
        self.confirm_bad = 0
        self.n_burst = self.n_fast = 0

    def is_fast(self, t):
        return (not self.enabled) or t < self.fast_until

    def probe_period(self, t):
        return 1.0 / (self.fast_hz if self.is_fast(t) else self.quiet_hz)

    def tick_period(self, t):
        return self.fast_tick if self.is_fast(t) else self.quiet_tick

    def force(self, t, hold=FAST_HOLD):
        """some part of the system is not calm: full rate until t + hold"""
        if t + hold > self.fast_until:
            self.fast_until = t + hold

    def sample(self, t, delayed):
        """one probe reply was processed. Returns 'burst' (send one probe to every reflector now), 'fast' (switched to the
        full rate) or None."""
        if not delayed:
            return None
        if self.is_fast(t):
            return None          # already at the full rate; the loop extends it while the estimator's vote / state says so
        if t < self.confirm_until:
            self.confirm_bad += 1
            if self.confirm_bad >= CONFIRM_N:
                self.force(t)
                self.confirm_until, self.confirm_bad = 0.0, 0
                self.n_fast += 1
                return "fast"
            return None
        self.confirm_until, self.confirm_bad = t + CONFIRM_WIN, 0
        self.n_burst += 1
        return "burst"

    def late(self, t):
        """a probe is late or lost: not a sample but direct evidence of delay"""
        if not self.is_fast(t):
            self.n_fast += 1
        self.force(t)


def collapsed(ach, rate, peak, collapse=0.7):
    """arrival rate fell well below the shaper AND from its own recent peak while the link had been loaded (the
    estimator's own capacity-loss signature); an idle or lightly loaded direction (peak < half the shaper rate, e.g. the
    ACK-only upstream of a download) is not a collapse"""
    return peak > 0.5 * rate and ach < collapse * rate and ach <= 0.8 * peak


def decay_peak(peak, ach, dt, tau=2.0):
    """running peak of the arrival rate with an exponential memory of tau seconds"""
    return max(ach, peak * math.exp(-dt / tau))


def ewma_alpha(dt, alpha_ref=0.6, dt_ref=0.1):
    """smoothing factor for an arbitrary tick length that equals alpha_ref at dt_ref (the ~200 ms EWMA of the 10 Hz loop)"""
    return 1.0 - (1.0 - alpha_ref) ** (dt / dt_ref)
