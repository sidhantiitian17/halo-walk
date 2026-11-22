"""M3 - Link-capacity estimator (pure logic, no I/O -> unit-testable with synthetic traces).

Hybrid passive design:
  * delay signal : one-way-delay (OWD) probes to >=4 reflectors, per-reflector baseline,
                   "delayed" if OWD - baseline > thresh_ms (15 ms, sqm-autorate default),
                   bloat = >= vote_k of the last vote_n samples delayed (3-of-6, cake-autorate).
  * capacity     : while the bottleneck queue is backlogged (bloat), the arrival rate measured
                   behind the bottleneck IS the link capacity -> c_est = achieved rate.
  * fast-down    : shaper -> drain_factor * c_est until the delay vote clears (drains the
                   upstream queue), then shaper -> margin * c_est (95 % of the estimate).
  * slow-up      : when load > load_thresh and no bloat: x up_factor per up_period, accelerating
                   to up_max; after a bloat episode the ceiling is held for an adaptive hold time
                   (doubles when the same ceiling is hit again) -> policy stability.
States: INIT -> STEADY <-> PROBING_UP -> DRAIN -> STEADY ; DEGRADED when < min_reflectors healthy.
"""
from collections import deque
from dataclasses import dataclass, field


@dataclass
class EstParams:
    r_min: float = 2.0            # Mbit/s
    r_max: float = 100.0
    thresh_ms: float = 15.0
    vote_n: int = 6
    vote_k: int = 3
    sample_ttl: float = 1.0       # s, older votes are ignored
    drain_factor: float = 0.70
    ref_margin: float = 0.95      # the shaper's usual operating point is ref_margin x capacity (r_max = 0.95 x plan):
                                  # the burst_at_capacity test and the arrival cap are relative to it, not to the settle margin
    margin: float = 0.90          # settle below the evidence: the arrival measurement lags a drop, so it reads 3-10 % high
    refractory: float = 0.30      # s between decisions inside an episode
    up_factor: float = 1.04       # first probe step (+4 %) ...
    up_accel: float = 0.8         # ... each further clean step grows the increment by (1 + up_accel): +4, +7, +13, +23, +41 %
    up_max: float = 1.50          # ... capped at +50 % per step (the shield admits probe steps up to max_probe_step)
    up_period: float = 0.5        # s
    load_thresh: float = 0.75
    hold_base: float = 6.0        # s ceiling hold after an episode
    hold_max: float = 12.0        # s: bounded so a capacity INCREASE is found and climbed back to within ~30 s (S2 recovery)
    min_reflectors: int = 2
    reflector_timeout: float = 3.0   # s without ANY reply (late replies still prove the reflector alive)
    base_alpha: float = 0.002     # slow upward drift of the per-reflector baseline
    min_drain: float = 0.25       # s the delay vote must be clear before leaving DRAIN
    confirm: float = 0.5          # s the bloat vote must persist before a new episode (rejects TCP slow-start bursts)
    confirm_fast: float = 0.2     # s, when the arrival rate has collapsed (< collapse x rate) and is not ramping:
    collapse: float = 0.7         #    a sustained capacity loss, not a sender burst
    deep_delay: float = 100.0     # ms: a standing queue this deep is drained with deep_drain instead of drain_factor
    deep_drain: float = 0.30      # a >100 ms standing queue is drained at 0.3 x capacity (fast latency recovery)
    deep_settle_margin: float = 0.875  # more headroom after a severe loss, before probing up again
    sample_window: float = 0.5    # s after the cut during which standing-queue arrival samples count as capacity evidence
    sample_q: float = 0.10        # ... its low (10th) percentile: the arrival rate can only be ABOVE the capacity while the
                                  # smoothed measurement still lags a drop (the minimum of a handful of samples)
    keep_frac: float = 0.85       # an episode whose evidence is within 15 % of the previous capacity estimate is noise
    keep_decay: float = 0.97      # around the same capacity (a mild burst queue, arrival below capacity): c_est may only
                                  # fall 3 % per episode (an unbounded fall spiralled 10 -> 6.8 Mbit/s in S2); a real
                                  # capacity loss (> 15 %) is taken at face value
    near_max_hold: float = 4.0    # probing hold multiplier when r_max is within 15 % of the settle point: little to gain
    burst_max: float = 1.5        # s: a queue that outlives this at full delivery is STANDING, not a burst -> drain
    at_capacity: float = 0.97     # behind: arrival >= 0.97 x (rate/margin) means the link still delivers our point
    start_ratio: float = 1.5      # flow-start signature: arrival grew >= 1.5x within start_win s with no action of ours since ...
    start_win: float = 1.5
    start_patience: float = 2.0   # ... a mild (< deep_delay) queue is then a slow-start burst for up to this long, not a capacity loss
    ramp_tol: float = 1.15        # a new episode needs achieved(now) <= ramp_tol * achieved(onset): a rising
                                  # arrival rate is a sender ramping up, not a capacity drop


@dataclass
class DirEstimator:
    p: EstParams
    rate: float                                  # current shaper rate (Mbit/s)
    behind: bool = True                          # True: shaper sits behind the bottleneck (download),
                                                 # arrival rate is observable; False: ahead of it (upload)
    delta_at_action: float = 0.0
    t_episode: float = 0.0
    rate_before: float = 0.0
    c_prev: float = 0.0
    samples: list = field(default_factory=list)
    state: str = "INIT"
    c_est: float = 0.0                           # capacity estimate (Mbit/s), 0 = unknown
    c_lo: float = 0.0                            # reported range
    c_hi: float = 0.0
    base: dict = field(default_factory=dict)     # reflector -> baseline OWD ms
    last_seen: dict = field(default_factory=dict)
    votes: deque = field(default_factory=lambda: deque(maxlen=6))
    last_delta: float = 0.0
    t_last_action: float = -1e9
    t_clear: float = -1e9
    t_hold_until: float = -1e9
    hold: float = 0.0
    up_streak: int = 0
    last_ceiling: float = 0.0
    episodes: int = 0
    t_bloat_on: float = -1.0
    t_native_collapse: float = float("-inf")
    t_burst_on: float = -1.0
    ach_onset: float = 0.0
    ach_hist: deque = field(default_factory=lambda: deque(maxlen=64))   # (t, achieved) for the 'has it fallen' test

    def __post_init__(self):
        self.votes = deque(maxlen=self.p.vote_n)
        self.hold = self.p.hold_base

    # ---- inputs -----------------------------------------------------------
    def on_probe(self, refl, owd_ms, t):
        b = self.base.get(refl)
        if b is None or owd_ms < b:
            b = owd_ms
        elif self.state != "DRAIN":
            b += self.p.base_alpha * (owd_ms - b)
        self.base[refl] = b
        self.last_seen[refl] = t
        self.last_delta = owd_ms - b
        self.votes.append((t, self.last_delta > self.p.thresh_ms))

    def on_late(self, t, age_ms):
        """a probe still unanswered after age_ms: in a standing queue replies arrive late, so an outstanding probe is
        evidence of at least age_ms of extra delay (counted only while some reflector answered recently, so a dead
        reflector is handled by healthy()/DEGRADED and not mistaken for bloat)."""
        if not self.last_seen or t - max(self.last_seen.values()) > 1.5:
            return
        self.last_delta = max(self.last_delta, age_ms)
        self.votes.append((t, age_ms > self.p.thresh_ms))

    def healthy(self, t):
        return sum(1 for v in self.last_seen.values() if t - v <= self.p.reflector_timeout)

    def bloat(self, t):
        fresh = [d for (ts, d) in tuple(self.votes) if t - ts <= self.p.sample_ttl]
        return sum(fresh) >= self.p.vote_k

    # ---- decision ---------------------------------------------------------
    def tick(self, t, achieved, shaper_load=None):
        """achieved: Mbit/s measured behind the bottleneck. Returns (new_rate|None, reason)."""
        p = self.p
        if self.healthy(t) < p.min_reflectors:
            if self.state != "DEGRADED":
                self.state = "DEGRADED"
                return None, "reflectors_lost_hold_rate"
            return None, ""
        if self.state in ("INIT", "DEGRADED"):
            self.state = "STEADY"
        bloat = self.bloat(t)
        self.ach_hist.append((t, achieved))
        if self.state == "DRAIN":
            standing = self.last_delta > p.thresh_ms
            if self.behind and standing and achieved > p.r_min and t - self.t_episode <= p.sample_window:
                # a standing queue at the bottleneck right now => arrival rate == link capacity. Evidence window: the
                # pre-confirmation bloat period (queue standing, nothing cut yet) plus sample_window s after the cut,
                # i.e. BEFORE the senders react to our cut (their back-off drains the queue and pulls the arrival below
                # the capacity: a p25 over the whole drain settled at 5 of 10 Mbit/s). The smoothed arrival measurement
                # LAGS a capacity drop (still shows the old, higher rate for a few ticks, longer when the control loop
                # stalls), so the statistic is a LOW percentile, not the top (the old p90 settled above a 5x-lower
                # capacity and cost a second episode).
                self.samples.append((t, achieved))
                srt = sorted(a for _, a in self.samples)
                self.c_est = self._smooth(srt[min(len(srt) - 1, int(p.sample_q * len(srt)))])
            if bloat:
                self.t_clear = t
                if t - self.t_last_action >= p.refractory:
                    self.t_last_action = t
                    if self.behind:
                        f = p.deep_drain if (self.last_delta > p.deep_delay or self._collapsed(t, achieved)) else p.drain_factor
                        target = max(p.r_min, f * self.c_est)
                        if abs(target - self.rate) > 0.03 * self.rate:
                            return self._set(target, "drain_refine")
                    else:
                        # upload: capacity is not observable; cut again only if the delay is not falling
                        if standing and self.last_delta >= 0.8 * self.delta_at_action:
                            self.c_est = max(p.r_min, 0.85 * self.c_est)
                            self.delta_at_action = self.last_delta
                            return self._set(max(p.r_min, p.drain_factor * self.c_est), "drain_refine")
                        self.delta_at_action = self.last_delta
                return None, ""
            if t - self.t_clear >= p.min_drain:
                # episode confirmed (>= confirm s of sustained bloat with a non-rising arrival rate), so it is
                # never undone: settle at margin x the capacity evidence gathered during the episode
                # (behind: 90th pct of arrival rate while the queue stood; ahead/upload: the cut estimate).
                self.state = "STEADY"
                head = p.r_max / max(1e-9, p.margin * self.c_est)
                self.t_hold_until = t + self.hold * (p.near_max_hold if head <= 1.15 else 1.0)
                self.c_lo, self.c_hi = 0.95 * self.c_est, 1.05 * self.c_est
                self.t_last_action = t
                margin = min(p.margin, p.deep_settle_margin) if self.behind and self.c_est < 0.5 * self.rate_before else p.margin
                return self._set(max(p.r_min, margin * self.c_est), "settle_at_margin")
            return None, ""
        if bloat and achieved < 0.10 * self.rate:
            self.t_bloat_on = -1.0
            return None, "delay_without_load"            # not our queue: never cut the rate on an idle link
        if not bloat:
            self.t_bloat_on = -1.0
        elif self.t_bloat_on < 0:
            self.t_bloat_on, self.ach_onset = t, achieved
            if self.behind and 0 <= t - self.t_native_collapse <= p.sample_ttl and self._collapsed(t, achieved):
                # The native watcher confirmed the arrival drop with a directional probe burst.
                # Count the time spent confirming it, while retaining this estimator's delay vote.
                self.t_bloat_on = self.t_native_collapse
        if bloat and (t - self.t_bloat_on < (p.confirm_fast if self._collapsed(t, achieved) else p.confirm)
                      or achieved > p.ramp_tol * max(self.ach_onset, 1e-3)
                      or self._flow_start(t, achieved)):
            if achieved > p.ramp_tol * max(self.ach_onset, 1e-3):
                self.t_bloat_on, self.ach_onset = t, achieved    # still ramping: restart confirmation
            return None, "bloat_unconfirmed"
        if not bloat:
            self.t_burst_on = -1.0
        elif self.t_burst_on < 0:
            self.t_burst_on = t
        if (bloat and self.behind and achieved >= p.at_capacity * self.rate / p.ref_margin
                and t - self.t_burst_on < p.burst_max):
            # the link is still DELIVERING our full operating point: a sender burst (slow-start restart, ABR chunk)
            # queued briefly upstream, not a capacity loss -> no cut (a cut cannot drain an upstream burst any faster
            # and only adds rate flapping). A real loss shows up as a fallen arrival rate within the next ticks.
            if self.t_bloat_on < 0:                      # the persistence clock keeps running through the burst
                self.t_bloat_on, self.ach_onset = t, achieved   # window, so a standing queue is confirmed at expiry
            return None, "burst_at_capacity"
        if bloat:
            tb, self.t_bloat_on = self.t_bloat_on, -1.0
            # new episode: capacity evidence = what actually arrived while the queue stood (the confirmation period)
            self.episodes += 1
            pre = sorted(a for (ts, a) in self.ach_hist if ts >= tb) if tb >= 0 else [achieved]
            ev = pre[min(len(pre) - 1, int(p.sample_q * len(pre)))] if pre else achieved
            self.c_prev = self.c_est
            c = max(p.r_min, min(ev, achieved, self.rate / p.ref_margin))
            if not self.behind:
                c = max(p.r_min, 0.9 * c)            # we only know we overshot
            else:
                c = self._smooth(c)
            self.delta_at_action = self.last_delta
            self.t_episode, self.samples = t, [(ts, a) for (ts, a) in self.ach_hist if ts >= tb] if tb >= 0 else []
            self.rate_before = self.rate
            near = self.last_ceiling > 0 and abs(c - self.last_ceiling) <= 0.10 * self.last_ceiling
            self.hold = min(p.hold_max, self.hold * 2) if near else p.hold_base
            self.last_ceiling = c
            self.c_est = c
            self.state, self.up_streak = "DRAIN", 0
            self.t_last_action = self.t_clear = t
            f = p.deep_drain if (self.last_delta > p.deep_delay or self._collapsed(t, achieved)) else p.drain_factor
            return self._set(max(p.r_min, f * c), "bloat_fast_down")
        # no bloat: maybe probe upwards
        load = shaper_load if shaper_load is not None else (achieved / self.rate if self.rate else 0)
        if (load >= p.load_thresh and t >= self.t_hold_until and self.rate < p.r_max
                and t - self.t_last_action >= p.up_period):
            pt = p.margin * self.last_ceiling            # last known-good operating point
            near_ceiling = self.last_ceiling > 0 and 0.85 * pt <= self.rate <= 1.03 * pt
            f = p.up_factor if near_ceiling else min(
                p.up_max, 1.0 + (p.up_factor - 1.0) * (1.0 + p.up_accel) ** self.up_streak)
            if near_ceiling and self.rate < 0.999 * pt:
                f = min(p.up_max, pt / self.rate)             # one step back to the known-good point
            self.up_streak += 1
            self.state = "PROBING_UP"
            self.t_last_action = t
            new = min(p.r_max, self.rate * f)
            if achieved > self.c_est:
                self.c_est = achieved                # only DEMONSTRATED capacity (carried without bloat) is claimed
                self.c_hi = max(self.c_hi, self.c_est)
            return self._set(new, "slow_up")
        if load < p.load_thresh:
            self.up_streak = 0
            if self.state == "PROBING_UP":
                self.state = "STEADY"
        return None, ""

    def _smooth(self, c_raw):
        prev = self.c_prev
        if self.behind and prev > 0 and c_raw >= self.p.keep_frac * prev:
            return max(c_raw, self.p.keep_decay * prev)
        return c_raw

    def _flow_start(self, t, achieved):
        """a slow-start burst, not a capacity loss: the arrival rate grew >= start_ratio x within the last start_win s
        (new flows ramping up), we did not act ourselves in that time (our own cut/settle also makes the arrival
        ramp), the queue is still mild and it has not outlived start_patience. Arrival evidence taken from such a
        ramp would also be BELOW the capacity (S2 start-up: 47.5 -> 28 -> 38.6 Mbit/s on a 50 link)."""
        p = self.p
        if (self.last_delta >= p.deep_delay or t - self.t_bloat_on >= p.start_patience
                or t - self.t_last_action < p.start_win + 1.0):
            return False
        lo = min((a for (ts, a) in self.ach_hist if t - p.start_win <= ts <= t), default=achieved)
        return achieved >= p.start_ratio * max(lo, 1e-3)

    def _collapsed(self, t, achieved):
        """capacity-loss signature: arrival well below the shaper AND fallen from its own recent peak (a sender that is
        still ramping up - TCP slow start - is rising, not falling, so it never takes the fast path)"""
        peak = max((a for (ts, a) in self.ach_hist if t - 2.0 <= ts <= t), default=0.0)
        return achieved < self.p.collapse * self.rate and achieved <= 0.8 * peak

    def _set(self, r, reason):
        r = round(max(self.p.r_min, min(self.p.r_max, r)), 3)
        if abs(r - self.rate) < 1e-6:
            return None, ""
        self.rate = r
        return r, reason


class Cusum:
    """A2 ablation: CUSUM change detector on the OWD delta (alternative to the 3-of-6 vote)."""

    def __init__(self, k=5.0, h=40.0):
        self.k, self.h, self.s = k, h, 0.0

    def update(self, delta_ms):
        self.s = max(0.0, self.s + delta_ms - self.k)
        if self.s > self.h:
            self.s = 0.0
            return True
        return False


def slops_trend(owds, pct_thr=0.55, pdt_thr=0.4):
    """SLoPS increasing-trend test on the one-way delays of one periodic stream
    (Jain & Dovrolis, ToN 2003): median-of-groups, PCT and PDT metrics."""
    import math
    k = len(owds)
    g = max(2, int(math.sqrt(k)))
    size = k // g
    med = []
    for i in range(g):
        grp = sorted(owds[i * size:(i + 1) * size])
        if grp:
            med.append(grp[len(grp) // 2])
    if len(med) < 3:
        return False, 0.0, 0.0
    pct = sum(1 for a, b in zip(med, med[1:]) if b > a) / (len(med) - 1)
    tv = sum(abs(b - a) for a, b in zip(med, med[1:]))
    pdt = (med[-1] - med[0]) / tv if tv > 0 else 0.0
    return (pct > pct_thr or pdt > pdt_thr), pct, pdt
