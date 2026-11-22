"""M3 capacity estimator (halo/estimator.py) - synthetic OWD / achieved-rate traces.

Inputs  : on_probe(reflector, owd_ms, t), tick(t, achieved_mbit)
Outputs : (new_rate | None, reason)
States  : INIT -> STEADY <-> PROBING_UP -> DRAIN -> STEADY ; DEGRADED
"""
import pytest

from halo.estimator import Cusum, DirEstimator, EstParams, slops_trend
from linksim import Link, run


def settled(est, cap=100.0, rate=None, seconds=3.0, **kw):
    link = Link(cap, **kw)
    out = run(est, link, seconds)
    return link, out


# --------------------------------------------------------------------------- steady link
def test_steady_link_at_plan_rate_no_rate_change():
    """link faster than the plan: shaper sits at r_max, fully loaded, no delay -> nothing to do"""
    e = DirEstimator(EstParams(r_max=100.0), rate=100.0)
    link = Link(120.0)
    link.jitter_ms = 4.0                         # sub-threshold jitter must not vote
    out = run(e, link, 30.0)
    assert [o for o in out if o[3]] == []
    assert e.rate == 100.0
    assert e.state == "STEADY"
    assert e.episodes == 0


def test_steady_link_light_load_no_probe():
    """load below load_thresh (0.75): never probes upwards, never cuts"""
    e = DirEstimator(EstParams(r_max=100.0), rate=50.0)
    link = Link(100.0)
    out = []
    t = 0.0
    for i in range(300):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        out.append(e.tick(t, 20.0))              # 40 % load
        t += 0.1
    assert all(v == (None, "") for v in out)
    assert e.rate == 50.0


def test_first_tick_leaves_init():
    e = DirEstimator(EstParams(), rate=50.0)
    for r in range(4):
        e.on_probe(r, 20.0, 0.0)
    e.tick(0.0, 0.0)
    assert e.state == "STEADY"


# --------------------------------------------------------------------------- 5:1 capacity step
def test_capacity_step_5_to_1_drains_and_settles():
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=95.0)
    link = Link(100.0)
    run(e, link, 5.0)                            # warm-up (may probe up to r_max)
    link.cap = 20.0
    out = run(e, link, 12.0, t0=5.0)
    reasons = [o[3] for o in out if o[3] and o[3] != "bloat_unconfirmed"]
    states = [o[1] for o in out]
    assert reasons[0] == "bloat_fast_down"
    # the episode is only confirmed after the vote persisted >= confirm s (sustained bloat, flat achieved)
    first_unconf = next(o[0] for o in out if o[3] == "bloat_unconfirmed")
    cut_t = next(o[0] for o in out if o[3] == "bloat_fast_down")
    # arrival collapsed (20 of 95 Mbit/s < collapse x rate): the fast confirmation window applies
    assert cut_t - first_unconf >= p.confirm_fast - 1e-9
    assert all(o[2] == out[0][2] for o in out if o[0] < cut_t)        # no rate change while unconfirmed
    assert "DRAIN" in states
    target = p.margin * 20.0                    # 0.95 * new capacity
    # first tick at which the rate is within +-10 % of target and the estimator left DRAIN
    idx = next(i for i, o in enumerate(out) if o[1] != "DRAIN" and abs(o[2] - target) <= 0.10 * target and i > 0)
    assert idx <= 35, "settling took %d ticks (> 3.5 s incl. 0.5 s confirmation)" % idx
    assert reasons.index("drain_refill") < reasons.index("settle_at_margin")
    # stays within +-10 % for the rest of the ceiling-hold window
    for o in out[idx:idx + int(p.hold_base / 0.1) - 5]:
        assert abs(o[2] - target) <= 0.10 * target, o
    assert 0.95 * 20.0 <= e.c_hi and e.c_lo <= 1.05 * 20.0     # reported range brackets the truth
    # emergency cut never drops below r_min and is ~drain_factor of the evidence
    cut = next(o for o in out if o[3] == "bloat_fast_down")
    assert cut[2] in (pytest.approx(p.drain_factor * 20.0, rel=0.05), pytest.approx(p.deep_drain * 20.0, rel=0.05))  # deep queue -> deep_drain


def test_capacity_step_queue_actually_drained():
    e = DirEstimator(EstParams(), rate=95.0)
    link = Link(100.0)
    run(e, link, 3.0)
    link.cap = 20.0
    out = run(e, link, 5.0, t0=3.0)
    assert max(o[4] for o in out) > 100.0       # big bloat happened
    assert out[-1][4] < 20.0 + 15.0             # queue drained below the delay threshold


def test_native_collapse_waits_for_delay_votes_and_uses_their_sample_times():
    e = DirEstimator(EstParams(), rate=95.0)
    for i in range(4):
        e.on_probe(i, 20.0, 5.0)
    e.tick(5.0, 95.0)
    e.t_native_collapse = 5.1
    assert e.tick(5.2, 20.0)[0] is None
    for i in range(3):
        e.on_probe(i, 120.0, 5.2)
    rate, reason = e.tick(5.45, 20.0)
    assert reason == "bloat_fast_down"
    assert rate == pytest.approx(6.0)


def test_overshoot_after_hold_converges():
    p = EstParams()
    e = DirEstimator(p, rate=95.0)
    link = Link(100.0)
    run(e, link, 5.0)
    link.cap = 20.0
    out = run(e, link, 60.0, t0=5.0)
    reasons = [o[3] for o in out]
    assert "false_alarm_restore" not in reasons                # confirmed episodes are never undone
    late = [o for o in out if o[0] > 35.0]
    assert sum(1 for o in late if o[3] == "bloat_fast_down") <= 2
    assert late[-1][2] <= 20.0
    # every probe overshoot ends at the margin again (no over-capacity rate is restored)
    for o in out:
        if o[3] == "settle_at_margin":
            assert o[2] == pytest.approx(p.margin * 20.0, rel=0.10)


# --------------------------------------------------------------------------- noise spike
def test_short_noise_spike_never_cuts():
    """a 200 ms delay spike is shorter than EstParams.confirm -> only bloat_unconfirmed, rate untouched"""
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=100.0)
    link = Link(120.0)
    run(e, link, 3.0)

    def spike(t, l):
        l.extra_ms = 60.0 if 3.0 <= t < 3.2 else 0.0
    out = run(e, link, 5.0, t0=3.0, hook=spike)
    assert {o[3] for o in out} <= {"", "bloat_unconfirmed"}
    assert "bloat_unconfirmed" in {o[3] for o in out}
    assert all(o[2] == 100.0 for o in out) and e.episodes == 0


def test_confirmed_spike_is_never_undone():
    """A queue that outlasts the full-delivery burst window is confirmed and then settled."""
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=100.0)
    link = Link(120.0)
    run(e, link, 3.0)

    def spike(t, l):
        l.extra_ms = 60.0 if 3.0 <= t < 3.0 + p.confirm + p.burst_max + 0.3 else 0.0
    out = run(e, link, 5.0, t0=3.0, hook=spike)
    acts = [o for o in out if o[3] and o[3] not in ("bloat_unconfirmed", "burst_at_capacity")]
    assert [o[3] for o in acts[:2]] == ["bloat_fast_down", "settle_at_margin"]
    assert "false_alarm_restore" not in [o[3] for o in out]
    # The observed arrival rate at onset is 100 Mbit/s.
    assert acts[0][2] == pytest.approx(p.drain_factor * 100.0)
    assert acts[1][2] == pytest.approx(p.margin * 100.0)
    assert e.episodes == 1 and e.state == "STEADY"


@pytest.mark.parametrize("cap", [20.0, 40.0])
def test_confirmed_episode_settles_at_margin_no_livelock(cap):
    """after a capacity drop: every episode ends with settle_at_margin at margin*c_est within +-10 % of
    0.95*capacity; re-probes are spaced by a growing ceiling hold (no livelock) and the rate spends
    >= 85 % of the time within +-10 % of 0.95*capacity"""
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=95.0)
    link = Link(100.0)
    run(e, link, 5.0)
    link.cap = cap
    out = run(e, link, 90.0, t0=5.0)
    target = p.margin * cap
    assert "false_alarm_restore" not in [o[3] for o in out]
    settles = [o for o in out if o[3] == "settle_at_margin"]
    assert settles
    for o in settles:
        assert abs(o[2] - target) <= 0.10 * target, o
    t0 = settles[0][0]
    after = [o for o in out if o[0] >= t0]
    inside = sum(1 for o in after if abs(o[2] - target) <= 0.10 * target)
    assert inside / len(after) >= 0.85          # was 0.90 with hold 10-20 s; probes now recur every 6-12 s (S2 recovery)
    eps = [o[0] for o in out if o[3] == "bloat_fast_down"]
    gaps = [b - a for a, b in zip(eps, eps[1:])]
    assert all(g2 >= g1 - 0.5 for g1, g2 in zip(gaps, gaps[1:]))   # hold doubles: episodes get rarer
    assert len(eps) <= 2 + int(90.0 // p.hold_max)    # bounded probing: at most one re-probe per hold_max


def test_slow_start_ramp_with_delay_spike_does_not_cut():
    """TCP slow start: delay rises while the achieved rate is still ramping (> ramp_tol per step) ->
    the confirmation restarts, the episode is never confirmed, the rate is not cut"""
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=100.0)
    t = 0.0
    for _ in range(20):                                   # learn the baseline on an idle link
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 0.0)
        t += 0.1
    ach, reasons = 12.0, []
    for _ in range(20):                                   # 2 s ramp: +20 % per 100 ms, 60 ms extra delay
        for r in range(4):
            e.on_probe(r, 80.0, t)
        ach = min(95.0, ach * 1.2)
        nr, why = e.tick(t, ach)
        reasons.append(why)
        assert nr is None
        t += 0.1
        if ach >= 95.0:
            break
    assert "bloat_unconfirmed" in reasons
    assert "bloat_fast_down" not in reasons
    assert e.rate == 100.0 and e.episodes == 0


def test_sustained_bloat_with_flat_rate_confirms_after_confirm_s():
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=100.0)
    t = 0.0
    for _ in range(20):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 60.0)    # flat arrival: no flow-start ramp
        t += 0.1
    seen = []
    for _ in range(15):
        for r in range(4):
            e.on_probe(r, 80.0, t)
        seen.append((round(t, 2), e.tick(t, 60.0)[1]))
        t += 0.1
    cut = [ts for ts, w in seen if w == "bloat_fast_down"]
    onset = next(ts for ts, w in seen if w == "bloat_unconfirmed")
    # 60 of 100 Mbit/s is below collapse x rate but has NOT fallen from a recent peak -> full confirm window
    assert len(cut) == 1 and cut[0] - onset >= p.confirm - 1e-9 and cut[0] - onset <= p.confirm + 0.15


def test_fallen_arrival_rate_takes_fast_confirm():
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=95.0)
    t = 0.0
    for _ in range(20):                                   # loaded, healthy: arrival ~ shaper rate
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 94.0)
        t += 0.1
    seen = []
    for _ in range(10):                                   # capacity loss: arrival falls to 20, queue stands
        for r in range(4):
            e.on_probe(r, 80.0, t)
        seen.append((round(t, 2), e.tick(t, 20.0)[1]))
        t += 0.1
    cut = [ts for ts, w in seen if w == "bloat_fast_down"]
    onset = next(ts for ts, w in seen if w == "bloat_unconfirmed")
    assert len(cut) == 1 and p.confirm_fast - 1e-9 <= cut[0] - onset <= p.confirm_fast + 0.15


def test_flat_rate_near_shaper_needs_full_confirm():
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=100.0)
    t = 0.0
    for _ in range(20):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 90.0)    # flat arrival: no flow-start ramp
        t += 0.1
    seen = []
    for _ in range(15):
        for r in range(4):
            e.on_probe(r, 80.0, t)
        seen.append((round(t, 2), e.tick(t, 90.0)[1]))     # arrival still ~ shaper rate (no collapse)
        t += 0.1
    cut = [ts for ts, w in seen if w == "bloat_fast_down"]
    onset = next(ts for ts, w in seen if w == "bloat_unconfirmed")
    assert len(cut) == 1 and cut[0] - onset >= p.confirm - 1e-9 and cut[0] - onset <= p.confirm + 0.15


# --------------------------------------------------------------------------- reflector loss
def test_reflector_loss_degraded_and_rate_held():
    p = EstParams()
    e = DirEstimator(p, rate=60.0)
    link = Link(100.0)
    run(e, link, 2.0, demand=False)
    # three of four reflectors stop answering -> after reflector_timeout only one is healthy (< min_reflectors=2)
    out = run(e, link, p.reflector_timeout + 0.5, t0=2.0, reflectors=(0,), demand=False)
    assert e.state == "DEGRADED"
    # while DEGRADED the remaining reflector reports a big delay under full load: the rate must be HELD
    link.extra_ms = 100.0
    out += run(e, link, 5.0, t0=2.5 + p.reflector_timeout, reflectors=(0,), demand=True)
    reasons = [o[3] for o in out if o[3] and o[3] != "bloat_unconfirmed"]
    assert "reflectors_lost_hold_rate" in reasons
    assert reasons.count("reflectors_lost_hold_rate") == 1          # reported once, on entry
    assert "bloat_fast_down" not in reasons and "slow_up" not in reasons
    assert e.state == "DEGRADED"
    assert e.rate == 60.0
    # reflectors return -> leaves DEGRADED
    link.extra_ms = 0.0
    run(e, link, 1.0, t0=8.5, demand=False)
    assert e.state != "DEGRADED"


def test_all_reflectors_lost_no_probes():
    e = DirEstimator(EstParams(), rate=40.0)
    assert e.tick(0.0, 40.0) == (None, "reflectors_lost_hold_rate")
    assert e.tick(0.1, 40.0) == (None, "")
    assert e.rate == 40.0 and e.state == "DEGRADED"


# --------------------------------------------------------------------------- slow-up
def test_slow_up_after_capacity_increase():
    p = EstParams(r_max=100.0)
    e = DirEstimator(p, rate=95.0)
    link = Link(100.0)
    run(e, link, 3.0)
    link.cap = 20.0
    run(e, link, 3.0, t0=3.0)
    assert e.rate == pytest.approx(19.0, rel=0.1)
    link.cap = 100.0                                         # capacity comes back
    out = run(e, link, 40.0, t0=6.0)
    ups = [o for o in out if o[3] == "slow_up"]
    assert ups, "never probed upwards"
    assert ups[0][0] >= 6.0 + p.hold_base - 3.0 - 0.01       # ceiling hold respected (settled at ~t=4)
    # every up-step is bounded by up_max
    prev = 19.0
    for o in out:
        if o[3] == "slow_up":
            assert o[2] <= prev * p.up_max + 1e-3
        prev = o[2]
    assert e.rate >= 0.9 * 100.0
    assert not any(o[3] == "bloat_fast_down" for o in out)
    t90 = next(o[0] for o in out if o[2] >= 90.0)
    assert t90 - 6.0 < 35.0


# --------------------------------------------------------------------------- idle link with delay
def test_delay_without_load_never_cuts():
    e = DirEstimator(EstParams(), rate=80.0)
    link = Link(100.0)
    run(e, link, 2.0, demand=False)                        # learn the baseline first
    link.extra_ms = 120.0                                   # someone else's queue / path change
    out = run(e, link, 20.0, t0=2.0, demand=False)
    reasons = {o[3] for o in out}
    assert "delay_without_load" in reasons
    assert reasons <= {"", "delay_without_load"}
    assert all(o[2] == 80.0 for o in out)
    assert e.episodes == 0


# --------------------------------------------------------------------------- upload direction
def test_upload_direction_cuts_on_bloat():
    p = EstParams(r_min=0.5, r_max=20.0)
    e = DirEstimator(p, rate=19.0, behind=False)
    link = Link(25.0)
    run(e, link, 2.0)                                     # learn the baseline before the queue builds
    link.cap = 5.0
    out = run(e, link, 6.0, t0=2.0)
    first = next(o for o in out if o[3] and o[3] != "bloat_unconfirmed")
    assert first[3] == "bloat_fast_down"
    assert first[2] < 19.0 * p.drain_factor + 1e-6
    assert min(o[2] for o in out) >= p.r_min


def test_upload_direction_settles_after_capacity_drop():
    p = EstParams(r_min=0.5, r_max=20.0)
    e = DirEstimator(p, rate=19.0, behind=False)
    link = Link(25.0)
    run(e, link, 2.0)
    link.cap = 5.0
    out = run(e, link, 40.0, t0=2.0)
    assert "false_alarm_restore" not in [o[3] for o in out]
    settles = [o for o in out if o[3] == "settle_at_margin"]
    assert settles
    for o in settles:
        # ahead of the bottleneck only the overshoot is known: c_est = 0.9 * evidence -> settle at margin * c_est
        assert 0.8 * 5.0 <= o[2] <= 5.0
    assert out[-1][2] <= 5.0
    eps = [o[0] for o in out if o[3] == "bloat_fast_down"]
    assert len(eps) <= 4                      # probes recur every hold (6 -> 12 s) so a capacity rise is found in time


def test_rate_always_within_bounds():
    p = EstParams(r_min=2.0, r_max=100.0)
    e = DirEstimator(p, rate=95.0)
    link = Link(100.0)
    for cap in (100.0, 3.0, 50.0, 1.0, 100.0):
        link.cap = cap
        for o in run(e, link, 8.0):
            assert p.r_min <= o[2] <= p.r_max


# --------------------------------------------------------------------------- Cusum / SLoPS
def test_cusum_quiet_never_fires():
    c = Cusum(k=5.0, h=40.0)
    assert not any(c.update(d) for d in [0, 3, 4.9, -10, 2] * 50)
    assert c.s >= 0.0


def test_cusum_detects_sustained_shift_and_resets():
    c = Cusum(k=5.0, h=40.0)
    fired = [c.update(25.0) for _ in range(3)]
    assert fired == [False, False, True]          # s = 20, 40 (not > h), 60 -> fire
    assert c.s == 0.0


def test_cusum_clamps_at_zero():
    c = Cusum()
    c.update(-100.0)
    assert c.s == 0.0


def test_slops_trend():
    inc = [10 + 0.5 * i for i in range(36)]
    flat = [10.0 + (i % 2) * 0.1 for i in range(36)]
    assert slops_trend(inc)[0] is True
    assert slops_trend(flat)[0] is False
    assert slops_trend([1, 2])[0] is False


def test_burst_at_capacity_never_cuts_but_real_drop_still_does():
    """S3 finding: ABR chunk bursts queue briefly upstream while the link still delivers our full operating point;
    cutting there only flaps the rate. A real capacity loss (arrival falls) must still be cut."""
    p = EstParams(r_max=19.0)
    e = DirEstimator(p, rate=19.0, behind=True)
    t = 0.0
    for _ in range(20):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 19.0)
        t += 0.1
    whys = []
    for _ in range(15):                                  # 1.5 s of upstream burst queue at the shaped rate
        for r in range(4):
            e.on_probe(r, 60.0, t)
        whys.append(e.tick(t, 19.0)[1])
        t += 0.1
    assert "bloat_fast_down" not in whys and "burst_at_capacity" in whys and e.rate == 19.0
    for _ in range(15):                                  # now the capacity really drops: arrival collapses to 10
        for r in range(4):
            e.on_probe(r, 80.0, t)
        whys.append(e.tick(t, 10.0)[1])
        t += 0.1
    assert "bloat_fast_down" in whys and e.rate < 10.0


def test_standing_queue_at_capacity_is_drained_after_burst_max():
    """S1 finding: a slow-start-filled modem buffer can STAND at full delivery (arrival = operating point); the burst
    exemption must expire after burst_max so the standing queue is drained."""
    p = EstParams(r_max=19.0)
    e = DirEstimator(p, rate=19.0, behind=True)
    t = 0.0
    for _ in range(20):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 19.0)
        t += 0.1
    whys = []
    for _ in range(40):                                  # 4 s of a 300 ms standing queue at the shaped rate
        for r in range(4):
            e.on_probe(r, 320.0, t)
        whys.append((round(t, 1), e.tick(t, 19.0)[1]))
        t += 0.1
    cut = [ts for ts, w in whys if w == "bloat_fast_down"]
    first = next(ts for ts, w in whys if w in ("burst_at_capacity", "bloat_unconfirmed"))
    assert cut and p.burst_max <= cut[0] - first <= p.burst_max + p.confirm + 0.3 and e.rate < 19.0


def _ramp_start(p, delay_ms, seconds, rate=47.5, cap_arrival=44.0, pre_s=3.0):
    """idle link, then at t=pre_s a bulk transfer ramps the arrival up to cap_arrival within 0.5 s while a queue of
    delay_ms stands (what 6 TCP slow-starts into a 50 Mbit link do); returns [(t, reason, rate)]"""
    e = DirEstimator(p, rate=rate)
    t, out = 0.0, []
    for _ in range(int(pre_s / 0.1)):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 1.5)
        t += 0.1
    t_on = t
    for _ in range(int(seconds / 0.1)):
        ach = min(cap_arrival, 1.5 + (t - t_on) * 100.0)
        for r in range(4):
            e.on_probe(r, 20.0 + delay_ms, t)
        new, why = e.tick(t, ach)
        out.append((round(t - t_on, 2), why, e.rate))
        t += 0.1
    return e, out


def test_flow_start_burst_with_mild_queue_is_not_a_capacity_loss():
    """S2 start-up: 6 slow-starting flows queue ~25 ms for ~1.5 s with the arrival still ramping below the shaper.
    Cutting (47.5 -> 28) and settling on the ramping arrival (38.6) cost 6 rate changes and 10 s of lost capacity."""
    p = EstParams(r_max=47.5)
    e, out = _ramp_start(p, 25.0, 1.5)
    assert not any(o[1] == "bloat_fast_down" for o in out)
    assert e.rate == 47.5


def test_flow_start_patience_is_bounded_standing_queue_still_drained():
    p = EstParams(r_max=47.5)
    e, out = _ramp_start(p, 25.0, 4.0)
    cut = [o for o in out if o[1] == "bloat_fast_down"]
    assert len(cut) == 1 and p.start_patience - 0.2 <= cut[0][0] <= p.start_patience + 0.5


def test_flow_start_with_deep_queue_is_cut_immediately():
    p = EstParams(r_max=47.5)
    e, out = _ramp_start(p, 150.0, 2.0)
    cut = [o for o in out if o[1] == "bloat_fast_down"]
    assert cut and cut[0][0] <= p.confirm + 0.4


# --------------------------------------------------------------------------- S2 fix-sprint regressions
def test_capacity_drop_with_lagging_arrival_settles_once_within_10pct():
    """the smoothed arrival measurement still shows the old rate for a few ticks after a 50 -> 10 drop; the capacity
    evidence must come from the LOW end of the standing-queue samples (the old p90 took the lag: settle at 19, a second
    episode, T_adapt 6.5 s instead of ~1.5 s)"""
    p = EstParams(r_max=47.5)
    e = DirEstimator(p, rate=47.5)
    t = 0.0
    for _ in range(30):
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 46.0)
        t += 0.1
    lag = [38.0, 28.0, 20.0, 15.0, 12.0, 10.4, 10.1, 10.0, 10.0, 10.0, 10.0, 10.0]
    out = []
    for i in range(80):
        a = lag[i] if i < len(lag) else 10.0
        standing = i < 15                                 # the cut drains the queue after ~1.5 s
        for r in range(4):
            e.on_probe(r, 220.0 if standing else 20.0, t)
        new, why = e.tick(t, a)
        out.append((t, new, why))
        t += 0.1
    ep = [o for o in out if o[2] == "bloat_fast_down"]
    st = [o for o in out if o[2] == "settle_at_margin"]
    assert len(ep) == 1 and len(st) == 1
    assert st[0][1] == pytest.approx(0.95 * 10.0, rel=0.10)


def test_mild_burst_episodes_do_not_spiral_capacity_estimate_down():
    """episodes whose arrival evidence is a little below the previous estimate (burst queues below the real capacity)
    may only lower c_est by keep_decay per episode (S2 low phase: 10 -> 9.3 -> 8.5 -> 7.4 -> 6.8 Mbit/s)"""
    p = EstParams(r_max=47.5)
    e = DirEstimator(p, rate=9.5)
    e.c_est = 10.0
    t = 0.0
    for _ in range(100):                                  # settled, loaded, healthy
        for r in range(4):
            e.on_probe(r, 20.0, t)
        e.tick(t, 9.4)
        t += 0.1
    for k in range(4):                                    # four mild episodes with arrival 8.8 (<< capacity 10)
        for _ in range(8):
            for r in range(4):
                e.on_probe(r, 60.0, t)
            e.tick(t, 8.8)
            t += 0.1
        for _ in range(60):
            for r in range(4):
                e.on_probe(r, 20.0, t)
            e.tick(t, 8.8)
            t += 0.1
    assert e.c_est >= 10.0 * p.keep_decay ** 4 - 0.05
    assert e.c_est >= 8.8


def test_capacity_increase_recovered_in_seconds_with_few_changes():
    """S2 recovery: 10 -> 50 Mbit/s. Probe steps accelerate (+4, +7, +13, +23, +41 %), so the shaper is back at the
    plan limit within ~15 s of the end of the hold and in <= 9 rate changes"""
    p = EstParams(r_max=47.5)
    e = DirEstimator(p, rate=47.5)
    link = Link(50.0)
    run(e, link, 5.0)
    link.cap = 10.0
    run(e, link, 8.0, t0=5.0)
    assert e.rate == pytest.approx(9.5, rel=0.12)
    link.cap = 50.0
    out = run(e, link, 40.0, t0=13.0)
    ups = [o for o in out if o[3] == "slow_up"]
    t_ok = next(o[0] for o in out if o[2] >= 0.9 * 0.95 * 50.0)
    assert t_ok - 13.0 <= 25.0
    assert len(ups) <= 9
    assert e.rate == pytest.approx(47.5, rel=0.01)


def test_probe_steps_accelerate_and_are_capped():
    p = EstParams(r_max=1000.0)
    e = DirEstimator(p, rate=10.0)
    link = Link(1000.0)
    out = run(e, link, 12.0)
    ratios, prev = [], 10.0
    for o in out:
        if o[3] == "slow_up":
            ratios.append(o[2] / prev)
        prev = o[2]
    assert ratios[0] == pytest.approx(1.04, abs=0.005)
    assert all(b > a for a, b in zip(ratios[:4], ratios[1:5]))
    assert max(ratios) <= p.up_max + 1e-3 and max(ratios) > 1.3


def test_hold_is_longer_when_plan_limit_is_close_to_the_settle_point():
    """little to gain from probing when r_max is within 15 % of the settle point (S2 steady state at 47.5 of a ~46
    effective capacity): probe 4x less often"""
    p = EstParams(r_max=47.5)

    def hold_after_settle(c):
        e = DirEstimator(p, rate=47.5)
        link = Link(c)
        out = run(e, link, 40.0)
        ep = [o[0] for o in out if o[3] == "bloat_fast_down"]
        return ep
    near = hold_after_settle(46.0)
    far = hold_after_settle(20.0)
    assert len(near) <= len(far)
    assert len(near) <= 2
