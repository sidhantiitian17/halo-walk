"""M12: adaptive probing governor (halo/probe_gov.py) and its wiring into the controller."""
import argparse, os, socket, threading, time
import pytest
from halo.probe_gov import (CONFIRM_N, CONFIRM_WIN, FAST_HOLD, WARM_S, ProbeGovernor, collapsed, decay_peak, ewma_alpha)


def test_warm_start_then_quiet():
    g = ProbeGovernor(20, 2, 0.1, 0.2, t0=100.0)
    assert g.is_fast(100.0) and g.probe_period(100.0) == pytest.approx(0.05)
    assert not g.is_fast(100.0 + WARM_S + 0.01)
    assert g.probe_period(110.0) == pytest.approx(0.5) and g.tick_period(110.0) == pytest.approx(0.2)


def test_quiet_rates_are_a_real_reduction():
    g = ProbeGovernor(20, 2, 0.1, 0.2, t0=0.0)
    t = 50.0
    assert 1 / g.probe_period(t) <= 0.2 * 20 and 1 / g.tick_period(t) <= 0.5 * 10


def test_disabled_when_rates_equal():
    g = ProbeGovernor(20, 20, 0.1, 0.1, t0=0.0)
    assert not g.enabled and g.is_fast(1e6) and g.probe_period(1e6) == pytest.approx(0.05)


def test_delayed_sample_bursts_then_two_confirmations_go_fast():
    g = ProbeGovernor(t0=0.0)
    t = 50.0
    assert g.sample(t, False) is None and not g.is_fast(t)
    assert g.sample(t, True) == "burst"                        # first delayed sample: confirmation burst, still quiet
    assert not g.is_fast(t)
    assert CONFIRM_N == 3
    assert g.sample(t + 0.05, True) is None                    # 1st confirming reply
    assert g.sample(t + 0.055, True) is None                   # 2nd
    assert g.sample(t + 0.06, True) == "fast"                  # 3rd -> full rate
    assert g.is_fast(t + 0.06 + FAST_HOLD - 0.01) and not g.is_fast(t + 0.06 + FAST_HOLD + 0.01)


def test_isolated_delay_blip_does_not_go_fast():
    g = ProbeGovernor(t0=0.0)
    t = 50.0
    assert g.sample(t, True) == "burst"
    for k in range(4):                                         # the burst replies are clean: a blip
        assert g.sample(t + 0.02 * k, False) is None
    assert not g.is_fast(t + 0.1)
    # a later blip opens a fresh confirmation window
    assert g.sample(t + CONFIRM_WIN + 1.0, True) == "burst"


def test_late_probe_goes_fast_at_once():
    g = ProbeGovernor(t0=0.0)
    assert not g.is_fast(50.0)
    g.late(50.0)
    assert g.is_fast(50.1) and g.n_fast == 1


def test_force_extends_and_never_shortens():
    g = ProbeGovernor(t0=0.0)
    g.force(50.0, 3.0)
    g.force(50.1, 0.5)
    assert g.is_fast(52.9)


def test_full_rate_ends_unless_the_loop_keeps_forcing_it():
    """the governor itself does not extend on delayed samples (they are noisy on a loaded gateway); the rate loop does,
    while the estimator's vote/state says the link is not calm"""
    g = ProbeGovernor(t0=0.0)
    g.force(50.0)
    g.sample(50.5, True)
    assert not g.is_fast(50.0 + FAST_HOLD + 0.01)


def test_collapse_signature():
    assert collapsed(10.0, 47.5, 47.0)                         # fell from 47 to 10 on a 47.5 shaper
    assert not collapsed(46.0, 47.5, 47.0)                     # loaded and healthy
    assert not collapsed(0.01, 47.5, 0.02)                     # idle link is calm, not a collapse
    assert not collapsed(40.0, 47.5, 44.0)                     # mild dip
    assert not collapsed(1.5, 9.5, 3.0)                        # ACK-only upstream fluctuating at 15-30 % of its shaper


def test_peak_decays():
    p = decay_peak(0.0, 40.0, 0.1)
    assert p == 40.0
    for _ in range(50):                                        # 5 s of silence
        p = decay_peak(p, 0.0, 0.1)
    assert p < 4.0


def test_ewma_alpha_matches_10hz_loop():
    assert ewma_alpha(0.1) == pytest.approx(0.6)
    assert ewma_alpha(0.2) == pytest.approx(0.84)
    assert ewma_alpha(0.2) > ewma_alpha(0.1) > ewma_alpha(0.05)


# ---------------------------------------------------------------------------- wiring in the controller
def _ctl(tmp_path, fake_sh, state_dir, **kw):
    from tests_halo.test_m6_enforcer import _ctl as mk
    kw.setdefault("quiet_probe_hz", 2.0)
    kw.setdefault("quiet_tick", 0.2)
    return mk(tmp_path, fake_sh, state_dir, **kw)


def test_govern_stays_quiet_when_idle_and_steady(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    now = time.time() + 100
    for e in c.est.values():
        e.state = "STEADY"
    ach, peak = {"dl": 0.0, "ul": 0.0}, {"dl": 0.0, "ul": 0.0}
    c.govern(now, ach, peak, 0.2)
    assert not c.gov.is_fast(now)


def test_govern_forces_full_rate_on_each_not_calm_condition(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    base = time.time() + 100
    peak = {"dl": 0.0, "ul": 0.0}

    def hot(mut, ach=None):
        c.gov.fast_until = 0.0
        for e in c.est.values():
            e.state = "STEADY"
            e.rate = e.p.r_max
        c.last_action = {"dl": 0.0, "ul": 0.0}
        c.fsm, c.txn = "STEADY", None
        mut()
        c.govern(base, dict(ach or {"dl": 0.0, "ul": 0.0}), dict(peak), 0.2)
        return c.gov.is_fast(base)

    assert not hot(lambda: None)
    assert hot(lambda: setattr(c.est["dl"], "state", "DRAIN"))
    assert hot(lambda: setattr(c.est["ul"], "state", "DEGRADED"))
    assert hot(lambda: c.last_action.update(dl=base - 1.0))                 # recent rate change
    assert hot(lambda: setattr(c, "fsm", "VERIFYING"))
    assert not hot(lambda: setattr(c, "fsm", "ADAPTING"))                    # sticky label after a rate change, not a reason
    assert hot(lambda: setattr(c, "txn", {"stage": "SHADOW"}))
    assert hot(lambda: [c.est["dl"].votes.append((base, True)) for _ in range(6)])   # bloat vote
    # about to probe: below r_max, loaded, hold expired
    def about_to_probe():
        e = c.est["dl"]
        e.rate, e.t_hold_until = 0.5 * e.p.r_max, base - 1
    assert hot(about_to_probe, {"dl": 0.5 * c.est["dl"].p.r_max, "ul": 0.0})
    # collapse of the arrival rate (peak 40 -> now 5 on a 47.5 shaper)
    p2 = dict(peak); p2["dl"] = 40.0
    c.gov.fast_until = 0.0
    for e in c.est.values():
        e.state, e.rate = "STEADY", e.p.r_max
    c.last_action, c.fsm = {"dl": 0.0, "ul": 0.0}, "STEADY"
    c.govern(base, {"dl": 5.0, "ul": 0.0}, p2, 0.1)
    assert c.gov.is_fast(base)


def test_probing_up_at_rmax_is_calm(tmp_path, fake_sh, state_dir, monkeypatch):
    """the estimator keeps state PROBING_UP while loaded even after it reached r_max: that alone is not a reason
    (saturation detection off here; see the next test)"""
    from halo import controller as C
    monkeypatch.setattr(C, "SAT_FRAC", 0.0)
    c = _ctl(tmp_path, fake_sh, state_dir)
    now = time.time() + 100
    for e in c.est.values():
        e.state, e.rate = "PROBING_UP", e.p.r_max
    c.govern(now, {"dl": 0.9 * c.est["dl"].rate, "ul": 0.0}, {"dl": 0.9 * c.est["dl"].rate, "ul": 0.0}, 0.2)
    assert not c.gov.is_fast(now)


def test_saturated_shaper_uses_native_monitor_or_fast_fallback(tmp_path, fake_sh, state_dir):
    """The native sentinel monitors saturation independently; Python falls back to the fast loop."""
    c = _ctl(tmp_path, fake_sh, state_dir)
    now = time.time() + 100
    for e in c.est.values():
        e.state, e.rate = "STEADY", e.p.r_max
    r = c.est["dl"].rate
    c.govern(now, {"dl": 0.5 * r, "ul": 0.0}, {"dl": 0.5 * r, "ul": 0.0}, 0.2)
    assert not c.gov.is_fast(now)                         # half loaded: calm
    c.sent = object()
    c.govern(now, {"dl": 0.95 * r, "ul": 0.0}, {"dl": 0.95 * r, "ul": 0.0}, 0.2)
    assert not c.gov.is_fast(now)
    c.sent = None
    c.govern(now, {"dl": 0.95 * r, "ul": 0.0}, {"dl": 0.95 * r, "ul": 0.0}, 0.2)
    assert c.gov.is_fast(now)                             # saturated: full rate


def test_prober_wire_quiet_sends_nothing_itself_fast_sends_20hz_burst_reaches_all(tmp_path, fake_sh, state_dir):
    """real UDP sockets on loopback with 4 echo reflectors: in calm mode the prober thread sends nothing (the rate loop
    carries the probe, via send_probe), at the full rate it sends ~20 Hz, and a burst reaches every reflector at once"""
    echo = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(4)]
    for s in echo:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in echo]
    got = [0]
    stopev = threading.Event()

    def reflect():
        import select, struct
        while not stopev.is_set():
            for s in select.select(echo, [], [], 0.05)[0]:
                d, ad = s.recvfrom(64)
                got[0] += 1
                _, sq, ts = struct.unpack("!IId", d[:16])
                s.sendto(struct.pack("!IIdd", 0x48414C4F, sq, ts, time.time()), ad)
    threading.Thread(target=reflect, daemon=True).start()
    from halo import controller
    real_socket = socket.socket
    c = _ctl(tmp_path, fake_sh, state_dir)
    c.a.reflectors = ["127.0.0.1"] * 4

    class S(real_socket):                                      # route the fixed port 7000 to the 4 echo ports
        n = 0

        def connect(self, addr):
            i = S.n % 4
            S.n += 1
            return super().connect((addr[0], ports[i]))
    controller.socket.socket = S
    try:
        c.gov.fast_until = 0.0                                 # calm from the start
        th = threading.Thread(target=c.prober, daemon=True)
        th.start()
        time.sleep(1.5)
        assert got[0] == 0, got[0]                             # calm: the prober thread itself sends nothing
        c.send_probe(1)                                        # the rate loop's calm probe: sent, answered, consumed
        time.sleep(0.2)
        assert got[0] == 1 and not c.pending and len(c.probes) == 1
        n0 = got[0]
        c.nudge_prober()                                       # burst: one probe to every reflector at once
        time.sleep(0.3)
        assert got[0] - n0 >= 4
        c.gov.force(time.time(), 1.0)                          # full rate: ~20 Hz for a second
        c.nudge_prober()
        n1 = got[0]
        time.sleep(1.0)
        assert 10 <= got[0] - n1 <= 40, got[0] - n1
        c.stop = True
        c._pwake[1].send(b"x")
        th.join(2)
    finally:
        controller.socket.socket = real_socket
        stopev.set()


def test_run_loop_executes_quiet_ticks_and_kick_wakes_it(tmp_path, fake_sh, state_dir, monkeypatch):
    """Ctl.run() end to end on loopback counters: it must survive its set-up (a NameError here once killed the
    controller in the VM), tick at the quiet period when calm, write the heartbeat and telemetry, emit the gov event, and
    a prober kick must end the quiet wait at once"""
    from halo import controller
    monkeypatch.setattr(controller, "WAN", "lo")
    c = _ctl(tmp_path, fake_sh, state_dir, tick=0.05, quiet_tick=0.3)
    c.gov = ProbeGovernor(20, 2, 0.05, 0.3, t0=0.0)           # calm from the start
    for e in c.est.values():
        e.state = "STEADY"
        e.last_seen = {0: time.time() + 60, 1: time.time() + 60}     # healthy reflectors (no prober in this test)
    monkeypatch.setattr(c, "prober", lambda: None)
    c.a.reflectors = []
    c.socks, sent = [object()], []
    monkeypatch.setattr(c, "send_probe", lambda i: sent.append(i))
    th = threading.Thread(target=c.run, daemon=True)
    th.start()
    time.sleep(1.0)
    n_quiet = c.n_tick
    assert 2 <= n_quiet <= 5, n_quiet                          # ~0.3 s ticks, not 0.05 s
    assert 1 <= len(sent) <= 3, sent                           # the calm probe rides on every 2nd tick (~2 Hz)
    t0 = c.n_tick
    c.kick.set()
    time.sleep(0.12)
    assert c.n_tick > t0                                       # woke before the 0.3 s period was up
    assert os.path.exists(os.path.join(state_dir, "heartbeat"))
    c.stop = True
    c.kick.set()
    th.join(2)
    c.tel.flush()
    assert len(open(os.path.join(c.a.out, "telemetry.csv")).read().splitlines()) >= 3


def test_slow_loop_is_event_driven_when_the_flow_table_is_settled(tmp_path, fake_sh, state_dir):
    from halo.controller import GUARD_POLL_S, NEED_BINS
    c = _ctl(tmp_path, fake_sh, state_dir)
    now = time.time()
    assert c.slow_period(now, now - 10.0, True) == 1.0          # woken (override / new flow)
    assert c.slow_period(now, now - 10.0, False) == GUARD_POLL_S    # empty flow table, nothing pending: guard poll only
    assert c.slow_period(now, now - 1.0, False) == GUARD_POLL_S     # a poll that just landed needs no follow-up pass
    key = ("udp", "10.0.0.10", 1, "10.9.0.2", 443)
    c.flows[key] = {"t0": now - 1.0, "bins": []}
    assert c.slow_period(now, now - 10.0, False) == 1.0         # a flow younger than 3 s
    c.flows[key] = {"t0": now - 20.0, "bins": [], "seen": now}
    assert c.slow_period(now, now - 10.0, False) == GUARD_POLL_S
    c.a.classifier = "ml"
    assert c.slow_period(now, now - 10.0, False) == 1.0         # ML flow still collecting its 1 s bins
    c.flows[key]["bins"] = [0] * NEED_BINS
    assert c.slow_period(now, now - 10.0, False) == GUARD_POLL_S    # bins complete: back to the guard poll
    c._ovr_cache = ("sig", {"k": {"cls": "bulk", "until": now + 1.0}})
    assert 1.0 < c.slow_period(now, now - 10.0, False) < 1.2    # an override expires in 1 s: revert promptly
