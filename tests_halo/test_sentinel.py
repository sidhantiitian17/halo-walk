"""M12 in-process C calm-mode sentinel (halo/csrc/sentinel.c + halo/sentinel.py): probing, alerts, heartbeat gating,
clean shutdown, and the fallback to the pure-Python calm path.  Runs on loopback (no root); skipped if the library
is not built (`make`)."""
import os, socket, struct, subprocess, threading, time

import pytest

from halo import sentinel as S

pytestmark = pytest.mark.skipif(not os.path.exists(S.LIB), reason="halo/libhalo_sentinel.so not built (make)")
MAGIC = 0x48414C4F


class Reflector(threading.Thread):
    """UDP echo in the reflector wire format; `extra_ms` shifts the reflector timestamp (an OWD rise), `drop` = silent"""
    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.s.settimeout(0.05)
        self.port = self.s.getsockname()[1]
        self.extra_ms, self.drop, self.run_, self.n, self.extra_n = 0.0, False, True, 0, None
        self.start()

    def run(self):
        while self.run_:
            try:
                d, a = self.s.recvfrom(64)
            except OSError:
                continue
            self.n += 1
            if self.drop or len(d) < 16:
                continue
            m, sq, ts = struct.unpack("!IId", d[:16])
            ex = self.extra_ms
            if self.extra_n is not None:                      # only the first extra_n replies are delayed
                ex = ex if self.extra_n > 0 else 0.0
                self.extra_n -= 1
            self.s.sendto(struct.pack("!IIdd", m, sq, ts, time.time() + ex * 1e-3), a)


@pytest.fixture
def refl():
    r = Reflector()
    yield r
    r.run_ = False


def _load(refl, tmp_path, n=4, log=None):
    sent = S.Sentinel.load(["127.0.0.1"] * n, "lo", str(tmp_path / "hb"), port=refl.port, log=log or (lambda m: None))
    assert sent is not None
    return sent


def _params(**kw):
    p = S.Params()
    p.tick_s, p.probe_s, p.thresh_ms, p.late_s, p.confirm_win, p.confirm_n = 0.1, 0.2, 15.0, 0.4, 0.4, 3
    p.base_alpha, p.peak_tau, p.gate_s, p.ewma_alpha_ref, p.ewma_dt_ref = 0.002, 2.0, S.GATE_S, 0.6, 0.1
    p.load_thresh, p.collapse = 0.75, 0.7
    for i in range(2):
        p.rate[i] = p.rmax[i] = 100.0
        p.hold_until[i] = time.time() + 1e6
        p.st[i].value = b"STEADY"
    p.fsm = b"STEADY"
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def test_struct_sizes_match_the_library():
    import ctypes
    lib = ctypes.CDLL(S.LIB)
    assert lib.hs_sizeof_params() == ctypes.sizeof(S.Params)
    assert lib.hs_sizeof_state() == ctypes.sizeof(S.State)
    assert lib.hs_sizeof_event() == ctypes.sizeof(S.Event)


def test_calm_mode_probes_counts_and_writes_telemetry_without_python(refl, tmp_path):
    sent = _load(refl, tmp_path)
    try:
        sent.arm(_params())
        t0 = time.time()
        while time.time() - t0 < 1.3:
            sent.bump()
            time.sleep(0.2)
        ev = sent.drain()
        probes = [e for e in ev if e[0] == S.EV_PROBE]
        achs = [e for e in ev if e[0] == S.EV_ACH]
        assert 4 <= len(probes) <= 8, len(probes)                  # 5 Hz probes round-robin
        assert 9 <= len(achs) <= 14, len(achs)                     # 10 Hz ticks
        assert all(abs(e[2]) < 50 and abs(e[3]) < 50 for e in probes)
        lines = sent.telemetry().splitlines()
        assert len(lines) == len(achs)
        cols = lines[0].split(",")
        assert len(cols) == 14 and cols[5] == "STEADY" and cols[13] == "STEADY"      # same schema as the Python path
        assert sent.ack_alert() == S.AL_NONE
        assert sent.state().armed == 1
        sent.disarm()
        assert sent.state().armed == 0
    finally:
        sent.stop()


def test_heartbeat_is_gated_on_the_python_liveness_counter(refl, tmp_path):
    """a hung Python main loop (no bump) must stop the heartbeat, even though the C thread is still running"""
    sent = _load(refl, tmp_path)
    hb = tmp_path / "hb"
    try:
        sent.arm(_params())
        t0 = time.time()
        while time.time() - t0 < 0.8:                             # alive: heartbeat advances
            sent.bump()
            time.sleep(0.1)
        assert time.time() - hb.stat().st_mtime < 0.6
        assert hb.read_text().endswith(" STEADY")
        time.sleep(S.GATE_S + 0.5)                                 # "hung": nobody bumps any more
        age = time.time() - hb.stat().st_mtime
        assert age > 0.4, age
        m1 = hb.stat().st_mtime_ns
        time.sleep(0.5)
        assert hb.stat().st_mtime_ns == m1                         # still stale, thread still armed
        assert sent.state().armed == 1
        sent.bump()                                                # Python recovers: heartbeat resumes
        time.sleep(0.3)
        assert hb.stat().st_mtime_ns > m1
    finally:
        sent.stop()


def test_late_probe_raises_an_alert_and_switches_to_full_rate(refl, tmp_path):
    sent = _load(refl, tmp_path)
    try:
        refl.drop = True
        p = _params()
        sent.set_fast(0.05, 0.4)
        sent.arm(p)                                                # fast -> calm switch works without a disarm
        t0 = time.time()
        while time.time() - t0 < 2.0 and sent.state().alert == 0:
            sent.bump()
            time.sleep(0.05)
        assert sent.ack_alert() == S.AL_LATE
        ev = sent.drain()
        assert any(e[0] == S.EV_LATE and e[2] >= 400 for e in ev), ev
        n0 = refl.n
        time.sleep(1.3)                                            # now probing at the full rate (20 Hz) with no gap
        assert refl.n - n0 >= 15
        assert any(e[0] == S.EV_LOST for e in sent.drain())        # unanswered > 1 s: reported lost
        assert sent.state().armed == 1
    finally:
        sent.stop()


def test_fast_mode_probes_at_full_rate_and_queues_samples(refl, tmp_path):
    sent = _load(refl, tmp_path)
    try:
        sent.set_fast(0.05, 0.4)
        time.sleep(1.0)
        probes = [e for e in sent.drain() if e[0] == S.EV_PROBE]
        assert 14 <= len(probes) <= 22, len(probes)                # 20 Hz aggregate, round-robin over the reflectors
        assert {e[4] for e in probes} == {0, 1, 2, 3}
        assert sent.telemetry() == ""                              # Python owns telemetry / heartbeat in FAST mode
        sent.set_fast(0.05, 0.4, True)                             # burst: one probe to every reflector at once
        time.sleep(0.02)
        sent.disarm()
        assert sent.state().armed == 0
    finally:
        sent.stop()


def _wait_alert(sent, secs=2.0):
    import select
    r = select.select([sent.efd], [], [], secs)[0]
    return sent.ack_alert() if r else 0


def test_delay_rise_triggers_confirmation_burst_then_full_rate_alert(refl, tmp_path):
    sent = _load(refl, tmp_path)
    try:
        refl.extra_ms = 60.0                                       # every reply shows +60 ms OWD against the baseline
        p = _params()
        for i in range(4):
            p.base_ul[i] = p.base_dl[i] = -0.5                     # baselines ~ the loopback OWD (~0), so delta ~ 60 ms
            p.has_base_ul[i] = p.has_base_dl[i] = 1
        sent.arm(p)
        assert _wait_alert(sent) == S.AL_DELAY
        kinds = [e[0] for e in sent.drain()]
        assert S.EV_BURST in kinds and S.EV_FAST in kinds
    finally:
        sent.stop()


def test_single_delayed_sample_does_not_alert(refl, tmp_path):
    """a blip (one delayed reply, burst replies on time) must not wake Python"""
    sent = _load(refl, tmp_path)
    try:
        p = _params()
        for i in range(4):
            p.base_ul[i] = p.base_dl[i] = -0.5
            p.has_base_ul[i] = p.has_base_dl[i] = 1
        refl.extra_ms, refl.extra_n = 60.0, 1                      # the first reply is delayed, the confirmation burst is not
        sent.arm(p)
        t0 = time.time()
        while time.time() - t0 < 1.0:
            sent.bump(); time.sleep(0.1)
        assert sent.state().armed == 1 and sent.ack_alert() in (S.AL_NONE,)
    finally:
        sent.stop()


def test_collapse_and_probe_up_alerts_use_the_params_python_hands_over(refl, tmp_path):
    sent = _load(refl, tmp_path)
    try:
        p = _params()
        p.rate[0] = p.rmax[0] = 10.0
        p.peak[0], p.ach[0] = 8.0, 8.0                             # was loaded, the arrival rate is gone (lo is idle)
        sent.set_fast(0.05)
        refl.extra_ms = -60.0                                     # shift delay into the downlink
        for i in range(4):
            p.has_base_dl[i] = 1
        sent.arm(p)
        assert _wait_alert(sent) == S.AL_COLLAPSE
        assert sent.state().dl_collapse_at > 0
        sent.disarm()
        refl.extra_ms = 0.0
        p = _params()
        p.rate[0], p.rmax[0], p.hold_until[0] = 1.0, 100.0, 0.0     # room to probe upwards, hold expired, link loaded
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stopl = threading.Event()

        def load():
            while not stopl.is_set():
                s.sendto(b"x" * 1400, ("127.0.0.1", 9))
                time.sleep(0.002)
        th = threading.Thread(target=load, daemon=True)
        th.start()
        try:
            sent.arm(p)
            assert _wait_alert(sent, 3.0) == S.AL_PROBEUP
            sent.disarm()

            # At the ceiling, steady traffic keeps the configured native probe cadence.
            # Stopping a sender should cause a check, but successful probes must leave Python asleep.
            p = _params(sat_frac=0.9, probe_s=0.2)
            p.rate[0] = p.rmax[0] = 1.0
            sent.arm(p)
            n0 = refl.n
            for _ in range(7):
                sent.bump()
                time.sleep(0.1)
            assert 2 <= refl.n - n0 <= 5
            assert sent.ack_alert() == S.AL_NONE
            stopl.set()
            th.join()
            assert _wait_alert(sent, 0.8) == S.AL_NONE
            assert any(event[0] == S.EV_BURST for event in sent.drain())
        finally:
            stopl.set(); th.join()
    finally:
        sent.stop()


def test_stop_is_prompt_idempotent_and_stops_the_heartbeat(refl, tmp_path):
    sent = _load(refl, tmp_path)
    hb = tmp_path / "hb"
    sent.arm(_params())
    for _ in range(5):
        sent.bump(); time.sleep(0.1)
    t0 = time.time()
    sent.stop()
    assert time.time() - t0 < 0.5
    m = hb.stat().st_mtime_ns
    time.sleep(0.4)
    assert hb.stat().st_mtime_ns == m
    sent.stop()                                                    # second stop: no crash


def test_fallback_to_pure_python_when_the_library_cannot_load(tmp_path, monkeypatch):
    logs = []
    bad = tmp_path / "libbad.so"
    bad.write_bytes(b"not an elf")
    assert S.Sentinel.load(["127.0.0.1"], "lo", "", log=logs.append, path=str(bad)) is None
    assert S.Sentinel.load(["127.0.0.1"], "lo", "", log=logs.append, path=str(tmp_path / "missing.so")) is None
    assert S.Sentinel.load(["127.0.0.1"], "nosuchdev0", "", log=logs.append) is None      # init failure (no counters) -> fallback
    assert len(logs) == 3 and all("pure-Python" in m for m in logs)
    monkeypatch.setenv("HALO_NO_SENTINEL", "1")
    assert S.Sentinel.load(["127.0.0.1"], "lo", "", log=logs.append) is None


def _ctl_sentinel(tmp_path, fake_sh, state_dir, monkeypatch, **kw):
    from halo import controller
    from tests_halo.test_m6_enforcer import _ctl as mk
    monkeypatch.setattr(controller, "WAN", "lo")
    c = mk(tmp_path, fake_sh, state_dir, sentinel=1, quiet_probe_hz=2.0, quiet_tick=0.1, **kw)
    c.gov = controller.ProbeGovernor(20, 2, 0.05, 0.1, t0=0.0)      # calm from the start
    for e in c.est.values():
        e.state = "STEADY"
        e.last_seen = {0: time.time() + 60, 1: time.time() + 60}
    c.a.reflectors = ["127.0.0.1"]
    monkeypatch.setattr(c, "prober", lambda: None)
    return c


def test_controller_hands_calm_mode_to_the_c_thread_and_python_sleeps(tmp_path, fake_sh, state_dir, monkeypatch, refl):
    c = _ctl_sentinel(tmp_path, fake_sh, state_dir, monkeypatch)
    monkeypatch.setattr(S.Sentinel, "load", classmethod(lambda cls, r, w, hb, port=7000, log=None, path=None: _real_load(cls, r, w, hb, refl.port, log)))
    th = threading.Thread(target=c.run, daemon=True)
    th.start()
    try:
        time.sleep(2.5)
        assert c.sent is not None and c.sent.armed
        n_py = c.n_tick
        time.sleep(2.0)
        assert c.n_tick - n_py <= 3, c.n_tick - n_py                # Python main loop: heavy pass every HEAVY_S, not 10 Hz
        hb = os.path.join(state_dir, "heartbeat")
        assert time.time() - os.path.getmtime(hb) < 0.5             # the C thread keeps the heartbeat
        assert refl.n >= 4                                          # probes went out from C
        c.tel.flush()
        rows = open(os.path.join(c.a.out, "telemetry.csv")).read().splitlines()
        assert len(rows) > 15 and all(len(r.split(",")) == 14 for r in rows)
        # a hung Python main loop: the loop's own wait never returns; the heartbeat must go stale although C still runs
        from halo import controller
        monkeypatch.setattr(controller.select, "select", lambda *a: time.sleep(60))
        t0 = time.time()
        while time.time() - t0 < 4 and time.time() - os.path.getmtime(hb) < 1.2:
            time.sleep(0.1)
        assert time.time() - os.path.getmtime(hb) >= 1.0, "heartbeat kept alive although the Python loop is hung"
        assert c.sent.state().armed == 1
    finally:
        c.stop = True
        c.sent.stop()


_real_load = S.Sentinel.load.__func__


def test_controller_falls_back_to_python_calm_path_and_logs(tmp_path, fake_sh, state_dir, monkeypatch):
    import json
    c = _ctl_sentinel(tmp_path, fake_sh, state_dir, monkeypatch)
    c.a.sentinel_lib = str(tmp_path / "missing.so")
    th = threading.Thread(target=c.run, daemon=True)
    th.start()
    time.sleep(1.0)
    c.stop = True
    c.kick.set()
    th.join(2)
    assert c.sent is None
    c.ev.flush()
    evs = [json.loads(l) for l in open(c.ev.name)]
    assert any(e["kind"] == "sentinel" and "pure-Python" in e["msg"] for e in evs)
    assert c.n_tick >= 5                                            # the Python path ticked normally
    assert os.path.exists(os.path.join(state_dir, "heartbeat"))


def test_sigterm_shuts_the_controller_down_cleanly(tmp_path, fake_sh, state_dir, monkeypatch, refl):
    """SIGTERM while the C thread is armed: run() unwinds (KeyboardInterrupt in the main thread), close() stops the C thread,
    the heartbeat stops with it"""
    import signal
    c = _ctl_sentinel(tmp_path, fake_sh, state_dir, monkeypatch)
    monkeypatch.setattr(S.Sentinel, "load", classmethod(lambda cls, r, w, hb, port=7000, log=None, path=None: _real_load(cls, r, w, hb, refl.port, log)))
    old = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGUSR1)
    threading.Timer(2.0, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    t0 = time.time()
    try:
        with pytest.raises(KeyboardInterrupt):
            c.run()
        assert time.time() - t0 < 4.0
        assert c.sent is not None and c.sent.armed
        c.close()
        assert c.sent is None and c.stop
        hb = os.path.join(state_dir, "heartbeat")
        m = os.path.getmtime(hb)
        time.sleep(0.5)
        assert os.path.getmtime(hb) == m                           # no heartbeat after shutdown
    finally:
        signal.signal(signal.SIGTERM, old[0]); signal.signal(signal.SIGUSR1, old[1])


def test_uncollected_replies_are_not_mistaken_for_late_probes(refl, tmp_path):
    """calm mode collects replies at its tick; with a tick longer than the late threshold an answered probe must not alert"""
    sent = _load(refl, tmp_path)
    try:
        p = _params()
        p.tick_s, p.probe_s = 0.6, 0.6
        sent.arm(p)
        t0 = time.time()
        while time.time() - t0 < 2.5:
            sent.bump()
            time.sleep(0.1)
        assert sent.ack_alert() == S.AL_NONE
        assert sent.state().armed == 1 and sum(1 for e in sent.drain() if e[0] == S.EV_PROBE) >= 2
    finally:
        sent.stop()


# ------------------------------------------------------------------------------------------------ conntrack in C
def _ct_parse(buf, keys):
    import ctypes
    lib = ctypes.CDLL(S.LIB)
    lib.hs_ct_parse.argtypes = [ctypes.c_char_p, ctypes.c_long, ctypes.POINTER(S.CKey), ctypes.c_int, ctypes.POINTER(S.CVal)]
    arr, vals = S.ct_keys(keys), (S.CVal * len(keys))()
    done = lib.hs_ct_parse(buf, len(buf), arr, len(keys), vals)
    return done, {k: (v.up_b, v.dn_b, v.up_p, v.dn_p) for k, v in zip(keys, vals) if v.found}


def test_c_conntrack_parser_agrees_with_the_python_parser():
    from halo import controller as C
    from tests_halo.test_ctl_fastpath import ct_msg
    buf = (ct_msg("10.0.0.2", "198.51.100.1", 50000, 443, 6, (10, 1000), (20, 30000)) +
           ct_msg("198.51.100.9", "10.0.0.2", 4000, 5000, 17, (3, 300), (4, 4000)) +          # WAN-initiated: flipped
           ct_msg("10.0.0.2", "1.1.1.1", 0, 0, 1, (1, 84), (1, 84)) +                          # icmp: skipped
           ct_msg("fd00::10", "fd00:9::2", 20000, 3478, 17, (120, 130560), (0, 0), v6=True) +
           ct_msg("10.0.0.7", "198.51.100.1", 1, 2, 6, (1, 1), (1, 1)) + struct.pack("IHHII", 16, 3, 2, 1, 0))   # + NLMSG_DONE
    want = {}
    for g in C.parse_ct_dump(buf):
        k, c = C.ct_entry_t(*g)
        want[k] = c
    tracked = list(want) + [("tcp", "10.0.0.99", 1, "8.8.8.8", 2)]                              # one flow that is not in the table
    done, got = _ct_parse(buf, tracked)
    assert done == 1 and got == want and len(want) == 4


def test_c_conntrack_dump_runs_or_reports_unavailable(refl, tmp_path):
    """live ctnetlink dump (needs nf_conntrack + privileges): either a dict or OSError -> the controller's Python fallback"""
    sent = _load(refl, tmp_path)
    try:
        try:
            assert sent.ct_dump([("tcp", "10.0.0.2", 1, "10.9.0.1", 2)]) == {}
        except OSError:
            pass
    finally:
        sent.stop()
