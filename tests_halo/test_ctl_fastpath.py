"""Control-path fast paths (ctl agent): in-process libnftables, rtnetlink CAKE change/read-back, ctnetlink accounting,
synchronous override + controller wake-up, prebuilt-LKG rollback. No kernel object is touched: every backend is a fake;
the wire formats are checked byte for byte against the kernel ABI (nlmsghdr / tcmsg / nfgenmsg / nlattr)."""
import json, os, socket, struct, subprocess, sys, threading, time, types

import pytest

from halo import controller as C
from halo import enforcer as E
from halo.enforcer import LAN, WAN, Enforcer


def nla(t, data, nested=False):
    n = 4 + len(data)
    return struct.pack("HH", n, t | (0x8000 if nested else 0)) + data + b"\0" * (-n % 4)


# ------------------------------------------------------------------------------------------------ rtnetlink / CAKE
def test_cake_rate_msg_is_a_qdisc_change_with_bandwidth_only():
    m = E.cake_rate_msg(7, 15.2)
    ln, typ, flags, seq, pid = struct.unpack_from("IHHII", m)
    assert ln == len(m) and typ == 36 and flags == 1 | 4          # RTM_NEWQDISC, REQUEST|ACK (no CREATE/REPLACE)
    fam, _, _, idx, handle, parent, info = struct.unpack_from("BBHiIII", m, 16)
    assert (fam, idx, handle, parent) == (0, 7, 0, 0xFFFFFFFF)     # root, handle left to the kernel (like `tc ... root`)
    assert m[36:44] == struct.pack("HH", 9, 1) + b"cake\0"[:4]      # TCA_KIND "cake"
    # nested TCA_OPTIONS { TCA_CAKE_BASE_RATE64 = bytes/s }: 15200 kbit = 1_900_000 B/s, exactly `tc ... bandwidth 15200kbit`
    assert struct.unpack_from("Q", m, len(m) - 8)[0] == 1_900_000
    assert len(m) % 4 == 0


def _qdisc_msg(idx, kind, parent, rate, handle=0x10000):
    opts = nla(2, nla(3, struct.pack("I", 1)) + nla(E.TCA_CAKE_BASE_RATE64, struct.pack("Q", rate)) + nla(5, b"\0\0\0\0"), True)
    body = struct.pack("BBHiIII", 0, 0, 0, idx, handle, parent, 1) + nla(1, kind + b"\0") + opts
    return struct.pack("IHHII", 16 + len(body), 36, 2, 1, 0) + body


def test_parse_cake_rates_picks_root_cake_only():
    buf = _qdisc_msg(2, b"cake", 0xFFFFFFFF, 2_375_000) + _qdisc_msg(3, b"fq_codel", 0xFFFFFFFF, 5) + \
        _qdisc_msg(4, b"cake", 0xFFFFFFF1, 7) + _qdisc_msg(5, b"cake", 0xFFFFFFFF, 250_000)
    buf += struct.pack("IHHII", 20, 3, 2, 1, 0) + b"\0\0\0\0"        # NLMSG_DONE
    assert E.parse_cake_rates(buf) == {2: 2_375_000, 5: 250_000}


def test_rollback_fast_path_spawns_nothing_and_reads_back(fake_sh, state_dir, monkeypatch):
    enf = Enforcer()
    enf.install(19.0, 3.8, marks=False)
    enf.commit({"autorate": 1})
    enf.set_rate(LAN, 2.0)                                            # the "bad policy"
    fake_sh.calls.clear()
    kern = {LAN: 2.0, WAN: 3.8}
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "rtnl_set_rates", lambda r: kern.update(r))
    monkeypatch.setattr(E, "rtnl_cake_rates", lambda devs: {d: kern[d] for d in devs})
    ok, dt, lkg = enf.rollback()
    assert ok and kern[LAN] == pytest.approx(19.0) and enf.rate[LAN] == 19.0
    assert fake_sh.calls == []                                        # no tc / nft / ip process at all
    assert dt < 0.5


def test_rollback_fast_path_detects_a_failed_restore(fake_sh, state_dir, monkeypatch):
    enf = Enforcer()
    enf.install(19.0, 3.8, marks=False)
    enf.commit({})
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "rtnl_set_rates", lambda r: None)           # kernel ignores the change
    monkeypatch.setattr(E, "rtnl_cake_rates", lambda devs: {LAN: 2.0, WAN: 3.8})
    assert enf.rollback()[0] is False                                 # read-back is real: mismatch -> not ok -> SAFE


def test_rollback_falls_back_to_one_prebuilt_tc_batch(fake_sh, state_dir, monkeypatch):
    enf = Enforcer()
    enf.install(19.0, 3.8, marks=False)
    enf.commit({})
    pre = enf._pre
    assert pre["change"].count("\n") == 2 and pre["change"].startswith("qdisc change dev lan0 root handle 1: cake bandwidth 19000kbit")
    enf.set_rate(LAN, 2.0)
    fake_sh.calls.clear()
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    def boom(*a, **k):
        raise OSError("no netlink")
    monkeypatch.setattr(E, "rtnl_set_rates", boom)
    monkeypatch.setattr(E, "rtnl_cake_rates", boom)
    ok, dt, lkg = enf.rollback()
    assert ok
    assert fake_sh.cmds().count("tc -batch -") == 1 and fake_sh.inputs()[0] == pre["change"]


def test_set_rate_uses_rtnetlink_when_available(fake_sh, state_dir, monkeypatch):
    enf = Enforcer()
    seen = []
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "rtnl_set_rates", lambda r: seen.append(dict(r)))
    enf.set_rate(LAN, 12.5)
    assert seen == [{LAN: 12.5}] and enf.rate[LAN] == 12.5 and fake_sh.calls == []


# ------------------------------------------------------------------------------------------------ libnftables
class FakeNft:
    def __init__(self, fail_first=False):
        self.texts, self.fail_first = [], fail_first

    def available(self):
        return True

    def run(self, text):
        self.texts.append(text)
        if self.fail_first and len(self.texts) == 1:
            raise RuntimeError("nft failed: boom")


def test_nft_batch_runs_in_process_one_transaction(fake_sh, state_dir, monkeypatch):
    f = FakeNft()
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "NFT", f)
    Enforcer().nft_batch(["destroy element inet halo dev4 { 10.0.0.2 }", "add element inet halo dev4 { 10.0.0.2 timeout 60s : 0x4 }"])
    assert len(f.texts) == 1 and f.texts[0].count("\n") == 2 and fake_sh.calls == []


def test_nft_batch_falls_back_line_by_line_in_process(fake_sh, state_dir, monkeypatch):
    f = FakeNft(fail_first=True)
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "NFT", f)
    Enforcer().nft_batch(["a", "b"])
    assert f.texts == ["a\nb\n", "a\n", "b\n"]


def test_safe_state_spawns_no_process_on_the_fast_path(fake_sh, state_dir, monkeypatch):
    f, seen = FakeNft(), []
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "NFT", f)
    monkeypatch.setattr(E, "rtnl_set_rates", lambda r: seen.append(dict(r)))
    E.safe_state(8.0, 1.6)
    assert fake_sh.calls == [] and seen == [{LAN: 8.0, WAN: 1.6}]
    assert "flush map inet halo flow4" in f.texts[0] and "flush set inet halo intent_mac" in f.texts[0]
    assert json.load(open(os.path.join(state_dir, "safe.json")))["rate_dl"] == 8.0


def test_safe_state_falls_back_to_one_tc_batch(fake_sh, state_dir, monkeypatch):
    f = FakeNft()
    monkeypatch.setattr(E, "_fast_ok", lambda: True)
    monkeypatch.setattr(E, "NFT", f)
    def boom(r):
        raise OSError("no netlink")
    monkeypatch.setattr(E, "rtnl_set_rates", boom)
    E.safe_state(8.0, 1.6)
    assert fake_sh.cmds().count("tc -batch -") == 1 and [c for c in fake_sh.cmds() if c.startswith("nft")] == []


def test_unit_tests_never_use_fast_paths(fake_sh):
    assert E._fast_ok() is False                                       # `sh` is the FakeKernel


# ------------------------------------------------------------------------------------------------ ctnetlink
def ct_msg(src, dst, sp, dp, proto, orig, reply, v6=False):
    ip = nla(1, (nla(3, socket.inet_pton(socket.AF_INET6, src)) + nla(4, socket.inet_pton(socket.AF_INET6, dst))) if v6 else
             (nla(1, socket.inet_aton(src)) + nla(2, socket.inet_aton(dst))), True)
    pr = nla(2, nla(1, bytes([proto])) + nla(2, struct.pack("!H", sp)) + nla(3, struct.pack("!H", dp)), True)
    ctr = lambda t, pk, by: nla(t, nla(1, struct.pack("!Q", pk)) + nla(2, struct.pack("!Q", by)), True)
    attrs = nla(1, ip + pr, True) + nla(3, struct.pack("!I", 14)) + ctr(9, *orig) + ctr(10, *reply)
    body = struct.pack("BBH", 2, 0, 0) + attrs
    return struct.pack("IHHII", 16 + len(body), 0x100, 2, 1, 0) + body


def test_parse_ct_dump_matches_the_text_parser():
    line = ("ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=198.51.100.1 sport=50000 dport=443 "
            "packets=10 bytes=1000 src=198.51.100.1 dst=10.0.0.2 sport=443 dport=50000 packets=20 bytes=30000 [ASSURED] mark=2 use=1")
    want = C.ct_entry(C.CT_RE.match(line))
    got = list(C.parse_ct_dump(ct_msg("10.0.0.2", "198.51.100.1", 50000, 443, 6, (10, 1000), (20, 30000))))
    assert [C.ct_entry_t(*g) for g in got] == [want]


def test_parse_ct_dump_orients_wan_initiated_and_skips_other_protocols():
    buf = ct_msg("198.51.100.9", "10.0.0.2", 4000, 5000, 17, (3, 300), (4, 4000)) + \
        ct_msg("10.0.0.2", "1.1.1.1", 0, 0, 1, (1, 84), (1, 84)) + \
        ct_msg("fd00::10", "fd00:9::2", 20000, 3478, 17, (120, 130560), (0, 0), v6=True)
    ents = [C.ct_entry_t(*g) for g in C.parse_ct_dump(buf)]
    assert ents[0] == (("udp", "10.0.0.2", 5000, "198.51.100.9", 4000), (4000, 300, 4, 3))   # flipped like ct_entry()
    assert ents[1] == (("udp", "fd00::10", 20000, "fd00:9::2", 3478), (130560, 0, 120, 0))
    assert len(ents) == 2                                              # icmp skipped


def test_ct_request_is_a_dump_of_all_families():
    r = C.ct_request()
    ln, typ, fl, seq, pid = struct.unpack_from("IHHII", r)
    assert (ln, typ, fl) == (20, (1 << 8) | 1, 0x301) and r[16:] == b"\0\0\0\0"


def _ctl(key):
    c = object.__new__(C.Ctl)
    c.flows = {key: {"key": key, "ct": None, "bins": [], "tot": (0, 0), "seen": 0.0}}
    c.flock = threading.Lock()
    return c


def test_poll_conntrack_uses_ctnetlink_without_exec(monkeypatch):
    key = ("tcp", "10.0.0.2", 50000, "198.51.100.1", 443)
    c = _ctl(key)
    outs = iter([{key: (1000, 30000, 10, 20)}, {key: (2000, 1_280_000, 20, 145)}])
    monkeypatch.setattr(C._enf_mod, "_fast_ok", lambda: True)
    monkeypatch.setattr(C, "ct_dump_netlink", lambda: next(outs))
    monkeypatch.setattr(C, "subprocess", types.SimpleNamespace(run=lambda *a, **k: pytest.fail("conntrack was exec'd")))
    monkeypatch.setattr(C, "_REAL_SUBPROCESS", C.subprocess)
    times = iter([100.0, 101.0])
    monkeypatch.setattr(C.time, "time", lambda: next(times))
    c.poll_conntrack(0)
    c.poll_conntrack(0)
    assert c.flows[key]["bins"] == [(1.0, 1000, 1_250_000, 10, 125)]


def test_poll_conntrack_falls_back_to_exec_when_ctnetlink_is_missing(monkeypatch):
    key = ("tcp", "10.0.0.2", 50000, "198.51.100.1", 443)
    c = _ctl(key)
    line = ("ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=198.51.100.1 sport=50000 dport=443 "
            "packets=10 bytes=1000 src=198.51.100.1 dst=10.0.0.2 sport=443 dport=50000 packets=20 bytes=30000 [ASSURED] mark=2 use=1")
    fake = types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(stdout=line))
    monkeypatch.setattr(C._enf_mod, "_fast_ok", lambda: True)
    def nonl():
        raise OSError("protocol not supported")
    monkeypatch.setattr(C, "ct_dump_netlink", nonl)
    monkeypatch.setattr(C, "subprocess", fake)
    monkeypatch.setattr(C, "_REAL_SUBPROCESS", fake)
    monkeypatch.setattr(C.time, "time", lambda: 100.0)
    c.poll_conntrack(0)
    assert c.flows[key]["tot"] == (1000, 30000) and c._ct_nl_broken


# ------------------------------------------------------------------------------------------------ slow-loop cadence
def test_poll_cadence_heuristic_needs_no_bins():
    c = object.__new__(C.Ctl)
    c.flock = threading.Lock()
    c.raw = None
    c.a = types.SimpleNamespace(classifier="heur")
    c.flows = {"b": {"bins": [], "t0": 0.0, "seen": 99.0, "tin": 2, "ovr": None}}
    assert c.poll_due(100.0, 99.5) is False                           # heuristic reads no bins: GUARD_POLL_S cadence only
    assert c.poll_due(100.0, 94.0) is True
    c.a = types.SimpleNamespace(classifier="ml")
    assert c.poll_due(100.0, 99.5) is True                            # ML still collects its bins at 1 Hz
    c.flows["b"]["bins"] = [0] * C.NEED_BINS
    assert c.poll_due(100.0, 99.5) is False


# ------------------------------------------------------------------------------------------------ override API
def test_override_is_applied_before_the_registry_write_and_wakes_the_controller(fake_sh, state_dir, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from halo import api
    monkeypatch.setattr(api, "OVR", os.path.join(state_dir, "overrides.json"))
    monkeypatch.setattr(api, "DATA", str(tmp_path / "data"))
    order = []
    orig_batch, orig_save = api.enf.nft_batch, api.save
    monkeypatch.setattr(api.enf, "nft_batch", lambda l: (order.append("nft"), orig_batch(l)))
    monkeypatch.setattr(api, "save", lambda p, o: (order.append("save"), orig_save(p, o)))
    monkeypatch.setattr(api, "poke_controller", lambda: order.append("poke"))
    r = TestClient(api.app).post("/v1/overrides", headers={"Authorization": "Bearer " + api.TOKEN},
                                 json={"device": "10.0.0.10", "cls": "call", "ttl": 120})
    assert r.status_code == 200 and r.json()["tin"] == "Voice"
    assert order == ["nft", "save", "poke"]
    assert len([c for c in fake_sh.cmds() if c.startswith("nft")]) == 1       # exactly one nft transaction, no second exec
    assert (tmp_path / "data" / "override_labels.jsonl").exists()


def test_poke_controller_signals_only_the_controller(state_dir, monkeypatch):
    from halo import api
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)  # halo.controller"])
    q = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    sent = []
    monkeypatch.setattr(api.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    try:
        for proc, want in ((q, []), (p, [(p.pid, api.signal.SIGUSR1)])):
            sent.clear()
            open(os.path.join(state_dir, "ctl.pid"), "w").write(str(proc.pid))
            time.sleep(0.2)
            api.poke_controller()
            assert sent == want
        open(os.path.join(state_dir, "ctl.pid"), "w").write("999999999")      # stale pid: silently ignored
        api.poke_controller()
    finally:
        p.kill(); q.kill()


def test_flow_override_is_one_atomic_replace(fake_sh, state_dir, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from halo import api
    monkeypatch.setattr(api, "OVR", os.path.join(state_dir, "overrides.json"))
    monkeypatch.setattr(api, "DATA", str(tmp_path / "data"))
    monkeypatch.setattr(api, "poke_controller", lambda: None)
    r = TestClient(api.app).post("/v1/overrides", headers={"Authorization": "Bearer " + api.TOKEN},
                                 json={"flow": ["udp", "10.0.0.2", 5000, "198.51.100.1", 443], "cls": "call", "ttl": 30})
    assert r.status_code == 200
    nft = [i for i in fake_sh.inputs() if "flow4" in i]
    assert len(nft) == 1 and nft[0].splitlines()[0].startswith("destroy element") and nft[0].splitlines()[1].startswith("add element")


# ------------------------------------------------------------------------------------------------ heuristic policy
def _heur_ctl(monkeypatch, flows):
    c = object.__new__(C.Ctl)
    c.a = types.SimpleNamespace(classifier="heur", voice_envelope=6.0)
    c.flows, c.flock, c.raw, c.model, c.promote_p = flows, threading.Lock(), None, None, 0.9
    c._ovr_cache, c._flows_json = (None, {}), (0.0, None)
    c.lim = C.policy.Limits()
    c.est = {"dl": types.SimpleNamespace(rate=19.0)}
    c.events, c.marks = [], []
    c.event = lambda kind, **kw: c.events.append((kind, kw))
    c.enf = types.SimpleNamespace(nft_batch=lambda lines: c.marks.extend(lines))
    return c


def _flow(key, tot, now=100.0):
    return {"key": key, "proto": key[0], "pkts": [], "t0": now - 30, "bins": [], "ct": None, "tot": tot, "cls": "other",
            "p": 0.0, "abstain": True, "stage": 0, "tin": 2, "done_h": 0, "seen": now, "ovr": None, "t_tin": now - 30}


def test_size_only_elephant_verdict_does_not_move_streaming_to_bulk(monkeypatch, state_dir):
    tv = ("tcp", "10.0.0.12", 40000, "10.9.0.2", 443)                   # 22 MB paced stream: size rule says bulk
    bt = ("tcp", "10.0.0.15", 40001, "10.9.0.2", 6881)                  # BitTorrent port rule
    call = ("udp", "10.0.0.10", 40002, "10.9.0.2", 3478)
    c = _heur_ctl(monkeypatch, {tv: _flow(tv, (0, 22_000_000)), bt: _flow(bt, (0, 1000)), call: _flow(call, (0, 1000))})
    monkeypatch.setattr(C, "HEUR_SIZE_ACTS", False)
    c.classify(100.0)
    assert c.flows[tv]["tin"] == 2 and not any("12" in m and "0x1" in m for m in c.marks)
    # merged scheme: the port rule's verdict is bulk, but the Bulk tin is entered only by an explicit override
    assert c.flows[bt]["cls"] == "bulk" and c.flows[bt]["tin"] == 2
    assert c.flows[tv]["cls"] == "other"
    assert c.flows[call]["tin"] == 4


def test_size_verdict_can_be_re_enabled_for_diagnostics(monkeypatch, state_dir):
    tv = ("tcp", "10.0.0.12", 40000, "10.9.0.2", 443)
    c = _heur_ctl(monkeypatch, {tv: _flow(tv, (0, 22_000_000))})
    monkeypatch.setattr(C, "HEUR_SIZE_ACTS", True)
    c.classify(100.0)
    assert c.flows[tv]["cls"] == "bulk" and c.flows[tv]["tin"] == 2      # verdict acted on, but no auto Bulk tin (lease)
    monkeypatch.setattr(C.policy, "AUTO_BULK_TIN", True)                 # the old demotion needs both switches
    c.flows[tv].update(cls="other", p=0.0, abstain=True)
    c.classify(101.0)
    assert c.flows[tv]["tin"] == 1


def test_voice_cap_demotion_needs_a_sustained_overshoot_and_is_reversible(monkeypatch, state_dir):
    """R2 (M4): a congestion episode cuts the shaped rate to ~3 Mbit for ~1 s; the 25 % Voice cap (0.75 Mbit) is then below
    a 1.5 Mbit call. That transient must not move the call into Best Effort (it did, permanently: call p95 +470 ms)."""
    call = ("udp", "10.0.0.10", 40002, "10.9.0.2", 3478)
    f = _flow(call, (0, 1000))
    f["rate"] = (0.0, 1.5)
    c = _heur_ctl(monkeypatch, {call: f})
    c.est["dl"].rate = 3.0
    for t in (100.0, 101.0, 102.0):                    # < VOICE_CAP_GRACE_S of overshoot
        c.classify(t)
        assert c.flows[call]["tin"] == 4 and not c.flows[call].get("capdem")
    c.est["dl"].rate = 9.0                             # episode over: budget 2.25 Mbit >= 1.5, timer resets
    c.classify(103.0)
    assert c.flows[call]["over_since"] is None
    c.est["dl"].rate = 3.0                             # a sustained shortage still demotes (shield invariant kept)
    for t in (104.0, 105.0, 106.0, 107.5):
        c.classify(t)
    assert c.flows[call].get("capdem") and any(k == "shield_voice_cap" for k, _ in c.events)
    c.classify(108.0)
    assert c.flows[call]["tin"] == 2
    c.est["dl"].rate = 9.0                             # and it is reversible
    c.classify(109.0)
    c.classify(110.0)
    assert not c.flows[call]["capdem"] and c.flows[call]["tin"] == 4


def test_drain_moves_the_call_to_video_and_back(monkeypatch, state_dir):
    """R2 (M4): while a drain holds the shaper near 0.3 x capacity the call rides in Video (50 % threshold), then returns."""
    call = ("udp", "10.0.0.10", 40002, "10.9.0.2", 3478)
    f = _flow(call, (0, 1000))
    f["rate"] = (0.0, 1.5)
    c = _heur_ctl(monkeypatch, {call: f})
    c.flock = threading.Lock()
    c.est["dl"].rate = 47.5
    c.classify(100.0)
    assert c.flows[call]["tin"] == 4 and c.voice_dl == 1.5
    c.marks.clear()
    c.voice_to_video(101.0)
    assert c.flows[call]["tin"] == 3 and c.vid_on
    assert any("destroy element" in m for m in c.marks) and any("0x3" in m or " 3 " in m or ": 3" in m for m in c.marks)
    c.est["dl"].rate = 3.5                                              # drain: 25 % = 0.9 Mbit < the call; must not demote
    for t in (102.0, 103.0, 104.0, 105.0, 106.0, 107.0):
        c.classify(t)
        assert c.flows[call]["tin"] == 3 and not c.flows[call].get("capdem")
    c.est["dl"].rate = 9.0
    c.video_to_voice(108.0)
    assert c.flows[call]["tin"] == 4 and not c.vid_on
    c.classify(109.0)
    assert c.flows[call]["tin"] == 4


def _many_ctl(rate=19.0):
    from halo.estimator import DirEstimator, EstParams
    c = object.__new__(C.Ctl)
    c.a = types.SimpleNamespace(plan_dl=20.0)
    c.lim = C.policy.Limits(r_max_dl=20.0)
    c.est = {"dl": DirEstimator(EstParams(r_min=2.0, r_max=19.0), rate=rate, behind=True)}
    c.dev, c.last_action, c.events, c.sets = {"dl": "lan0"}, {"dl": 0.0}, [], []
    c.event = lambda kind, **kw: c.events.append((kind, kw))
    c.enf = types.SimpleNamespace(set_rate=lambda dev, r: c.sets.append((dev, r)))
    return c


def test_many_flows_lowers_the_ceiling_with_hysteresis():
    """R2 (M3): 32 concurrent bulk flows overshoot the modem FIFO upstream of the shaper; the ceiling drops to MANY_FLOWS_MARGIN x 19."""
    c = _many_ctl()
    c.n_bulk = 8                                         # S1 (6-8 flows): nothing changes
    c.many_flows_cap(10.0)
    assert c.est["dl"].p.r_max == 19.0 and not c.sets
    c.n_bulk = 32
    c.many_flows_cap(11.0)
    assert abs(c.est["dl"].p.r_max - 19.0 * C.MANY_FLOWS_MARGIN) < 1e-9
    assert c.sets and abs(c.sets[-1][1] - 19.0 * C.MANY_FLOWS_MARGIN) < 0.01 and c.est["dl"].rate == c.sets[-1][1]
    n_sets = len(c.sets)
    c.n_bulk = 14                                        # between the on and off thresholds: hysteresis keeps it
    c.many_flows_cap(12.0)
    assert c.est["dl"].p.r_max < 19.0 and len(c.sets) == n_sets
    c.n_bulk = 3
    c.many_flows_cap(13.0)                               # < 4 s since the last >= 12-flow evidence: still on
    c.many_flows_cap(15.0)
    assert c.est["dl"].p.r_max < 19.0
    assert c.est["dl"].p.r_max < 19.0
    c.many_flows_cap(17.0)
    assert c.est["dl"].p.r_max == 19.0                   # restored; the estimator's own probe climbs back


def test_n_bulk_keeps_flows_counted_between_the_first_and_second_conntrack_poll(monkeypatch, state_dir):
    """int2 (M3 x event-driven slow loop): polls are GUARD_POLL_S apart and a rate needs two of them. A flow older than
    GUARD_POLL_S with no rate yet must still count (S1x32 had n 33 -> 0 -> 32, releasing the M3 ceiling for ~1 s); a flow
    that was measured idle, or never measured for over 2 polls, must not."""
    flows = {}
    for i in range(32):
        k = ("tcp", "10.0.0.12", 40000 + i, "10.9.0.2", 5201)
        f = _flow(k, (0, 0), now=100.0)
        f["t0"] = f["seen"] = 100.0 - 7.0                                 # 7 s old, one poll seen, no rate yet
        flows[k] = f
    c = _heur_ctl(monkeypatch, flows)
    c.classify(100.0)
    assert c.n_bulk == 32
    for f in flows.values():                                              # second poll: measured and moving
        f["rate"], f["seen"] = (0.0, 0.5), 100.0
    c.classify(100.0)
    assert c.n_bulk == 32
    c.classify(100.0 + C.GUARD_POLL_S + 2.0)                              # nothing moved for > one poll period
    assert c.n_bulk == 0
    for f in flows.values():
        f.pop("rate")
        f["t0"], f["seen"] = 100.0 - 20.0, 100.0 - 20.0                   # never measured and far older than 2 polls
    c.classify(100.0)
    assert c.n_bulk == 0
