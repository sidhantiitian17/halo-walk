"""M6 enforcer (halo/enforcer.py) + the controller's two-phase transaction (halo/controller.py).

No tc/nft is executed: halo.enforcer.sh is replaced by tests_halo.conftest.FakeKernel, which records
the rendered commands and emulates read-back. Inputs: rates / leases / overrides.
Outputs: tc + nft command text. Failure handling: read-back mismatch -> rollback to LKG; tc failure -> safe state.
"""
import argparse, json, os, re

import pytest

from halo import enforcer as E
from halo.enforcer import LAN, WAN, Enforcer


@pytest.fixture
def enf(fake_sh, state_dir):
    return Enforcer()


# --------------------------------------------------------------------------- rendering
def test_cake_cmd_rendering():
    assert E.cake_cmd("lan0", "replace", 95.5, "diffserv4") == \
        "tc qdisc replace dev lan0 root handle 1: cake bandwidth 95500kbit diffserv4"


def test_install_egress_cake_lines(enf, fake_sh):
    enf.install(95.0, 19.0, marks=True)
    dl = fake_sh.matching(r"^tc qdisc replace dev %s root .*cake" % LAN)
    ul = fake_sh.matching(r"^tc qdisc replace dev %s root .*cake" % WAN)
    assert len(dl) == 1 and len(ul) == 1
    for line in dl + ul:
        assert "diffserv4" in line
        assert "fwmark 0x0f" in line                    # tin selected from the low nibble of the fwmark
    assert "bandwidth 95000kbit" in dl[0] and "bandwidth 19000kbit" in ul[0]
    # download is shaped on the LAN egress (lab "Mode L"): ingress keyword compensates for the
    # upstream bottleneck, per-host fairness on the destination
    assert "ingress" in dl[0] and "dual-dsthost" in dl[0]
    assert "dual-srchost" in ul[0] and "ack-filter" in ul[0]
    assert enf.rate == {LAN: 95.0, WAN: 19.0}


def test_install_ingress_path_is_lan_egress_mode(enf, fake_sh):
    """the implementation uses LAN-egress shaping (Mode L), not IFB+ctinfo: no qdisc on ifb, no ctinfo action;
    the per-flow mark comes from nftables `ct mark set meta mark` and the fw filter only mirrors sampled pkts."""
    enf.install(50.0, 10.0, marks=True)
    cmds = fake_sh.cmds()
    assert not any(E.IFB in c for c in cmds)
    mirror = fake_sh.matching(r"tc filter add dev \S+ egress .*fw action mirred egress mirror dev %s" % E.MON)
    assert len(mirror) == 2 and "handle 0x100/0x100" in mirror[0]
    nft = [i for i in fake_sh.inputs() if "table inet halo" in i][0]
    assert "ct mark set meta mark" in nft
    assert "ct packets < %d" % (E.SAMPLE_PKTS + 1) in nft
    for s in ("intent_mac", "intent_v4", "intent_v6"):
        assert re.search(r"set %s\s+\{[^}]*flags timeout" % s, nft)       # leases expire in the kernel
    assert 'iifname "lan0"' in nft and "%(" not in nft                  # template fully rendered


def test_install_without_marks_skips_nft(enf, fake_sh):
    enf.install(50.0, 10.0, marks=False)
    assert not any(c.startswith("nft") for c in fake_sh.cmds())
    assert len(fake_sh.matching(r"cake bandwidth")) == 2


def test_set_rate_uses_qdisc_change(enf, fake_sh):
    enf.install(95.0, 19.0, marks=False)
    fake_sh.calls.clear()
    enf.set_rate(LAN, 42.5)
    assert fake_sh.cmds() == ["tc qdisc change dev lan0 root cake bandwidth 42500kbit"]
    assert enf.rate[LAN] == 42.5
    assert enf.read_rate(LAN) == pytest.approx(42.5)


def test_flow_element_rendering_v4_v6():
    assert Enforcer.flow_element(("udp", "10.0.0.2", 5000, "198.51.100.1", 3478), 4, ttl=30) == \
        "add element inet halo flow4 { udp . 10.0.0.2 . 5000 . 198.51.100.1 . 3478 timeout 30s : 0x4 }"
    assert Enforcer.flow_element(("tcp", "fd00::2", 5000, "2001:db8::1", 443), 1).startswith(
        "add element inet halo flow6 { tcp . fd00::2")
    assert Enforcer.flow_delete(("tcp", "fd00::2", 1, "2001:db8::1", 2)).startswith("delete element inet halo flow6")


def test_add_lease_one_atomic_batch(enf, fake_sh):
    enf.add_lease("02:00:00:00:00:01", ["10.0.0.2", "fd00::2"], 600)
    assert fake_sh.cmds() == ["nft -f -"]
    lines = fake_sh.inputs()[0].strip().splitlines()
    # kernel timeout = TTL - LEASE_TTL_MARGIN_S: the element may expire early, never late
    assert lines == ["add element inet halo intent_mac { 02:00:00:00:00:01 timeout 599s }",
                     "add element inet halo intent_v4 { 10.0.0.2 timeout 599s }",
                     "add element inet halo intent_v6 { fd00::2 timeout 599s }"]


@pytest.mark.parametrize("ttl", [1, 2, 3, 16, 600, 7200])
def test_lease_kernel_timeout_never_exceeds_ttl(ttl):
    k = E.lease_timeout(ttl)
    assert 1 <= k <= ttl and (ttl < 2 or k == ttl - E.LEASE_TTL_MARGIN_S)


def test_lease_boost_is_a_budget_not_a_blank_cheque(enf, fake_sh):
    """regression S4: an unmetered `mark set 0x4` let a leased device push 7-8 Mbit/s of bulk into the Voice tin
    and starve the Bulk tin. Every lease mark rule must be metered per device, and udp and non-udp separately."""
    enf.install(20.0, 4.0, marks=True)
    nft = [i for i in fake_sh.inputs() if "table inet halo" in i][0]
    rules = [l for l in nft.splitlines() if "@intent_" in l]
    assert len(rules) == 6                                   # (udp, other) x (ul mac, dl v4, dl v6)
    for r in rules:
        assert "meter lease_" in r and "limit rate" in r and "meta mark set 0x4" in r
        assert re.search(r"limit rate \d+ kbytes/second burst \d+ kbytes", r)
    assert sum("l4proto udp" in r for r in rules) == 3 and sum("l4proto != udp" in r for r in rules) == 3
    # the budget fits inside CAKE's Voice share at the test rates (25 % of 20 Mbit/s = 625 kB/s) and the
    # non-realtime budget is a small fraction of it
    assert E.LEASE_UDP_DL * 8 / 1000 <= 0.25 * 20 and E.LEASE_OTHER_DL < E.LEASE_UDP_DL
    assert "%(" not in nft


def test_nft_batch_falls_back_line_by_line(enf, fake_sh):
    fake_sh.fail = r"BAD"
    enf.nft_batch(["add element inet halo flow4 { good }", "add element inet halo flow4 { BAD }"])
    assert fake_sh.cmds() == ["nft -f -"] * 3       # batch, then each line on its own
    assert fake_sh.inputs()[1] == "add element inet halo flow4 { good }\n"


def test_override_device_replaces_element(enf, fake_sh):
    enf.override_device("10.0.0.7", 1, 300)
    # one atomic nft transaction: destroy (delete-if-present) + add
    assert fake_sh.inputs()[-1].strip().splitlines() == [
        "destroy element inet halo dev4 { 10.0.0.7 }",
        "add element inet halo dev4 { 10.0.0.7 timeout 300s : 0x1 }"]


def test_leases_parse(enf):
    assert enf.leases() == [{"mac": "02:00:00:00:00:01", "expires_s": 42}]


# --------------------------------------------------------------------------- safe state
FLUSH_SETS = ("intent_mac", "intent_v4", "intent_v6")
FLUSH_MAPS = ("flow4", "flow6", "dev4", "dev6")


def test_safe_state_one_tc_batch_one_nft_transaction(fake_sh, state_dir):
    E.safe_state(8.0, 1.6)
    assert fake_sh.cmds() == ["tc -batch -", "nft -f -"]            # exactly two process spawns
    tcb = fake_sh.calls[0][1].strip().splitlines()
    assert len(tcb) == 2
    dl = [l for l in tcb if l.startswith("qdisc replace dev lan0 root handle 1: cake")][0]
    ul = [l for l in tcb if l.startswith("qdisc replace dev wan0 root handle 1: cake")][0]
    assert "bandwidth 8000kbit" in dl and "diffserv4" in dl and "dual-dsthost" in dl and "ingress" in dl
    assert "bandwidth 1600kbit" in ul and "diffserv4" in ul and "dual-srchost" in ul
    assert "fwmark" not in dl + ul                  # static: does not depend on controller marks
    nft = fake_sh.calls[1][1].strip().splitlines()
    assert sorted(nft) == sorted(["flush set inet halo %s" % x for x in FLUSH_SETS] +
                                 ["flush map inet halo %s" % x for x in FLUSH_MAPS])
    assert fake_sh.qdisc["lan0"]["mbit"] == 8.0 and fake_sh.qdisc["wan0"]["mbit"] == 1.6
    rec = json.load(open(os.path.join(state_dir, "safe.json")))
    assert rec["rate_dl"] == 8.0 and rec["rate_ul"] == 1.6


def test_safe_state_fallback_when_batches_raise(fake_sh, state_dir):
    """batch failure -> per-command fallback with check=False: every step is still attempted"""
    fake_sh.fail = r"^(tc -batch -|nft -f -)"
    E.safe_state(8.0, 1.6)
    cmds = fake_sh.cmds()
    assert cmds[0] == "tc -batch -"
    dl = [c for c in cmds if c.startswith("tc qdisc replace dev lan0")]
    ul = [c for c in cmds if c.startswith("tc qdisc replace dev wan0")]
    assert len(dl) == 1 and "diffserv4" in dl[0] and "bandwidth 8000kbit" in dl[0]
    assert len(ul) == 1 and "diffserv4" in ul[0] and "bandwidth 1600kbit" in ul[0]
    assert "nft -f -" in cmds
    for x in FLUSH_SETS:
        assert "nft flush set inet halo %s" % x in cmds
    for x in FLUSH_MAPS:
        assert "nft flush map inet halo %s" % x in cmds
    assert fake_sh.qdisc["lan0"]["mbit"] == 8.0                     # fallback really applied the rate
    assert os.path.exists(os.path.join(state_dir, "safe.json"))


def test_safe_state_tolerates_total_failure(fake_sh, state_dir):
    """even if the fallback commands fail too, safe_state finishes and records the safe state"""
    fake_sh.fail = r"."
    E.safe_state(8.0, 1.6)
    assert len(fake_sh.matching(r"^nft flush")) == 7
    assert os.path.exists(os.path.join(state_dir, "safe.json"))


# --------------------------------------------------------------------------- checkpoint / read-back / rollback
def test_commit_writes_lkg(enf, fake_sh, state_dir):
    enf.install(95.0, 19.0, marks=False)
    h = enf.commit({"autorate": True})
    lkg = json.load(open(os.path.join(state_dir, "lkg.json")))
    assert lkg["hash"] == h and lkg["rate"] == {LAN: 95.0, WAN: 19.0}
    assert "cake" in lkg["tc"][LAN]


def test_verify_applied_ok_and_mismatch(enf, fake_sh):
    enf.install(95.0, 19.0, marks=False)
    assert enf.verify_applied({LAN: 95.0, WAN: 19.0}) == []
    fake_sh.ignore_change = True
    enf.set_rate(LAN, 40.0)                          # kernel silently keeps 95
    bad = enf.verify_applied({LAN: 40.0, WAN: 19.0})
    assert bad == [(LAN, 40.0, pytest.approx(95.0))]


def test_apply_mismatch_rollback_to_lkg(enf, fake_sh, state_dir):
    enf.install(95.0, 19.0, marks=False)
    enf.commit()
    fake_sh.ignore_change = True
    enf.set_rate(LAN, 40.0)
    enf.set_rate(WAN, 5.0)
    assert enf.verify_applied({LAN: 40.0, WAN: 5.0})
    fake_sh.ignore_change = False
    fake_sh.calls.clear()
    ok, dt, lkg = enf.rollback()
    assert ok and dt >= 0
    batch = [i for c, i in fake_sh.calls if c == "tc -batch -"][0]
    assert "qdisc change dev lan0 root handle 1: cake bandwidth 95000kbit " + Enforcer.DL_OPTS in batch  # in-place restore
    assert "qdisc change dev wan0 root handle 1: cake bandwidth 19000kbit " + Enforcer.UL_OPTS in batch
    assert enf.rate == {LAN: 95.0, WAN: 19.0}
    assert enf.rates_now() == {LAN: pytest.approx(95.0), WAN: pytest.approx(19.0)}


def test_rollback_from_disk_and_restore_nft(fake_sh, state_dir):
    a = Enforcer()
    a.install(80.0, 16.0, marks=False)
    fake_sh.nft_text = "table inet halo { set intent_mac { type ether_addr; } }"
    a.commit()
    b = Enforcer()                                   # fresh process: LKG only on disk
    b.set_rate(LAN, 30.0)
    ok, _, lkg = b.rollback(restore_nft=True)
    assert ok and b.rate == {LAN: 80.0, WAN: 16.0}
    nft_in = [i for c, i in fake_sh.calls if c == "nft -f -"][-1]
    assert nft_in.startswith("flush table inet halo\n") and "intent_mac" in nft_in


def test_rollback_reports_failure_when_readback_differs(enf, fake_sh):
    enf.install(95.0, 19.0, marks=False)
    enf.commit()
    fake_sh.fail = r"^tc -batch"                     # restore itself fails
    with pytest.raises(RuntimeError):
        enf.rollback()


# --------------------------------------------------------------------------- controller transaction (wiring)
def _ctl(tmp_path, fake_sh, state_dir, **kw):
    from halo import controller
    a = argparse.Namespace(plan_dl=100.0, plan_ul=20.0, rmin_dl=2.0, rmin_ul=0.5, safe_dl=8.0, safe_ul=1.6,
                           autorate=1, classifier="none", model=None, collect=False, promote_p=0.9,
                           voice_envelope=6.0, reflectors=[], probe_hz=20.0, tick=0.1, health_s=5.0,
                           out=str(tmp_path / "out"))
    vars(a).update(kw)
    from collections import deque
    c = controller.Ctl(a)
    c.ach_hist = deque(maxlen=600)
    return c


def _events(c):
    c.ev.flush()
    return [json.loads(l) for l in open(c.ev.name)]


def test_ctl_txn_readback_mismatch_rolls_back(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    lkg_rates = dict(c.enf.rate)
    assert lkg_rates == {LAN: 95.0, WAN: 19.0}
    # the shadow check needs `unshare -n` (root): inject its result and start at the SHADOW stage
    c.txn = {"stage": "SHADOW", "req": {"rate_dl": 40.0, "autorate": 0}, "cand": {LAN: 40.0, WAN: 19.0},
             "res": (True, ""), "t": 0.0}
    c.fsm = "VERIFYING"
    fake_sh.ignore_change = True                      # apply "succeeds" but kernel keeps the old rate
    c.finish_txn(100.0)                               # SHADOW -> apply -> read-back
    assert c.txn["stage"] == "HEALTH" and c.txn["bad"]
    assert c.autorate is False                        # candidate params applied ...
    fake_sh.ignore_change = False
    c.finish_txn(100.1)                               # ... read-back mismatch -> immediate rollback
    ev = _events(c)
    rb = [e for e in ev if e["kind"] == "rollback"]
    assert rb and rb[-1]["ok"] is True and rb[-1]["info"] == {"reason": "readback"}
    assert c.enf.rate == lkg_rates and c.enf.rates_now()[LAN] == pytest.approx(95.0)
    assert c.est["dl"].rate == 95.0
    assert c.autorate == 1 and c.promote_p == 0.9     # params restored from the LKG bundle
    assert c.fsm == "STEADY" and c.txn is None


def test_ctl_txn_commit_when_healthy(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    c.txn = {"stage": "SHADOW", "req": {"rate_dl": 60.0}, "cand": {LAN: 60.0, WAN: 19.0}, "res": (True, ""), "t": 0.0}
    c.finish_txn(10.0)
    assert c.txn["bad"] == []
    c.txn["t"] = 0.0
    c.finish_txn(10.0)                                # health window elapsed, no samples -> NEUTRAL -> commit
    ev = _events(c)
    assert ev[-1]["kind"] == "commit" and ev[-1]["verdict"] == "NEUTRAL"
    assert json.load(open(os.path.join(state_dir, "lkg.json")))["rate"][LAN] == 60.0


def test_ctl_shadow_check_failure_rejects(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    c.txn = {"stage": "SHADOW", "req": {"rate_dl": 60.0}, "cand": {LAN: 60.0, WAN: 19.0},
             "res": (False, "cake: unknown"), "t": 0.0}
    c.finish_txn(1.0)
    assert c.txn is None and c.enf.rate[LAN] == 95.0
    assert not fake_sh.matching(r"tc qdisc change")


def test_ctl_shield_rejects_bad_policy(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    c.start_txn({"tin_mode": "besteffort"}, 0.0)
    assert c.txn is None
    assert _events(c)[-1]["kind"] == "txn_rejected"


def test_ctl_rollback_failure_enters_safe_state(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    c.txn = {"stage": "SHADOW", "req": {"rate_dl": 40.0}, "cand": {LAN: 40.0, WAN: 19.0}, "res": (True, ""), "t": 0.0}
    fake_sh.ignore_change = True
    c.finish_txn(1.0)
    c.enf.rollback = lambda: (False, 0.01, c.enf.lkg)  # restore could not be verified
    c.finish_txn(1.1)
    assert c.fsm == "SAFE" and c.autorate is False
    nft = [i for cmd, i in fake_sh.calls if cmd == "nft -f -" and i and "flush" in i]
    assert nft and "flush set inet halo intent_mac" in nft[-1]


def test_ctl_repeated_rollbacks_degrade(tmp_path, fake_sh, state_dir):
    c = _ctl(tmp_path, fake_sh, state_dir)
    for i in range(4):
        c.txn = {"stage": "SHADOW", "req": {"rate_dl": 40.0}, "cand": {LAN: 40.0, WAN: 19.0}, "res": (True, ""), "t": 0.0}
        fake_sh.ignore_change = True
        c.finish_txn(10.0 + i)
        fake_sh.ignore_change = False
        c.finish_txn(10.0 + i)
    assert c.fsm == "DEGRADED" and c.autorate is False
