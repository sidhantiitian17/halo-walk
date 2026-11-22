"""M5 policy engine + safety shield (halo/policy.py): every invariant -> clip or reject.

Property tests use hypothesis (installed); a few parametrised cases pin the exact reason strings.
"""
import pytest
from hypothesis import assume, given, settings, strategies as st

from halo import policy
from halo.policy import Limits, admit_voice, shield_lease, shield_policy, shield_rate, tin_for

LIM = Limits()
rates = st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False)
pos_rates = st.floats(min_value=0.5, max_value=200.0, allow_nan=False, allow_infinity=False)


# --------------------------------------------------------------------------- shield_rate
@settings(max_examples=400, deadline=None)
@given(new=rates, cur=pos_rates, emergency=st.booleans())
def test_shield_rate_result_always_in_bounds(new, cur, emergency):
    v = shield_rate(new, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=emergency)
    assert v.ok
    assert LIM.r_min_dl <= v.value <= LIM.r_max_dl


@settings(max_examples=400, deadline=None)
@given(new=rates, cur=st.floats(min_value=2.0, max_value=100.0), emergency=st.booleans())
def test_shield_rate_max_up_step(new, cur, emergency):
    v = shield_rate(new, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=emergency)
    # never more than +10 % per action, even in an emergency (r_min floor aside)
    assert v.value <= max(LIM.r_min_dl, round(cur * (1 + LIM.max_up_step), 3)) + 1e-9


@settings(max_examples=400, deadline=None)
@given(new=rates, cur=st.floats(min_value=4.0, max_value=100.0))
def test_shield_rate_max_down_step_non_emergency(new, cur):
    v = shield_rate(new, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=False)
    assert v.value >= min(round(cur * (1 - LIM.max_down_step), 3), LIM.r_max_dl) - 1e-9


@settings(max_examples=200, deadline=None)
@given(new=st.floats(min_value=0.0, max_value=10.0), cur=st.floats(min_value=20.0, max_value=100.0))
def test_shield_rate_emergency_may_cut_deep(new, cur):
    """fast-down is exempt from the max-down-step (it must be able to drain a queue), but not from r_min"""
    v = shield_rate(new, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=True)
    assert v.value == pytest.approx(max(LIM.r_min_dl, new), abs=1e-3)
    assert "clip_down_step" not in v.reasons


@settings(max_examples=200, deadline=None)
@given(new=rates, cur=pos_rates, gap=st.floats(min_value=0.0, max_value=LIM.min_action_gap - 1e-3))
def test_shield_rate_action_rate_limit_rejects(new, cur, gap):
    v = shield_rate(new, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=False, since_last=gap)
    assert not v.ok and v.value == cur and v.reasons == ["action_rate_limit"]


def test_shield_rate_action_rate_limit_not_for_emergency():
    v = shield_rate(10.0, 50.0, 2.0, 100.0, LIM, emergency=True, since_last=0.0)
    assert v.ok and v.value == 10.0


@pytest.mark.parametrize("new,cur,emerg,value,reason", [
    (200.0, 95.0, False, 100.0, "clip_r_max"),
    (200.0, 50.0, False, 55.0, "clip_up_step"),
    (10.0, 50.0, False, 25.0, "clip_down_step"),
    (0.1, 3.0, False, 2.0, "clip_r_min"),
    (0.1, 50.0, True, 2.0, "clip_r_min"),
    (48.0, 50.0, False, 48.0, None),
])
def test_shield_rate_reasons(new, cur, emerg, value, reason):
    v = shield_rate(new, cur, 2.0, 100.0, LIM, emergency=emerg)
    assert v.ok and v.value == pytest.approx(value)
    if reason:
        assert reason in v.reasons
    else:
        assert v.reasons == []


def test_shield_rate_never_raises_on_odd_input():
    assert shield_rate("42", 40.0, 2.0, 100.0, LIM).ok


# --------------------------------------------------------------------------- shield_lease
def lease(owner="a", ttl=600, cls="call", device="10.0.0.2"):
    return {"device": device, "ttl": ttl, "owner": owner, "cls": cls}


@settings(max_examples=300, deadline=None)
@given(ttl=st.integers(min_value=-10_000, max_value=100_000))
def test_lease_ttl_bounds(ttl):
    v = shield_lease(lease(ttl=ttl), [], LIM)
    assert v.ok == (1 <= ttl <= LIM.max_lease_ttl)
    if not v.ok:
        assert any(r.startswith("ttl_out_of_bounds") for r in v.reasons)


def test_lease_max_concurrent():
    active = [lease(owner="x"), lease(owner="y")]
    v = shield_lease(lease(owner="z"), active, LIM)
    assert not v.ok and "max_concurrent_leases(2)" in v.reasons


def test_lease_one_per_owner():
    v = shield_lease(lease(owner="a"), [lease(owner="a")], LIM)
    assert not v.ok and "owner_quota" in v.reasons
    assert shield_lease(lease(owner="b"), [lease(owner="a")], LIM).ok


@pytest.mark.parametrize("cls,ok", [("call", True), ("gaming", True), ("streaming", False), ("bulk", False), ("other", False)])
def test_lease_only_interactive(cls, ok):
    v = shield_lease(lease(cls=cls), [], LIM)
    assert v.ok is ok
    if not ok:
        assert "only_interactive_boost" in v.reasons


@settings(max_examples=300, deadline=None)
@given(n_active=st.integers(0, 4), same_owner=st.booleans(), ttl=st.integers(-5, 10_000),
       cls=st.sampled_from(policy.CLASSES))
def test_lease_admission_property(n_active, same_owner, ttl, cls):
    active = [lease(owner="o%d" % i) for i in range(n_active)]
    req = lease(owner="o0" if same_owner and n_active else "new", ttl=ttl, cls=cls)
    v = shield_lease(req, active, LIM)
    expected = (1 <= ttl <= LIM.max_lease_ttl and n_active < LIM.max_leases
                and not (same_owner and n_active) and cls in policy.INTERACTIVE)
    assert v.ok == expected
    assert v.ok == (v.reasons == [])


# --------------------------------------------------------------------------- shield_policy
@pytest.mark.parametrize("mode", ["diffserv3", "besteffort", "precedence", "diffserv8"])
def test_policy_bulk_tin_never_removed(mode):
    v = shield_policy({"tin_mode": mode}, LIM)
    assert not v.ok and any("bulk tin never removed" in r for r in v.reasons)


def test_policy_accepts_valid():
    v = shield_policy({"tin_mode": "diffserv4", "rate_dl": 50.0, "rate_ul": 10.0, "promote_p": 0.95, "autorate": 1}, LIM)
    assert v.ok and v.reasons == []


@settings(max_examples=300, deadline=None)
@given(dl=st.floats(-10, 300, allow_nan=False), ul=st.floats(-10, 50, allow_nan=False))
def test_policy_rate_bounds(dl, ul):
    v = shield_policy({"rate_dl": dl, "rate_ul": ul}, LIM)
    ok = LIM.r_min_dl <= dl <= LIM.r_max_dl and LIM.r_min_ul <= ul <= LIM.r_max_ul
    assert v.ok == ok


@settings(max_examples=200, deadline=None)
@given(pp=st.floats(0.0, 2.0, allow_nan=False))
def test_policy_promote_p_bounds(pp):
    assert shield_policy({"promote_p": pp}, LIM).ok == (0.5 <= pp <= 1.0)


def test_policy_unknown_fields_fail_closed():
    v = shield_policy({"rate_dl": 50.0, "max_up_step": 5.0}, LIM)
    assert not v.ok and any(r.startswith("unknown_fields") for r in v.reasons)


# --------------------------------------------------------------------------- tin mapping / never promote on doubt
def test_tin_numbers_match_cake_diffserv4():
    assert policy.TIN == {"bulk": 1, "other": 2, "streaming": 3, "call": 4, "gaming": 4}
    assert policy.TIN_NAME[1] == "Bulk" and policy.TIN_NAME[4] == "Voice"


@settings(max_examples=400, deadline=None)
@given(cls=st.sampled_from(policy.CLASSES + ("unknown",)), p=st.floats(0, 1), abstain=st.booleans(),
       promote_p=st.floats(0.5, 1.0))
def test_never_promote_on_doubt(cls, p, abstain, promote_p):
    tin = tin_for(cls, p, abstain, promote_p)
    if abstain or p < promote_p or cls not in policy.TIN or cls == "bulk":
        assert tin == policy.TIN["other"]           # classifier-decided bulk is not auto-demoted (AUTO_BULK_TIN off)
    else:
        assert tin == policy.TIN[cls]


def test_bulk_tin_only_on_explicit_override():
    """regression S3/S4: auto-demotion of ABR streams / bulk victims into the Bulk tin cost 20+ ms of game p99
    and pinned the victim to the 1/16 floor. An operator override (explicit) and auto_bulk=True still reach it."""
    assert policy.AUTO_BULK_TIN is False
    assert tin_for("bulk", 1.0, False, 0.9) == policy.TIN["other"]
    assert tin_for("bulk", 1.0, False, 0.9, explicit=True) == policy.TIN["bulk"] == 1
    assert tin_for("bulk", 1.0, False, 0.9, auto_bulk=True) == 1
    assert tin_for("bulk", 0.5, False, 0.9, explicit=True) == policy.TIN["other"]      # doubt still wins
    for c in ("call", "gaming", "streaming"):
        assert tin_for(c, 1.0, False, 0.9) == policy.TIN[c]


# --------------------------------------------------------------------------- Voice-tin admission
@settings(max_examples=300, deadline=None)
@given(flows=st.lists(st.tuples(st.integers(0, 10_000), st.floats(0, 30), st.floats(0, 1000)), max_size=20,
                      unique_by=lambda f: f[0]),
       rate=st.floats(2, 100))
def test_admit_voice_budget(flows, rate):
    keep, demote = admit_voice(flows, rate, LIM)
    by = {k: m for k, m, _ in flows}
    assert sum(by[k] for k in keep) <= LIM.voice_share * rate + 1e-9
    assert sorted(keep + demote) == sorted(by)


def test_admit_voice_demotes_newest_first():
    flows = [("old", 10.0, 1.0), ("new", 10.0, 5.0), ("mid", 10.0, 3.0)]
    keep, demote = admit_voice(flows, 100.0, LIM)             # budget 25 Mbit/s
    assert keep == ["old", "mid"] and demote == ["new"]


# --------------------------------------------------------------------------- restore_to (undo of a false alarm)
def test_restore_to_bypasses_up_step_clip():
    v = shield_rate(100.0, 70.0, 2.0, 100.0, LIM, emergency=True, restore_to=100.0)
    assert v.ok and v.value == 100.0 and "clip_up_step" not in v.reasons


def test_restore_to_other_value_still_clipped():
    v = shield_rate(100.0, 70.0, 2.0, 100.0, LIM, emergency=True, restore_to=90.0)
    assert v.value == pytest.approx(77.0) and "clip_up_step" in v.reasons


def test_restore_to_none_is_default_behaviour():
    assert shield_rate(100.0, 70.0, 2.0, 100.0, LIM).value == pytest.approx(77.0)


@settings(max_examples=300, deadline=None)
@given(target=st.floats(0.0, 500.0), cur=st.floats(1.0, 200.0), emergency=st.booleans(),
       gap=st.floats(0.0, 2.0))
def test_restore_to_only_bypasses_up_step(target, cur, emergency, gap):
    """bounds, the down-step and the action-rate limit still apply when restoring"""
    v = shield_rate(target, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=emergency, since_last=gap,
                    restore_to=target)
    base = shield_rate(target, cur, LIM.r_min_dl, LIM.r_max_dl, LIM, emergency=emergency, since_last=gap)
    assert v.ok == base.ok
    if not v.ok:
        assert v.reasons == ["action_rate_limit"]
        return
    assert LIM.r_min_dl <= v.value <= LIM.r_max_dl
    assert "clip_up_step" not in v.reasons
    if "clip_up_step" not in base.reasons:
        assert v.value == base.value and v.reasons == base.reasons
    else:
        assert v.value == pytest.approx(min(LIM.r_max_dl, max(LIM.r_min_dl, target)), abs=1e-3)


def test_shield_rate_probe_may_climb_up_to_max_probe_step_but_no_more():
    v = shield_rate(100.0, 10.0, 2.0, 100.0, LIM, probe=True)
    assert v.ok and v.value == pytest.approx(10.0 * (1 + LIM.max_probe_step))
    assert "clip_up_step" in v.reasons
    v2 = shield_rate(12.0, 10.0, 2.0, 100.0, LIM, probe=True)
    assert v2.value == 12.0 and not v2.reasons


def test_shield_rate_non_probe_up_step_unchanged_by_probe_option():
    v = shield_rate(100.0, 10.0, 2.0, 100.0, LIM)
    assert v.value == pytest.approx(10.0 * (1 + LIM.max_up_step))
    v = shield_rate(100.0, 10.0, 2.0, 100.0, LIM, emergency=True)
    assert v.value == pytest.approx(10.0 * (1 + LIM.max_up_step))


def test_shield_rate_probe_never_exceeds_bounds_or_rate_limit():
    v = shield_rate(500.0, 90.0, 2.0, 100.0, LIM, probe=True)
    assert v.value == 100.0
    v = shield_rate(20.0, 10.0, 2.0, 100.0, LIM, probe=True, since_last=0.1)
    assert not v.ok and v.value == 10.0


def test_voice_floor_keeps_a_call_inside_its_tin_threshold_during_a_drain():
    from halo.policy import voice_floor
    lim = Limits()
    assert voice_floor(2.0, 0.0, 10.0, lim) == 2.0                       # no promoted flow: no floor
    f = voice_floor(2.0, 1.5, 12.0, lim)                                 # Voice: 1.15 * 1.5 / 0.25 = 6.9
    assert abs(f - 6.9) < 1e-9 and 0.25 * f >= 1.5
    f = voice_floor(2.0, 1.5, 10.3, lim, lim.video_share)                # Video: 1.15 * 1.5 / 0.5 = 3.45
    assert abs(f - 3.45) < 1e-9 and 0.5 * f >= 1.5
    assert voice_floor(2.0, 1.5, 8.0, lim) == 0.7 * 8.0                  # never above 0.7 c_est: the queue must drain
    assert voice_floor(2.0, 0.1, 10.0, lim, lim.video_share) == 2.0      # tiny flow: the usual r_min dominates
