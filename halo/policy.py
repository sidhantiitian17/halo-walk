"""M5 - deterministic policy engine + safety shield (pure functions -> property-testable).

Tin numbers are CAKE diffserv4 `fwmark` values (sch_cake.c: mark 1=Bulk, 2=Best Effort, 3=Video, 4=Voice).
"""
from dataclasses import dataclass, field

TIN = {"bulk": 1, "other": 2, "streaming": 3, "call": 4, "gaming": 4}
TIN_NAME = {1: "Bulk", 2: "Best Effort", 3: "Video", 4: "Voice"}
INTERACTIVE = ("call", "gaming")
CLASSES = ("call", "gaming", "streaming", "bulk", "other")


# Automatic demotion of "bulk" flows into the CAKE Bulk tin is OFF (measured, see REPORT.md):
#  * S3/C3: the elephant rule put the 3 DASH TVs in Bulk -> game p99 +35 ms (vs +13.7 ms with the TVs in Best
#    Effort, same seeds) and the TVs got 2-3 instead of 4.8 Mbit/s. The Bulk tin runs CoDel with the *tin's* 1/16
#    threshold rate (target 15 ms / interval 110 ms), so a tin that carries real traffic builds a standing queue.
#  * S4/C4: the ML-"bulk" victim got exactly the 1/16 floor (~1.2 Mbit/s = one 128 KB block per second).
# Best Effort already gives per-host fairness (dual-dsthost); the Bulk tin stays in the qdisc (shield: tin_mode)
# and stays reachable by an explicit operator override (/v1/overrides cls=bulk), which passes explicit=True.
AUTO_BULK_TIN = False

# the Voice-tin share cap (admit_voice) demotes a flow only after being exceeded this long without a break
VOICE_CAP_GRACE_S = 3.0


# many concurrent bulk flows (>= MANY_FLOWS_N active TCP flows): the shaper's ceiling drops from 0.95 to
# 0.95 x MANY_FLOWS_MARGIN of the plan rate (0.85: 16.15 of a 20 Mbit plan; 0.90 left the median at 10.6 ms, see REPORT)
MANY_FLOWS_N = 16
MANY_FLOWS_MARGIN = 0.85

VOICE_FLOOR_MARGIN = 1.15     # headroom over the promoted flows' own rate when sizing the drain floor
VOICE_FLOOR_MAX_FRAC = 0.70   # never hold the drain rate above this fraction of the capacity estimate (the queue must drain)


def voice_floor(r_min, voice_mbps, c_est, lim: "Limits", share=None):
    """lowest rate a congestion DRAIN may cut to while promoted flows carry `voice_mbps`.
    CAKE serves a priority tin at priority only while it is within its threshold: voice_share (25 %) of the shaped rate
    for Voice, video_share (50 %) for Video. A deep cut (0.3 x capacity) puts a 1.5 Mbit call far above 25 % of 3 Mbit; the
    call is then rationed to the threshold behind the saturating Best-Effort flows and its delay grows by the second until
    the rate is raised (S2: call p95 +470 ms). The drain rate is floored at voice / share (+margin) for the tin the flow
    sits in (the controller moves the call to Video for the drain, see Ctl.voice_to_video), but never above
    VOICE_FLOOR_MAX_FRAC x c_est, so that the standing queue still drains."""
    share = lim.voice_share if share is None else share
    if voice_mbps <= 0 or share <= 0:
        return r_min
    need = VOICE_FLOOR_MARGIN * voice_mbps / share
    return max(r_min, min(need, VOICE_FLOOR_MAX_FRAC * c_est))


def tin_for(cls, p, abstain, promote_p=0.9, explicit=False, auto_bulk=None):
    """never promote on doubt: a flow leaves Best Effort only with calibrated p >= promote_p.
    A classifier-decided "bulk" is not demoted to the Bulk tin unless AUTO_BULK_TIN (an explicit override is)."""
    if abstain or cls not in TIN or p < promote_p:
        return TIN["other"]
    if cls == "bulk" and not explicit and not (AUTO_BULK_TIN if auto_bulk is None else auto_bulk):
        return TIN["other"]
    return TIN[cls]


@dataclass
class Limits:
    r_min_dl: float = 2.0
    r_max_dl: float = 100.0
    r_min_ul: float = 0.5
    r_max_ul: float = 20.0
    max_down_step: float = 0.50       # non-emergency: at most -50 % per action
    max_up_step: float = 0.10         # at most +10 % per action
    max_probe_step: float = 0.50      # the estimator's own capacity probe (slow_up, no bloat seen) may climb +50 % per action
    min_action_gap: float = 0.5       # s between non-emergency rate actions
    voice_share: float = 0.25         # CAKE Voice-tin threshold (tc-cake(8))
    video_share: float = 0.50         # CAKE Video-tin threshold
    max_leases: int = 2
    max_lease_ttl: int = 7200
    leases_per_owner: int = 1
    tin_mode: str = "diffserv4"       # the Bulk tin can never be removed


@dataclass
class Verdict:
    ok: bool
    value: object
    reasons: list = field(default_factory=list)


def shield_rate(new, cur, lim_min, lim_max, lim: Limits, emergency=False, since_last=1e9, restore_to=None, probe=False):
    """clip a candidate shaper rate to the safe set; never raises.
    restore_to: a previously committed rate (undo of a false alarm) may be restored in one step.
    probe: the candidate is a capacity probe by the estimator (clean arrival, no bloat); it may climb up to
    max_probe_step per action instead of max_up_step, so that a 5x capacity increase is found in seconds, not minutes.
    Probes stay bounded (+50 %/action, one action per min_action_gap) and a bloat vote cuts them again at once."""
    reasons = []
    r = float(new)
    if not emergency and since_last < lim.min_action_gap:
        return Verdict(False, cur, ["action_rate_limit"])
    up = lim.max_probe_step if probe else lim.max_up_step
    if r > cur * (1 + up) and not (restore_to is not None and abs(r - restore_to) < 1e-6):
        r = cur * (1 + up); reasons.append("clip_up_step")
    if not emergency and r < cur * (1 - lim.max_down_step):
        r = cur * (1 - lim.max_down_step); reasons.append("clip_down_step")
    if r < lim_min:
        r = lim_min; reasons.append("clip_r_min")
    if r > lim_max:
        r = lim_max; reasons.append("clip_r_max")
    return Verdict(True, round(r, 3), reasons)


def shield_lease(req, active, lim: Limits):
    """admit / reject an intent lease. req: {device, ttl, owner, cls}; active: list of leases."""
    reasons = []
    ttl = int(req.get("ttl", 0))
    if ttl <= 0 or ttl > lim.max_lease_ttl:
        reasons.append("ttl_out_of_bounds(1..%d)" % lim.max_lease_ttl)
    if len(active) >= lim.max_leases:
        reasons.append("max_concurrent_leases(%d)" % lim.max_leases)
    if sum(1 for l in active if l.get("owner") == req.get("owner")) >= lim.leases_per_owner:
        reasons.append("owner_quota")
    if req.get("cls", "call") not in INTERACTIVE:
        reasons.append("only_interactive_boost")
    return Verdict(not reasons, req, reasons)


def shield_policy(pol, lim: Limits):
    """structural policy candidate (used by the two-phase transaction)."""
    reasons = []
    if pol.get("tin_mode", lim.tin_mode) != lim.tin_mode:
        reasons.append("tin_mode_must_be_diffserv4(bulk tin never removed)")
    for k, lo, hi in (("rate_dl", lim.r_min_dl, lim.r_max_dl), ("rate_ul", lim.r_min_ul, lim.r_max_ul)):
        if k in pol and pol[k] is not None and not (lo <= float(pol[k]) <= hi):
            reasons.append("%s_out_of_bounds[%s,%s]" % (k, lo, hi))
    pp = pol.get("promote_p")
    if pp is not None and not (0.5 <= float(pp) <= 1.0):
        reasons.append("promote_p_out_of_bounds")
    unknown = set(pol) - {"tin_mode", "rate_dl", "rate_ul", "promote_p", "autorate", "note", "force"}
    if unknown:
        reasons.append("unknown_fields:%s" % sorted(unknown))     # fail closed
    return Verdict(not reasons, pol, reasons)


def admit_voice(flows, rate_dl, lim: Limits):
    """keep promoted (Voice-tin) load <= voice_share * rate; demote newest first. flows: [(key, mbps, t_promoted)]"""
    budget = lim.voice_share * rate_dl
    keep, demote, used = [], [], 0.0
    for key, mbps, _ in sorted(flows, key=lambda f: f[2]):
        if used + mbps <= budget:
            keep.append(key); used += mbps
        else:
            demote.append(key)
    return keep, demote
