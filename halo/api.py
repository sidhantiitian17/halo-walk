#!/usr/bin/env python3
"""M4 - Intent / Override / Policy API (FastAPI). Runs in the gateway, bound to the LAN address only.
Auth: bearer token from the environment (HALO_API_TOKEN) - never from source control."""
import json, os, re, signal, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from halo import policy
from halo.enforcer import LAN, STATE_DIR, WAN, Enforcer, sh

app = FastAPI(title="HALO-Walk intent API", version="1.0")
enf, lim = Enforcer(), policy.Limits()
TOKEN = os.environ.get("HALO_API_TOKEN", "")
LEASES = os.path.join(STATE_DIR, "leases.json")
OVR = os.path.join(STATE_DIR, "overrides.json")
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def auth(authorization: str = Header(default="")):
    if not TOKEN or authorization != "Bearer " + TOKEN:
        raise HTTPException(401, "missing or invalid bearer token")


def load(p, d):
    try:
        return json.load(open(p))
    except Exception:
        return d


def save(p, o):
    os.makedirs(STATE_DIR, exist_ok=True)
    json.dump(o, open(p + ".tmp", "w")); os.replace(p + ".tmp", p)


def device_addrs(ip):
    """MAC of the device and every IPv4/IPv6 address the gateway has learnt for that MAC (privacy addresses too)"""
    neigh = sh("ip neigh show dev %s" % LAN, check=False)
    mac = None
    for l in neigh.splitlines():
        f = l.split()
        if f and f[0] == ip and "lladdr" in f:
            mac = f[f.index("lladdr") + 1]
    if not mac:
        return None, []
    ips = [l.split()[0] for l in neigh.splitlines() if mac in l and not l.startswith("fe80")]
    return mac, ips


class Intent(BaseModel):
    device: str = Field(..., description="LAN IPv4/IPv6 address of the device to protect")
    cls: str = "call"
    ttl: int = Field(3600, description="seconds; the kernel expires the lease")
    owner: str = "user"
    reason: str = ""


class Override(BaseModel):
    device: str | None = None
    flow: list | None = Field(None, description="[proto, lan_ip, lan_port, wan_ip, wan_port]")
    cls: str
    ttl: int = 600


class Policy(BaseModel):
    rate_dl: float | None = None
    rate_ul: float | None = None
    autorate: int | None = None
    promote_p: float | None = None
    tin_mode: str | None = None
    note: str | None = None


@app.get("/v1/health")
def health():
    hb = load(os.path.join(STATE_DIR, "safe.json"), None)
    try:
        age = time.time() - os.path.getmtime(os.path.join(STATE_DIR, "heartbeat"))
    except OSError:
        age = None
    return {"controller_heartbeat_age_s": age, "safe_state": hb}


@app.post("/v1/intents", status_code=201, dependencies=[Depends(auth)])
def add_intent(i: Intent):
    now = time.time()
    active = [l for l in load(LEASES, []) if l["expires_at"] > now]
    v = policy.shield_lease(i.model_dump(), active, lim)
    if not v.ok:
        return JSONResponse({"admitted": False, "reasons": v.reasons}, status_code=409)
    mac, ips = device_addrs(i.device)
    if not mac:
        return JSONResponse({"admitted": False, "reasons": ["device_not_found_on_lan"]}, status_code=404)
    enf.add_lease(mac, ips, i.ttl)
    lease = {"lease_id": mac, "device": i.device, "ips": ips, "cls": i.cls, "owner": i.owner, "reason": i.reason,
             "granted_at": now, "expires_at": now + i.ttl}
    save(LEASES, active + [lease])
    return {"admitted": True, **lease}


@app.get("/v1/intents", dependencies=[Depends(auth)])
def list_intents():
    return {"kernel": enf.leases(), "registry": [l for l in load(LEASES, []) if l["expires_at"] > time.time()]}


@app.delete("/v1/intents/{lease_id}", dependencies=[Depends(auth)])
def del_intent(lease_id: str):
    ls = load(LEASES, [])
    for l in ls:
        if l["lease_id"] == lease_id:
            enf.del_lease(l["lease_id"], l["ips"])
    save(LEASES, [l for l in ls if l["lease_id"] != lease_id])
    return {"revoked": lease_id}


def poke_controller():
    """SIGUSR1 -> the controller's slow loop classifies now (it picks up overrides.json) instead of at its next 1 s tick.
    Only a live process whose cmdline is the controller is signalled (a stale pid file must never hit another process)."""
    try:
        pid = int(open(os.path.join(STATE_DIR, "ctl.pid")).read())
        if b"halo.controller" in open("/proc/%d/cmdline" % pid, "rb").read():
            os.kill(pid, signal.SIGUSR1)
    except (OSError, ValueError):
        pass


def write_label(o):
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "override_labels.jsonl"), "a") as f:
        f.write(json.dumps({"t": time.time(), **o.model_dump()}) + "\n")


@app.post("/v1/overrides", dependencies=[Depends(auth)])
def override(o: Override, bg: BackgroundTasks):
    """correction of a misclassification: the nft mark is written SYNCHRONOUSLY in the request (one in-process
    libnftables transaction, no exec) and the call returns; the registry write, the controller wake-up (SIGUSR1) and the
    training label happen after the data plane is already correct. Expiry is the kernel's (element timeout) + TTL."""
    if o.cls not in policy.TIN:
        raise HTTPException(422, "cls must be one of %s" % list(policy.TIN))
    t_rx = time.time()
    tin, until = policy.TIN[o.cls], t_rx + o.ttl
    if o.flow:
        key = (o.flow[0], o.flow[1], int(o.flow[2]), o.flow[3], int(o.flow[4]))
        # replace-in-place in ONE atomic transaction (destroy = delete-if-present)
        enf.nft_batch([Enforcer.flow_destroy(key), Enforcer.flow_element(key, tin, o.ttl)])
        name = "|".join(map(str, key))
    elif o.device:
        enf.override_device(o.device, tin, o.ttl)
        name = o.device
    else:
        raise HTTPException(422, "device or flow required")
    t_applied = time.time()
    ov = load(OVR, {})
    ov[name] = {"cls": o.cls, "until": until}
    save(OVR, ov)
    poke_controller()
    bg.add_task(write_label, o)
    return {"applied": True, "tin": policy.TIN_NAME[tin], "expires_at": until, "t_rx": t_rx, "apply_latency_s": round(t_applied - t_rx, 3)}


@app.get("/v1/flows", dependencies=[Depends(auth)])
def flows():
    return load(os.path.join(STATE_DIR, "flows.json"), {"flows": []})


@app.post("/v1/policy", status_code=202, dependencies=[Depends(auth)])
def push_policy(p: Policy):
    req = {k: v for k, v in p.model_dump().items() if v is not None}
    v = policy.shield_policy(req, lim)
    if not v.ok:
        return JSONResponse({"accepted": False, "reasons": v.reasons}, status_code=409)
    save(os.path.join(STATE_DIR, "txn_request.json"), req)
    return {"accepted": True, "transaction": "prepare -> shadow-check -> apply -> read-back -> health window -> commit|rollback"}


@app.get("/v1/state", dependencies=[Depends(auth)])
def state():
    return {"rate_dl": enf.read_rate(LAN), "rate_ul": enf.read_rate(WAN), "lkg": load(os.path.join(STATE_DIR, "lkg.json"), {}).get("hash"),
            "heartbeat": open(os.path.join(STATE_DIR, "heartbeat")).read() if os.path.exists(os.path.join(STATE_DIR, "heartbeat")) else None}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    """Prometheus exposition: shaper rate and CAKE per-tin counters (queue depth, drops, delay)"""
    out = []
    for name, dev in (("download", LAN), ("upload", WAN)):
        q = enf.tin_stats(dev)
        if not q:
            continue
        out.append('halo_shaper_rate_mbit{dir="%s"} %.3f' % (name, q["options"]["bandwidth"] * 8 / 1e6))
        for t, tn in zip(q.get("tins", []), ("bulk", "best_effort", "video", "voice")):
            for k in ("sent_bytes", "backlog_bytes", "drops", "ecn_mark", "peak_delay_us", "avg_delay_us"):
                out.append('halo_tin_%s{dir="%s",tin="%s"} %s' % (k, name, tn, t.get(k, 0)))
    return "\n".join(out) + "\n"


def warm_up():
    """first-request costs (pydantic validation, auth, JSON, the nft library, the threadpool) are paid at start-up,
    not by the first user request: on the emulated gateway they were ~1 s of the first override."""
    try:
        enf.nft_batch([])
        from halo.enforcer import NFT, _fast_ok
        if _fast_ok():
            NFT.available()
        o = Override(device="10.0.0.254", cls="call", ttl=1)
        o.model_dump()
        json.dumps({"a": 1})
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn
    warm_up()
    # NOT niced (deliberate, see docs/PRIORITY_SCHEME.md): the intent API is idle almost always, but user requests
    # (override/lease) must be served promptly; latency comes from the synchronous in-process nft write, not priority
    uvicorn.run(app, host=os.environ.get("HALO_API_BIND", "10.0.0.1"), port=8080, log_level="warning")
